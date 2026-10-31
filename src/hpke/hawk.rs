//! Hawk HPKE: confidentiality from X25519 + ML-KEM-768, authentication from
//! X25519 (paper p.18; byte layout fixed by SPEC §3.5 [CB-8], plus PSK mode
//! for `Device.epoch_storage_key` post-compromise PQ healing under `I16`).
//!
//! Standard mode (`hawk_encrypt` / `hawk_decrypt`, used for MEK distribution):
//! ```text
//! ss1  = X25519(senderAuthPriv, recip.x25519)
//! ss2  = X25519(eph_priv, recip.x25519)
//! (kem_ct, ss3) = ML-KEM-768.Encaps(recip.mlkem)
//! info = "catbird.labyrinth.hawk.v1:" || senderAuthPub || recip.x25519
//!        || sha256(recip.mlkem) || eph_pub || kem_ct
//! key  = kdf(ss1 || ss2 || ss3, MINOS_SALT, info)
//! out  = 0x01 || eph_pub || kem_ct || AES-256-GCM(key, 0^12, aad, pt)
//! ```
//!
//! PSK mode (`hawk_encrypt_with_psk` / `hawk_decrypt_with_psk`, used for
//! `EpochMember.encrypted_entropy` under `epoch_storage_key`):
//! ```text
//! info = "catbird.labyrinth.hawk.psk.v1:" || senderAuthPub || recip.x25519
//!        || sha256(recip.mlkem) || eph_pub || kem_ct || aad
//! key  = kdf(ss1 || ss2 || ss3, salt = psk, info)
//! out  = 0x01 || eph_pub || kem_ct || AES-256-GCM(key, 0^12, aad, pt)
//! ```

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{B32, Seed};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{X25519Public, X25519Secret, prims};
use crate::Error;

/// ML-KEM-768 encapsulation key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;
/// Encoded [`HawkEncPublic`] length (`32 + 1184 = 1216`).
pub const HAWK_ENC_PUBLIC_LEN: usize = 32 + MLKEM768_EK_LEN;
/// Encoded [`HawkEncSecret`] length (`32 + 64 = 96`).
pub const HAWK_ENC_SECRET_LEN: usize = 32 + 64;
/// Maximum pre-shared key length for [`hawk_encrypt_with_psk`].
pub const MAX_PSK_LEN: usize = 32;
/// Version byte that prefixes every Hawk ciphertext.
pub const VERSION: u8 = 0x01;
const HEADER_LEN: usize = 1 + 32 + MLKEM768_CT_LEN;
const TAG_LEN: usize = 16;
const INFO_PREFIX: &[u8] = b"catbird.labyrinth.hawk.v1:";
const INFO_PSK_PREFIX: &[u8] = b"catbird.labyrinth.hawk.psk.v1:";
const INFO_AUTH_X25519: &[u8] = b"catbird.labyrinth.hawk.auth.x25519";
const INFO_ENC_X25519: &[u8] = b"catbird.labyrinth.hawk.enc.x25519";
const INFO_ENC_MLKEM: &[u8] = b"catbird.labyrinth.hawk.enc.mlkem768";

/// Hawk authentication keypair = X25519.
pub type HawkAuthSecret = X25519Secret;
pub type HawkAuthPublic = X25519Public;

/// Hawk encryption public key: `x25519(32) || mlkem768_ek(1184)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HawkEncPublic {
    pub x25519: X25519Public,
    pub mlkem: Vec<u8>,
}

/// Hawk encryption private key: the X25519 private key plus the 64-byte
/// ML-KEM-768 seed `d || z` (FIPS 203 `KeyGen_internal` inputs).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HawkEncSecret {
    pub(crate) x25519: X25519Secret,
    pub(crate) mlkem_seed: [u8; 64],
}

impl HawkEncPublic {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HAWK_ENC_PUBLIC_LEN);
        out.extend_from_slice(&self.x25519.0);
        out.extend_from_slice(&self.mlkem);
        out
    }

    /// Parses and validates (FIPS 203 encapsulation-key modulus check) the
    /// encoding produced by [`HawkEncPublic::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> crate::Result<Self> {
        if b.len() != HAWK_ENC_PUBLIC_LEN {
            return Err(Error::Malformed("hawk enc public key length"));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[..32]);
        let pk = Self {
            x25519: X25519Public(x),
            mlkem: b[32..].to_vec(),
        };
        pk.mlkem_ek()?;
        Ok(pk)
    }

    /// Re-validates the in-memory ML-KEM-768 encapsulation key against FIPS 203.
    pub fn validate(&self) -> crate::Result<()> {
        let _ = self.mlkem_ek()?;
        Ok(())
    }

    fn mlkem_ek(&self) -> crate::Result<EncapsulationKey> {
        let arr = Array::try_from(self.mlkem.as_slice()).map_err(|_| Error::BadPublicKey)?;
        EncapsulationKey::new(&arr).map_err(|_| Error::BadPublicKey)
    }
}

impl HawkEncSecret {
    /// Serializes `x25519(32) || mlkem_seed(64)` into 96 bytes.
    pub fn to_bytes(&self) -> [u8; HAWK_ENC_SECRET_LEN] {
        let mut out = [0u8; HAWK_ENC_SECRET_LEN];
        out[..32].copy_from_slice(&self.x25519.0);
        out[32..].copy_from_slice(&self.mlkem_seed);
        out
    }

    /// Restores from the 96-byte `x25519(32) || mlkem_seed(64)` representation.
    pub fn from_bytes(mut b: [u8; HAWK_ENC_SECRET_LEN]) -> Self {
        let mut x = [0u8; 32];
        let mut mlkem_seed = [0u8; 64];
        x.copy_from_slice(&b[..32]);
        mlkem_seed.copy_from_slice(&b[32..]);
        b.zeroize();
        let s = Self {
            x25519: X25519Secret(x),
            mlkem_seed,
        };
        x.zeroize();
        mlkem_seed.zeroize();
        s
    }

    /// Parses from a slice, requiring exactly [`HAWK_ENC_SECRET_LEN`] (96) bytes.
    pub fn from_slice(b: &[u8]) -> crate::Result<Self> {
        let arr: [u8; HAWK_ENC_SECRET_LEN] = b
            .try_into()
            .map_err(|_| Error::Malformed("hawk enc secret length"))?;
        Ok(Self::from_bytes(arr))
    }

    pub fn public(&self) -> HawkEncPublic {
        HawkEncPublic {
            x25519: self.x25519.public(),
            mlkem: self.mlkem_dk().encapsulation_key().to_bytes().to_vec(),
        }
    }

    fn mlkem_dk(&self) -> DecapsulationKey {
        DecapsulationKey::from_seed(Seed::from(self.mlkem_seed))
    }
}

pub fn hawk_auth_keygen() -> crate::Result<(HawkAuthSecret, HawkAuthPublic)> {
    let s = X25519Secret::generate()?;
    let p = s.public();
    Ok((s, p))
}

pub fn hawk_enc_keygen() -> crate::Result<(HawkEncSecret, HawkEncPublic)> {
    let x25519 = X25519Secret::generate()?;
    let mut mlkem_seed = [0u8; 64];
    prims::random(&mut mlkem_seed)?;
    let s = HawkEncSecret { x25519, mlkem_seed };
    mlkem_seed.zeroize();
    let p = s.public();
    Ok((s, p))
}

/// `priv = kdf(seed, MINOS_SALT, "catbird.labyrinth.hawk.auth.x25519")`.
pub fn hawk_derive_auth(seed: &[u8; 32]) -> (HawkAuthSecret, HawkAuthPublic) {
    let s = X25519Secret(prims::kdf32(
        seed,
        Some(&prims::minos_salt()),
        INFO_AUTH_X25519,
    ));
    let p = s.public();
    (s, p)
}

/// X25519 from `kdf(seed, MINOS_SALT, "…enc.x25519")`; ML-KEM-768 from
/// `(d, z) = kdf(seed, MINOS_SALT, "…enc.mlkem768", 64)`.
pub fn hawk_derive_enc(seed: &[u8; 32]) -> (HawkEncSecret, HawkEncPublic) {
    let salt = prims::minos_salt();
    let x25519 = X25519Secret(prims::kdf32(seed, Some(&salt), INFO_ENC_X25519));
    let mut mlkem_seed = [0u8; 64];
    prims::kdf(seed, Some(&salt), INFO_ENC_MLKEM, &mut mlkem_seed);
    let s = HawkEncSecret { x25519, mlkem_seed };
    mlkem_seed.zeroize();
    let p = s.public();
    (s, p)
}

pub fn hawk_encrypt(
    recipient: &HawkEncPublic,
    sender_auth_priv: &HawkAuthSecret,
    sender_auth_pub: &HawkAuthPublic,
    aad: &[u8],
    pt: &[u8],
) -> crate::Result<Vec<u8>> {
    let eph = X25519Secret::generate()?;
    let mut m = Zeroizing::new([0u8; 32]);
    prims::random(&mut *m)?;
    hawk_encrypt_deterministic(
        recipient,
        sender_auth_priv,
        sender_auth_pub,
        aad,
        pt,
        &eph,
        &m,
    )
}

/// [`hawk_encrypt`] with caller-chosen ephemeral X25519 key and ML-KEM
/// encapsulation randomness `m` (KATs only).
pub(crate) fn hawk_encrypt_deterministic(
    recipient: &HawkEncPublic,
    sender_auth_priv: &HawkAuthSecret,
    sender_auth_pub: &HawkAuthPublic,
    aad: &[u8],
    pt: &[u8],
    eph: &X25519Secret,
    m: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    let ek = recipient.mlkem_ek()?;
    let eph_pub = eph.public();
    let ss1 = sender_auth_priv.dh(&recipient.x25519)?;
    let ss2 = eph.dh(&recipient.x25519)?;
    let (kem_ct, ss3) = ek.encapsulate_deterministic(&B32::from(*m));
    let ss3 = Zeroizing::new(<[u8; 32]>::from(ss3));
    let key = derive_key(
        &ss1,
        &ss2,
        &ss3,
        sender_auth_pub,
        recipient,
        &eph_pub,
        kem_ct.as_slice(),
    );
    let ct = prims::aes256gcm_zero_nonce_seal(&key, aad, pt)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&eph_pub.0);
    out.extend_from_slice(kem_ct.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn hawk_decrypt(
    recipient_pub: &HawkEncPublic,
    recipient_priv: &HawkEncSecret,
    sender_auth_pub: &HawkAuthPublic,
    aad: &[u8],
    ct: &[u8],
) -> crate::Result<Vec<u8>> {
    if ct.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Malformed("hawk ciphertext too short"));
    }
    if ct[0] != VERSION {
        return Err(Error::Unsupported(ct[0]));
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&ct[1..33]);
    let eph_pub = X25519Public(eph);
    let kem_ct_bytes = &ct[33..HEADER_LEN];
    let kem_ct = Ciphertext::try_from(kem_ct_bytes).map_err(|_| Error::Malformed("kem ct"))?;

    let ss1 = recipient_priv.x25519.dh(sender_auth_pub)?;
    let ss2 = recipient_priv.x25519.dh(&eph_pub)?;
    let ss3 = Zeroizing::new(<[u8; 32]>::from(
        recipient_priv.mlkem_dk().decapsulate(&kem_ct),
    ));
    let key = derive_key(
        &ss1,
        &ss2,
        &ss3,
        sender_auth_pub,
        recipient_pub,
        &eph_pub,
        kem_ct_bytes,
    );
    prims::aes256gcm_zero_nonce_open(&key, aad, &ct[HEADER_LEN..])
}

/// Seal `pt` under `X25519 + ML-KEM-768` AND `psk` (`psk.len() <= 32`) for
/// post-compromise PQ healing of `EpochMember.encrypted_entropy` (`I16`).
pub fn hawk_encrypt_with_psk(
    recipient: &HawkEncPublic,
    sender_auth_priv: &HawkAuthSecret,
    sender_auth_pub: &HawkAuthPublic,
    psk: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> crate::Result<Vec<u8>> {
    let eph = X25519Secret::generate()?;
    let mut m = Zeroizing::new([0u8; 32]);
    prims::random(&mut *m)?;
    hawk_encrypt_with_psk_deterministic(
        recipient,
        sender_auth_priv,
        sender_auth_pub,
        psk,
        aad,
        pt,
        &eph,
        &m,
    )
}

pub(crate) fn hawk_encrypt_with_psk_deterministic(
    recipient: &HawkEncPublic,
    sender_auth_priv: &HawkAuthSecret,
    sender_auth_pub: &HawkAuthPublic,
    psk: &[u8],
    aad: &[u8],
    pt: &[u8],
    eph: &X25519Secret,
    m: &[u8; 32],
) -> crate::Result<Vec<u8>> {
    if psk.len() > MAX_PSK_LEN {
        return Err(Error::Malformed("psk longer than 32 bytes"));
    }
    let ek = recipient.mlkem_ek()?;
    let eph_pub = eph.public();
    let ss1 = sender_auth_priv.dh(&recipient.x25519)?;
    let ss2 = eph.dh(&recipient.x25519)?;
    let (kem_ct, ss3) = ek.encapsulate_deterministic(&B32::from(*m));
    let ss3 = Zeroizing::new(<[u8; 32]>::from(ss3));
    let key = derive_key_with_psk(
        &ss1,
        &ss2,
        &ss3,
        psk,
        sender_auth_pub,
        recipient,
        &eph_pub,
        kem_ct.as_slice(),
        aad,
    );
    let ct = prims::aes256gcm_zero_nonce_seal(&key, aad, pt)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&eph_pub.0);
    out.extend_from_slice(kem_ct.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`hawk_encrypt_with_psk`].
pub fn hawk_decrypt_with_psk(
    recipient_pub: &HawkEncPublic,
    recipient_priv: &HawkEncSecret,
    sender_auth_pub: &HawkAuthPublic,
    psk: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> crate::Result<Vec<u8>> {
    if psk.len() > MAX_PSK_LEN {
        return Err(Error::Malformed("psk longer than 32 bytes"));
    }
    if ct.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Malformed("hawk ciphertext too short"));
    }
    if ct[0] != VERSION {
        return Err(Error::Unsupported(ct[0]));
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&ct[1..33]);
    let eph_pub = X25519Public(eph);
    let kem_ct_bytes = &ct[33..HEADER_LEN];
    let kem_ct = Ciphertext::try_from(kem_ct_bytes).map_err(|_| Error::Malformed("kem ct"))?;

    let ss1 = recipient_priv.x25519.dh(sender_auth_pub)?;
    let ss2 = recipient_priv.x25519.dh(&eph_pub)?;
    let ss3 = Zeroizing::new(<[u8; 32]>::from(
        recipient_priv.mlkem_dk().decapsulate(&kem_ct),
    ));
    let key = derive_key_with_psk(
        &ss1,
        &ss2,
        &ss3,
        psk,
        sender_auth_pub,
        recipient_pub,
        &eph_pub,
        kem_ct_bytes,
        aad,
    );
    prims::aes256gcm_zero_nonce_open(&key, aad, &ct[HEADER_LEN..])
}

fn derive_key(
    ss1: &[u8; 32],
    ss2: &[u8; 32],
    ss3: &[u8; 32],
    sender_auth_pub: &X25519Public,
    recipient: &HawkEncPublic,
    eph_pub: &X25519Public,
    kem_ct: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[..32].copy_from_slice(ss1);
    ikm[32..64].copy_from_slice(ss2);
    ikm[64..].copy_from_slice(ss3);
    let mut info = Vec::with_capacity(INFO_PREFIX.len() + 32 * 4 + kem_ct.len());
    info.extend_from_slice(INFO_PREFIX);
    info.extend_from_slice(&sender_auth_pub.0);
    info.extend_from_slice(&recipient.x25519.0);
    info.extend_from_slice(&prims::sha256(&recipient.mlkem));
    info.extend_from_slice(&eph_pub.0);
    info.extend_from_slice(kem_ct);
    Zeroizing::new(prims::kdf32(&*ikm, Some(&prims::minos_salt()), &info))
}

#[allow(clippy::too_many_arguments)]
fn derive_key_with_psk(
    ss1: &[u8; 32],
    ss2: &[u8; 32],
    ss3: &[u8; 32],
    psk: &[u8],
    sender_auth_pub: &X25519Public,
    recipient: &HawkEncPublic,
    eph_pub: &X25519Public,
    kem_ct: &[u8],
    aad: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[..32].copy_from_slice(ss1);
    ikm[32..64].copy_from_slice(ss2);
    ikm[64..].copy_from_slice(ss3);
    let mut info = Vec::with_capacity(INFO_PSK_PREFIX.len() + 32 * 4 + kem_ct.len() + aad.len());
    info.extend_from_slice(INFO_PSK_PREFIX);
    info.extend_from_slice(&sender_auth_pub.0);
    info.extend_from_slice(&recipient.x25519.0);
    info.extend_from_slice(&prims::sha256(&recipient.mlkem));
    info.extend_from_slice(&eph_pub.0);
    info.extend_from_slice(kem_ct);
    info.extend_from_slice(aad);
    Zeroizing::new(prims::kdf32(&*ikm, Some(psk), &info))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_layout() {
        let (rs, rp) = hawk_enc_keygen().unwrap();
        let (ss, sp) = hawk_auth_keygen().unwrap();
        let ct = hawk_encrypt(&rp, &ss, &sp, b"aad", b"mek-bytes").unwrap();
        assert_eq!(ct.len(), 1 + 32 + MLKEM768_CT_LEN + 9 + 16);
        assert_eq!(
            hawk_decrypt(&rp, &rs, &sp, b"aad", &ct).unwrap(),
            b"mek-bytes"
        );
        assert_eq!(rs.public(), rp);
        assert_eq!(rp.mlkem.len(), MLKEM768_EK_LEN);

        // PSK round-trip + secret serialization round-trip.
        let rebuilt = HawkEncSecret::from_bytes(rs.to_bytes());
        assert_eq!(rebuilt.public(), rp);
        for psk in [&[][..], &[7u8; 16][..], &[9u8; 32][..]] {
            let ct_psk =
                hawk_encrypt_with_psk(&rp, &ss, &sp, psk, b"epoch__1", b"entropy").unwrap();
            assert_eq!(
                hawk_decrypt_with_psk(&rp, &rebuilt, &sp, psk, b"epoch__1", &ct_psk).unwrap(),
                b"entropy"
            );
        }
        assert_eq!(
            hawk_encrypt_with_psk(&rp, &ss, &sp, &[0u8; 33], b"", b"").unwrap_err(),
            Error::Malformed("psk longer than 32 bytes")
        );
    }

    #[test]
    fn derive_enc_mlkem_seed_is_kdf_output() {
        let (s, _) = hawk_derive_enc(&[3u8; 32]);
        let mut expect = [0u8; 64];
        prims::kdf(
            &[3u8; 32],
            Some(&prims::minos_salt()),
            INFO_ENC_MLKEM,
            &mut expect,
        );
        assert_eq!(s.mlkem_seed, expect);
        assert_eq!(s.mlkem_dk().to_seed().unwrap().as_slice(), &expect[..]);
    }

    #[test]
    fn from_bytes_rejects_bad_lengths_and_ek() {
        let (_, p) = hawk_derive_enc(&[1u8; 32]);
        let bytes = p.to_bytes();
        assert!(HawkEncPublic::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut bad = bytes.clone();
        bad[32] = 0xff;
        bad[33] |= 0x0f;
        assert_eq!(
            HawkEncPublic::from_bytes(&bad).unwrap_err(),
            Error::BadPublicKey
        );
    }
}

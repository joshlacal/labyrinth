//! Labyrinth HPKE exactly as in paper p.17 (SPEC §3.4).
//!
//! ```text
//! fresh     = X25519(sender_auth_priv, recip_enc_pub) || X25519(eph_priv, recip_enc_pub)
//! inner_aad = 0x01 || sender_auth_pub || recip_enc_pub || eph_pub || aad
//! subkey    = kdf(fresh, salt = psk, info = inner_aad)
//! ct        = AES-256-GCM(subkey, nonce = 0^12, aad, pt)
//! out       = 0x01 || eph_pub || ct
//! ```

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;

/// Version byte that prefixes every Labyrinth HPKE ciphertext and `inner_aad`.
pub const VERSION: u8 = 0x01;
/// Maximum pre-shared key length (paper p.17).
pub const MAX_PSK_LEN: usize = 32;
/// `version(1) || eph_pub(32)`.
const HEADER_LEN: usize = 1 + 32;
/// AES-GCM tag length.
const TAG_LEN: usize = 16;

/// X25519 private key. Stored as the raw 32 bytes; clamping happens at use.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret(pub(crate) [u8; 32]);

/// X25519 public key (Montgomery u-coordinate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct X25519Public(pub [u8; 32]);

impl X25519Secret {
    /// Fresh key from the OS CSPRNG.
    pub fn generate() -> crate::Result<Self> {
        let mut b = [0u8; 32];
        prims::random(&mut b)?;
        let s = Self(b);
        b.zeroize();
        Ok(s)
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    pub fn public(&self) -> X25519Public {
        X25519Public(PublicKey::from(&StaticSecret::from(self.0)).to_bytes())
    }

    /// X25519 with contributory check: an all-zero output (i.e. `peer` is a
    /// low-order point) is rejected with [`Error::BadPublicKey`].
    pub(crate) fn dh(&self, peer: &X25519Public) -> crate::Result<Zeroizing<[u8; 32]>> {
        let ss = StaticSecret::from(self.0).diffie_hellman(&PublicKey::from(peer.0));
        if !ss.was_contributory() {
            return Err(Error::BadPublicKey);
        }
        Ok(Zeroizing::new(ss.to_bytes()))
    }
}

/// `labyrinth_hpke_encrypt`. `psk.len() <= 32`.
///
/// The psk is used verbatim as the HKDF salt. An empty psk therefore means an
/// empty salt, which HKDF-SHA256 treats identically to its default salt of 32
/// zero bytes (HMAC pads short keys with zeros), so "no psk" and "empty psk"
/// are the same thing.
pub fn encrypt(
    recipient_enc_pub: &X25519Public,
    sender_auth_pub: &X25519Public,
    sender_auth_priv: &X25519Secret,
    psk: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> crate::Result<Vec<u8>> {
    let eph = X25519Secret::generate()?;
    encrypt_with_ephemeral(
        recipient_enc_pub,
        sender_auth_pub,
        sender_auth_priv,
        psk,
        aad,
        pt,
        &eph,
    )
}

/// [`encrypt`] with a caller-chosen ephemeral key (KATs only).
pub(crate) fn encrypt_with_ephemeral(
    recipient_enc_pub: &X25519Public,
    sender_auth_pub: &X25519Public,
    sender_auth_priv: &X25519Secret,
    psk: &[u8],
    aad: &[u8],
    pt: &[u8],
    eph: &X25519Secret,
) -> crate::Result<Vec<u8>> {
    if psk.len() > MAX_PSK_LEN {
        return Err(Error::Malformed("psk longer than 32 bytes"));
    }
    let eph_pub = eph.public();
    let id_id = sender_auth_priv.dh(recipient_enc_pub)?;
    let id_eph = eph.dh(recipient_enc_pub)?;
    let key = subkey(
        &id_id,
        &id_eph,
        psk,
        sender_auth_pub,
        recipient_enc_pub,
        &eph_pub,
        aad,
    );
    let ct = prims::aes256gcm_zero_nonce_seal(&key, aad, pt)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.push(VERSION);
    out.extend_from_slice(&eph_pub.0);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`encrypt`].
pub fn decrypt(
    recipient_enc_pub: &X25519Public,
    recipient_enc_priv: &X25519Secret,
    sender_auth_pub: &X25519Public,
    psk: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> crate::Result<Vec<u8>> {
    if psk.len() > MAX_PSK_LEN {
        return Err(Error::Malformed("psk longer than 32 bytes"));
    }
    if ct.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Malformed("labyrinth hpke ciphertext too short"));
    }
    if ct[0] != VERSION {
        return Err(Error::Unsupported(ct[0]));
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&ct[1..HEADER_LEN]);
    let eph_pub = X25519Public(eph);
    let id_id = recipient_enc_priv.dh(sender_auth_pub)?;
    let id_eph = recipient_enc_priv.dh(&eph_pub)?;
    let key = subkey(
        &id_id,
        &id_eph,
        psk,
        sender_auth_pub,
        recipient_enc_pub,
        &eph_pub,
        aad,
    );
    prims::aes256gcm_zero_nonce_open(&key, aad, &ct[HEADER_LEN..])
}

fn subkey(
    id_id: &[u8; 32],
    id_eph: &[u8; 32],
    psk: &[u8],
    sender_auth_pub: &X25519Public,
    recipient_enc_pub: &X25519Public,
    eph_pub: &X25519Public,
    aad: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut fresh = Zeroizing::new([0u8; 64]);
    fresh[..32].copy_from_slice(id_id);
    fresh[32..].copy_from_slice(id_eph);
    let mut inner_aad = Vec::with_capacity(1 + 96 + aad.len());
    inner_aad.push(VERSION);
    inner_aad.extend_from_slice(&sender_auth_pub.0);
    inner_aad.extend_from_slice(&recipient_enc_pub.0);
    inner_aad.extend_from_slice(&eph_pub.0);
    inner_aad.extend_from_slice(aad);
    Zeroizing::new(prims::kdf32(&*fresh, Some(psk), &inner_aad))
}

/// Primitive helpers used by `hpke` and `orf` while `crate::encoding` is
/// being written in parallel.
///
/// TODO(integration): replace each helper marked below with the matching
/// `crate::encoding::…` function and delete this module. The AES-256-GCM
/// zero-nonce helpers stay: plain GCM is not one of the `crate::aead` suites.
pub(crate) mod prims {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256, Sha512};

    use crate::Error;

    // TODO(integration): replace with crate::encoding::kdf
    pub(crate) fn kdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) {
        hkdf::Hkdf::<Sha256>::new(salt, ikm)
            .expand(info, out)
            .expect("HKDF output length within 255*32");
    }

    // TODO(integration): replace with crate::encoding::kdf32
    pub(crate) fn kdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        kdf(ikm, salt, info, &mut out);
        out
    }

    // TODO(integration): replace with crate::encoding::mac
    /// `mac(data, key)` = HMAC-SHA256(key, data).
    pub(crate) fn mac(data: &[u8], key: &[u8]) -> [u8; 32] {
        let mut m =
            <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
        m.update(data);
        m.finalize().into_bytes().into()
    }

    // TODO(integration): replace with crate::encoding::sha256
    pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    pub(crate) fn sha512(data: &[u8]) -> [u8; 64] {
        Sha512::digest(data).into()
    }

    // TODO(integration): replace with crate::encoding::minos_salt
    pub(crate) fn minos_salt() -> [u8; 32] {
        sha256(b"minos encrypted backup protocol\n")
    }

    // TODO(integration): replace with crate::encoding::random
    pub(crate) fn random(out: &mut [u8]) -> crate::Result<()> {
        getrandom::fill(out).map_err(|_| Error::Rng)
    }

    /// AES-256-GCM with the all-zero 96-bit nonce. Safe only because every
    /// key passed here is single-use (derived from a fresh ephemeral DH).
    pub(crate) fn aes256gcm_zero_nonce_seal(
        key: &[u8; 32],
        aad: &[u8],
        pt: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Malformed("aes key"))?;
        cipher
            .encrypt(&Nonce::default(), Payload { msg: pt, aad })
            .map_err(|_| Error::Malformed("aes-gcm encrypt"))
    }

    pub(crate) fn aes256gcm_zero_nonce_open(
        key: &[u8; 32],
        aad: &[u8],
        ct: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Malformed("aes key"))?;
        cipher
            .decrypt(&Nonce::default(), Payload { msg: ct, aad })
            .map_err(|_| Error::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> (X25519Secret, X25519Public) {
        let s = X25519Secret::generate().unwrap();
        let p = s.public();
        (s, p)
    }

    #[test]
    fn round_trip_and_psk_lengths() {
        let (rs, rp) = kp();
        let (ss, sp) = kp();
        for psk in [&[][..], &[7u8; 1][..], &[9u8; 32][..]] {
            let ct = encrypt(&rp, &sp, &ss, psk, b"aad", b"hello").unwrap();
            assert_eq!(ct[0], VERSION);
            assert_eq!(ct.len(), 1 + 32 + 5 + 16);
            assert_eq!(decrypt(&rp, &rs, &sp, psk, b"aad", &ct).unwrap(), b"hello");
        }
        assert_eq!(
            encrypt(&rp, &sp, &ss, &[0u8; 33], b"", b"").unwrap_err(),
            Error::Malformed("psk longer than 32 bytes")
        );
    }

    #[test]
    fn empty_psk_equals_default_salt() {
        assert_eq!(
            prims::kdf32(b"ikm", Some(&[]), b"info"),
            prims::kdf32(b"ikm", None, b"info")
        );
        assert_eq!(
            prims::kdf32(b"ikm", Some(&[0u8; 32]), b"info"),
            prims::kdf32(b"ikm", None, b"info")
        );
    }

    #[test]
    fn bad_version_byte() {
        let (rs, rp) = kp();
        let (ss, sp) = kp();
        let mut ct = encrypt(&rp, &sp, &ss, b"", b"", b"x").unwrap();
        ct[0] = 0x02;
        assert_eq!(
            decrypt(&rp, &rs, &sp, b"", b"", &ct).unwrap_err(),
            Error::Unsupported(2)
        );
        assert!(matches!(
            decrypt(&rp, &rs, &sp, b"", b"", &ct[..40]),
            Err(Error::Malformed(_))
        ));
    }
}

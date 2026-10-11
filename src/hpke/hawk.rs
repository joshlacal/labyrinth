//! Hawk HPKE: confidentiality from X25519 + ML-KEM-768, authentication from
//! X25519 (paper p.18; byte layout fixed by SPEC §3.5 [CB-8]).
//!
//! ```text
//! ss1  = X25519(senderAuthPriv, recip.x25519)
//! ss2  = X25519(eph_priv, recip.x25519)
//! (kem_ct, ss3) = ML-KEM-768.Encaps(recip.mlkem)
//! info = "catbird.labyrinth.hawk.v1:" || senderAuthPub || recip.x25519
//!        || sha256(recip.mlkem) || eph_pub || kem_ct
//! key  = kdf(ss1 || ss2 || ss3, MINOS_SALT, info)
//! out  = 0x01 || eph_pub || kem_ct || AES-256-GCM(key, 0^12, aad, pt)
//! ```

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{B32, Seed};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::labyrinth::{X25519Public, X25519Secret, prims};
use crate::Error;

/// ML-KEM-768 encapsulation key length.
pub const MLKEM768_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const MLKEM768_CT_LEN: usize = 1088;
/// Encoded [`HawkEncPublic`] length.
pub const HAWK_ENC_PUBLIC_LEN: usize = 32 + MLKEM768_EK_LEN;
/// Version byte that prefixes every Hawk ciphertext.
pub const VERSION: u8 = 0x01;
const HEADER_LEN: usize = 1 + 32 + MLKEM768_CT_LEN;
const TAG_LEN: usize = 16;
const INFO_PREFIX: &[u8] = b"catbird.labyrinth.hawk.v1:";
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

    fn mlkem_ek(&self) -> crate::Result<EncapsulationKey> {
        let arr = Array::try_from(self.mlkem.as_slice()).map_err(|_| Error::BadPublicKey)?;
        EncapsulationKey::new(&arr).map_err(|_| Error::BadPublicKey)
    }
}

impl HawkEncSecret {
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
    // ML-KEM decapsulation uses implicit rejection: a tampered kem_ct yields
    // an unrelated ss3 and the AEAD below fails.
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
        // The DecapsulationKey round-trips its seed as d || z.
        assert_eq!(s.mlkem_dk().to_seed().unwrap().as_slice(), &expect[..]);
    }

    #[test]
    fn from_bytes_rejects_bad_lengths_and_ek() {
        let (_, p) = hawk_derive_enc(&[1u8; 32]);
        let bytes = p.to_bytes();
        assert!(HawkEncPublic::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        // Coefficient 0xFFF >= q = 3329 fails the FIPS 203 modulus check.
        let mut bad = bytes.clone();
        bad[32] = 0xff;
        bad[33] |= 0x0f;
        assert_eq!(
            HawkEncPublic::from_bytes(&bad).unwrap_err(),
            Error::BadPublicKey
        );
    }
}

/// Regression KATs in `tests/vectors/hpke_orf.json`.
///
/// Regenerate with
/// `LABYRINTH_REGEN_KATS=1 cargo test --lib kat::regenerate -- --ignored`.
/// `kat::encrypt_matches` checks that the deterministic encrypt paths still
/// reproduce the committed ciphertexts; `tests/hpke_orf.rs` checks the rest
/// through the public API.
#[cfg(test)]
mod kat {
    use super::*;
    use crate::hpke::labyrinth;
    use crate::orf;
    use serde_json::{Value, json};

    /// `(name, domain/psk, domain/aad, input/pt)`.
    type Case4 = (&'static str, &'static [u8], &'static [u8], &'static [u8]);

    const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/hpke_orf.json");

    fn label(l: &str) -> [u8; 32] {
        prims::sha256(format!("catbird.labyrinth.kat/{l}").as_bytes())
    }

    fn h(v: &Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap()).unwrap()
    }

    fn a32(v: &Value, k: &str) -> [u8; 32] {
        h(v, k).try_into().unwrap()
    }

    fn labyrinth_cases() -> Vec<Value> {
        let inputs: [Case4; 3] = [
            ("empty-psk", b"", b"", b""),
            (
                "psk-16",
                &[0x42; 16],
                b"epoch__7",
                b"32 bytes of fresh epoch entropy",
            ),
            ("psk-32", &[0xa5; 32], b"some aad", &[0x11; 100]),
        ];
        inputs
            .iter()
            .map(|(name, psk, aad, pt)| {
                let sa = X25519Secret(label(&format!("{name}/sender_auth")));
                let r = X25519Secret(label(&format!("{name}/recipient_enc")));
                let e = X25519Secret(label(&format!("{name}/ephemeral")));
                let ct = labyrinth::encrypt_with_ephemeral(
                    &r.public(),
                    &sa.public(),
                    &sa,
                    psk,
                    aad,
                    pt,
                    &e,
                )
                .unwrap();
                json!({
                    "name": name,
                    "sender_auth_priv": hex::encode(sa.0),
                    "sender_auth_pub": hex::encode(sa.public().0),
                    "recipient_enc_priv": hex::encode(r.0),
                    "recipient_enc_pub": hex::encode(r.public().0),
                    "ephemeral_priv": hex::encode(e.0),
                    "psk": hex::encode(psk),
                    "aad": hex::encode(aad),
                    "pt": hex::encode(pt),
                    "ct": hex::encode(ct),
                })
            })
            .collect()
    }

    fn hawk_cases() -> Vec<Value> {
        let inputs: [(&str, &[u8], &[u8]); 2] = [
            ("empty", b"", b""),
            (
                "mek",
                b"minos.hpke.mek_distribution_from_minos_v2:mek_id=00",
                &[0x5a; 32],
            ),
        ];
        inputs
            .iter()
            .map(|(name, aad, pt)| {
                let auth_seed = label(&format!("hawk-{name}/auth_seed"));
                let enc_seed = label(&format!("hawk-{name}/enc_seed"));
                let (sa, sp) = hawk_derive_auth(&auth_seed);
                let (rs, rp) = hawk_derive_enc(&enc_seed);
                let e = X25519Secret(label(&format!("hawk-{name}/ephemeral")));
                let m = label(&format!("hawk-{name}/mlkem_m"));
                let ct = hawk_encrypt_deterministic(&rp, &sa, &sp, aad, pt, &e, &m).unwrap();
                json!({
                    "name": name,
                    "auth_seed": hex::encode(auth_seed),
                    "auth_priv": hex::encode(sa.0),
                    "auth_pub": hex::encode(sp.0),
                    "enc_seed": hex::encode(enc_seed),
                    "enc_x25519_priv": hex::encode(rs.x25519.0),
                    "enc_mlkem_seed": hex::encode(rs.mlkem_seed),
                    "enc_pub": hex::encode(rp.to_bytes()),
                    "ephemeral_priv": hex::encode(e.0),
                    "mlkem_m": hex::encode(m),
                    "aad": hex::encode(aad),
                    "pt": hex::encode(pt),
                    "ct": hex::encode(ct),
                })
            })
            .collect()
    }

    /// Scalars from labels, reduced mod l so they are canonical.
    fn scalar(l: &str) -> [u8; 32] {
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&prims::sha512(
            format!("catbird.labyrinth.kat/{l}").as_bytes(),
        ));
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&wide).to_bytes()
    }

    fn orf_cases() -> Vec<Value> {
        let inputs: [Case4; 2] = [
            (
                "attachment-key",
                b"attachment_key_scope",
                b"attachment_key_scope",
                b"[\"backup-1\",\"object-1\"]",
            ),
            ("token-salt", b"attachment_token_salt_scope", b"server", b""),
        ];
        inputs
            .iter()
            .map(|(name, cd, sd, input)| {
                let c =
                    orf::OrfClientState::from_bytes(scalar(&format!("orf-{name}/client"))).unwrap();
                let s =
                    orf::OrfServerState::from_bytes(scalar(&format!("orf-{name}/server"))).unwrap();
                let r = scalar(&format!("orf-{name}/token"));
                let id = orf::orf_client_map(&c, cd, input);
                let out = orf::orf_server_map(&s, sd, &id).unwrap();
                let s2 = orf::orf_server_evolve(&s, &orf::EvolveToken(r)).unwrap();
                json!({
                    "name": name,
                    "client_state": hex::encode(c.to_bytes()),
                    "server_state": hex::encode(s.to_bytes()),
                    "client_domain": hex::encode(cd),
                    "server_domain": hex::encode(sd),
                    "input": hex::encode(input),
                    "oblivious_id": hex::encode(id.0),
                    "output": hex::encode(out),
                    "evolve_token": hex::encode(r),
                    "evolved_server_state": hex::encode(s2.to_bytes()),
                })
            })
            .collect()
    }

    fn all() -> Value {
        json!({
            "description": "Catbird Labyrinth regression KATs (not Meta vectors): Labyrinth HPKE (SPEC §3.4), Hawk HPKE (§3.5), ORF (§3.6). Inputs are sha256/sha512 of 'catbird.labyrinth.kat/<label>'. All byte fields are lowercase hex.",
            "labyrinth_hpke": labyrinth_cases(),
            "hawk_hpke": hawk_cases(),
            "orf": orf_cases(),
        })
    }

    #[test]
    #[ignore]
    fn regenerate() {
        if std::env::var_os("LABYRINTH_REGEN_KATS").is_none() {
            return;
        }
        let s = serde_json::to_string_pretty(&all()).unwrap() + "\n";
        std::fs::write(PATH, s).unwrap();
    }

    /// Every value the generator would produce matches the committed file.
    #[test]
    fn encrypt_matches() {
        let committed: Value =
            serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
        assert_eq!(all(), committed);
        // Spot-check the fields really drive the derivation.
        let c = &committed["hawk_hpke"][0];
        let (rs, _) = hawk_derive_enc(&a32(c, "enc_seed"));
        assert_eq!(rs.mlkem_seed.to_vec(), h(c, "enc_mlkem_seed"));
    }
}

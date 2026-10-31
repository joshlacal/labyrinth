//! Hybrid Post-Quantum One-Time-Code (`OTC`) device transfer (SPEC §6.5, `I16`).
//!
//! Combines CPace over ristretto255 / SHA-512 (`draft-irtf-cfrg-cpace-21`) with
//! an ephemeral `ML-KEM-768` encapsulation bound into the CPace transcript:
//!
//! ```text
//! initiator (new device)                               responder (enrolled device)
//!   (dk_otc, ek_otc) = ML-KEM-768.KeyGen()
//!   ad_a = SHA256(ek_otc)
//!   Initiator::start(code, did)
//!     ── InitiatorMessage { sid, ya, ek_otc, ad_a } ──▶  Responder::respond(...)
//!                                                        (consumes 1 of 3 attempts)
//!                                                        (kem_ct, mlkem_ss) = Encaps(ek_otc)
//!                                                        ad_b = SHA256(kem_ct)
//!                                                        cpace_isk = CPace_ISK(ya, ad_a, yb, ad_b)
//!                                                        otc_seal_key = HKDF(cpace_isk || mlkem_ss,
//!                                                                            MINOS_SALT,
//!                                                                            "catbird.labyrinth.otc.pq.v2")
//!     ◀── ResponderMessage { yb, kem_ct, ad_b } + sealed payload ──
//!   Initiator::finish(msg) -> otc_seal_key
//! ```
//!
//! Even a Harvest-Now-Decrypt-Later (`HNDL`) quantum adversary who later obtains
//! the 6-digit code AND breaks `ristretto255` discrete logarithms (`cpace_isk`)
//! cannot compute `mlkem_ss` without `dk_otc`, keeping `epoch_root` confidential.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate as _, KeyExport as _};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{B32, Seed};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{kdf32, minos_salt, random, sha256};
use crate::hpke::hawk::{MLKEM768_CT_LEN, MLKEM768_EK_LEN};
use crate::{Error, Result};

/// Prefix of the CPace channel identifier; the DID follows it.
pub const CI_PREFIX: &[u8] = b"catbird.labyrinth.otc.v1";
/// HKDF info for hybrid PQ [`derive_otc_seal_key`] (`I16`).
pub const OTC_PQ_KDF_INFO: &[u8] = b"catbird.labyrinth.otc.pq.v2";
/// AEAD associated data for the sealed payload (SPEC §6.5).
pub const PAYLOAD_AAD: &[u8] = b"otc_payload";
/// Attempts allowed per code (paper p.44).
pub const MAX_ATTEMPTS: u8 = 3;
/// Number of digits in a code.
pub const CODE_DIGITS: usize = 6;
/// Length of the CPace session id.
pub const SID_LEN: usize = 16;
/// Length of the CPace ISK.
pub const ISK_LEN: usize = 64;

/// A 6-digit one-time code. Secret: zeroized on drop, redacted in `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct OneTimeCode([u8; CODE_DIGITS]);

impl OneTimeCode {
    /// Uniform random code in `000000..=999999` (rejection sampling).
    pub fn generate() -> Result<Self> {
        const LIMIT: u32 = (u32::MAX / 1_000_000) * 1_000_000;
        loop {
            let mut b = [0u8; 4];
            random(&mut b)?;
            let mut x = u32::from_le_bytes(b);
            b.zeroize();
            if x < LIMIT {
                let mut n = x % 1_000_000;
                x.zeroize();
                let mut digits = [0u8; CODE_DIGITS];
                for d in digits.iter_mut().rev() {
                    *d = b'0' + (n % 10) as u8;
                    n /= 10;
                }
                return Ok(Self(digits));
            }
        }
    }

    /// Parse exactly 6 ASCII digits; surrounding whitespace and inner spaces
    /// or `-` are ignored.
    pub fn parse(input: &str) -> Result<Self> {
        let mut digits = [0u8; CODE_DIGITS];
        let mut n = 0;
        for &b in input.as_bytes() {
            if b == b'-' || b.is_ascii_whitespace() {
                continue;
            }
            if !b.is_ascii_digit() || n == CODE_DIGITS {
                digits.zeroize();
                return Err(Error::Malformed("one-time code must be 6 digits"));
            }
            digits[n] = b;
            n += 1;
        }
        if n != CODE_DIGITS {
            digits.zeroize();
            return Err(Error::Malformed("one-time code must be 6 digits"));
        }
        Ok(Self(digits))
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).expect("ASCII digits")
    }

    pub fn format_grouped(&self) -> String {
        let s = self.as_str();
        format!("{}-{}", &s[..3], &s[3..])
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for OneTimeCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OneTimeCode(<redacted>)")
    }
}

/// Generate a fresh [`OneTimeCode`].
pub fn generate_code() -> Result<OneTimeCode> {
    OneTimeCode::generate()
}

/// `CI = "catbird.labyrinth.otc.v1" || did`.
pub fn channel_identifier(did: &str) -> Vec<u8> {
    [CI_PREFIX, did.as_bytes()].concat()
}

/// The 64-byte CPace intermediate session key (`cpace_isk`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Isk([u8; ISK_LEN]);

impl Isk {
    pub fn as_bytes(&self) -> &[u8; ISK_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Isk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Isk(<redacted>)")
    }
}

impl PartialEq for Isk {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for Isk {}

/// Hybrid PQ 32-byte sealing key derived from `cpace_isk || mlkem_ss` (`I16`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OtcSessionKey([u8; 32]);

impl OtcSessionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for OtcSessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OtcSessionKey(<redacted>)")
    }
}

impl PartialEq for OtcSessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for OtcSessionKey {}

/// `otc_seal_key = HKDF-SHA256(cpace_isk || mlkem_ss, MINOS_SALT, "catbird.labyrinth.otc.pq.v2")`.
pub fn derive_otc_seal_key(cpace_isk: &Isk, mlkem_ss: &[u8; 32]) -> OtcSessionKey {
    let mut ikm = Zeroizing::new([0u8; ISK_LEN + 32]);
    ikm[..ISK_LEN].copy_from_slice(cpace_isk.as_bytes());
    ikm[ISK_LEN..].copy_from_slice(mlkem_ss);
    OtcSessionKey(kdf32(&*ikm, Some(&minos_salt()), OTC_PQ_KDF_INFO))
}

/// First message, from the new device (`blue.catbird.labyrinth.otcSession` initiated).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitiatorMessage {
    /// CPace session id, chosen by the initiator.
    pub sid: [u8; SID_LEN],
    /// Public share `Ya` (ristretto255 encoding).
    pub ya: [u8; 32],
    /// Ephemeral `ML-KEM-768` encapsulation key (1,184 bytes).
    pub ek_otc: Vec<u8>,
    /// Associated data `ADa = SHA256(ek_otc)` (32 bytes).
    pub ad: Vec<u8>,
}

/// Reply from the enrolled device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponderMessage {
    /// Public share `Yb` (ristretto255 encoding).
    pub yb: [u8; 32],
    /// `ML-KEM-768` ciphertext encapsulated to `ek_otc` (1,088 bytes).
    pub kem_ct: Vec<u8>,
    /// Associated data `ADb = SHA256(kem_ct)` (32 bytes).
    pub ad: Vec<u8>,
}

/// The new device's side of one hybrid PQ `CPace + ML-KEM-768` session.
pub struct Initiator {
    scalar: Scalar,
    mlkem_seed: Zeroizing<[u8; 64]>,
    sid: [u8; SID_LEN],
    ya: [u8; 32],
    ad: Vec<u8>,
}

impl Initiator {
    /// Start a session with a fresh random `sid`, CPace scalar, and ephemeral `ML-KEM-768` keypair.
    pub fn start(code: &OneTimeCode, did: &str) -> Result<(Self, InitiatorMessage)> {
        let mut sid = [0u8; SID_LEN];
        random(&mut sid)?;
        let y = cpace::sample_scalar()?;
        Self::start_deterministic(code, did, sid, y)
    }

    /// Start a session with caller-supplied `sid` and CPace `scalar` plus fresh `ML-KEM-768` seed.
    pub fn start_deterministic(
        code: &OneTimeCode,
        did: &str,
        sid: [u8; SID_LEN],
        scalar: Scalar,
    ) -> Result<(Self, InitiatorMessage)> {
        let mut mlkem_seed = Zeroizing::new([0u8; 64]);
        random(mlkem_seed.as_mut())?;
        let dk = DecapsulationKey::from_seed(Seed::from(*mlkem_seed));
        let ek_otc = dk.encapsulation_key().to_bytes().to_vec();
        let ad = sha256(&ek_otc).to_vec();

        let ci = channel_identifier(did);
        let g = cpace::calculate_generator(code.as_bytes(), &ci, &sid);
        let ya = cpace::scalar_mult(&scalar, &g);
        let msg = InitiatorMessage {
            sid,
            ya,
            ek_otc,
            ad: ad.clone(),
        };
        Ok((
            Self {
                scalar,
                mlkem_seed,
                sid,
                ya,
                ad,
            },
            msg,
        ))
    }

    /// Process the responder's reply and output the hybrid PQ [`OtcSessionKey`].
    pub fn finish(self, msg: &ResponderMessage) -> Result<OtcSessionKey> {
        if msg.kem_ct.len() != MLKEM768_CT_LEN {
            return Err(Error::Malformed("otc kem_ct length"));
        }
        let expected_ad = sha256(&msg.kem_ct);
        if !bool::from(msg.ad.as_slice().ct_eq(expected_ad.as_slice())) {
            return Err(Error::Malformed("otc responder ad mismatch"));
        }
        let kem_ct = Ciphertext::try_from(msg.kem_ct.as_slice())
            .map_err(|_| Error::Malformed("otc kem_ct"))?;
        let k = cpace::scalar_mult_vfy(&self.scalar, &msg.yb).ok_or(Error::BadPublicKey)?;
        let cpace_isk = cpace::isk_ir(&self.sid, &k, &self.ya, &self.ad, &msg.yb, &msg.ad);
        let dk = DecapsulationKey::from_seed(Seed::from(*self.mlkem_seed));
        let mlkem_ss = Zeroizing::new(<[u8; 32]>::from(dk.decapsulate(&kem_ct)));
        Ok(derive_otc_seal_key(&cpace_isk, &mlkem_ss))
    }
}

impl Drop for Initiator {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

/// The enrolled device's side: one code, up to [`MAX_ATTEMPTS`] sessions.
pub struct Responder {
    code: OneTimeCode,
    did: String,
    attempts: u8,
}

impl Responder {
    /// Hold `code` (shown to the user) for transfers into `did`'s mailbox.
    pub fn new(code: OneTimeCode, did: &str) -> Self {
        Self {
            code,
            did: did.to_owned(),
            attempts: 0,
        }
    }

    /// Generate a code and a responder for it.
    pub fn generate(did: &str) -> Result<Self> {
        Ok(Self::new(OneTimeCode::generate()?, did))
    }

    /// The code to display.
    pub fn code(&self) -> &OneTimeCode {
        &self.code
    }

    /// Sessions left for this code.
    pub fn remaining_attempts(&self) -> u8 {
        MAX_ATTEMPTS - self.attempts
    }

    /// Answer one initiator session. Consumes an attempt even if the initiator's
    /// share or `ek_otc` is invalid.
    pub fn respond(&mut self, msg: &InitiatorMessage) -> Result<(ResponderMessage, OtcSessionKey)> {
        let y = cpace::sample_scalar()?;
        self.respond_deterministic(msg, y)
    }

    pub fn respond_deterministic(
        &mut self,
        msg: &InitiatorMessage,
        mut scalar: Scalar,
    ) -> Result<(ResponderMessage, OtcSessionKey)> {
        if self.attempts >= MAX_ATTEMPTS {
            scalar.zeroize();
            return Err(Error::Malformed("one-time code attempts exhausted"));
        }
        self.attempts += 1;

        if msg.ek_otc.len() != MLKEM768_EK_LEN {
            scalar.zeroize();
            return Err(Error::BadPublicKey);
        }
        let ek_arr = Array::try_from(msg.ek_otc.as_slice()).map_err(|_| {
            scalar.zeroize();
            Error::BadPublicKey
        })?;
        let ek = EncapsulationKey::new(&ek_arr).map_err(|_| {
            scalar.zeroize();
            Error::BadPublicKey
        })?;
        let expected_ad_a = sha256(&msg.ek_otc);
        if !bool::from(msg.ad.as_slice().ct_eq(expected_ad_a.as_slice())) {
            scalar.zeroize();
            return Err(Error::Malformed("otc initiator ad mismatch"));
        }

        let mut m = Zeroizing::new([0u8; 32]);
        if let Err(e) = random(&mut *m) {
            scalar.zeroize();
            return Err(e);
        }
        let (kem_ct, ss) = ek.encapsulate_deterministic(&B32::from(*m));
        let mlkem_ss = Zeroizing::new(<[u8; 32]>::from(ss));
        let kem_ct_vec = kem_ct.as_slice().to_vec();
        let ad_b = sha256(&kem_ct_vec).to_vec();

        let ci = channel_identifier(&self.did);
        let g = cpace::calculate_generator(self.code.as_bytes(), &ci, &msg.sid);
        let yb = cpace::scalar_mult(&scalar, &g);
        let k = cpace::scalar_mult_vfy(&scalar, &msg.ya);
        scalar.zeroize();
        let k = k.ok_or(Error::BadPublicKey)?;
        let cpace_isk = cpace::isk_ir(&msg.sid, &k, &msg.ya, &msg.ad, &yb, &ad_b);
        let key = derive_otc_seal_key(&cpace_isk, &mlkem_ss);
        Ok((
            ResponderMessage {
                yb,
                kem_ct: kem_ct_vec,
                ad: ad_b,
            },
            key,
        ))
    }
}

/// CPace over ristretto255 / SHA-512, draft-irtf-cfrg-cpace-21 §6–8.3.
pub mod cpace {
    use super::*;

    pub const DSI: &[u8] = b"CPaceRistretto255";
    pub const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";
    pub const S_IN_BYTES: usize = 128;

    pub fn prepend_len(out: &mut Vec<u8>, data: &[u8]) {
        let mut n = data.len();
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out.extend_from_slice(data);
    }

    pub fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in parts {
            prepend_len(&mut out, p);
        }
        out
    }

    fn leb_len(n: usize) -> usize {
        let mut v = Vec::new();
        prepend_len(&mut v, &vec![0u8; n]);
        v.len() - n
    }

    pub fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Zeroizing<Vec<u8>> {
        let len_prs = leb_len(prs.len()) + prs.len();
        let len_dsi = leb_len(DSI.len()) + DSI.len();
        let zpad = S_IN_BYTES.saturating_sub(len_prs + len_dsi + 1);
        Zeroizing::new(lv_cat(&[DSI, prs, &vec![0u8; zpad], ci, sid]))
    }

    pub fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
        let gen_str = generator_string(prs, ci, sid);
        let mut h: [u8; 64] = Sha512::digest(gen_str.as_slice()).into();
        let g = RistrettoPoint::from_uniform_bytes(&h);
        h.zeroize();
        g
    }

    pub fn sample_scalar() -> Result<Scalar> {
        loop {
            let mut b = [0u8; 32];
            random(&mut b)?;
            let s = scalar_from_bytes(&b);
            b.zeroize();
            if s != Scalar::ZERO {
                return Ok(s);
            }
        }
    }

    pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
        let mut b = *bytes;
        b[31] &= 0x0f;
        let s = Scalar::from_bytes_mod_order(b);
        b.zeroize();
        s
    }

    pub fn scalar_mult(y: &Scalar, g: &RistrettoPoint) -> [u8; 32] {
        (g * y).compress().to_bytes()
    }

    pub fn scalar_mult_vfy(y: &Scalar, x: &[u8; 32]) -> Option<[u8; 32]> {
        let p = CompressedRistretto(*x).decompress()?;
        let k = (p * y).compress();
        if k.to_bytes() == [0u8; 32] {
            None
        } else {
            Some(k.to_bytes())
        }
    }

    pub fn transcript_ir(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
        let mut t = lv_cat(&[ya, ada]);
        t.extend_from_slice(&lv_cat(&[yb, adb]));
        t
    }

    pub fn transcript_oc(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
        let a = lv_cat(&[ya, ada]);
        let b = lv_cat(&[yb, adb]);
        let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
        let mut t = b"oc".to_vec();
        t.extend_from_slice(&hi);
        t.extend_from_slice(&lo);
        t
    }

    pub fn isk(sid: &[u8], k: &[u8; 32], transcript: &[u8]) -> Isk {
        let mut h = Sha512::new();
        h.update(lv_cat(&[DSI_ISK, sid, k]));
        h.update(transcript);
        Isk(h.finalize().into())
    }

    pub fn isk_ir(sid: &[u8], k: &[u8; 32], ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Isk {
        isk(sid, k, &transcript_ir(ya, ada, yb, adb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:testvector";

    fn run(code_a: &str, code_b: &str) -> (OtcSessionKey, OtcSessionKey) {
        let a = OneTimeCode::parse(code_a).unwrap();
        let b = OneTimeCode::parse(code_b).unwrap();
        let (init, m1) = Initiator::start(&a, DID).unwrap();
        let mut resp = Responder::new(b, DID);
        let (m2, key_b) = resp.respond(&m1).unwrap();
        let key_a = init.finish(&m2).unwrap();
        (key_a, key_b)
    }

    #[test]
    fn both_sides_agree() {
        let (a, b) = run("123456", "123456");
        assert_eq!(a, b);
    }

    #[test]
    fn wrong_code_disagrees() {
        let (a, b) = run("123456", "123457");
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_did_disagrees() {
        let code = OneTimeCode::parse("000001").unwrap();
        let (init, m1) = Initiator::start(&code, "did:plc:a").unwrap();
        let mut resp = Responder::new(code, "did:plc:b");
        let (m2, key_b) = resp.respond(&m1).unwrap();
        assert_ne!(init.finish(&m2).unwrap(), key_b);
    }

    #[test]
    fn attempts_are_limited() {
        let code = OneTimeCode::parse("424242").unwrap();
        let wrong = OneTimeCode::parse("000000").unwrap();
        let mut resp = Responder::new(code, DID);
        assert_eq!(resp.remaining_attempts(), 3);
        for left in (0..3).rev() {
            let (_, m1) = Initiator::start(&wrong, DID).unwrap();
            resp.respond(&m1).unwrap();
            assert_eq!(resp.remaining_attempts(), left);
        }
        let (_, m1) = Initiator::start(&wrong, DID).unwrap();
        assert!(resp.respond(&m1).is_err());
    }

    #[test]
    fn rejects_identity_and_invalid_shares() {
        let code = OneTimeCode::parse("111111").unwrap();
        let (_, mut m1) = Initiator::start(&code, DID).unwrap();
        m1.ya = [0; 32];
        let mut resp = Responder::new(code.clone(), DID);
        assert_eq!(resp.respond(&m1).unwrap_err(), Error::BadPublicKey);

        let (init, m1_good) = Initiator::start(&code, DID).unwrap();
        let (mut m2, _) = resp.respond(&m1_good).unwrap();
        let mut invalid = [0xffu8; 32];
        invalid[31] = 0x7f;
        m2.yb = invalid;
        assert!(init.finish(&m2).is_err());
    }
}

//! One-time-code device transfer (SPEC §6.5, paper p.44–45, [CB-14]).
//!
//! An enrolled device (the *responder*) shows a random 6-digit code. The new
//! device (the *initiator*) asks for the transfer, the user types the code on
//! it, and the two run CPace over ristretto255 / SHA-512
//! (draft-irtf-cfrg-cpace-21) with:
//!
//! - `PRS` = the 6 ASCII digits,
//! - `CI` = `"catbird.labyrinth.otc.v1" || did`,
//! - `sid` = 16 random bytes chosen by the initiator,
//! - the initiator–responder transcript (`transcript_ir`).
//!
//! The resulting 64-byte ISK is the paper's `otc_secret`. The responder
//! seals the transfer payload under [`payload_key`]`(ISK)` with AAD
//! [`PAYLOAD_AAD`]; sealing itself is left to the caller (`crate::aead`).
//!
//! # Flow
//!
//! ```text
//! initiator (new device)                      responder (enrolled device)
//!   Initiator::start(code, did, ADa)
//!     ── InitiatorMessage { sid, Ya, ADa } ──▶  Responder::respond(...)
//!                                               (consumes 1 of 3 attempts)
//!     ◀── ResponderMessage { Yb, ADb } + sealed payload ──
//!   Initiator::finish(msg) -> ISK
//! ```
//!
//! CPace has no key confirmation; a wrong code shows up as a payload that
//! fails to decrypt. Each [`Responder::respond`] call is one online guess, so
//! the responder allows [`MAX_ATTEMPTS`] per code. On failure, the new device
//! starts a new session (new `sid`) and the enrolled device answers with the
//! same [`Responder`] until it is exhausted.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result};

/// Prefix of the CPace channel identifier; the DID follows it.
pub const CI_PREFIX: &[u8] = b"catbird.labyrinth.otc.v1";
/// HKDF info for [`payload_key`].
pub const PAYLOAD_KDF_INFO: &[u8] = b"catbird.labyrinth.otc.payload";
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

use crate::encoding::{minos_salt, random};

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    crate::encoding::kdf32(ikm, Some(salt), info)
}

// ---------------------------------------------------------------------------
// One-time code
// ---------------------------------------------------------------------------

/// A 6-digit one-time code. Secret: zeroized on drop, redacted in `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct OneTimeCode([u8; CODE_DIGITS]);

impl OneTimeCode {
    /// Uniform random code in `000000..=999999` (rejection sampling).
    pub fn generate() -> Result<Self> {
        // Largest multiple of 10^6 that fits in 2^32.
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

    /// The 6 digits as a string.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).expect("ASCII digits")
    }

    /// The CPace password (`PRS`): the 6 ASCII digits.
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

/// `payload_key = kdf(ISK, MINOS_SALT, "catbird.labyrinth.otc.payload")`.
///
/// The caller seals the CBOR payload with
/// `crate::aead::encrypt(payload_key, PAYLOAD_AAD, payload)`.
pub fn payload_key(isk: &Isk) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hkdf32(isk.as_bytes(), &minos_salt(), PAYLOAD_KDF_INFO))
}

/// The 64-byte CPace intermediate session key (`otc_secret`).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Isk([u8; ISK_LEN]);

impl Isk {
    /// The raw key bytes.
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
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for Isk {}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// First message, from the new device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitiatorMessage {
    /// CPace session id, chosen by the initiator.
    pub sid: [u8; SID_LEN],
    /// Public share `Ya` (ristretto255 encoding).
    pub ya: [u8; 32],
    /// Associated data `ADa` (may be empty).
    pub ad: Vec<u8>,
}

/// Reply from the enrolled device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponderMessage {
    /// Public share `Yb` (ristretto255 encoding).
    pub yb: [u8; 32],
    /// Associated data `ADb` (may be empty).
    pub ad: Vec<u8>,
}

/// The new device's side of one CPace session.
pub struct Initiator {
    scalar: Scalar,
    sid: [u8; SID_LEN],
    ya: [u8; 32],
    ad: Vec<u8>,
}

impl Initiator {
    /// Start a session with a fresh random `sid`.
    pub fn start(code: &OneTimeCode, did: &str, ad: &[u8]) -> Result<(Self, InitiatorMessage)> {
        let mut sid = [0u8; SID_LEN];
        random(&mut sid)?;
        let y = cpace::sample_scalar()?;
        Ok(Self::start_with(code, did, ad, sid, y))
    }

    fn start_with(
        code: &OneTimeCode,
        did: &str,
        ad: &[u8],
        sid: [u8; SID_LEN],
        scalar: Scalar,
    ) -> (Self, InitiatorMessage) {
        let ci = channel_identifier(did);
        let g = cpace::calculate_generator(code.as_bytes(), &ci, &sid);
        let ya = cpace::scalar_mult(&scalar, &g);
        let msg = InitiatorMessage {
            sid,
            ya,
            ad: ad.to_vec(),
        };
        (
            Self {
                scalar,
                sid,
                ya,
                ad: ad.to_vec(),
            },
            msg,
        )
    }

    /// Process the responder's reply and output the ISK.
    pub fn finish(self, msg: &ResponderMessage) -> Result<Isk> {
        let k = cpace::scalar_mult_vfy(&self.scalar, &msg.yb).ok_or(Error::BadPublicKey)?;
        Ok(cpace::isk_ir(
            &self.sid, &k, &self.ya, &self.ad, &msg.yb, &msg.ad,
        ))
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

    /// Answer one initiator session. Consumes an attempt even if the
    /// initiator's share is invalid. Once [`MAX_ATTEMPTS`] are used, the code
    /// is dead and the user must consent to a new one.
    pub fn respond(
        &mut self,
        msg: &InitiatorMessage,
        ad: &[u8],
    ) -> Result<(ResponderMessage, Isk)> {
        let y = cpace::sample_scalar()?;
        self.respond_with(msg, ad, y)
    }

    fn respond_with(
        &mut self,
        msg: &InitiatorMessage,
        ad: &[u8],
        mut scalar: Scalar,
    ) -> Result<(ResponderMessage, Isk)> {
        if self.attempts >= MAX_ATTEMPTS {
            scalar.zeroize();
            return Err(Error::Malformed("one-time code attempts exhausted"));
        }
        self.attempts += 1;
        let ci = channel_identifier(&self.did);
        let g = cpace::calculate_generator(self.code.as_bytes(), &ci, &msg.sid);
        let yb = cpace::scalar_mult(&scalar, &g);
        let k = cpace::scalar_mult_vfy(&scalar, &msg.ya);
        scalar.zeroize();
        let k = k.ok_or(Error::BadPublicKey)?;
        let isk = cpace::isk_ir(&msg.sid, &k, &msg.ya, &msg.ad, &yb, ad);
        Ok((
            ResponderMessage {
                yb,
                ad: ad.to_vec(),
            },
            isk,
        ))
    }
}

/// CPace over ristretto255 / SHA-512, draft-irtf-cfrg-cpace-21 §6–8.3.
///
/// Public so the draft's test vectors (Appendix B.3) can be checked.
pub mod cpace {
    use super::*;

    /// `G_Ristretto255.DSI`.
    pub const DSI: &[u8] = b"CPaceRistretto255";
    /// `G.DSI || "_ISK"`.
    pub const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";
    /// SHA-512 input block size (`H.s_in_bytes`).
    pub const S_IN_BYTES: usize = 128;

    /// LEB128 length prefix (`prepend_len`).
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

    /// `lv_cat(parts...)`.
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

    /// `generator_string(G.DSI, PRS, CI, sid, H.s_in_bytes)`.
    pub fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Zeroizing<Vec<u8>> {
        let len_prs = leb_len(prs.len()) + prs.len();
        let len_dsi = leb_len(DSI.len()) + DSI.len();
        let zpad = S_IN_BYTES.saturating_sub(len_prs + len_dsi + 1);
        Zeroizing::new(lv_cat(&[DSI, prs, &vec![0u8; zpad], ci, sid]))
    }

    /// `G.calculate_generator(H, PRS, CI, sid)` (internal representation).
    pub fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
        let gen_str = generator_string(prs, ci, sid);
        let mut h: [u8; 64] = Sha512::digest(gen_str.as_slice()).into();
        let g = RistrettoPoint::from_uniform_bytes(&h);
        h.zeroize();
        g
    }

    /// `G.sample_scalar()`: 32 random bytes with bits ≥ 252 cleared, read
    /// little-endian (the draft's recommended method). Zero is resampled.
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

    /// Interpret 32 little-endian bytes as a scalar after clearing bits ≥ 252
    /// (so the value is below the group order and reduction is a no-op).
    pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
        let mut b = *bytes;
        b[31] &= 0x0f;
        let s = Scalar::from_bytes_mod_order(b);
        b.zeroize();
        s
    }

    /// `G.scalar_mult(y, _g)`: returns the public encoding.
    pub fn scalar_mult(y: &Scalar, g: &RistrettoPoint) -> [u8; 32] {
        (g * y).compress().to_bytes()
    }

    /// `G.scalar_mult_vfy(y, X)`. `None` stands for `G.I`: `X` doesn't
    /// decode, or the product is the identity. Callers MUST abort on `None`.
    pub fn scalar_mult_vfy(y: &Scalar, x: &[u8; 32]) -> Option<[u8; 32]> {
        let p = CompressedRistretto(*x).decompress()?;
        let k = (p * y).compress();
        if k.to_bytes() == [0u8; 32] {
            None
        } else {
            Some(k.to_bytes())
        }
    }

    /// `transcript_ir(Ya, ADa, Yb, ADb) = lv_cat(Ya, ADa) || lv_cat(Yb, ADb)`.
    pub fn transcript_ir(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
        let mut t = lv_cat(&[ya, ada]);
        t.extend_from_slice(&lv_cat(&[yb, adb]));
        t
    }

    /// `transcript_oc(...) = o_cat(lv_cat(Ya, ADa), lv_cat(Yb, ADb))`.
    /// Not used by the OTC flow; provided to check the draft's vectors.
    pub fn transcript_oc(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
        let a = lv_cat(&[ya, ada]);
        let b = lv_cat(&[yb, adb]);
        let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
        let mut t = b"oc".to_vec();
        t.extend_from_slice(&hi);
        t.extend_from_slice(&lo);
        t
    }

    /// `ISK = H.hash(lv_cat(DSI_ISK, sid, K) || transcript)`.
    pub fn isk(sid: &[u8], k: &[u8; 32], transcript: &[u8]) -> Isk {
        let mut h = Sha512::new();
        h.update(lv_cat(&[DSI_ISK, sid, k]));
        h.update(transcript);
        Isk(h.finalize().into())
    }

    /// ISK in the initiator–responder setting.
    pub fn isk_ir(sid: &[u8], k: &[u8; 32], ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Isk {
        isk(sid, k, &transcript_ir(ya, ada, yb, adb))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:testvector";

    fn run(code_a: &str, code_b: &str) -> (Isk, Isk) {
        let a = OneTimeCode::parse(code_a).unwrap();
        let b = OneTimeCode::parse(code_b).unwrap();
        let (init, m1) = Initiator::start(&a, DID, b"new-device").unwrap();
        let mut resp = Responder::new(b, DID);
        let (m2, isk_b) = resp.respond(&m1, b"old-device").unwrap();
        let isk_a = init.finish(&m2).unwrap();
        (isk_a, isk_b)
    }

    #[test]
    fn both_sides_agree() {
        let (a, b) = run("123456", "123456");
        assert_eq!(a, b);
        assert_eq!(payload_key(&a).as_slice(), payload_key(&b).as_slice());
    }

    #[test]
    fn wrong_code_disagrees() {
        let (a, b) = run("123456", "123457");
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_did_disagrees() {
        let code = OneTimeCode::parse("000001").unwrap();
        let (init, m1) = Initiator::start(&code, "did:plc:a", b"").unwrap();
        let mut resp = Responder::new(code.clone(), "did:plc:b");
        let (m2, isk_b) = resp.respond(&m1, b"").unwrap();
        assert_ne!(init.finish(&m2).unwrap(), isk_b);
    }

    #[test]
    fn attempts_are_limited() {
        let code = OneTimeCode::parse("424242").unwrap();
        let wrong = OneTimeCode::parse("000000").unwrap();
        let mut resp = Responder::new(code, DID);
        assert_eq!(resp.remaining_attempts(), 3);
        for left in (0..3).rev() {
            let (_, m1) = Initiator::start(&wrong, DID, b"").unwrap();
            resp.respond(&m1, b"").unwrap();
            assert_eq!(resp.remaining_attempts(), left);
        }
        let (_, m1) = Initiator::start(&wrong, DID, b"").unwrap();
        assert!(resp.respond(&m1, b"").is_err());
    }

    #[test]
    fn rejects_identity_and_invalid_shares() {
        let code = OneTimeCode::parse("111111").unwrap();
        let mut resp = Responder::new(code.clone(), DID);
        let bad = InitiatorMessage {
            sid: [7; SID_LEN],
            ya: [0; 32],
            ad: vec![],
        };
        assert_eq!(resp.respond(&bad, b"").unwrap_err(), Error::BadPublicKey);
        let (init, _) = Initiator::start(&code, DID, b"").unwrap();
        let mut invalid = [0xffu8; 32];
        invalid[31] = 0x7f;
        assert!(
            init.finish(&ResponderMessage {
                yb: invalid,
                ad: vec![]
            })
            .is_err()
        );
    }

    #[test]
    fn code_generation_and_parsing() {
        for _ in 0..1000 {
            let c = generate_code().unwrap();
            assert_eq!(c.as_str().len(), 6);
            assert!(c.as_str().bytes().all(|b| b.is_ascii_digit()));
            assert_eq!(OneTimeCode::parse(c.as_str()).unwrap(), c);
        }
        assert_eq!(OneTimeCode::parse(" 123-456 ").unwrap().as_str(), "123456");
        assert!(OneTimeCode::parse("12345").is_err());
        assert!(OneTimeCode::parse("1234567").is_err());
        assert!(OneTimeCode::parse("12345a").is_err());
        assert!(!format!("{:?}", OneTimeCode::parse("987654").unwrap()).contains("987654"));
    }

    #[test]
    fn code_distribution_roughly_uniform() {
        // First digit should be roughly uniform over 0..=9.
        let mut counts = [0u32; 10];
        for _ in 0..20_000 {
            let c = generate_code().unwrap();
            counts[(c.as_bytes()[0] - b'0') as usize] += 1;
        }
        for c in counts {
            assert!((1600..2400).contains(&c), "{counts:?}");
        }
    }

    #[test]
    fn deterministic_session() {
        // Fixed scalars reproduce: the state machine is the cpace module.
        let code = OneTimeCode::parse("314159").unwrap();
        let ya = cpace::scalar_from_bytes(&[3; 32]);
        let yb = cpace::scalar_from_bytes(&[5; 32]);
        let (init, m1) = Initiator::start_with(&code, DID, b"A", [1; 16], ya);
        let mut resp = Responder::new(code, DID);
        let (m2, isk_b) = resp.respond_with(&m1, b"B", yb).unwrap();
        assert_eq!(init.finish(&m2).unwrap(), isk_b);
    }
}

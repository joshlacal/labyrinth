//! Signatures (SPEC §3.3): XEdDSA over X25519 keys for Labyrinth keys, and
//! Ed25519 for the chat transport key ([CB-3]).
//!
//! XEdDSA follows <https://signal.org/docs/specifications/xeddsa/> (rev. 1,
//! 2016-10-20), §2.3 `calculate_key_pair`, §2.4 `xeddsa_sign` /
//! `xeddsa_verify`, with `hash_1(X) = SHA-512(0xFE || 0xFF^31 || X)`:
//!
//! ```text
//! sign(k, M, Z):  A, a = calculate_key_pair(k)        // A.s forced to 0
//!                 r = hash_1(a || M || Z) mod q       // Z = 64 random bytes
//!                 R = rB;  h = SHA-512(R || A || M) mod q;  s = r + h·a mod q
//! verify(u, M, R || s):
//!   reject u ≥ p, s ≥ 2^253, u not on the curve
//!   A = convert_mont(u);  h = SHA-512(R || A || M) mod q
//!   accept iff encode(sB − hA) == R
//! ```
//!
//! Two checks are stricter than the spec (both reject only signatures an
//! honest signer never produces): `s` must be canonical (`s < q`, which
//! removes `s + q` malleability), and a small-order public key is rejected.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use ed25519_dalek::Signer as _;
use sha2::{Digest as _, Sha512};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// `2^255 - 19`, little-endian.
const P_LE: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// `hash_1` prefix: `2^256 - 1 - 1` little-endian = `0xFE || 0xFF^31`.
const HASH1_PREFIX: [u8; 32] = {
    let mut b = [0xffu8; 32];
    b[0] = 0xfe;
    b
};

/// XEdDSA / X25519 private scalar (clamped on use).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct XSigningKey(pub(crate) [u8; 32]);

/// X25519 (Montgomery u-coordinate) public key used for XEdDSA verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct XVerifyingKey(pub [u8; 32]);

/// `calculate_key_pair(k)`: the Edwards public key `A` (sign bit 0) and the
/// matching private scalar `a`.
fn calculate_key_pair(k: &[u8; 32]) -> (EdwardsPoint, Scalar) {
    let mut clamped = clamp_integer(*k);
    let mut a = Scalar::from_bytes_mod_order(clamped);
    clamped.zeroize();
    let e = EdwardsPoint::mul_base(&a);
    let sign = e.compress().as_bytes()[31] >> 7;
    if sign == 1 {
        a = -a;
        (-e, a)
    } else {
        (e, a)
    }
}

fn challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(msg);
    let mut wide: [u8; 64] = h.finalize().into();
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    s
}

/// Little-endian `x < p`.
fn is_reduced_field(x: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if x[i] != P_LE[i] {
            return x[i] < P_LE[i];
        }
    }
    false
}

impl XSigningKey {
    pub fn generate() -> crate::Result<Self> {
        let mut b = [0u8; 32];
        let r = crate::encoding::random(&mut b);
        let k = Self(b);
        b.zeroize();
        r.map(|()| k)
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    pub fn public(&self) -> XVerifyingKey {
        XVerifyingKey(MontgomeryPoint::mul_base_clamped(self.0).to_bytes())
    }
    /// XEdDSA signature over `msg` with fresh 64-byte randomness.
    pub fn sign(&self, msg: &[u8]) -> crate::Result<[u8; 64]> {
        let mut z = [0u8; 64];
        crate::encoding::random(&mut z)?;
        let sig = self.sign_with_z(msg, &z);
        z.zeroize();
        Ok(sig)
    }
    /// `pk_sign(priv, use_case_byte, data)` = sign(`use_case || data`).
    pub fn sign_use_case(&self, use_case: u8, data: &[u8]) -> crate::Result<[u8; 64]> {
        let mut m = Vec::with_capacity(1 + data.len());
        m.push(use_case);
        m.extend_from_slice(data);
        self.sign(&m)
    }

    /// `xeddsa_sign(k, M, Z)` with caller-supplied `Z` (deterministic; tests only).
    fn sign_with_z(&self, msg: &[u8], z: &[u8; 64]) -> [u8; 64] {
        let (a_point, mut a) = calculate_key_pair(&self.0);
        let a_bytes = a_point.compress().to_bytes();

        let mut h1 = Sha512::new();
        h1.update(HASH1_PREFIX);
        h1.update(a.as_bytes());
        h1.update(msg);
        h1.update(z);
        let mut wide: [u8; 64] = h1.finalize().into();
        let mut r = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();

        let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let h = challenge(&r_bytes, &a_bytes, msg);
        let s = r + h * a;
        r.zeroize();
        a.zeroize();

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(s.as_bytes());
        sig
    }
}

impl XVerifyingKey {
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> crate::Result<()> {
        let u = &self.0;
        let r_bytes: &[u8; 32] = sig[..32].try_into().expect("32-byte half");
        let s_bytes: [u8; 32] = sig[32..].try_into().expect("32-byte half");

        // u >= p (also rejects the high bit set).
        if !is_reduced_field(u) {
            return Err(Error::BadPublicKey);
        }
        // s >= 2^|q| = 2^253, and (stricter) s >= q.
        if s_bytes[31] & 0xe0 != 0 {
            return Err(Error::BadSignature);
        }
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
            .ok_or(Error::BadSignature)?;
        // on_curve(u) and convert_mont(u) with sign bit 0.
        let a_point = MontgomeryPoint(*u)
            .to_edwards(0)
            .ok_or(Error::BadPublicKey)?;
        if a_point.is_small_order() {
            return Err(Error::BadPublicKey);
        }
        let a_bytes = a_point.compress().to_bytes();
        let h = challenge(r_bytes, &a_bytes, msg);
        let r_check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&-h, &a_point, &s);
        if bool::from(r_check.compress().as_bytes().ct_eq(r_bytes)) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
    pub fn verify_use_case(&self, use_case: u8, data: &[u8], sig: &[u8; 64]) -> crate::Result<()> {
        let mut m = Vec::with_capacity(1 + data.len());
        m.push(use_case);
        m.extend_from_slice(data);
        self.verify(&m, sig)
    }
}

/// The sending chat device's transport key ([CB-3]): Ed25519.
pub trait TransportSigner {
    fn transport_public_key(&self) -> [u8; 32];
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64];
}

/// Verify an Ed25519 transport signature (RFC 8032 strict: canonical `s`,
/// canonical `R`/`A`, no small-order `A` or `R`).
pub fn verify_transport(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> crate::Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public).map_err(|_| Error::BadPublicKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig).map_err(|_| Error::BadSignature)
}

/// In-memory Ed25519 transport signer (tests, and clients holding raw keys).
pub struct Ed25519Transport(pub ed25519_dalek::SigningKey);

impl TransportSigner for Ed25519Transport {
    fn transport_public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng as _, SeedableRng as _};
    use xeddsa::xed25519;
    use xeddsa::{CalculateKeyPair as _, Sign as _, Verify as _};

    /// Test key and expected Edwards keys from the `xeddsa` crate's own test
    /// suite (`src/tests/xed25519.rs`).
    const PRIV_IN: [u8; 32] = [
        0xf8, 0xce, 0xd4, 0x2b, 0x07, 0xe7, 0x81, 0x0a, 0x04, 0xcc, 0x85, 0x4b, 0x03, 0x57, 0x6d,
        0xf1, 0xe4, 0xc0, 0xfe, 0xb1, 0x6d, 0x68, 0x5e, 0x0a, 0xc0, 0x42, 0x5e, 0x1c, 0x3c, 0x5e,
        0xb2, 0x47,
    ];
    const ED_PUB_SIGN0: &str = "d76d40332ed11388caa69b50676d630825cddad03246edd61ed3ca72e6cb2c2e";

    fn x(k: [u8; 32]) -> XSigningKey {
        XSigningKey::from_bytes(k)
    }

    #[test]
    fn hash1_prefix() {
        assert_eq!(HASH1_PREFIX[0], 0xfe);
        assert!(HASH1_PREFIX[1..].iter().all(|&b| b == 0xff));
    }

    #[test]
    fn calculate_key_pair_known_answer() {
        let (a_point, a) = calculate_key_pair(&PRIV_IN);
        assert_eq!(hex::encode(a_point.compress().as_bytes()), ED_PUB_SIGN0);
        assert_eq!(EdwardsPoint::mul_base(&a), a_point);
        // convert_mont(public) gives the same A.
        let u = x(PRIV_IN).public();
        assert_eq!(MontgomeryPoint(u.0).to_edwards(0).unwrap(), a_point);
    }

    #[test]
    fn public_matches_x25519_dalek() {
        for seed in 0..16u8 {
            let k = [seed.wrapping_mul(37).wrapping_add(1); 32];
            let ours = x(k).public().0;
            let theirs =
                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(k)).to_bytes();
            assert_eq!(ours, theirs);
        }
    }

    #[test]
    fn sign_verify_round_trip_and_tamper() {
        let sk = XSigningKey::generate().unwrap();
        let pk = sk.public();
        let msg = b"minos.unstructured_signature.epoch_self:head";
        let sig = sk.sign(msg).unwrap();
        pk.verify(msg, &sig).unwrap();
        assert_ne!(sig, sk.sign(msg).unwrap(), "randomized");
        for i in 0..64 {
            for bit in [0x01u8, 0x80] {
                let mut bad = sig;
                bad[i] ^= bit;
                assert!(pk.verify(msg, &bad).is_err(), "sig byte {i} bit {bit:#x}");
            }
        }
        assert!(pk.verify(b"other message", &sig).is_err());
        let other = XSigningKey::generate().unwrap().public();
        assert!(other.verify(msg, &sig).is_err());
    }

    #[test]
    fn use_case_byte_binds() {
        let sk = XSigningKey::generate().unwrap();
        let pk = sk.public();
        let sig = sk.sign_use_case(0x30, b"epoch storage pub").unwrap();
        pk.verify_use_case(0x30, b"epoch storage pub", &sig)
            .unwrap();
        pk.verify(b"\x30epoch storage pub", &sig).unwrap();
        assert!(
            pk.verify_use_case(0x31, b"epoch storage pub", &sig)
                .is_err()
        );
        assert!(pk.verify(b"epoch storage pub", &sig).is_err());
    }

    #[test]
    fn verify_rejects_bad_u_and_s() {
        let sk = x(PRIV_IN);
        let pk = sk.public();
        let sig = sk.sign(b"m").unwrap();
        // u with the high bit set (u >= 2^255 > p).
        let mut hi = pk;
        hi.0[31] |= 0x80;
        assert_eq!(hi.verify(b"m", &sig), Err(Error::BadPublicKey));
        // u = p and u = p + 1 (non-canonical encodings of 0 and 1).
        let mut p1 = P_LE;
        assert_eq!(
            XVerifyingKey(p1).verify(b"m", &sig),
            Err(Error::BadPublicKey)
        );
        p1[0] += 1;
        assert_eq!(
            XVerifyingKey(p1).verify(b"m", &sig),
            Err(Error::BadPublicKey)
        );
        // u = p - 1 = -1 is on the twist.
        let mut m1 = P_LE;
        m1[0] -= 1;
        assert_eq!(
            XVerifyingKey(m1).verify(b"m", &sig),
            Err(Error::BadPublicKey)
        );
        // Small-order u (0 and 1).
        assert_eq!(
            XVerifyingKey([0u8; 32]).verify(b"m", &sig),
            Err(Error::BadPublicKey)
        );
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(
            XVerifyingKey(one).verify(b"m", &sig),
            Err(Error::BadPublicKey)
        );
        // s >= 2^253.
        let mut big_s = sig;
        big_s[63] |= 0x20;
        assert_eq!(pk.verify(b"m", &big_s), Err(Error::BadSignature));
        // s + q (in range < 2^253 but non-canonical) is rejected.
        let s = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).unwrap();
        let s_plus_q = add_le(s.as_bytes(), &L_LE);
        if s_plus_q[31] & 0xe0 == 0 {
            let mut mall = sig;
            mall[32..].copy_from_slice(&s_plus_q);
            assert_eq!(pk.verify(b"m", &mall), Err(Error::BadSignature));
        }
    }

    const L_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    fn add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let t = a[i] as u16 + b[i] as u16 + carry;
            out[i] = t as u8;
            carry = t >> 8;
        }
        out
    }

    #[test]
    fn signature_is_valid_ed25519_under_converted_key() {
        // XEdDSA signatures verify as plain Ed25519 under A = convert_mont(u).
        let sk = XSigningKey::generate().unwrap();
        let sig = sk.sign(b"hello").unwrap();
        let a = MontgomeryPoint(sk.public().0)
            .to_edwards(0)
            .unwrap()
            .compress()
            .to_bytes();
        verify_transport(&a, b"hello", &sig).unwrap();
    }

    /// Cross-check against the independent `xeddsa` crate (v1.1.0):
    /// signatures verify in both directions, and when `calculate_key_pair`
    /// negates the scalar (E.s = 1) both implementations hash the same
    /// reduced `a`, so with the same `Z` the signatures are byte-identical.
    ///
    /// When E.s = 0 the `xeddsa` crate (like libsignal-protocol-c) feeds the
    /// unreduced clamped `k` into `hash_1`, whereas the spec says
    /// `a = k mod q`; the nonce `r` then differs but both signatures are valid.
    #[test]
    fn cross_check_xeddsa_crate() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1ab7);
        let mut identical = 0;
        for i in 0..64u32 {
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut k);
            let msg = format!("message {i}").into_bytes();
            let ours = x(k);
            let theirs = xed25519::PrivateKey(k);
            let their_pub = xed25519::PublicKey(ours.public().0);
            assert_eq!(
                ours.public().0,
                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(k)).to_bytes()
            );

            // Theirs -> ours.
            // Two identically seeded RNGs: one hands `Z` to the xeddsa crate,
            // the other lets us read the same `Z`.
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let mut z = [0u8; 64];
            rand::rngs::StdRng::from_seed(seed).fill_bytes(&mut z);
            let their_sig: [u8; 64] = theirs.sign(&msg, rand::rngs::StdRng::from_seed(seed));
            ours.public().verify(&msg, &their_sig).unwrap();

            // Ours -> theirs.
            let our_sig = ours.sign_with_z(&msg, &z);
            their_pub.verify(&msg, &our_sig).unwrap();

            let (their_a, their_pub_ed) = theirs.calculate_key_pair(0);
            let (our_pub_ed, our_a) = calculate_key_pair(&k);
            assert_eq!(their_pub_ed, our_pub_ed.compress().to_bytes());
            let e_sign = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(clamp_integer(k)))
                .compress()
                .as_bytes()[31]
                >> 7;
            if e_sign == 1 {
                assert_eq!(their_a, our_a.to_bytes());
                assert_eq!(
                    our_sig, their_sig,
                    "deterministic match for negated key {i}"
                );
                identical += 1;
            } else {
                assert_eq!(Scalar::from_bytes_mod_order(their_a), our_a);
                // Different nonce r (unreduced vs reduced `a` in hash_1).
                assert_ne!(our_sig, their_sig);
            }
        }
        assert!(identical > 0, "seed should exercise the negated branch");
    }

    #[test]
    fn transport_round_trip() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let t = Ed25519Transport(sk);
        let pk = t.transport_public_key();
        let sig = t.sign_transport(b"minos.unstructured_signature.message:ct");
        verify_transport(&pk, b"minos.unstructured_signature.message:ct", &sig).unwrap();
        assert_eq!(
            verify_transport(&pk, b"other", &sig),
            Err(Error::BadSignature)
        );
        for i in 0..64 {
            let mut bad = sig;
            bad[i] ^= 1;
            assert!(
                verify_transport(&pk, b"minos.unstructured_signature.message:ct", &bad).is_err()
            );
        }
    }

    /// RFC 8032 §7.1 TEST 1 (empty message).
    #[test]
    fn transport_rfc8032_test1() {
        let sk: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let t = Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&sk));
        assert_eq!(
            hex::encode(t.transport_public_key()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = t.sign_transport(b"");
        assert_eq!(
            hex::encode(sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        verify_transport(&t.transport_public_key(), b"", &sig).unwrap();
    }
}

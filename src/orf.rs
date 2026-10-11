//! Oblivious Revocable Function over Ristretto255 (paper p.18–20, SPEC §3.6).
//! The server half runs on mls-ds ([CB-17]).
//!
//! ```text
//! hash_to_curve(x)          = ristretto_from_uniform_bytes(sha512(x))
//! client_map(c, domain, x)  = hash_to_curve(HMAC(key = domain, data = x)) * c
//! server_map(s, domain, P)  = HMAC(key = domain, data = compress(P * s))
//! client_evolve(c)          = (c * r, r)          r random, nonzero
//! server_evolve(s, r)       = s * r^-1
//! ```
//!
//! Invariant: `server_map(s', d2, client_map(c', d1, x)) ==
//! server_map(s, d2, client_map(c, d1, x))` for any evolve chain.
//!
//! The paper writes `hmac(input, domain)`; with SPEC §2's `mac(data, key)`
//! convention that is HMAC keyed by the domain.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::hpke::labyrinth::prims;

/// Client scalar (canonical, nonzero).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OrfClientState(pub(crate) [u8; 32]);
/// Server scalar (canonical, nonzero).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OrfServerState(pub(crate) [u8; 32]);
/// Random scalar `r` handed to the server on evolve.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EvolveToken(pub [u8; 32]);
/// Compressed Ristretto point sent from client to server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObliviousId(pub [u8; 32]);

impl OrfClientState {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    /// Rejects non-canonical and zero scalars.
    pub fn from_bytes(b: [u8; 32]) -> crate::Result<Self> {
        nonzero_scalar(b, "orf client state")?;
        Ok(Self(b))
    }
}
impl OrfServerState {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    /// Rejects non-canonical and zero scalars.
    pub fn from_bytes(b: [u8; 32]) -> crate::Result<Self> {
        nonzero_scalar(b, "orf server state")?;
        Ok(Self(b))
    }
}

fn nonzero_scalar(b: [u8; 32], what: &'static str) -> crate::Result<Scalar> {
    let s: Option<Scalar> = Scalar::from_canonical_bytes(b).into();
    match s {
        Some(s) if s != Scalar::ZERO => Ok(s),
        _ => Err(Error::Malformed(what)),
    }
}

/// Uniform nonzero scalar from 64 bytes of OS randomness.
fn random_scalar() -> crate::Result<Scalar> {
    loop {
        let mut wide = [0u8; 64];
        prims::random(&mut wide)?;
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        if s != Scalar::ZERO {
            return Ok(s);
        }
    }
}

fn hash_to_curve(x: &[u8]) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(&prims::sha512(x))
}

/// Internal accessor; states are validated at construction.
fn scalar_of(b: &[u8; 32]) -> Scalar {
    Scalar::from_canonical_bytes(*b).expect("validated at construction")
}

pub fn orf_client_init() -> crate::Result<OrfClientState> {
    Ok(OrfClientState(random_scalar()?.to_bytes()))
}

pub fn orf_server_init() -> crate::Result<OrfServerState> {
    Ok(OrfServerState(random_scalar()?.to_bytes()))
}

pub fn orf_client_map(state: &OrfClientState, domain: &[u8], input: &[u8]) -> ObliviousId {
    let scoped = prims::mac(input, domain);
    let p = hash_to_curve(&scoped) * scalar_of(&state.0);
    ObliviousId(p.compress().to_bytes())
}

/// Rejects ids that are not valid Ristretto encodings or that are the identity.
pub fn orf_server_map(
    state: &OrfServerState,
    domain: &[u8],
    id: &ObliviousId,
) -> crate::Result<[u8; 32]> {
    let p = CompressedRistretto(id.0)
        .decompress()
        .ok_or(Error::Malformed("oblivious id is not a ristretto point"))?;
    if p.is_identity() {
        return Err(Error::Malformed("oblivious id is the identity"));
    }
    let q = p * scalar_of(&state.0);
    Ok(prims::mac(q.compress().as_bytes(), domain))
}

pub fn orf_client_evolve(state: &OrfClientState) -> crate::Result<(OrfClientState, EvolveToken)> {
    let r = random_scalar()?;
    Ok(client_evolve_with(state, &r))
}

fn client_evolve_with(state: &OrfClientState, r: &Scalar) -> (OrfClientState, EvolveToken) {
    let next = scalar_of(&state.0) * r;
    (OrfClientState(next.to_bytes()), EvolveToken(r.to_bytes()))
}

/// Rejects non-canonical and zero tokens.
pub fn orf_server_evolve(
    state: &OrfServerState,
    token: &EvolveToken,
) -> crate::Result<OrfServerState> {
    let r = nonzero_scalar(token.0, "evolve token")?;
    let next = scalar_of(&state.0) * r.invert();
    Ok(OrfServerState(next.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evolve_preserves_output() {
        let c = orf_client_init().unwrap();
        let s = orf_server_init().unwrap();
        let base = orf_server_map(&s, b"sd", &orf_client_map(&c, b"cd", b"x")).unwrap();
        let r = Scalar::from(7u64);
        let (c2, t) = client_evolve_with(&c, &r);
        let s2 = orf_server_evolve(&s, &t).unwrap();
        assert_eq!(
            orf_server_map(&s2, b"sd", &orf_client_map(&c2, b"cd", b"x")).unwrap(),
            base
        );
    }

    #[test]
    fn rejects_zero_and_noncanonical() {
        assert!(OrfClientState::from_bytes([0u8; 32]).is_err());
        assert!(OrfServerState::from_bytes([0xff; 32]).is_err());
        let s = orf_server_init().unwrap();
        assert!(orf_server_evolve(&s, &EvolveToken([0u8; 32])).is_err());
        assert!(orf_server_map(&s, b"d", &ObliviousId([0u8; 32])).is_err());
        assert!(orf_server_map(&s, b"d", &ObliviousId([0xff; 32])).is_err());
    }
}

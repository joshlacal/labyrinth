//! Public-key encryption: 100% Post-Quantum Hawk HPKE (`X25519 + ML-KEM-768`,
//! SPEC §3.5, `I16`). Classical-only `lhpke` has been retired.

pub mod hawk;

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;

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

/// Primitive helpers shared inside `hpke`: `crate::encoding` functions plus
/// single-use zero-nonce AES-256-GCM.
pub(crate) mod prims {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    use crate::Error;

    pub(crate) use crate::encoding::{kdf, kdf32, minos_salt, random, sha256};

    /// AES-256-GCM with the all-zero 96-bit nonce. Safe only because every
    /// key passed here is single-use (derived from fresh ephemeral DH + ML-KEM).
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

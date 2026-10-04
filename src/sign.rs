//! Signatures (SPEC §3.3): XEdDSA over X25519 keys for Labyrinth keys, and
//! Ed25519 for the chat transport key ([CB-3]).

use zeroize::{Zeroize, ZeroizeOnDrop};

/// XEdDSA / X25519 private scalar (clamped on use).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct XSigningKey(pub(crate) [u8; 32]);

/// X25519 (Montgomery u-coordinate) public key used for XEdDSA verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct XVerifyingKey(pub [u8; 32]);

impl XSigningKey {
    pub fn generate() -> crate::Result<Self> { todo!() }
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }
    pub fn to_bytes(&self) -> [u8; 32] { self.0 }
    pub fn public(&self) -> XVerifyingKey { todo!() }
    /// XEdDSA signature over `msg` with fresh 64-byte randomness.
    pub fn sign(&self, msg: &[u8]) -> crate::Result<[u8; 64]> { todo!() }
    /// `pk_sign(priv, use_case_byte, data)` = sign(`use_case || data`).
    pub fn sign_use_case(&self, use_case: u8, data: &[u8]) -> crate::Result<[u8; 64]> { todo!() }
}

impl XVerifyingKey {
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> crate::Result<()> { todo!() }
    pub fn verify_use_case(&self, use_case: u8, data: &[u8], sig: &[u8; 64]) -> crate::Result<()> { todo!() }
}

/// The sending chat device's transport key ([CB-3]): Ed25519.
pub trait TransportSigner {
    fn transport_public_key(&self) -> [u8; 32];
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64];
}

/// Verify an Ed25519 transport signature.
pub fn verify_transport(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> crate::Result<()> {
    todo!()
}

/// In-memory Ed25519 transport signer (tests, and clients holding raw keys).
pub struct Ed25519Transport(pub ed25519_dalek::SigningKey);

impl TransportSigner for Ed25519Transport {
    fn transport_public_key(&self) -> [u8; 32] { todo!() }
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64] { todo!() }
}

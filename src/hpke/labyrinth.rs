//! Labyrinth HPKE exactly as in paper p.17 (SPEC §3.4).

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret(pub(crate) [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct X25519Public(pub [u8; 32]);

impl X25519Secret {
    pub fn generate() -> crate::Result<Self> { todo!() }
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }
    pub fn to_bytes(&self) -> [u8; 32] { self.0 }
    pub fn public(&self) -> X25519Public { todo!() }
}

/// `labyrinth_hpke_encrypt`. `psk.len() <= 32`.
pub fn encrypt(
    recipient_enc_pub: &X25519Public,
    sender_auth_pub: &X25519Public,
    sender_auth_priv: &X25519Secret,
    psk: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> crate::Result<Vec<u8>> {
    todo!()
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
    todo!()
}

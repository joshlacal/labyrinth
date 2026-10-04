//! Hawk HPKE: confidentiality from X25519 + ML-KEM-768, authentication from
//! X25519 (paper p.18; byte layout fixed by SPEC §3.5 [CB-8]).

use super::labyrinth::{X25519Public, X25519Secret};

/// ML-KEM-768 encapsulation key length.
pub const MLKEM768_EK_LEN: usize = 1184;

/// Hawk authentication keypair = X25519.
pub type HawkAuthSecret = X25519Secret;
pub type HawkAuthPublic = X25519Public;

/// Hawk encryption public key: `x25519(32) || mlkem768_ek(1184)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HawkEncPublic {
    pub x25519: X25519Public,
    pub mlkem: Vec<u8>,
}

/// Hawk encryption private key.
pub struct HawkEncSecret {
    pub(crate) x25519: X25519Secret,
    pub(crate) mlkem_seed: [u8; 64],
}

impl HawkEncPublic {
    pub fn to_bytes(&self) -> Vec<u8> { todo!() }
    pub fn from_bytes(b: &[u8]) -> crate::Result<Self> { todo!() }
}

impl HawkEncSecret {
    pub fn public(&self) -> HawkEncPublic { todo!() }
}

pub fn hawk_auth_keygen() -> crate::Result<(HawkAuthSecret, HawkAuthPublic)> { todo!() }
pub fn hawk_enc_keygen() -> crate::Result<(HawkEncSecret, HawkEncPublic)> { todo!() }
pub fn hawk_derive_auth(seed: &[u8; 32]) -> (HawkAuthSecret, HawkAuthPublic) { todo!() }
pub fn hawk_derive_enc(seed: &[u8; 32]) -> (HawkEncSecret, HawkEncPublic) { todo!() }

pub fn hawk_encrypt(
    recipient: &HawkEncPublic,
    sender_auth_priv: &HawkAuthSecret,
    sender_auth_pub: &HawkAuthPublic,
    aad: &[u8],
    pt: &[u8],
) -> crate::Result<Vec<u8>> {
    todo!()
}

pub fn hawk_decrypt(
    recipient_pub: &HawkEncPublic,
    recipient_priv: &HawkEncSecret,
    sender_auth_pub: &HawkAuthPublic,
    aad: &[u8],
    ct: &[u8],
) -> crate::Result<Vec<u8>> {
    todo!()
}

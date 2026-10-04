//! Symmetric AEAD `encrypt(key, aad, pt)` / `decrypt` (SPEC §3.1).
//!
//! Output = `suite(1) || suite-specific ciphertext`.

pub mod dndk_gcm;
pub mod gcm_extended;

/// AEAD suite selector, the first byte of every ciphertext ([CB-6]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Suite {
    /// Labyrinth 1.0 AES-GCM-Extended (HChaCha20 subkey + AES-256-GCM, 28-byte nonce).
    GcmExtended = 0x01,
    /// Labyrinth 1.1 AES-256-DNDK-GCM, KC_Choice = 1, LN = 24.
    DndkGcm = 0x02,
}

/// Encrypt with a fresh random nonce under `suite`.
pub fn encrypt(suite: Suite, key: &[u8; 32], aad: &[u8], pt: &[u8]) -> crate::Result<Vec<u8>> {
    todo!()
}

/// Encrypt with the v1.1 default suite ([`Suite::DndkGcm`]).
pub fn seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> crate::Result<Vec<u8>> {
    encrypt(Suite::DndkGcm, key, aad, pt)
}

/// Decrypt any supported suite, dispatching on the first byte.
pub fn decrypt(key: &[u8; 32], aad: &[u8], ct: &[u8]) -> crate::Result<Vec<u8>> {
    todo!()
}

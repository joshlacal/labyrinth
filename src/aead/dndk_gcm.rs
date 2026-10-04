//! AES-256-DNDK-GCM (draft-gueron-cfrg-dndkgcm), KC_Choice = 1, LN = 24.
//! Built on the `aes` block cipher and `aes-gcm`; verified against the
//! draft's own test vectors in `tests/vectors/dndk_gcm.json`.

/// Nonce length used by Labyrinth (LN = 24).
pub const NONCE_LEN: usize = 24;

/// Raw DNDK-GCM encryption with an explicit nonce. Returns the draft's
/// ciphertext layout (including the key-commitment value) without the nonce.
pub fn encrypt_with_nonce(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> crate::Result<Vec<u8>> {
    todo!()
}

/// Inverse of [`encrypt_with_nonce`]; verifies tag and key commitment.
pub fn decrypt_with_nonce(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> crate::Result<Vec<u8>> {
    todo!()
}

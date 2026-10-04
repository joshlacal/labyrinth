//! AES-GCM-Extended (Labyrinth 1.0, paper p.15):
//! `subkey = HChaCha20(key, nonce[0..16])`, `subnonce = nonce[16..28]`.

pub const NONCE_LEN: usize = 28;

pub fn encrypt_with_nonce(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> crate::Result<Vec<u8>> {
    todo!()
}

pub fn decrypt_with_nonce(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> crate::Result<Vec<u8>> {
    todo!()
}

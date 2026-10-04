//! PADMÉ padding with a 4-byte big-endian length prefix (SPEC §3.2).

/// `u32_be(len) || data || zeros`, padded with PADMÉ (minimum 10 data bytes).
pub fn pad(data: &[u8]) -> Vec<u8> {
    todo!()
}

/// Inverse of [`pad`]; rejects a length prefix larger than the buffer.
pub fn unpad(padded: &[u8]) -> crate::Result<Vec<u8>> {
    todo!()
}

/// PADMÉ padded length for an input of `len` bytes (before the length prefix).
pub fn padme_len(len: usize) -> usize {
    todo!()
}

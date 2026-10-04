//! Encodings and KDF helpers (SPEC §2).

/// `sha256("minos encrypted backup protocol\n")` (SPEC §2, paper p.27).
pub fn minos_salt() -> [u8; 32] {
    todo!()
}

/// HKDF-SHA256 with `L = out.len()`. `salt = None` is HKDF's default salt.
pub fn kdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) {
    todo!()
}

/// Convenience: 32-byte [`kdf`].
pub fn kdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    todo!()
}

/// `HMAC-SHA256(key, data)`; the paper writes this `mac(data, key)`.
pub fn mac(data: &[u8], key: &[u8]) -> [u8; 32] {
    todo!()
}

/// `SHA-256(data)`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    todo!()
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    todo!()
}

/// Standard padded Base64 of the decimal string of `n` (`3` → `"Mw=="`).
pub fn b64_decimal(n: u64) -> String {
    todo!()
}

/// Fill `out` from the OS CSPRNG.
pub fn random(out: &mut [u8]) -> crate::Result<()> {
    todo!()
}

//! Symmetric AEAD `encrypt(key, aad, pt)` / `decrypt` (SPEC §3.1).
//!
//! Output = `suite(1) || suite-specific ciphertext`:
//!
//! - `0x01 || nonce(28) || ct || tag(16)` — AES-GCM-Extended
//! - `0x02 || nonce(24) || ct || tag(16) || kc(32)` — AES-256-DNDK-GCM
//!
//! The AEAD layer does not pad; callers pad message plaintexts with
//! [`crate::padding`] ([CB-7]).

pub mod dndk_gcm;
pub mod gcm_extended;

use crate::{Error, Result};

/// AEAD suite selector, the first byte of every ciphertext ([CB-6]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Suite {
    /// Labyrinth 1.0 AES-GCM-Extended (HChaCha20 subkey + AES-256-GCM, 28-byte nonce).
    GcmExtended = 0x01,
    /// Labyrinth 1.1 AES-256-DNDK-GCM, KC_Choice = 1, LN = 24.
    DndkGcm = 0x02,
}

impl Suite {
    /// Parse a suite byte.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Self::GcmExtended),
            0x02 => Ok(Self::DndkGcm),
            other => Err(Error::Unsupported(other)),
        }
    }
}

/// Encrypt with a fresh random nonce under `suite`.
pub fn encrypt(suite: Suite, key: &[u8; 32], aad: &[u8], pt: &[u8]) -> crate::Result<Vec<u8>> {
    match suite {
        Suite::GcmExtended => {
            let mut nonce = [0u8; gcm_extended::NONCE_LEN];
            crate::encoding::random(&mut nonce)?;
            let ct = gcm_extended::encrypt_with_nonce(key, &nonce, aad, pt)?;
            Ok(frame(suite, &nonce, &ct))
        }
        Suite::DndkGcm => {
            let mut nonce = [0u8; dndk_gcm::NONCE_LEN];
            crate::encoding::random(&mut nonce)?;
            let ct = dndk_gcm::encrypt_with_nonce(key, &nonce, aad, pt)?;
            Ok(frame(suite, &nonce, &ct))
        }
    }
}

fn frame(suite: Suite, nonce: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + nonce.len() + ct.len());
    out.push(suite as u8);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ct);
    out
}

/// Encrypt with the v1.1 default suite ([`Suite::DndkGcm`]).
pub fn seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> crate::Result<Vec<u8>> {
    encrypt(Suite::DndkGcm, key, aad, pt)
}

/// Decrypt any supported suite, dispatching on the first byte.
///
/// Only Labyrinth 1.0 owner messages may legitimately carry
/// [`Suite::GcmExtended`]; every object this crate seals on a v1.1 path
/// must be opened with [`decrypt_suite`] so a ciphertext relabelled to the
/// weaker suite is refused.
pub fn decrypt(key: &[u8; 32], aad: &[u8], ct: &[u8]) -> crate::Result<Vec<u8>> {
    let suite = *ct.first().ok_or(Error::Malformed("empty ciphertext"))?;
    decrypt_as(Suite::from_byte(suite)?, key, aad, ct)
}

/// Decrypt a ciphertext that must use `expected`; any other suite byte
/// fails with [`Error::Unsupported`] before any key is used.
pub fn decrypt_suite(
    expected: Suite,
    key: &[u8; 32],
    aad: &[u8],
    ct: &[u8],
) -> crate::Result<Vec<u8>> {
    let suite = *ct.first().ok_or(Error::Malformed("empty ciphertext"))?;
    if suite != expected as u8 {
        return Err(Error::Unsupported(suite));
    }
    decrypt_as(expected, key, aad, ct)
}

fn decrypt_as(suite: Suite, key: &[u8; 32], aad: &[u8], ct: &[u8]) -> crate::Result<Vec<u8>> {
    let rest = &ct[1..];
    match suite {
        Suite::GcmExtended => {
            let (nonce, body) = rest
                .split_first_chunk::<{ gcm_extended::NONCE_LEN }>()
                .ok_or(Error::Malformed("ciphertext shorter than nonce"))?;
            gcm_extended::decrypt_with_nonce(key, nonce, aad, body)
        }
        Suite::DndkGcm => {
            let (nonce, body) = rest
                .split_first_chunk::<{ dndk_gcm::NONCE_LEN }>()
                .ok_or(Error::Malformed("ciphertext shorter than nonce"))?;
            dndk_gcm::decrypt_with_nonce(key, nonce, aad, body)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x11; 32];

    #[test]
    fn layouts() {
        let a = encrypt(Suite::GcmExtended, &KEY, b"aad", b"hello").unwrap();
        assert_eq!(a[0], 0x01);
        assert_eq!(a.len(), 1 + 28 + 5 + 16);
        let b = seal(&KEY, b"aad", b"hello").unwrap();
        assert_eq!(b[0], 0x02);
        assert_eq!(b.len(), 1 + 24 + 5 + 16 + 32);
        // The body after the suite byte is exactly the raw construction.
        let nonce: [u8; 24] = b[1..25].try_into().unwrap();
        assert_eq!(
            dndk_gcm::encrypt_with_nonce(&KEY, &nonce, b"aad", b"hello").unwrap(),
            b[25..]
        );
    }

    #[test]
    fn round_trip_both_suites() {
        for suite in [Suite::GcmExtended, Suite::DndkGcm] {
            for len in [0usize, 1, 100] {
                let pt = vec![7u8; len];
                let ct = encrypt(suite, &KEY, b"ctx", &pt).unwrap();
                assert_eq!(decrypt(&KEY, b"ctx", &ct).unwrap(), pt);
            }
        }
    }

    #[test]
    fn nonces_are_fresh() {
        let a = seal(&KEY, b"", b"same").unwrap();
        let b = seal(&KEY, b"", b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tamper_every_byte_both_suites() {
        for suite in [Suite::GcmExtended, Suite::DndkGcm] {
            let ct = encrypt(suite, &KEY, b"aad", b"message body").unwrap();
            for i in 0..ct.len() {
                let mut bad = ct.clone();
                bad[i] ^= 0x01;
                assert!(decrypt(&KEY, b"aad", &bad).is_err(), "{suite:?} byte {i}");
            }
            assert_eq!(decrypt(&KEY, b"aaD", &ct), Err(Error::Decrypt));
            assert_eq!(decrypt(&[0x12; 32], b"aad", &ct), Err(Error::Decrypt));
        }
    }

    #[test]
    fn suite_dispatch_rejects_unknown_and_swapped() {
        let ct = seal(&KEY, b"", b"x").unwrap();
        for b in [0x00u8, 0x03, 0xff] {
            let mut bad = ct.clone();
            bad[0] = b;
            assert_eq!(decrypt(&KEY, b"", &bad), Err(Error::Unsupported(b)));
        }
        // Relabelling a DNDK ciphertext as GCM-Extended (and vice versa) fails.
        let mut swapped = ct.clone();
        swapped[0] = 0x01;
        assert!(decrypt(&KEY, b"", &swapped).is_err());
        let mut ext = encrypt(Suite::GcmExtended, &KEY, b"", b"x").unwrap();
        ext[0] = 0x02;
        assert!(decrypt(&KEY, b"", &ext).is_err());
    }

    #[test]
    fn decrypt_suite_pins_the_suite() {
        let ext = encrypt(Suite::GcmExtended, &KEY, b"a", b"x").unwrap();
        let dndk = seal(&KEY, b"a", b"x").unwrap();
        assert_eq!(
            decrypt_suite(Suite::DndkGcm, &KEY, b"a", &ext),
            Err(Error::Unsupported(0x01))
        );
        assert_eq!(
            decrypt_suite(Suite::DndkGcm, &KEY, b"a", &dndk).unwrap(),
            b"x"
        );
        assert_eq!(
            decrypt_suite(Suite::GcmExtended, &KEY, b"a", &dndk),
            Err(Error::Unsupported(0x02))
        );
        assert!(decrypt_suite(Suite::DndkGcm, &KEY, b"a", &[]).is_err());
    }

    #[test]
    fn short_inputs() {
        assert!(decrypt(&KEY, b"", &[]).is_err());
        assert!(decrypt(&KEY, b"", &[0x01]).is_err());
        assert!(decrypt(&KEY, b"", &[0x02; 25]).is_err());
        assert!(decrypt(&KEY, b"", &[0x01; 29]).is_err());
        let mut just_nonce = vec![0x02];
        just_nonce.extend_from_slice(&[0u8; 24 + 47]);
        assert_eq!(decrypt(&KEY, b"", &just_nonce), Err(Error::Decrypt));
    }
}

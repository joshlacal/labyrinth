//! PADMÉ padding with a 4-byte big-endian length prefix (SPEC §3.2).
//!
//! PADMÉ is from Nikitin et al., "Reducing Metadata Leakage from Encrypted
//! Files and Communication with PURBs" (PoPETs 2019), Algorithm 1:
//! `E = ⌊log2 L⌋`, `S = ⌊log2 E⌋ + 1`, `lastBits = E − S`,
//! `mask = 2^lastBits − 1`, `padded = (L + mask) & !mask`.
//! Labyrinth pads anything shorter than 10 bytes to 10 (paper p.15).

use crate::{Error, Result};

/// Minimum padded data length (paper p.15).
const MIN_LEN: usize = 10;
/// Length-prefix size.
const PREFIX: usize = 4;

/// `u32_be(len) || data || zeros`, padded with PADMÉ (minimum 10 data bytes).
///
/// # Panics
///
/// Panics if `data.len()` does not fit in a `u32` (the length prefix).
pub fn pad(data: &[u8]) -> Vec<u8> {
    let len = u32::try_from(data.len()).expect("padded plaintext must be shorter than 4 GiB");
    let total = PREFIX + padme_len(data.len());
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out.resize(total, 0);
    out
}

/// Inverse of [`pad`]; rejects a length prefix larger than the buffer.
///
/// Strict: the buffer must be exactly `4 + padme_len(len)` bytes long and
/// every padding byte must be zero, so each plaintext has one encoding.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    let (prefix, rest) = padded
        .split_first_chunk::<PREFIX>()
        .ok_or(Error::Malformed(
            "padded plaintext shorter than length prefix",
        ))?;
    let len = usize::try_from(u32::from_be_bytes(*prefix))
        .map_err(|_| Error::Malformed("padding length prefix overflows usize"))?;
    if len > rest.len() {
        return Err(Error::Malformed("padding length prefix exceeds buffer"));
    }
    if rest.len() != padme_len(len) {
        return Err(Error::Malformed("padded length is not the PADMÉ length"));
    }
    let (data, padding) = rest.split_at(len);
    if padding.iter().any(|&b| b != 0) {
        return Err(Error::Malformed("non-zero padding byte"));
    }
    Ok(data.to_vec())
}

/// PADMÉ padded length for an input of `len` bytes (before the length prefix).
pub fn padme_len(len: usize) -> usize {
    let l = len.max(MIN_LEN);
    // l >= 10, so e >= 3 and s >= 2.
    let e = usize::BITS - 1 - l.leading_zeros();
    let s = (u32::BITS - 1 - e.leading_zeros()) + 1;
    let last_bits = e - s;
    let mask = (1usize << last_bits) - 1;
    (l + mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference PADMÉ, written directly from the paper with floating-point
    /// logs, for cross-checking the integer version.
    fn padme_reference(l: usize) -> usize {
        let l = l.max(10) as u64;
        let e = (l as f64).log2().floor() as u64;
        let s = (e as f64).log2().floor() as u64 + 1;
        let last_bits = e - s;
        let mask = (1u64 << last_bits) - 1;
        ((l + mask) & !mask) as usize
    }

    #[test]
    fn padme_known_values() {
        for (l, p) in [
            (0, 10),
            (1, 10),
            (9, 10),
            (10, 10),
            (11, 12),
            (12, 12),
            (13, 14),
            (16, 16),
            (17, 18),
            (100, 104),
            (255, 256),
            (256, 256),
            (257, 272),
            (1000, 1024),
            (1 << 16, 1 << 16),
            ((1 << 16) + 1, (1 << 16) + 2048),
        ] {
            assert_eq!(padme_len(l), p, "padme_len({l})");
        }
    }

    #[test]
    fn padme_matches_reference_and_overhead_bound() {
        for l in 0..70_000usize {
            let p = padme_len(l);
            assert_eq!(p, padme_reference(l), "len {l}");
            assert!(p >= l.max(10));
            // PADMÉ overhead is at most ~12 %.
            if l >= 10 {
                assert!((p - l) * 100 <= l * 12 + 100, "overhead for {l}");
            }
        }
    }

    #[test]
    fn padme_is_monotone_and_idempotent() {
        let mut prev = 0;
        for l in 0..20_000usize {
            let p = padme_len(l);
            assert!(p >= prev);
            assert_eq!(padme_len(p), p);
            prev = p;
        }
    }

    #[test]
    fn round_trip_boundaries() {
        for len in [0usize, 1, 9, 10, 11, 255, 256, 257, 1 << 16, (1 << 16) + 1] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8 + 1).collect();
            let padded = pad(&data);
            assert_eq!(padded.len(), 4 + padme_len(len));
            assert_eq!(&padded[..4], &(len as u32).to_be_bytes());
            assert_eq!(&padded[4..4 + len], &data[..]);
            assert!(padded[4 + len..].iter().all(|&b| b == 0));
            assert_eq!(unpad(&padded).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn short_inputs_pad_to_ten() {
        assert_eq!(pad(b"").len(), 14);
        assert_eq!(pad(b"hi").len(), 14);
        assert_eq!(pad(&[7u8; 9]).len(), 14);
        assert_eq!(pad(&[7u8; 10]).len(), 14);
        assert_eq!(pad(&[7u8; 11]).len(), 16);
    }

    #[test]
    fn unpad_rejects_malformed() {
        // Too short for the prefix.
        for n in 0..4 {
            assert!(unpad(&vec![0u8; n]).is_err());
        }
        let good = pad(b"hello world!!"); // 13 bytes -> 14, one padding byte
        // Length prefix larger than the buffer.
        let mut big = good.clone();
        big[..4].copy_from_slice(&1000u32.to_be_bytes());
        assert!(unpad(&big).is_err());
        let mut max = good.clone();
        max[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(unpad(&max).is_err());
        // Non-zero padding byte.
        let mut nz = good.clone();
        *nz.last_mut().unwrap() = 1;
        assert!(unpad(&nz).is_err());
        // Truncated or extended buffer (not the PADMÉ length).
        assert!(unpad(&good[..good.len() - 1]).is_err());
        let mut ext = good.clone();
        ext.push(0);
        assert!(unpad(&ext).is_err());
        // Prefix that is smaller than the real data but still fits.
        let mut shorter = good.clone();
        shorter[..4].copy_from_slice(&3u32.to_be_bytes());
        assert!(unpad(&shorter).is_err());
        // Unpadded data (no padding applied at all).
        let mut raw = 5u32.to_be_bytes().to_vec();
        raw.extend_from_slice(b"hello");
        assert!(unpad(&raw).is_err());
        // Empty data padded correctly is accepted; empty with no padding is not.
        assert_eq!(unpad(&pad(b"")).unwrap(), Vec::<u8>::new());
        assert!(unpad(&[0, 0, 0, 0]).is_err());
    }
}

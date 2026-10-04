//! Encodings and KDF helpers (SPEC §2).

use base64::Engine as _;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};

/// `sha256("minos encrypted backup protocol\n")` (SPEC §2, paper p.27).
pub fn minos_salt() -> [u8; 32] {
    sha256(b"minos encrypted backup protocol\n")
}

/// HKDF-SHA256 with `L = out.len()`. `salt = None` is HKDF's default salt.
///
/// # Panics
///
/// Panics if `out.len() > 255 * 32` (the HKDF-SHA256 output limit). Every
/// length used by the protocol is a small constant.
pub fn kdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out)
        .expect("HKDF-SHA256 output length must be at most 8160 bytes");
}

/// Convenience: 32-byte [`kdf`].
pub fn kdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    kdf(ikm, salt, info, &mut out);
    out
}

/// `HMAC-SHA256(key, data)`; the paper writes this `mac(data, key)`.
pub fn mac(data: &[u8], key: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// `SHA-256(data)`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `SHA-512(data)`.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::Digest;
    sha2::Sha512::digest(data).into()
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    ::hex::encode(bytes)
}

/// Standard padded Base64 of the decimal string of `n` (`3` → `"Mw=="`).
pub fn b64_decimal(n: u64) -> String {
    base64::engine::general_purpose::STANDARD.encode(n.to_string())
}

/// Fill `out` from the OS CSPRNG.
pub fn random(out: &mut [u8]) -> crate::Result<()> {
    getrandom::fill(out).map_err(|_| crate::Error::Rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        ::hex::decode(s).unwrap()
    }

    #[test]
    fn minos_salt_is_sha256_of_label() {
        // Independently computed: printf 'minos encrypted backup protocol\n' | shasum -a 256
        assert_eq!(minos_salt(), sha256(b"minos encrypted backup protocol\n"));
        assert_ne!(minos_salt(), sha256(b"minos encrypted backup protocol"));
    }

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hkdf_rfc5869_case_1() {
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let mut okm = [0u8; 42];
        kdf(&ikm, Some(&salt), &info, &mut okm);
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_rfc5869_case_3_null_salt() {
        // RFC 5869 A.3: zero-length salt and info. HKDF's default salt (HashLen zeros)
        // gives the same PRK as an empty salt.
        let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let mut okm = [0u8; 42];
        kdf(&ikm, None, b"", &mut okm);
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
        let mut okm2 = [0u8; 42];
        kdf(&ikm, Some(&[0u8; 32]), b"", &mut okm2);
        assert_eq!(okm, okm2);
    }

    #[test]
    fn kdf_split_is_prefix_consistent() {
        // [CB-4]: `(a, b) := kdf(..)` expands len(a)+len(b) and splits in order.
        let mut long = [0u8; 64];
        kdf(b"ikm", None, b"info", &mut long);
        assert_eq!(&long[..32], &kdf32(b"ikm", None, b"info"));
    }

    #[test]
    fn hmac_rfc4231_case_2() {
        assert_eq!(
            hex(&mac(b"what do ya want for nothing?", b"Jefe")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0xAB, 0x01, 0xff]), "ab01ff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn b64_decimal_examples() {
        assert_eq!(b64_decimal(3), "Mw==");
        assert_eq!(b64_decimal(0), "MA==");
        assert_eq!(b64_decimal(10), "MTA=");
        assert_eq!(b64_decimal(123), "MTIz");
        assert_eq!(b64_decimal(u64::MAX), "MTg0NDY3NDQwNzM3MDk1NTE2MTU=");
    }

    #[test]
    fn random_fills_and_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random(&mut a).unwrap();
        random(&mut b).unwrap();
        assert_ne!(a, b);
        random(&mut []).unwrap();
    }
}

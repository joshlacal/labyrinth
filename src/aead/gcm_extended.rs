//! AES-GCM-Extended (Labyrinth 1.0, paper p.15):
//! `subkey = HChaCha20(key, nonce[0..16])`, `subnonce = nonce[16..28]`.
//!
//! Output (without the nonce, which [`crate::aead`] prepends) is the
//! AES-256-GCM `ct || tag(16)` under `subkey` / `subnonce`.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20::{R20, hchacha};
use zeroize::Zeroize;

use crate::Error;

pub const NONCE_LEN: usize = 28;
/// GCM tag length.
pub const TAG_LEN: usize = 16;

fn subkey_cipher(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> (Aes256Gcm, [u8; 12]) {
    let mut head = [0u8; 16];
    head.copy_from_slice(&nonce[..16]);
    let mut subkey = hchacha::<R20>(key.into(), &head.into());
    let cipher = Aes256Gcm::new(&subkey);
    subkey.zeroize();
    let mut subnonce = [0u8; 12];
    subnonce.copy_from_slice(&nonce[16..]);
    (cipher, subnonce)
}

pub fn encrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> crate::Result<Vec<u8>> {
    let (cipher, subnonce) = subkey_cipher(key, nonce);
    cipher
        .encrypt((&subnonce).into(), Payload { msg: pt, aad })
        .map_err(|_| Error::Malformed("AES-GCM input out of range"))
}

pub fn decrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> crate::Result<Vec<u8>> {
    if ct.len() < TAG_LEN {
        return Err(Error::Decrypt);
    }
    let (cipher, subnonce) = subkey_cipher(key, nonce);
    cipher
        .decrypt((&subnonce).into(), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HChaCha20 test vector from draft-irtf-cfrg-xchacha-03 §2.2.1.
    #[test]
    fn hchacha20_draft_vector() {
        let key: [u8; 32] =
            hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .try_into()
                .unwrap();
        let input: [u8; 16] = hex::decode("000000090000004a0000000031415927")
            .unwrap()
            .try_into()
            .unwrap();
        let out = hchacha::<R20>((&key).into(), &input.into());
        assert_eq!(
            hex::encode(out),
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
        );
    }

    /// The construction equals AES-256-GCM under the HChaCha20 subkey.
    #[test]
    fn matches_manual_construction() {
        let key = [0x42u8; 32];
        let mut nonce = [0u8; 28];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = i as u8;
        }
        let ct = encrypt_with_nonce(&key, &nonce, b"aad", b"plaintext").unwrap();
        let head: [u8; 16] = nonce[..16].try_into().unwrap();
        let sub = hchacha::<R20>((&key).into(), &head.into());
        let manual = Aes256Gcm::new(&sub)
            .encrypt(
                (&<[u8; 12]>::try_from(&nonce[16..]).unwrap()).into(),
                Payload {
                    msg: b"plaintext",
                    aad: b"aad",
                },
            )
            .unwrap();
        assert_eq!(ct, manual);
        assert_eq!(ct.len(), 9 + TAG_LEN);
    }

    #[test]
    fn round_trip_lengths() {
        let key = [3u8; 32];
        let nonce = [8u8; 28];
        for len in [0usize, 1, 16, 33, 4096] {
            let pt = vec![0x5Au8; len];
            let ct = encrypt_with_nonce(&key, &nonce, b"x", &pt).unwrap();
            assert_eq!(decrypt_with_nonce(&key, &nonce, b"x", &ct).unwrap(), pt);
        }
    }

    #[test]
    fn tamper_every_byte() {
        let key = [1u8; 32];
        let nonce = [2u8; 28];
        let aad = b"associated";
        let ct = encrypt_with_nonce(&key, &nonce, aad, b"hello labyrinth").unwrap();
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                decrypt_with_nonce(&key, &nonce, aad, &bad),
                Err(Error::Decrypt)
            );
        }
        for i in 0..aad.len() {
            let mut bad = aad.to_vec();
            bad[i] ^= 0x01;
            assert_eq!(
                decrypt_with_nonce(&key, &nonce, &bad, &ct),
                Err(Error::Decrypt)
            );
        }
        for i in 0..nonce.len() {
            let mut bad = nonce;
            bad[i] ^= 0x01;
            assert_eq!(
                decrypt_with_nonce(&key, &bad, aad, &ct),
                Err(Error::Decrypt),
                "nonce {i}"
            );
        }
        let mut wrong = key;
        wrong[31] ^= 1;
        assert_eq!(
            decrypt_with_nonce(&wrong, &nonce, aad, &ct),
            Err(Error::Decrypt)
        );
        assert_eq!(
            decrypt_with_nonce(&key, &nonce, aad, &ct[..15]),
            Err(Error::Decrypt)
        );
    }
}

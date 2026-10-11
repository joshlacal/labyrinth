//! AES-256-DNDK-GCM (draft-gueron-cfrg-dndkgcm), KC_Choice = 1, LN = 24.
//! Built on the `aes` block cipher and `aes-gcm`; verified against the
//! draft's own test vectors in `tests/vectors/dndk_gcm.json`.
//!
//! Implemented from **draft-gueron-cfrg-dndkgcm-05** (16 September 2026),
//! Section 4 (Algorithms 1–3). The draft fixes no wire format; we use its
//! canonical "ciphertext-blob" `C || T || KC` (Section 3, "Note
//! (serialization)"), and the nonce travels separately (prepended by
//! [`crate::aead`]).
//!
//! `Derive(K, N)` (Algorithm 1):
//!
//! ```text
//! NPadded    = N || 0^(27-LN);  NHead = NPadded[0..15];  GCM_IV = NPadded[15..27]
//! ConfigByte = 128*KC_Choice + 8*(LN-12)
//! X_i        = AES256(K, NHead || (ConfigByte + i))      i = 0..=2 (0..=4 with KC)
//! DerivedKey = (X1^X0) || (X2^X0);  KeyCommit = (X3^X0) || (X4^X0)
//! ```
//!
//! then `(C, T) = AES-256-GCM(DerivedKey, GCM_IV, A, P)`.

use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Payload};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// Draft revision this module implements and is tested against.
pub const DRAFT_REVISION: &str = "draft-gueron-cfrg-dndkgcm-05";

/// Nonce length used by Labyrinth (LN = 24).
pub const NONCE_LEN: usize = 24;
/// GCM tag length (T_LEN).
pub const TAG_LEN: usize = 16;
/// Key-commitment length (KC_LEN) when `KC_Choice = 1`.
pub const KC_LEN: usize = 32;
/// Minimum nonce length the draft's Derive accepts.
pub const MIN_NONCE_LEN: usize = 12;
/// Maximum nonce length the draft's Derive accepts.
pub const MAX_NONCE_LEN: usize = 27;
/// Maximum plaintext length (P_MAX = 2^36 - 32).
pub const P_MAX: u64 = (1 << 36) - 32;

/// Output of the draft's `Derive` preamble (Algorithm 1).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Derived {
    /// The 12-byte AES-GCM nonce (`NTail`).
    pub gcm_iv: [u8; 12],
    /// The 32-byte per-nonce AES-GCM key.
    pub derived_key: [u8; 32],
    /// The 32-byte key commitment (`None` when `KC_Choice = 0`).
    pub key_commit: Option<[u8; 32]>,
}

/// The draft's `Derive(K, N)` for any `KC_Choice` and `12 <= LN <= 27`.
pub fn derive(kc_choice: bool, key: &[u8; 32], nonce: &[u8]) -> Result<Derived> {
    let ln = nonce.len();
    if !(MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&ln) {
        return Err(Error::Malformed("DNDK-GCM nonce length must be 12..=27"));
    }
    let mut padded = [0u8; 27];
    padded[..ln].copy_from_slice(nonce);
    let mut gcm_iv = [0u8; 12];
    gcm_iv.copy_from_slice(&padded[15..27]);

    // ln <= 27 so 8*(ln-12) <= 120; with KC the byte is at most 248 + 4.
    let config = 128 * u8::from(kc_choice) + 8 * (ln as u8 - 12);
    let n_blocks = if kc_choice { 5 } else { 3 };

    let cipher = Aes256::new(key.into());
    let mut x = [[0u8; 16]; 5];
    for (i, xi) in x.iter_mut().enumerate().take(n_blocks) {
        xi[..15].copy_from_slice(&padded[..15]);
        xi[15] = config + i as u8;
        cipher.encrypt_block(xi.into());
    }

    let mut derived_key = [0u8; 32];
    let mut key_commit = [0u8; 32];
    for j in 0..16 {
        derived_key[j] = x[1][j] ^ x[0][j];
        derived_key[16 + j] = x[2][j] ^ x[0][j];
        key_commit[j] = x[3][j] ^ x[0][j];
        key_commit[16 + j] = x[4][j] ^ x[0][j];
    }
    x.zeroize();
    padded.zeroize();
    let out = Derived {
        gcm_iv,
        derived_key,
        key_commit: kc_choice.then_some(key_commit),
    };
    key_commit.zeroize();
    derived_key.zeroize();
    Ok(out)
}

/// `DNDK-GCM.Enc` (Algorithm 2) for any `KC_Choice` / `LN`.
/// Returns the ciphertext-blob `C || T || KC` (`KC` empty when `kc_choice` is false).
pub fn encrypt_with_params(
    kc_choice: bool,
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    if pt.len() as u64 > P_MAX {
        return Err(Error::Malformed("DNDK-GCM plaintext too long"));
    }
    let d = derive(kc_choice, key, nonce)?;
    let gcm = Aes256Gcm::new((&d.derived_key).into());
    let mut out = gcm
        .encrypt((&d.gcm_iv).into(), Payload { msg: pt, aad })
        .map_err(|_| Error::Malformed("AES-GCM input out of range"))?;
    if let Some(kc) = &d.key_commit {
        out.extend_from_slice(kc);
    }
    Ok(out)
}

/// `DNDK-GCM.Dec` (Algorithm 3, early-exit variant) for any `KC_Choice` / `LN`.
/// The key commitment is compared in constant time before AES-GCM runs.
pub fn decrypt_with_params(
    kc_choice: bool,
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>> {
    let kc_len = if kc_choice { KC_LEN } else { 0 };
    if blob.len() < TAG_LEN + kc_len {
        return Err(Error::Decrypt);
    }
    let (ct_tag, kc) = blob.split_at(blob.len() - kc_len);
    if (ct_tag.len() - TAG_LEN) as u64 > P_MAX {
        return Err(Error::Decrypt);
    }
    let d = derive(kc_choice, key, nonce)?;
    if let Some(expected) = &d.key_commit
        && !bool::from(expected[..].ct_eq(kc))
    {
        return Err(Error::Decrypt);
    }
    let gcm = Aes256Gcm::new((&d.derived_key).into());
    gcm.decrypt((&d.gcm_iv).into(), Payload { msg: ct_tag, aad })
        .map_err(|_| Error::Decrypt)
}

/// Raw DNDK-GCM encryption with an explicit nonce. Returns the draft's
/// ciphertext layout (including the key-commitment value) without the nonce:
/// `C || T(16) || KC(32)`.
pub fn encrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> crate::Result<Vec<u8>> {
    encrypt_with_params(true, key, nonce, aad, pt)
}

/// Inverse of [`encrypt_with_nonce`]; verifies tag and key commitment.
pub fn decrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> crate::Result<Vec<u8>> {
    decrypt_with_params(true, key, nonce, aad, ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    const KEY_A: [u8; 32] = {
        let mut k = [0u8; 32];
        k[0] = 1;
        k
    };
    const NONCE_A24: [u8; 24] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    ];

    /// draft-05 Appendix A.1 (LN = 24, KC_Choice = 1), including intermediates.
    #[test]
    fn appendix_a1() {
        let d = derive(true, &KEY_A, &NONCE_A24).unwrap();
        assert_eq!(
            d.derived_key.to_vec(),
            unhex("3d1480ee39a968d581d16a578bdaf0e6719dcfff6e127b40bbdd844accea7e1c")
        );
        assert_eq!(d.gcm_iv.to_vec(), unhex("0f1011121314151617000000"));
        assert_eq!(
            d.key_commit.unwrap().to_vec(),
            unhex("2baf00efd298de13055c9a6c39e05aee571583384357635e144fa21444239968")
        );
        let blob = encrypt_with_nonce(&KEY_A, &NONCE_A24, &unhex("0100000011"), &unhex("11000001"))
            .unwrap();
        assert_eq!(
            blob,
            unhex(
                "8eee8a4b8a1c8d0ceb7e07e3c834cafe75aa001f2baf00efd298de13055c9a6c\
                 39e05aee571583384357635e144fa21444239968"
            )
        );
        assert_eq!(
            decrypt_with_nonce(&KEY_A, &NONCE_A24, &unhex("0100000011"), &blob).unwrap(),
            unhex("11000001")
        );
    }

    /// draft-05 Appendix A.2–A.4 (other parameter sets).
    #[test]
    fn appendix_a2_a3_a4() {
        let aad = unhex("0100000011");
        let pt = unhex("11000001");
        assert_eq!(
            encrypt_with_params(false, &KEY_A, &NONCE_A24, &aad, &pt).unwrap(),
            unhex("7f6e39ccb61df0a502c167164e99fa23b7d12b9d")
        );
        assert_eq!(
            encrypt_with_params(true, &KEY_A, &NONCE_A24[..12], &aad, &pt).unwrap(),
            unhex(
                "1915d0bd187b392eeb9b231a57a852db20e02201675fb3ec6d0e56002333c250\
                 4d1b70db47c3713775999c9600bedcfda76f8d8c"
            )
        );
        assert_eq!(
            encrypt_with_params(false, &KEY_A, &NONCE_A24[..12], &aad, &pt).unwrap(),
            unhex("b95cf25839e74511d997eaafd0f567d13758305b")
        );
    }

    #[test]
    fn nonce_length_range() {
        let key = [7u8; 32];
        assert!(derive(true, &key, &[0u8; 11]).is_err());
        assert!(derive(true, &key, &[0u8; 28]).is_err());
        for ln in 12..=27 {
            let n = vec![3u8; ln];
            let ct = encrypt_with_params(true, &key, &n, b"a", b"p").unwrap();
            assert_eq!(
                decrypt_with_params(true, &key, &n, b"a", &ct).unwrap(),
                b"p"
            );
        }
    }

    #[test]
    fn output_layout_and_round_trip() {
        let key = [9u8; 32];
        let nonce = [5u8; 24];
        for len in [0usize, 1, 15, 16, 17, 1000] {
            let pt = vec![0xA5u8; len];
            let ct = encrypt_with_nonce(&key, &nonce, b"aad", &pt).unwrap();
            assert_eq!(ct.len(), len + TAG_LEN + KC_LEN);
            let kc = derive(true, &key, &nonce).unwrap().key_commit.unwrap();
            assert_eq!(&ct[ct.len() - KC_LEN..], &kc);
            assert_eq!(decrypt_with_nonce(&key, &nonce, b"aad", &ct).unwrap(), pt);
        }
    }

    #[test]
    fn tamper_every_byte() {
        let key = [1u8; 32];
        let nonce = [2u8; 24];
        let aad = b"associated data";
        let ct = encrypt_with_nonce(&key, &nonce, aad, b"hello labyrinth").unwrap();
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                decrypt_with_nonce(&key, &nonce, aad, &bad),
                Err(Error::Decrypt),
                "ct byte {i}"
            );
        }
        for i in 0..aad.len() {
            let mut bad = aad.to_vec();
            bad[i] ^= 0x80;
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
                Err(Error::Decrypt)
            );
        }
        for i in 0..32 {
            let mut bad = key;
            bad[i] ^= 0x01;
            assert_eq!(
                decrypt_with_nonce(&bad, &nonce, aad, &ct),
                Err(Error::Decrypt)
            );
        }
        // Truncation / extension.
        assert_eq!(
            decrypt_with_nonce(&key, &nonce, aad, &ct[..ct.len() - 1]),
            Err(Error::Decrypt)
        );
        let mut ext = ct.clone();
        ext.push(0);
        assert_eq!(
            decrypt_with_nonce(&key, &nonce, aad, &ext),
            Err(Error::Decrypt)
        );
        assert_eq!(
            decrypt_with_nonce(&key, &nonce, aad, &[0u8; 47]),
            Err(Error::Decrypt)
        );
    }

    #[test]
    fn kc_mode_mismatch_rejected() {
        let key = [4u8; 32];
        let nonce = [6u8; 24];
        let with_kc = encrypt_with_params(true, &key, &nonce, b"", b"x").unwrap();
        let without = encrypt_with_params(false, &key, &nonce, b"", b"x").unwrap();
        assert!(
            decrypt_with_params(false, &key, &nonce, b"", &with_kc[..with_kc.len() - 32]).is_err()
        );
        assert!(decrypt_with_params(true, &key, &nonce, b"", &without).is_err());
    }
}

//! Passkey PRF wrap of a recovery code (SPEC §6.4, [CB-13]).
//!
//! ```text
//! wrapKey = kdf(prf_output, MINOS_SALT, "catbird.labyrinth.passkey_wrap.v1")
//! wrapped = encrypt(wrapKey, "catbird.labyrinth.passkey_wrapped_code", code40)
//! ```
//!
//! `code40` is the canonical 40-character ASCII code. The ciphertext is
//! stored next to the bundle (`passkeyWrappedCode`).

use zeroize::Zeroizing;

use crate::aead;
use crate::encoding::{kdf32, minos_salt};
use crate::recovery_code::RecoveryCode;
use crate::{Error, Result};

pub const WRAP_INFO: &[u8] = b"catbird.labyrinth.passkey_wrap.v1";
pub const WRAP_AAD: &[u8] = b"catbird.labyrinth.passkey_wrapped_code";

/// Validate the exact WebAuthn PRF output shape used by this profile.
///
/// The protocol accepts the raw 32-byte PRF result only: callers must not
/// truncate, pad, or pass an encoded representation.
pub(crate) fn validate_prf_output(prf_output: &[u8]) -> Result<&[u8; 32]> {
    prf_output
        .try_into()
        .map_err(|_| Error::Malformed("passkey PRF output must be 32 bytes"))
}

fn wrap_key(prf_output: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let prf_output = validate_prf_output(prf_output)?;
    Ok(Zeroizing::new(kdf32(
        prf_output,
        Some(&minos_salt()),
        WRAP_INFO,
    )))
}

/// Seal `code` under the key derived from a WebAuthn PRF output.
pub fn wrap_code(prf_output: &[u8], code: &RecoveryCode) -> Result<Vec<u8>> {
    let key = wrap_key(prf_output)?;
    aead::seal(&key, WRAP_AAD, code.as_str().as_bytes())
}

/// Inverse of [`wrap_code`]; the result is parsed strictly (valid ECC).
pub fn unwrap_code(prf_output: &[u8], wrapped: &[u8]) -> Result<RecoveryCode> {
    let key = wrap_key(prf_output)?;
    let pt = Zeroizing::new(aead::decrypt_suite(
        aead::Suite::DndkGcm,
        &key,
        WRAP_AAD,
        wrapped,
    )?);
    let s = core::str::from_utf8(&pt).map_err(|_| crate::Error::BadRecoveryCode)?;
    RecoveryCode::parse(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_wrong_prf() {
        let code = RecoveryCode::generate().unwrap();
        let w = wrap_code(&[1u8; 32], &code).unwrap();
        assert_eq!(unwrap_code(&[1u8; 32], &w).unwrap(), code);
        assert_eq!(unwrap_code(&[2u8; 32], &w), Err(Error::Decrypt));
        let mut bad = w.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(unwrap_code(&[1u8; 32], &bad).is_err());
    }

    #[test]
    fn wrap_rejects_non_32_byte_prf_outputs() {
        let code = RecoveryCode::generate().unwrap();
        for len in [0, 1, 31, 33, 64] {
            let prf_output = vec![7u8; len];
            assert_eq!(
                wrap_code(&prf_output, &code).err(),
                Some(crate::Error::Malformed(
                    "passkey PRF output must be 32 bytes"
                )),
                "length {len}"
            );
        }
    }

    #[test]
    fn unwrap_rejects_non_32_byte_prf_outputs() {
        let code = RecoveryCode::generate().unwrap();
        let wrapped = wrap_code(&[7u8; 32], &code).unwrap();
        for len in [0, 1, 31, 33, 64] {
            let prf_output = vec![7u8; len];
            assert_eq!(
                unwrap_code(&prf_output, &wrapped).err(),
                Some(crate::Error::Malformed(
                    "passkey PRF output must be 32 bytes"
                )),
                "length {len}"
            );
        }
    }

    #[test]
    fn wrap_refuses_the_v10_suite() {
        let code = RecoveryCode::generate().unwrap();
        let w = aead::encrypt(
            aead::Suite::GcmExtended,
            &wrap_key(&[1u8; 32]).unwrap(),
            WRAP_AAD,
            code.as_str().as_bytes(),
        )
        .unwrap();
        assert_eq!(
            unwrap_code(&[1u8; 32], &w).err(),
            Some(crate::Error::Unsupported(0x01))
        );
    }
}

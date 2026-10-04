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

use crate::Result;
use crate::aead;
use crate::encoding::{kdf32, minos_salt};
use crate::recovery_code::RecoveryCode;

pub const WRAP_INFO: &[u8] = b"catbird.labyrinth.passkey_wrap.v1";
pub const WRAP_AAD: &[u8] = b"catbird.labyrinth.passkey_wrapped_code";

fn wrap_key(prf_output: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(kdf32(prf_output, Some(&minos_salt()), WRAP_INFO))
}

/// Seal `code` under the key derived from a WebAuthn PRF output.
pub fn wrap_code(prf_output: &[u8], code: &RecoveryCode) -> Result<Vec<u8>> {
    aead::seal(&wrap_key(prf_output), WRAP_AAD, code.as_str().as_bytes())
}

/// Inverse of [`wrap_code`]; the result is parsed strictly (valid ECC).
pub fn unwrap_code(prf_output: &[u8], wrapped: &[u8]) -> Result<RecoveryCode> {
    let pt = Zeroizing::new(aead::decrypt(&wrap_key(prf_output), WRAP_AAD, wrapped)?);
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
        assert!(unwrap_code(&[2u8; 32], &w).is_err());
        let mut bad = w.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(unwrap_code(&[1u8; 32], &bad).is_err());
    }
}

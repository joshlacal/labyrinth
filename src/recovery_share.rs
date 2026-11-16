//! Erasable recovery shares for version-3 recovery codes (SPEC §6.1).
//!
//! A version-3 code derives three independent values from its 34 entropy
//! characters:
//!
//! ```text
//! (vdeviceId16, codeKey32, fetchToken32) =
//!     HKDF-SHA256(ikm = entropyChars, salt = null,
//!                 info = "BackupRecoveryCode_v3_0_" || did, L = 80)
//! ```
//!
//! The bundle key additionally needs a 32-byte random share that the
//! account's home delivery service holds:
//!
//! ```text
//! vdeviceKey = HKDF-SHA256(ikm  = codeKey || share,
//!                          salt = "catbird.labyrinth.recovery_share.v1",
//!                          info = "vdevice_key|did=" || did || "|vid=" || hex(vdeviceId),
//!                          L = 32)
//! ```
//!
//! The service releases the share only to a caller that presents
//! `fetchToken`; it stores
//!
//! ```text
//! fetchVerifier = SHA-256("catbird.labyrinth.recovery_share.fetch.v1|" || did
//!                         || "|" || hex(vdeviceId) || "|" || fetchToken)
//! ```
//!
//! Deleting the share makes the code useless for every bundle sealed under
//! it. The record format is unchanged: a version-3 bundle is a
//! `formatVersion 2` `virtualDevice` whose fields are sealed under
//! `vdeviceKey` instead of the version-2 code key.

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::Result;
use crate::encoding::{kdf, random, sha256};
use crate::store::{MaybeSend, MaybeSync};
use crate::virtual_device::Mechanism;

/// HKDF salt for the bundle key of a version-3 code.
pub const VDEVICE_KEY_SALT: &[u8] = b"catbird.labyrinth.recovery_share.v1";
/// Prefix of the bundle-key HKDF `info`.
pub const VDEVICE_KEY_INFO_PREFIX: &[u8] = b"vdevice_key|did=";
/// Domain prefix of the fetch verifier.
pub const FETCH_VERIFIER_PREFIX: &[u8] = b"catbird.labyrinth.recovery_share.fetch.v1|";
/// Length of a share, a fetch token and a fetch verifier.
pub const SHARE_LEN: usize = 32;

/// The 32-byte random share held by the delivery service. Secret: zeroized
/// on drop, redacted in `Debug`, compared in constant time.
#[derive(Clone)]
pub struct RecoveryShare(Zeroizing<[u8; SHARE_LEN]>);

impl RecoveryShare {
    /// A fresh share from the CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut s = Zeroizing::new([0u8; SHARE_LEN]);
        random(s.as_mut())?;
        Ok(Self(s))
    }

    pub fn from_bytes(bytes: [u8; SHARE_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; SHARE_LEN] {
        &self.0
    }
}

impl PartialEq for RecoveryShare {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}
impl Eq for RecoveryShare {}

impl core::fmt::Debug for RecoveryShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryShare(<redacted>)")
    }
}

/// Everything a version-3 code derives before the share is known.
pub struct V3Derivation {
    pub vdevice_id: [u8; 16],
    pub code_key: Zeroizing<[u8; 32]>,
    pub fetch_token: Zeroizing<[u8; 32]>,
}

impl V3Derivation {
    /// The verifier the delivery service stores for this code's share.
    pub fn fetch_verifier(&self, did: &str) -> [u8; 32] {
        fetch_verifier(did, &self.vdevice_id, &self.fetch_token)
    }

    /// The bundle key for this code combined with `share`.
    pub fn vdevice_key(&self, did: &str, share: &RecoveryShare) -> Zeroizing<[u8; 32]> {
        vdevice_key(did, &self.vdevice_id, &self.code_key, share)
    }
}

/// `SHA-256("catbird.labyrinth.recovery_share.fetch.v1|" || did || "|" ||
/// hex(vdeviceId) || "|" || fetchToken)`.
pub fn fetch_verifier(did: &str, vdevice_id: &[u8; 16], fetch_token: &[u8; 32]) -> [u8; 32] {
    let mut m = Zeroizing::new(Vec::with_capacity(
        FETCH_VERIFIER_PREFIX.len() + did.len() + 2 + 32 + 32,
    ));
    m.extend_from_slice(FETCH_VERIFIER_PREFIX);
    m.extend_from_slice(did.as_bytes());
    m.push(b'|');
    m.extend_from_slice(hex::encode(vdevice_id).as_bytes());
    m.push(b'|');
    m.extend_from_slice(fetch_token);
    sha256(&m)
}

/// `HKDF-SHA256(codeKey || share, "catbird.labyrinth.recovery_share.v1",
/// "vdevice_key|did=" || did || "|vid=" || hex(vdeviceId), 32)`.
pub fn vdevice_key(
    did: &str,
    vdevice_id: &[u8; 16],
    code_key: &[u8; 32],
    share: &RecoveryShare,
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(code_key);
    ikm[32..].copy_from_slice(share.as_bytes());
    let mut info = Vec::with_capacity(VDEVICE_KEY_INFO_PREFIX.len() + did.len() + 5 + 32);
    info.extend_from_slice(VDEVICE_KEY_INFO_PREFIX);
    info.extend_from_slice(did.as_bytes());
    info.extend_from_slice(b"|vid=");
    info.extend_from_slice(hex::encode(vdevice_id).as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    kdf(ikm.as_slice(), Some(VDEVICE_KEY_SALT), &info, out.as_mut());
    out
}

/// Where version-3 recovery shares live: the account's home delivery
/// service. Labyrinth never sends a share to the PDS.
///
/// Implementations talk to the private `blue.catbird.labyrinth.*`
/// recovery-share procedures. `get_share` must be a signed procedure with
/// the fetch token in the request body, never a query parameter.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait ShareStore: MaybeSend + MaybeSync {
    /// Store `share` for `vdevice_id` with its fetch verifier.
    async fn put_share(
        &self,
        vdevice_id: &[u8; 16],
        share: &RecoveryShare,
        fetch_verifier: &[u8; 32],
        mechanism: Mechanism,
    ) -> Result<()>;

    /// The share for `vdevice_id`, released against `fetch_token`; `None`
    /// when the service holds no share for it (deleted, or never stored).
    async fn get_share(
        &self,
        vdevice_id: &[u8; 16],
        fetch_token: &[u8; 32],
    ) -> Result<Option<RecoveryShare>>;

    /// Delete the share for `vdevice_id`. Deleting an absent share succeeds.
    async fn delete_share(&self, vdevice_id: &[u8; 16]) -> Result<()>;
}

/// The recovery-share configuration a [`crate::client::Labyrinth`] runs with.
///
/// Supplying a store enables reading version-3 codes and deleting shares
/// when methods are removed or re-keyed. New recovery methods stay version 2.
pub struct RecoveryShares {
    pub(crate) store: Box<dyn ShareStore>,
}

impl RecoveryShares {
    /// Version-3 codes restore and removals delete shares; new methods are
    /// still version 2.
    pub fn reader(store: Box<dyn ShareStore>) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &dyn ShareStore {
        self.store.as_ref()
    }
}

impl core::fmt::Debug for RecoveryShares {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryShares").finish_non_exhaustive()
    }
}

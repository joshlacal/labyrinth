//! Encrypted account-private state records in the personal OwnerMailbox Space:
//!
//! - [`ReadState`] (`blue.catbird.labyrinth.readState`, `rkey = <conversationId>`):
//!   monotonic `MAX(readThroughSeq)` read-watermark CRDT across sibling devices.
//! - [`CircleOwnerState`] (`blue.catbird.labyrinth.circleOwnerState`, `rkey = <circleId>`):
//!   encrypted Circle membership, `joinedAtVersion` map, and pending Space ACL
//!   operations with optimistic CAS updates and tombstone-wins merge semantics.
//!
//! Plaintexts are JSON-encoded, PADMÉ-padded ([`crate::padding`]), and sealed
//! with [`crate::aead::Suite::DndkGcm`] under domain-separated keys derived
//! from the personal mailbox [`crate::epoch::EpochSecret::root`], with AAD
//! binding `(accountDid, collectionNsid, rkey, epochSeq)`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::Labyrinth;
use crate::aead::{self, Suite};
use crate::encoding::{kdf32, minos_salt, random};
use crate::epoch::EpochKeys as _;
use crate::padding::{pad, unpad};
use crate::records::{CircleOwnerStateRecord, ReadStateRecord, ms_from_datetime, nsid};
use crate::{Error, Result};

const READ_STATE_KDF_LABEL: &[u8] = b"catbird.labyrinth.read_state.v1\0";
const CIRCLE_OWNER_STATE_KDF_LABEL: &[u8] = b"catbird.labyrinth.circle_owner_state.v1\0";
const OWNER_STATE_AAD_PREFIX_LEGACY_V1: &[u8] = b"catbird.labyrinth.owner_state_aad.v1\0";
const OWNER_STATE_AAD_PREFIX_V2: &[u8] = b"catbird.labyrinth.owner_state_aad.v2\0";

/// Maximum optimistic CAS retry attempts for `readState` and `circleOwnerState`
/// merges under multi-device write contention.
const CAS_MAX_ATTEMPTS: usize = 6;

/// Prefix for pending Space ACL removal tombstones in [`CircleOwnerState::pending_ops`].
pub const ACL_TOMBSTONE_PREFIX: &str = "__acl__:";
/// Prefix recording the key version at which an active `__acl__:<did>` tombstone was issued.
pub const ACL_TOMBSTONE_VER_PREFIX: &str = "__acl_ver__:";
/// Prefix recording the highest settled key version at which a DID's ACL removal completed.
pub const ACL_CLEARED_TOMBSTONE_PREFIX: &str = "__acl_cleared__:";
/// Pending Space ACL removal marker (key not yet rotated or rotation tracked separately).
pub const ACL_REMOVE_PENDING: &str = "aclRemovePending";
/// Pending Space ACL removal marker after the Circle key version has already rotated.
pub const ACL_REMOVE_PENDING_ROTATED: &str = "aclRemovePending:rotated";

/// Decrypted payload of `blue.catbird.labyrinth.readState` (`rkey = conversationId`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadState {
    pub conversation_id: String,
    pub read_through_seq: u64,
    pub updated_at: String,
}

impl ReadState {
    /// Construct and validate a [`ReadState`].
    pub fn new(
        conversation_id: impl Into<String>,
        read_through_seq: u64,
        updated_at: String,
    ) -> Result<Self> {
        let state = Self {
            conversation_id: conversation_id.into(),
            read_through_seq,
            updated_at,
        };
        state.validate()?;
        Ok(state)
    }

    /// Validate structural invariants.
    pub fn validate(&self) -> Result<()> {
        if self.conversation_id.is_empty() || self.conversation_id.len() > 256 {
            return Err(Error::Malformed("readState conversationId length"));
        }
        let _ = ms_from_datetime(&self.updated_at)?;
        Ok(())
    }

    /// Commutative, associative, idempotent `MAX(readThroughSeq)` CRDT merge.
    pub fn merge(&self, other: &Self) -> Result<Self> {
        self.validate()?;
        other.validate()?;
        if self.conversation_id != other.conversation_id {
            return Err(Error::Malformed("readState conversationId mismatch"));
        }
        Ok(Self {
            conversation_id: self.conversation_id.clone(),
            read_through_seq: self.read_through_seq.max(other.read_through_seq),
            updated_at: newer_datetime(&self.updated_at, &other.updated_at)?,
        })
    }
}

/// Decrypted payload of `blue.catbird.labyrinth.circleOwnerState` (`rkey = circleId`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CircleOwnerState {
    pub circle_id: String,
    pub space_uri: String,
    pub current_key_version: u64,
    #[serde(default)]
    pub joined_at_version_by_did: BTreeMap<String, u64>,
    #[serde(default)]
    pub pending_ops: BTreeMap<String, String>,
    pub updated_at: String,
}

/// Lenient read of a Space URI stored during the alpha: old-form `at://{did}/space/{rest}` ->
/// `at:space/{did}/{rest}`; `None` for anything else. Never for request input.
/// TODO: remove before beta.
pub fn from_legacy_space_uri(raw: &str) -> Option<String> {
    let rest = raw.strip_prefix("at://")?;
    let (authority, tail) = rest.split_once('/')?;
    let tail = tail.strip_prefix("space/")?;
    if !authority.starts_with("did:") || tail.is_empty() {
        return None;
    }
    Some(format!("at:space/{authority}/{tail}"))
}

/// A stored `spaceUri` in the current form (old-form Space URIs rewritten, others unchanged).
/// TODO: remove before beta.
fn normalize_space_uri(raw: &str) -> String {
    from_legacy_space_uri(raw).unwrap_or_else(|| raw.to_owned())
}

impl CircleOwnerState {
    /// Key used in [`Self::pending_ops`] for a pending Space ACL removal tombstone.
    pub fn acl_tombstone_key(did: &str) -> String {
        format!("{ACL_TOMBSTONE_PREFIX}{did}")
    }

    /// Key used in [`Self::pending_ops`] to bind an active removal tombstone to its key version.
    pub fn acl_tombstone_ver_key(did: &str) -> String {
        format!("{ACL_TOMBSTONE_VER_PREFIX}{did}")
    }

    /// Key used in [`Self::pending_ops`] for a monotone settled ACL removal watermark.
    pub fn acl_cleared_tombstone_key(did: &str) -> String {
        format!("{ACL_CLEARED_TOMBSTONE_PREFIX}{did}")
    }

    /// Highest settled removal key version for `did`, if any removal has been cleared.
    pub fn cleared_acl_version(&self, did: &str) -> Option<u64> {
        self.pending_ops
            .get(&Self::acl_cleared_tombstone_key(did))
            .and_then(|v| parse_acl_version_str(v).ok())
    }

    fn active_tombstone_birth_version(&self, did: &str) -> Option<u64> {
        if !self.has_acl_tombstone(did) {
            return None;
        }
        let ver = self
            .pending_ops
            .get(&Self::acl_tombstone_ver_key(did))
            .and_then(|v| parse_acl_version_str(v).ok())
            .unwrap_or(self.current_key_version);
        Some(ver)
    }

    /// Validate structural invariants.
    pub fn validate(&self) -> Result<()> {
        if self.circle_id.is_empty() || self.circle_id.len() > 256 {
            return Err(Error::Malformed("circleOwnerState circleId length"));
        }
        if self.space_uri.is_empty() || self.space_uri.len() > 512 {
            return Err(Error::Malformed("circleOwnerState spaceUri length"));
        }
        if self.joined_at_version_by_did.keys().any(String::is_empty) {
            return Err(Error::Malformed("circleOwnerState empty member DID"));
        }
        for (key, val) in &self.pending_ops {
            if key.is_empty() {
                return Err(Error::Malformed("circleOwnerState empty pendingOps key"));
            }
            if let Some(did) = key.strip_prefix(ACL_TOMBSTONE_PREFIX)
                && did.is_empty()
            {
                return Err(Error::Malformed("circleOwnerState empty tombstone DID"));
            }
            if let Some(did) = key.strip_prefix(ACL_TOMBSTONE_VER_PREFIX) {
                if did.is_empty() {
                    return Err(Error::Malformed("circleOwnerState empty tombstone DID"));
                }
                let _ = parse_acl_version_str(val)?;
            }
            if let Some(did) = key.strip_prefix(ACL_CLEARED_TOMBSTONE_PREFIX) {
                if did.is_empty() {
                    return Err(Error::Malformed("circleOwnerState empty tombstone DID"));
                }
                let _ = parse_acl_version_str(val)?;
            }
        }
        let _ = ms_from_datetime(&self.updated_at)?;
        Ok(())
    }

    /// Whether `did` currently carries an active `__acl__:<did>` removal tombstone.
    pub fn has_acl_tombstone(&self, did: &str) -> bool {
        self.pending_ops.contains_key(&Self::acl_tombstone_key(did))
    }

    /// Record an `__acl__:<did>` removal tombstone, suppressing any active
    /// `joinedAtVersionByDid` or non-tombstone `pendingOps` entry for `did`.
    pub fn mark_acl_remove_pending(&mut self, did: &str, rotated: bool) {
        if let Some(cleared_ver) = self.cleared_acl_version(did)
            && self.current_key_version <= cleared_ver
        {
            self.current_key_version = cleared_ver.saturating_add(1);
        }
        self.joined_at_version_by_did.remove(did);
        self.pending_ops.remove(did);
        let key = Self::acl_tombstone_key(did);
        let ver_key = Self::acl_tombstone_ver_key(did);
        let next = if rotated {
            ACL_REMOVE_PENDING_ROTATED
        } else {
            ACL_REMOVE_PENDING
        };
        match self.pending_ops.get(&key).map(String::as_str) {
            Some(ACL_REMOVE_PENDING_ROTATED) => {}
            _ => {
                self.pending_ops.insert(key, next.to_owned());
            }
        }
        let birth = self
            .pending_ops
            .get(&ver_key)
            .and_then(|v| parse_acl_version_str(v).ok())
            .map_or(self.current_key_version, |cur| {
                cur.max(self.current_key_version)
            });
        self.pending_ops.insert(ver_key, birth.to_string());
    }

    /// Monotonically settle an active removal tombstone for `did`, replacing
    /// `__acl__:<did>` with a versioned `__acl_cleared__:<did>` floor so stale
    /// pre-removal or pre-clear sibling snapshots cannot resurrect `did` or
    /// re-open the settled tombstone.
    pub fn record_acl_tombstone_cleared(&mut self, did: &str) -> bool {
        let birth_ver = self.active_tombstone_birth_version(did).unwrap_or(0);
        let join_ver = self.joined_at_version_by_did.get(did).copied().unwrap_or(0);
        let prev_cleared = self.cleared_acl_version(did);
        let removed_tombstone = self
            .pending_ops
            .remove(&Self::acl_tombstone_key(did))
            .is_some();
        let _ = self.pending_ops.remove(&Self::acl_tombstone_ver_key(did));
        let removed_op = self.pending_ops.remove(did).is_some();
        let removed_member = self.joined_at_version_by_did.remove(did).is_some();
        if !removed_tombstone && !removed_member && !removed_op {
            return false;
        }
        let settle_ver = self
            .current_key_version
            .max(birth_ver)
            .max(join_ver)
            .max(prev_cleared.unwrap_or(0));
        self.pending_ops
            .insert(Self::acl_cleared_tombstone_key(did), settle_ver.to_string());
        true
    }

    /// Monotonic merge of two [`CircleOwnerState`] snapshots for the same Circle:
    ///
    /// - `currentKeyVersion = max(a, b)`
    /// - `__acl_cleared__:<did>` tracks `max(cleared_ver)` so settled removals suppress
    ///   both stale pre-removal `joinedAtVersionByDid[d] <= cleared_ver` and stale
    ///   pre-clear `__acl__:<did>` tombstones at `<= cleared_ver`, while permitting
    ///   re-adds (`joinedAtVersionByDid[d] > cleared_ver`) and newer removals (`> cleared_ver`).
    /// - Active `__acl__:<did>` tombstones (`birth_ver > cleared_ver`) win over concurrent
    ///   re-adds or non-tombstone `pendingOps` entries (`aclRemovePending:rotated` dominates
    ///   `aclRemovePending`).
    /// - `joinedAtVersionByDid[d] = max(a, b)` for active members so a stale sibling
    ///   device cannot downgrade a re-added member's join floor and expose prior history.
    pub fn merge(&self, other: &Self) -> Result<Self> {
        self.validate()?;
        other.validate()?;
        if self.circle_id != other.circle_id {
            return Err(Error::Malformed("circleOwnerState circleId mismatch"));
        }
        // Devices that wrote during the alpha stored the old `at://{did}/space/...` form.
        let space_uri = normalize_space_uri(&self.space_uri);
        if space_uri != normalize_space_uri(&other.space_uri) {
            return Err(Error::Malformed("circleOwnerState spaceUri mismatch"));
        }

        let mut cleared_vers: BTreeMap<String, u64> = BTreeMap::new();
        for (k, v) in self.pending_ops.iter().chain(other.pending_ops.iter()) {
            if let Some(did) = k.strip_prefix(ACL_CLEARED_TOMBSTONE_PREFIX) {
                let ver = parse_acl_version_str(v)?;
                cleared_vers
                    .entry(did.to_owned())
                    .and_modify(|cur| *cur = (*cur).max(ver))
                    .or_insert(ver);
            }
        }

        let mut active_tombstones: BTreeMap<String, (String, u64)> = BTreeMap::new();
        let mut tombstoned_dids: BTreeSet<String> = BTreeSet::new();
        for src in [self, other] {
            for (k, v) in &src.pending_ops {
                if let Some(did) = k.strip_prefix(ACL_TOMBSTONE_PREFIX) {
                    let birth_ver = src
                        .active_tombstone_birth_version(did)
                        .unwrap_or(src.current_key_version);
                    if cleared_vers.get(did).is_some_and(|&c| birth_ver <= c) {
                        continue;
                    }
                    tombstoned_dids.insert(did.to_owned());
                    active_tombstones
                        .entry(did.to_owned())
                        .and_modify(|(cur_val, cur_ver)| {
                            let incoming_rank = tombstone_rank(v);
                            let existing_rank = tombstone_rank(cur_val);
                            if (incoming_rank, v.as_str()) > (existing_rank, cur_val.as_str()) {
                                *cur_val = v.clone();
                            }
                            *cur_ver = (*cur_ver).max(birth_ver);
                        })
                        .or_insert_with(|| (v.clone(), birth_ver));
                }
            }
        }

        let mut joined_at_version_by_did: BTreeMap<String, u64> = BTreeMap::new();
        for (did, &ver) in self
            .joined_at_version_by_did
            .iter()
            .chain(other.joined_at_version_by_did.iter())
        {
            if tombstoned_dids.contains(did) {
                continue;
            }
            if cleared_vers.get(did).is_some_and(|&c| ver <= c) {
                continue;
            }
            joined_at_version_by_did
                .entry(did.clone())
                .and_modify(|cur| *cur = (*cur).max(ver))
                .or_insert(ver);
        }

        let self_ms = ms_from_datetime(&self.updated_at)?;
        let other_ms = ms_from_datetime(&other.updated_at)?;
        let other_newer = (other_ms, &other.updated_at) > (self_ms, &self.updated_at);

        let is_internal_acl_key = |k: &str| {
            k.starts_with(ACL_TOMBSTONE_PREFIX)
                || k.starts_with(ACL_TOMBSTONE_VER_PREFIX)
                || k.starts_with(ACL_CLEARED_TOMBSTONE_PREFIX)
        };

        let mut pending_ops: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &self.pending_ops {
            if is_internal_acl_key(k)
                || tombstoned_dids.contains(k)
                || (cleared_vers.contains_key(k) && !joined_at_version_by_did.contains_key(k))
            {
                continue;
            }
            pending_ops.insert(k.clone(), v.clone());
        }
        for (k, v) in &other.pending_ops {
            if is_internal_acl_key(k)
                || tombstoned_dids.contains(k)
                || (cleared_vers.contains_key(k) && !joined_at_version_by_did.contains_key(k))
            {
                continue;
            }
            match pending_ops.get_mut(k) {
                Some(cur) => {
                    if other_newer
                        || (self_ms == other_ms
                            && self.updated_at == other.updated_at
                            && v.as_str() > cur.as_str())
                    {
                        *cur = v.clone();
                    }
                }
                None => {
                    pending_ops.insert(k.clone(), v.clone());
                }
            }
        }
        for (did, ver) in cleared_vers {
            pending_ops.insert(Self::acl_cleared_tombstone_key(&did), ver.to_string());
        }
        for (did, (val, birth_ver)) in active_tombstones {
            pending_ops.insert(Self::acl_tombstone_key(&did), val);
            pending_ops.insert(Self::acl_tombstone_ver_key(&did), birth_ver.to_string());
        }

        Ok(Self {
            circle_id: self.circle_id.clone(),
            space_uri,
            current_key_version: self.current_key_version.max(other.current_key_version),
            joined_at_version_by_did,
            pending_ops,
            updated_at: newer_datetime(&self.updated_at, &other.updated_at)?,
        })
    }
}

fn parse_acl_version_str(raw: &str) -> Result<u64> {
    let trimmed = raw.strip_prefix("aclRemovedCleared:").unwrap_or(raw);
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Malformed("circleOwnerState invalid ACL version"));
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| Error::Malformed("circleOwnerState invalid ACL version"))
}

fn tombstone_rank(v: &str) -> u8 {
    if v == ACL_REMOVE_PENDING_ROTATED || v.ends_with(":rotated") {
        2
    } else if v == ACL_REMOVE_PENDING {
        1
    } else {
        0
    }
}

fn newer_datetime(a: &str, b: &str) -> Result<String> {
    let a_ms = ms_from_datetime(a)?;
    let b_ms = ms_from_datetime(b)?;
    if (b_ms, b) > (a_ms, a) {
        Ok(b.to_owned())
    } else {
        Ok(a.to_owned())
    }
}

fn derive_owner_state_key(label: &[u8], root: &[u8; 32], epoch_seq: u64) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(label.len() + 8);
    info.extend_from_slice(label);
    info.extend_from_slice(&epoch_seq.to_be_bytes());
    Zeroizing::new(kdf32(root, Some(&minos_salt()), &info))
}

fn owner_state_aad_legacy_v1(did: &str, collection: &str, rkey: &str, epoch_seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        OWNER_STATE_AAD_PREFIX_LEGACY_V1.len()
            + 4
            + did.len()
            + 4
            + collection.len()
            + 4
            + rkey.len()
            + 8,
    );
    aad.extend_from_slice(OWNER_STATE_AAD_PREFIX_LEGACY_V1);
    for part in [did.as_bytes(), collection.as_bytes(), rkey.as_bytes()] {
        let len = u32::try_from(part.len()).expect("owner state identifier fits in u32");
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(part);
    }
    aad.extend_from_slice(&epoch_seq.to_be_bytes());
    aad
}

fn owner_state_aad(
    did: &str,
    collection: &str,
    rkey: &str,
    epoch_seq: u64,
    cas_version: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        OWNER_STATE_AAD_PREFIX_V2.len()
            + 4
            + did.len()
            + 4
            + collection.len()
            + 4
            + rkey.len()
            + 16,
    );
    aad.extend_from_slice(OWNER_STATE_AAD_PREFIX_V2);
    for part in [did.as_bytes(), collection.as_bytes(), rkey.as_bytes()] {
        let len = u32::try_from(part.len()).expect("owner state identifier fits in u32");
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(part);
    }
    aad.extend_from_slice(&epoch_seq.to_be_bytes());
    aad.extend_from_slice(&cas_version.to_be_bytes());
    aad
}

#[allow(clippy::too_many_arguments)]
fn seal_json<T: Serialize>(
    label: &[u8],
    root: &[u8; 32],
    did: &str,
    collection: &str,
    rkey: &str,
    epoch_seq: u64,
    cas_version: u64,
    value: &T,
) -> Result<Vec<u8>> {
    let json = Zeroizing::new(
        serde_json::to_vec(value).map_err(|_| Error::Malformed("owner state JSON encode"))?,
    );
    let padded = Zeroizing::new(pad(&json));
    let key = derive_owner_state_key(label, root, epoch_seq);
    let aad = owner_state_aad(did, collection, rkey, epoch_seq, cas_version);
    aead::seal(&key, &aad, &padded)
}

#[allow(clippy::too_many_arguments)]
fn open_json<T: for<'de> Deserialize<'de>>(
    label: &[u8],
    root: &[u8; 32],
    did: &str,
    collection: &str,
    rkey: &str,
    epoch_seq: u64,
    cas_version: u64,
    ciphertext: &[u8],
) -> Result<T> {
    let key = derive_owner_state_key(label, root, epoch_seq);
    let aad = owner_state_aad(did, collection, rkey, epoch_seq, cas_version);
    let padded = match aead::decrypt_suite(Suite::DndkGcm, &key, &aad, ciphertext) {
        Ok(plain) => Zeroizing::new(plain),
        Err(err) if cas_version == 0 => {
            let legacy_aad = owner_state_aad_legacy_v1(did, collection, rkey, epoch_seq);
            Zeroizing::new(
                aead::decrypt_suite(Suite::DndkGcm, &key, &legacy_aad, ciphertext)
                    .map_err(|_| err)?,
            )
        }
        Err(err) => return Err(err),
    };
    let json = Zeroizing::new(unpad(&padded)?);
    serde_json::from_slice(&json).map_err(|_| Error::Malformed("owner state JSON decode"))
}

pub(super) fn conflict_backoff_jitter() {
    let mut jitter = [0u8; 1];
    let _ = random(&mut jitter);
    #[cfg(not(target_arch = "wasm32"))]
    {
        let delay_ms = 1 + u64::from(jitter[0] & 0x07);
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
    }
}

impl Labyrinth {
    async fn root_for_owner_state_epoch(&mut self, epoch_seq: u64) -> Result<[u8; 32]> {
        if epoch_seq > self.latest {
            self.sync_epochs_for_archive().await?;
        }
        let secret = self.epoch_secret(epoch_seq).await?;
        Ok(*secret.root())
    }

    async fn decrypt_read_state(
        &mut self,
        rkey: &str,
        record: &ReadStateRecord,
        cas_version: u64,
    ) -> Result<ReadState> {
        record.check()?;
        let root = self.root_for_owner_state_epoch(record.epoch).await?;
        let did = self.did.clone();
        let state: ReadState = open_json(
            READ_STATE_KDF_LABEL,
            &root,
            &did,
            nsid::READ_STATE,
            rkey,
            record.epoch,
            cas_version,
            &record.ciphertext.0,
        )?;
        state.validate()?;
        if state.conversation_id != rkey {
            return Err(Error::Malformed("readState rkey mismatch"));
        }
        self.confirm_owner_state_version(nsid::READ_STATE, rkey, cas_version)?;
        Ok(state)
    }

    async fn encrypt_read_state(
        &mut self,
        state: &ReadState,
        cas_version: u64,
    ) -> Result<ReadStateRecord> {
        state.validate()?;
        self.sync_epochs_for_archive().await?;
        let epoch_seq = self.latest;
        let root = *self.epoch_secret(epoch_seq).await?.root();
        let ct = seal_json(
            READ_STATE_KDF_LABEL,
            &root,
            &self.did,
            nsid::READ_STATE,
            &state.conversation_id,
            epoch_seq,
            cas_version,
            state,
        )?;
        ReadStateRecord::new(ct, epoch_seq, state.updated_at.clone())
    }

    async fn decrypt_circle_owner_state(
        &mut self,
        rkey: &str,
        record: &CircleOwnerStateRecord,
        cas_version: u64,
    ) -> Result<CircleOwnerState> {
        record.check()?;
        let root = self.root_for_owner_state_epoch(record.epoch).await?;
        let did = self.did.clone();
        let state: CircleOwnerState = open_json(
            CIRCLE_OWNER_STATE_KDF_LABEL,
            &root,
            &did,
            nsid::CIRCLE_OWNER_STATE,
            rkey,
            record.epoch,
            cas_version,
            &record.ciphertext.0,
        )?;
        state.validate()?;
        if state.circle_id != rkey {
            return Err(Error::Malformed("circleOwnerState rkey mismatch"));
        }
        self.confirm_owner_state_version(nsid::CIRCLE_OWNER_STATE, rkey, cas_version)?;
        Ok(state)
    }

    async fn encrypt_circle_owner_state(
        &mut self,
        state: &CircleOwnerState,
        cas_version: u64,
    ) -> Result<CircleOwnerStateRecord> {
        state.validate()?;
        self.sync_epochs_for_archive().await?;
        let epoch_seq = self.latest;
        let root = *self.epoch_secret(epoch_seq).await?.root();
        let ct = seal_json(
            CIRCLE_OWNER_STATE_KDF_LABEL,
            &root,
            &self.did,
            nsid::CIRCLE_OWNER_STATE,
            &state.circle_id,
            epoch_seq,
            cas_version,
            state,
        )?;
        CircleOwnerStateRecord::new(ct, epoch_seq, state.updated_at.clone())
    }

    /// Fetch and decrypt `blue.catbird.labyrinth.readState/<conversation_id>`,
    /// across any current or historical mailbox epoch.
    pub async fn get_read_state(&mut self, conversation_id: &str) -> Result<Option<ReadState>> {
        if conversation_id.is_empty() || conversation_id.len() > 256 {
            return Err(Error::Malformed("readState conversationId length"));
        }
        self.seed_store_writer_floors();
        self.seed_store_owner_state_floors();
        let fetched = self
            .b
            .mailbox
            .get_read_state_versioned(conversation_id)
            .await?;
        self.sync_store_writer_floors()?;
        self.sync_store_owner_state_floors()?;
        let Some((record, _cid, cas_version)) = fetched else {
            return Ok(None);
        };
        self.decrypt_read_state(conversation_id, &record, cas_version)
            .await
            .map(Some)
    }

    /// Advance `blue.catbird.labyrinth.readState/<conversation_id>` monotonically
    /// via optimistic CAS (`MAX(readThroughSeq)` CRDT), retrying bounded jittered
    /// merges on [`Error::Conflict`].
    pub async fn advance_read_state(
        &mut self,
        conversation_id: &str,
        read_through_seq: u64,
    ) -> Result<ReadState> {
        if conversation_id.is_empty() || conversation_id.len() > 256 {
            return Err(Error::Malformed("readState conversationId length"));
        }
        let mut candidate = ReadState::new(conversation_id, read_through_seq, self.now())?;
        for attempt in 0..CAS_MAX_ATTEMPTS {
            self.seed_store_writer_floors();
            self.seed_store_owner_state_floors();
            let current = self
                .b
                .mailbox
                .get_read_state_versioned(conversation_id)
                .await?;
            self.sync_store_writer_floors()?;
            self.sync_store_owner_state_floors()?;

            let (expected_cid, next_cas_version) = match current {
                Some((record, cid, cur_ver)) => {
                    let existing = self
                        .decrypt_read_state(conversation_id, &record, cur_ver)
                        .await?;
                    if existing.read_through_seq >= candidate.read_through_seq {
                        return Ok(existing);
                    }
                    candidate = existing.merge(&candidate)?;
                    let next_ver = cur_ver
                        .checked_add(1)
                        .ok_or_else(|| Error::Backend("cas version overflow".into()))?;
                    (cid, next_ver)
                }
                None => (None, 1),
            };

            let record = self
                .encrypt_read_state(&candidate, next_cas_version)
                .await?;
            self.seed_store_owner_state_floors();
            match self
                .b
                .mailbox
                .put_read_state(conversation_id, &record, expected_cid.as_deref())
                .await
            {
                Ok(_cid) => {
                    self.sync_store_owner_state_floors()?;
                    return Ok(candidate);
                }
                Err(Error::Conflict) => {
                    self.sync_store_owner_state_floors()?;
                    self.seed_store_writer_floors();
                    self.seed_store_owner_state_floors();
                    let latest = self
                        .b
                        .mailbox
                        .get_read_state_versioned(conversation_id)
                        .await?;
                    self.sync_store_writer_floors()?;
                    self.sync_store_owner_state_floors()?;
                    if let Some((latest_rec, _, latest_ver)) = latest {
                        let existing = self
                            .decrypt_read_state(conversation_id, &latest_rec, latest_ver)
                            .await?;
                        if existing.read_through_seq >= candidate.read_through_seq {
                            return Ok(existing);
                        }
                        candidate = existing.merge(&candidate)?;
                    }
                    if attempt + 1 < CAS_MAX_ATTEMPTS {
                        conflict_backoff_jitter();
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Err(Error::Conflict)
    }

    /// List and decrypt every `blue.catbird.labyrinth.readState` record in the
    /// personal mailbox Space across current and historical epochs.
    pub async fn list_read_states(&mut self) -> Result<Vec<ReadState>> {
        self.seed_store_writer_floors();
        self.seed_store_owner_state_floors();
        let stored_list = self.b.mailbox.list_read_states_versioned().await?;
        self.sync_store_writer_floors()?;
        self.sync_store_owner_state_floors()?;
        let mut out = Vec::with_capacity(stored_list.len());
        for (rkey, record, _cid, cas_version) in stored_list {
            out.push(self.decrypt_read_state(&rkey, &record, cas_version).await?);
        }
        Ok(out)
    }

    /// Fetch and decrypt `blue.catbird.labyrinth.circleOwnerState/<circle_id>`
    /// together with its store CID for optimistic CAS updates.
    pub async fn get_circle_owner_state(
        &mut self,
        circle_id: &str,
    ) -> Result<Option<(CircleOwnerState, Option<String>)>> {
        if circle_id.is_empty() || circle_id.len() > 256 {
            return Err(Error::Malformed("circleOwnerState circleId length"));
        }
        self.seed_store_writer_floors();
        self.seed_store_owner_state_floors();
        let fetched = self
            .b
            .mailbox
            .get_circle_owner_state_versioned(circle_id)
            .await?;
        self.sync_store_writer_floors()?;
        self.sync_store_owner_state_floors()?;
        let Some((record, cid, cas_version)) = fetched else {
            return Ok(None);
        };
        let state = self
            .decrypt_circle_owner_state(circle_id, &record, cas_version)
            .await?;
        if let Some(ref c) = cid {
            self.circle_cas_versions
                .insert((circle_id.to_owned(), c.clone()), cas_version);
        }
        Ok(Some((state, cid)))
    }

    /// Encrypt and write `blue.catbird.labyrinth.circleOwnerState/<circle_id>`
    /// with explicit CAS (`None` = create-if-absent `#create`, `Some(cid)` = CAS
    /// update). Returns the newly written record's CID.
    pub async fn put_circle_owner_state(
        &mut self,
        state: &CircleOwnerState,
        expected_cid: Option<&str>,
    ) -> Result<String> {
        let next_cas_version = match expected_cid {
            None => 1,
            Some(exp) => {
                let cur_ver = if let Some(&cached) = self
                    .circle_cas_versions
                    .get(&(state.circle_id.clone(), exp.to_owned()))
                {
                    cached
                } else {
                    self.seed_store_writer_floors();
                    self.seed_store_owner_state_floors();
                    let current = self
                        .b
                        .mailbox
                        .get_circle_owner_state_versioned(&state.circle_id)
                        .await?;
                    self.sync_store_writer_floors()?;
                    self.sync_store_owner_state_floors()?;
                    let Some((_, cur_cid, cur_ver)) = current else {
                        return Err(Error::Conflict);
                    };
                    if cur_cid.as_deref() != Some(exp) {
                        return Err(Error::Conflict);
                    }
                    cur_ver
                };
                cur_ver
                    .checked_add(1)
                    .ok_or_else(|| Error::Backend("cas version overflow".into()))?
            }
        };
        let record = self
            .encrypt_circle_owner_state(state, next_cas_version)
            .await?;
        self.seed_store_owner_state_floors();
        let written_cid = self
            .b
            .mailbox
            .put_circle_owner_state(&state.circle_id, &record, expected_cid)
            .await?;
        self.sync_store_owner_state_floors()?;
        self.circle_cas_versions.insert(
            (state.circle_id.clone(), written_cid.clone()),
            next_cas_version,
        );
        Ok(written_cid)
    }

    /// Read-merge-CAS write `blue.catbird.labyrinth.circleOwnerState/<circle_id>`,
    /// enforcing monotonic `currentKeyVersion`, monotonic `joinedAtVersion = MAX`,
    /// and `__acl__:<did>` tombstone dominance across concurrent owner devices.
    pub async fn merge_circle_owner_state(
        &mut self,
        update: &CircleOwnerState,
    ) -> Result<(CircleOwnerState, String)> {
        update.validate()?;
        for attempt in 0..CAS_MAX_ATTEMPTS {
            let current = self.get_circle_owner_state(&update.circle_id).await?;
            let mut merged = match &current {
                Some((existing, _)) => existing.merge(update)?,
                None => {
                    let mut initial = update.clone();
                    // Enforce self-consistency if caller supplied both a tombstone
                    // and a stale entry for the same DID.
                    initial = initial.merge(update)?;
                    initial
                }
            };
            merged.updated_at = newer_datetime(&merged.updated_at, &self.now())?;
            let expected_cid = current.and_then(|(_, cid)| cid);
            match self
                .put_circle_owner_state(&merged, expected_cid.as_deref())
                .await
            {
                Ok(new_cid) => return Ok((merged, new_cid)),
                Err(Error::Conflict) if attempt + 1 < CAS_MAX_ATTEMPTS => {
                    conflict_backoff_jitter();
                }
                Err(err) => return Err(err),
            }
        }
        Err(Error::Conflict)
    }

    /// Clear a completed `__acl__:<did>` Space ACL removal tombstone via CAS,
    /// after `com.atproto.memberspace.removeMembers` has succeeded, recording a
    /// monotonic `__acl_cleared__:<did>` floor so stale snapshots cannot resurrect
    /// the removed member or re-open the settled tombstone.
    pub async fn clear_circle_acl_tombstone(
        &mut self,
        circle_id: &str,
        did: &str,
    ) -> Result<Option<(CircleOwnerState, String)>> {
        if circle_id.is_empty() || did.is_empty() {
            return Err(Error::Malformed("circleOwnerState tombstone identifier"));
        }
        for attempt in 0..CAS_MAX_ATTEMPTS {
            let Some((mut state, expected_cid)) = self.get_circle_owner_state(circle_id).await?
            else {
                return Ok(None);
            };
            if !state.record_acl_tombstone_cleared(did) {
                return Ok(Some((state, expected_cid.unwrap_or_default())));
            }
            state.updated_at = newer_datetime(&state.updated_at, &self.now())?;
            match self
                .put_circle_owner_state(&state, expected_cid.as_deref())
                .await
            {
                Ok(new_cid) => return Ok(Some((state, new_cid))),
                Err(Error::Conflict) if attempt + 1 < CAS_MAX_ATTEMPTS => {
                    conflict_backoff_jitter();
                }
                Err(err) => return Err(err),
            }
        }
        Err(Error::Conflict)
    }

    /// List and decrypt every `blue.catbird.labyrinth.circleOwnerState` record
    /// in the personal mailbox Space across current and historical epochs.
    pub async fn list_circle_owner_states(&mut self) -> Result<Vec<CircleOwnerState>> {
        self.seed_store_writer_floors();
        self.seed_store_owner_state_floors();
        let stored_list = self.b.mailbox.list_circle_owner_states_versioned().await?;
        self.sync_store_writer_floors()?;
        self.sync_store_owner_state_floors()?;
        let mut out = Vec::with_capacity(stored_list.len());
        for (rkey, record, cid, cas_version) in stored_list {
            if let Some(c) = cid {
                self.circle_cas_versions
                    .insert((rkey.clone(), c), cas_version);
            }
            out.push(
                self.decrypt_circle_owner_state(&rkey, &record, cas_version)
                    .await?,
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_state_aad_binds_cas_version_and_restricts_legacy_fallback_to_zero() {
        let root = [0x42u8; 32];
        let did = "did:plc:alice0000000000000000000";
        let rkey = "123e4567-e89b-12d3-a456-123456789012";
        let state = ReadState::new(rkey, 77, "2026-11-15T10:00:00.000Z".to_owned()).unwrap();

        let ct_v1 = seal_json(
            READ_STATE_KDF_LABEL,
            &root,
            did,
            nsid::READ_STATE,
            rkey,
            0,
            1,
            &state,
        )
        .unwrap();
        let opened_v1: ReadState = open_json(
            READ_STATE_KDF_LABEL,
            &root,
            did,
            nsid::READ_STATE,
            rkey,
            0,
            1,
            &ct_v1,
        )
        .unwrap();
        assert_eq!(opened_v1, state);

        // Copying v1 ciphertext into v2 or unversioned v0 must fail AEAD authentication.
        let err_v2 = open_json::<ReadState>(
            READ_STATE_KDF_LABEL,
            &root,
            did,
            nsid::READ_STATE,
            rkey,
            0,
            2,
            &ct_v1,
        )
        .unwrap_err();
        assert!(matches!(err_v2, Error::Decrypt));
        let err_v0 = open_json::<ReadState>(
            READ_STATE_KDF_LABEL,
            &root,
            did,
            nsid::READ_STATE,
            rkey,
            0,
            0,
            &ct_v1,
        )
        .unwrap_err();
        assert!(matches!(err_v0, Error::Decrypt));

        // Genuine legacy v1-AAD row (`cas_version == 0`) opens at version 0, but never at version >= 1.
        let json = serde_json::to_vec(&state).unwrap();
        let padded = pad(&json);
        let key = derive_owner_state_key(READ_STATE_KDF_LABEL, &root, 0);
        let legacy_aad = owner_state_aad_legacy_v1(did, nsid::READ_STATE, rkey, 0);
        let legacy_ct = aead::seal(&key, &legacy_aad, &padded).unwrap();

        let opened_legacy: ReadState = open_json(
            READ_STATE_KDF_LABEL,
            &root,
            did,
            nsid::READ_STATE,
            rkey,
            0,
            0,
            &legacy_ct,
        )
        .unwrap();
        assert_eq!(opened_legacy, state);
        let err_promoted = open_json::<ReadState>(
            READ_STATE_KDF_LABEL,
            &root,
            did,
            nsid::READ_STATE,
            rkey,
            0,
            1,
            &legacy_ct,
        )
        .unwrap_err();
        assert!(matches!(err_promoted, Error::Decrypt));
    }

    #[test]
    fn circle_owner_state_merge_accepts_alpha_space_uri_and_emits_new_form() {
        let state = |space_uri: &str| CircleOwnerState {
            circle_id: "circle-uri".to_owned(),
            space_uri: space_uri.to_owned(),
            current_key_version: 1,
            joined_at_version_by_did: BTreeMap::new(),
            pending_ops: BTreeMap::new(),
            updated_at: "2026-11-15T10:00:00.000Z".to_owned(),
        };
        let old =
            state("at://did:plc:alice0000000000000000000/space/blue.catbird.circles.circle/c1");
        let new = state("at:space/did:plc:alice0000000000000000000/blue.catbird.circles.circle/c1");
        for merged in [
            old.merge(&new).unwrap(),
            new.merge(&old).unwrap(),
            old.merge(&old).unwrap(),
        ] {
            assert_eq!(merged.space_uri, new.space_uri);
        }
        let other =
            state("at:space/did:plc:alice0000000000000000000/blue.catbird.circles.circle/c2");
        assert!(old.merge(&other).is_err());
    }

    #[test]
    fn circle_owner_state_settled_tombstone_forms_associative_semilattice() {
        let circle_id = "circle-semilattice";
        let space_uri =
            "at://did:plc:alice0000000000000000000/com.atproto.space.space/3k00000000001";
        let bob = "did:plc:bob000000000000000000000";

        // v1: Bob joined at version 1.
        let s_v1 = CircleOwnerState {
            circle_id: circle_id.to_owned(),
            space_uri: space_uri.to_owned(),
            current_key_version: 1,
            joined_at_version_by_did: BTreeMap::from([(bob.to_owned(), 1)]),
            pending_ops: BTreeMap::new(),
            updated_at: "2026-11-15T10:00:00.000Z".to_owned(),
        };
        s_v1.validate().unwrap();

        // v2: Bob removed at key version 2 (active tombstone).
        let mut s_v2_pending = s_v1.clone();
        s_v2_pending.current_key_version = 2;
        s_v2_pending.updated_at = "2026-11-15T10:01:00.000Z".to_owned();
        s_v2_pending.mark_acl_remove_pending(bob, true);
        assert!(s_v2_pending.has_acl_tombstone(bob));
        assert!(!s_v2_pending.joined_at_version_by_did.contains_key(bob));

        // v2 settled: tombstone cleared after removeMembers succeeds.
        let mut s_v2_cleared = s_v2_pending.clone();
        s_v2_cleared.updated_at = "2026-11-15T10:02:00.000Z".to_owned();
        assert!(s_v2_cleared.record_acl_tombstone_cleared(bob));
        assert!(!s_v2_cleared.has_acl_tombstone(bob));
        assert_eq!(s_v2_cleared.cleared_acl_version(bob), Some(2));

        // Stale pre-removal v1 snapshot cannot resurrect Bob after tombstone is cleared!
        let m_stale_join = s_v2_cleared.merge(&s_v1).unwrap();
        assert!(!m_stale_join.joined_at_version_by_did.contains_key(bob));
        assert!(!m_stale_join.has_acl_tombstone(bob));
        assert_eq!(s_v1.merge(&s_v2_cleared).unwrap(), m_stale_join);

        // Stale pre-clear v2 snapshot cannot re-open `__acl__:bob` after clear!
        let m_stale_pending = s_v2_cleared.merge(&s_v2_pending).unwrap();
        assert!(!m_stale_pending.has_acl_tombstone(bob));
        assert!(!m_stale_pending.joined_at_version_by_did.contains_key(bob));
        assert_eq!(s_v2_pending.merge(&s_v2_cleared).unwrap(), m_stale_pending);

        // v3: Bob legitimately re-added at version 3 (> cleared_ver 2).
        let mut s_v3_readd = s_v2_cleared.clone();
        s_v3_readd.current_key_version = 3;
        s_v3_readd
            .joined_at_version_by_did
            .insert(bob.to_owned(), 3);
        s_v3_readd.updated_at = "2026-11-15T10:03:00.000Z".to_owned();

        // Check full commutativity + associativity across {s_v1, s_v2_pending, s_v2_cleared, s_v3_readd}:
        let left = s_v3_readd
            .merge(&s_v2_cleared)
            .unwrap()
            .merge(&s_v2_pending)
            .unwrap();
        let right = s_v3_readd
            .merge(&s_v2_cleared.merge(&s_v2_pending).unwrap())
            .unwrap();
        assert_eq!(left, right);
        assert_eq!(left.joined_at_version_by_did.get(bob), Some(&3));
        assert!(!left.has_acl_tombstone(bob));

        // v4: Subsequent removal at version 4 (> join_ver 3 and > cleared_ver 2) evicts Bob again.
        let mut s_v4_remove = left.clone();
        s_v4_remove.current_key_version = 4;
        s_v4_remove.updated_at = "2026-11-15T10:04:00.000Z".to_owned();
        s_v4_remove.mark_acl_remove_pending(bob, true);
        let after_re_remove = left.merge(&s_v4_remove).unwrap();
        assert!(!after_re_remove.joined_at_version_by_did.contains_key(bob));
        assert!(after_re_remove.has_acl_tombstone(bob));
    }
}

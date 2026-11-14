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
const OWNER_STATE_AAD_PREFIX: &[u8] = b"catbird.labyrinth.owner_state_aad.v1\0";

/// Maximum optimistic CAS retry attempts for `readState` and `circleOwnerState`
/// merges under multi-device write contention.
const CAS_MAX_ATTEMPTS: usize = 6;

/// Prefix for pending Space ACL removal tombstones in [`CircleOwnerState::pending_ops`].
pub const ACL_TOMBSTONE_PREFIX: &str = "__acl__:";
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

impl CircleOwnerState {
    /// Key used in [`Self::pending_ops`] for a pending Space ACL removal tombstone.
    pub fn acl_tombstone_key(did: &str) -> String {
        format!("{ACL_TOMBSTONE_PREFIX}{did}")
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
        for key in self.pending_ops.keys() {
            if key.is_empty() {
                return Err(Error::Malformed("circleOwnerState empty pendingOps key"));
            }
            if let Some(did) = key.strip_prefix(ACL_TOMBSTONE_PREFIX)
                && did.is_empty()
            {
                return Err(Error::Malformed("circleOwnerState empty tombstone DID"));
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
        self.joined_at_version_by_did.remove(did);
        self.pending_ops.remove(did);
        let key = Self::acl_tombstone_key(did);
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
    }

    /// Monotonic merge of two [`CircleOwnerState`] snapshots for the same Circle:
    ///
    /// - `currentKeyVersion = max(a, b)`
    /// - `__acl__:<did>` tombstones win over concurrent re-adds or non-tombstone
    ///   `pendingOps` entries (`aclRemovePending:rotated` dominates `aclRemovePending`)
    /// - `joinedAtVersionByDid[d] = max(a, b)` for non-tombstoned members so a
    ///   stale sibling device cannot downgrade a re-added member's join floor
    ///   and expose prior history.
    pub fn merge(&self, other: &Self) -> Result<Self> {
        self.validate()?;
        other.validate()?;
        if self.circle_id != other.circle_id {
            return Err(Error::Malformed("circleOwnerState circleId mismatch"));
        }
        if self.space_uri != other.space_uri {
            return Err(Error::Malformed("circleOwnerState spaceUri mismatch"));
        }

        let mut tombstones: BTreeMap<String, String> = BTreeMap::new();
        let mut tombstoned_dids: BTreeSet<String> = BTreeSet::new();
        for (k, v) in self.pending_ops.iter().chain(other.pending_ops.iter()) {
            if let Some(did) = k.strip_prefix(ACL_TOMBSTONE_PREFIX) {
                tombstoned_dids.insert(did.to_owned());
                tombstones
                    .entry(k.clone())
                    .and_modify(|cur| {
                        if tombstone_rank(v) > tombstone_rank(cur)
                            || (tombstone_rank(v) == tombstone_rank(cur)
                                && v.as_str() > cur.as_str())
                        {
                            *cur = v.clone();
                        }
                    })
                    .or_insert_with(|| v.clone());
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
            joined_at_version_by_did
                .entry(did.clone())
                .and_modify(|cur| *cur = (*cur).max(ver))
                .or_insert(ver);
        }

        let self_ms = ms_from_datetime(&self.updated_at)?;
        let other_ms = ms_from_datetime(&other.updated_at)?;
        let other_newer = (other_ms, &other.updated_at) > (self_ms, &self.updated_at);

        let mut pending_ops: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &self.pending_ops {
            if k.starts_with(ACL_TOMBSTONE_PREFIX) || tombstoned_dids.contains(k) {
                continue;
            }
            pending_ops.insert(k.clone(), v.clone());
        }
        for (k, v) in &other.pending_ops {
            if k.starts_with(ACL_TOMBSTONE_PREFIX) || tombstoned_dids.contains(k) {
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
        pending_ops.extend(tombstones);

        Ok(Self {
            circle_id: self.circle_id.clone(),
            space_uri: self.space_uri.clone(),
            current_key_version: self.current_key_version.max(other.current_key_version),
            joined_at_version_by_did,
            pending_ops,
            updated_at: newer_datetime(&self.updated_at, &other.updated_at)?,
        })
    }
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

fn owner_state_aad(did: &str, collection: &str, rkey: &str, epoch_seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        OWNER_STATE_AAD_PREFIX.len() + 4 + did.len() + 4 + collection.len() + 4 + rkey.len() + 8,
    );
    aad.extend_from_slice(OWNER_STATE_AAD_PREFIX);
    for part in [did.as_bytes(), collection.as_bytes(), rkey.as_bytes()] {
        let len = u32::try_from(part.len()).expect("owner state identifier fits in u32");
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(part);
    }
    aad.extend_from_slice(&epoch_seq.to_be_bytes());
    aad
}

fn seal_json<T: Serialize>(
    label: &[u8],
    root: &[u8; 32],
    did: &str,
    collection: &str,
    rkey: &str,
    epoch_seq: u64,
    value: &T,
) -> Result<Vec<u8>> {
    let json = Zeroizing::new(
        serde_json::to_vec(value).map_err(|_| Error::Malformed("owner state JSON encode"))?,
    );
    let padded = Zeroizing::new(pad(&json));
    let key = derive_owner_state_key(label, root, epoch_seq);
    let aad = owner_state_aad(did, collection, rkey, epoch_seq);
    aead::seal(&key, &aad, &padded)
}

fn open_json<T: for<'de> Deserialize<'de>>(
    label: &[u8],
    root: &[u8; 32],
    did: &str,
    collection: &str,
    rkey: &str,
    epoch_seq: u64,
    ciphertext: &[u8],
) -> Result<T> {
    let key = derive_owner_state_key(label, root, epoch_seq);
    let aad = owner_state_aad(did, collection, rkey, epoch_seq);
    let padded = Zeroizing::new(aead::decrypt_suite(Suite::DndkGcm, &key, &aad, ciphertext)?);
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
            &record.ciphertext.0,
        )?;
        state.validate()?;
        if state.conversation_id != rkey {
            return Err(Error::Malformed("readState rkey mismatch"));
        }
        Ok(state)
    }

    async fn encrypt_read_state(&mut self, state: &ReadState) -> Result<ReadStateRecord> {
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
            state,
        )?;
        ReadStateRecord::new(ct, epoch_seq, state.updated_at.clone())
    }

    async fn decrypt_circle_owner_state(
        &mut self,
        rkey: &str,
        record: &CircleOwnerStateRecord,
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
            &record.ciphertext.0,
        )?;
        state.validate()?;
        if state.circle_id != rkey {
            return Err(Error::Malformed("circleOwnerState rkey mismatch"));
        }
        Ok(state)
    }

    async fn encrypt_circle_owner_state(
        &mut self,
        state: &CircleOwnerState,
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
        let fetched = self.b.mailbox.get_read_state(conversation_id).await?;
        self.sync_store_writer_floors()?;
        let Some((record, _cid)) = fetched else {
            return Ok(None);
        };
        self.decrypt_read_state(conversation_id, &record)
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
            let current = self.b.mailbox.get_read_state(conversation_id).await?;
            self.sync_store_writer_floors()?;

            let expected_cid = match current {
                Some((record, cid)) => {
                    let existing = self.decrypt_read_state(conversation_id, &record).await?;
                    if existing.read_through_seq >= candidate.read_through_seq {
                        return Ok(existing);
                    }
                    candidate = existing.merge(&candidate)?;
                    cid
                }
                None => None,
            };

            let record = self.encrypt_read_state(&candidate).await?;
            match self
                .b
                .mailbox
                .put_read_state(conversation_id, &record, expected_cid.as_deref())
                .await
            {
                Ok(_cid) => return Ok(candidate),
                Err(Error::Conflict) => {
                    self.seed_store_writer_floors();
                    let latest = self.b.mailbox.get_read_state(conversation_id).await?;
                    self.sync_store_writer_floors()?;
                    if let Some((latest_rec, _)) = latest {
                        let existing = self
                            .decrypt_read_state(conversation_id, &latest_rec)
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
        let stored_list = self.b.mailbox.list_read_states().await?;
        self.sync_store_writer_floors()?;
        let mut out = Vec::with_capacity(stored_list.len());
        for (rkey, record, _cid) in stored_list {
            out.push(self.decrypt_read_state(&rkey, &record).await?);
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
        let fetched = self.b.mailbox.get_circle_owner_state(circle_id).await?;
        self.sync_store_writer_floors()?;
        let Some((record, cid)) = fetched else {
            return Ok(None);
        };
        let state = self.decrypt_circle_owner_state(circle_id, &record).await?;
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
        let record = self.encrypt_circle_owner_state(state).await?;
        self.b
            .mailbox
            .put_circle_owner_state(&state.circle_id, &record, expected_cid)
            .await
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
    /// after `com.atproto.memberspace.removeMembers` has succeeded.
    pub async fn clear_circle_acl_tombstone(
        &mut self,
        circle_id: &str,
        did: &str,
    ) -> Result<Option<(CircleOwnerState, String)>> {
        if circle_id.is_empty() || did.is_empty() {
            return Err(Error::Malformed("circleOwnerState tombstone identifier"));
        }
        let tombstone_key = CircleOwnerState::acl_tombstone_key(did);
        for attempt in 0..CAS_MAX_ATTEMPTS {
            let Some((mut state, expected_cid)) = self.get_circle_owner_state(circle_id).await?
            else {
                return Ok(None);
            };
            let removed_tombstone = state.pending_ops.remove(&tombstone_key).is_some();
            let removed_member = state.joined_at_version_by_did.remove(did).is_some();
            if !removed_tombstone && !removed_member {
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
        let stored_list = self.b.mailbox.list_circle_owner_states().await?;
        self.sync_store_writer_floors()?;
        let mut out = Vec::with_capacity(stored_list.len());
        for (rkey, record, _cid) in stored_list {
            out.push(self.decrypt_circle_owner_state(&rkey, &record).await?);
        }
        Ok(out)
    }
}

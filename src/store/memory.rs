//! In-memory backend for tests and examples.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use sha2::{Digest, Sha256};

use super::{
    AtomicEnrollBundle, ChatDeviceKey, EnrollCleanup, MailboxStore, MemberDeviceKey,
    SequencerReceiptKey, ServerOrder, Stored, TimeRange,
};
use crate::attachment::{AttachmentCiphertextMeta, verify_attachment_ciphertext};
use crate::epoch::space_epoch_id;
use crate::records::{
    AttachmentManifest, CircleOwnerStateRecord, Device, Epoch, EpochMember, MailboxKeysRecord,
    OtcSession, OwnerBatch, ReadStateRecord, VirtualDevice,
};
use crate::sign::XVerifyingKey;
use crate::{Error, Result};

mod directory;
mod heads;
mod lifecycle;
mod threads;

pub use directory::MemoryDirectory;
pub use heads::{MemoryDsDirectory, MemoryDsPublisher, MemoryPdsPublisher};
pub use threads::MemoryThreads;

#[derive(Default)]
struct Mailbox {
    devices: BTreeMap<String, Device>,
    epochs: BTreeMap<String, Epoch>,
    members: BTreeMap<String, EpochMember>,
    vdevices: BTreeMap<String, VirtualDevice>,
    otc_sessions: BTreeMap<String, OtcSession>,
    read_states: BTreeMap<String, (ReadStateRecord, String, u64)>,
    circle_owner_states: BTreeMap<String, (CircleOwnerStateRecord, String, u64)>,
    owner_batches: BTreeMap<String, (OwnerBatch, Option<ServerOrder>)>,
    attachments: BTreeMap<String, AttachmentManifest>,
    next_seq: u64,
}

#[derive(Default)]
struct Repo {
    meks: BTreeMap<String, (crate::records::MekDistribution, Option<ServerOrder>)>,
    batches: BTreeMap<String, (crate::records::Batch, Option<ServerOrder>)>,
    attachments: BTreeMap<String, AttachmentManifest>,
}

#[derive(Default)]
struct ThreadSpace {
    repos: BTreeMap<String, Repo>,
    /// Immutable per-author, per-message unsends. Deliberately outside repos:
    /// leave/account cleanup removes ciphertext repos but never these records.
    author_redactions: BTreeMap<(String, String), crate::records::AuthorRedaction>,
    no_read: BTreeSet<String>,
    /// Labyrinth write counter (server order).
    next_seq: u64,
    /// Seq of the conversation's last MLS chat entry.
    chat_seq: u64,
    /// Per-DID device leaves, once any leaf was recorded.
    leaves: Option<BTreeMap<String, Vec<MemberDeviceKey>>>,
}

#[derive(Default)]
struct ChatDevices {
    current: Vec<[u8; 32]>,
    /// Removed keys with their removal time (ms).
    removed: Vec<([u8; 32], u64)>,
}

#[derive(Default)]
struct State {
    mailboxes: HashMap<String, Mailbox>,
    blobs: HashMap<(String, String), Vec<u8>>,
    public_keys: HashMap<String, MailboxKeysRecord>,
    /// Every published `mailboxKeys`, by DID and epoch number ([CB-29]).
    public_history: HashMap<String, BTreeMap<u64, MailboxKeysRecord>>,
    threads: HashMap<String, ThreadSpace>,
    chat_devices: HashMap<String, ChatDevices>,
    tid: u64,
    /// Stamp writes with [`ServerOrder`].
    stamping: bool,
    /// The server clock for stamps (ms), set by tests.
    server_now: u64,
    /// `mls-ds` `labyrinth.epoch_heads`, by DID and epoch number.
    ds_heads: HashMap<String, BTreeMap<u64, crate::mailbox::EpochPublic>>,
    /// Pruned `floor_seq` per DID (`L-F01`, Gate 6).
    ds_floors: HashMap<String, u64>,
    /// Adversarial override for `floor_seq` (`Gate 6` test injection).
    ds_floor_overrides: HashMap<String, u64>,
    /// Per-thread `I13` ES256 receipt verification keys (`Gate 1`).
    receipt_keys: HashMap<String, SequencerReceiptKey>,
    /// Exact verification-method history, retained across current-key rotation.
    receipt_key_history: HashMap<String, HashMap<String, SequencerReceiptKey>>,
}

impl State {
    /// A sortable 13-character TID-shaped rkey (base32-sortable counter).
    fn next_tid(&mut self) -> String {
        const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
        self.tid += 1;
        (0..13)
            .rev()
            .map(|i| S32[((self.tid >> (5 * i)) & 31) as usize] as char)
            .collect()
    }

    fn store_blob(&mut self, did: &str, bytes: &[u8]) -> String {
        self.tid += 1;
        let mut h = Sha256::new();
        h.update(bytes);
        h.update(self.tid.to_be_bytes());
        let cid = format!("bafkrei{}", hex::encode(&h.finalize()[..16]));
        self.blobs
            .insert((did.to_owned(), cid.clone()), bytes.to_vec());
        cid
    }

    /// Writes `did`'s public `mailboxKeys` (`self` and the per-epoch copy).
    fn publish_pds(&mut self, did: &str, record: &MailboxKeysRecord) -> Result<()> {
        let seq = record.current.epoch_number;
        let history = self.public_history.entry(did.to_owned()).or_default();
        if history
            .get(&seq)
            .is_some_and(|r| r.current != record.current)
        {
            return Err(Error::Conflict);
        }
        history.insert(seq, record.clone());
        if let Some(existing) = self.public_keys.get(did)
            && let Ok(existing_pub) = existing.to_public()
            && existing_pub.verify(did, None).is_ok()
            && existing_pub.seq > seq
        {
            return Err(Error::EpochRollback {
                pinned: existing_pub.seq,
                offered: seq,
            });
        }
        self.public_keys.insert(did.to_owned(), record.clone());
        Ok(())
    }

    /// The server stamp for a write into `thread_id` (`None` unless stamping).
    fn stamp_thread(&mut self, thread_id: &str) -> Option<ServerOrder> {
        if !self.stamping {
            return None;
        }
        let now = self.server_now;
        let t = self.threads.entry(thread_id.to_owned()).or_default();
        t.next_seq += 1;
        Some(ServerOrder {
            labyrinth_seq: t.next_seq,
            chat_seq: t.leaves.as_ref().map(|_| t.chat_seq),
            received_at_ms: now,
        })
    }
}

/// The shared in-memory "network". Cheap to clone.
#[derive(Clone, Default)]
pub struct MemoryBackend {
    state: Arc<Mutex<State>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `did`'s personal mailbox, as `did` sees it.
    pub fn mailbox(&self, did: &str) -> MemoryMailbox {
        MemoryMailbox {
            did: did.to_owned(),
            backend: self.clone(),
            version_floors: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// The conversation spaces, as `did` sees them.
    pub fn threads(&self, did: &str) -> MemoryThreads {
        MemoryThreads::new(did, self.clone())
    }

    /// Public `mailboxKeys` records plus the MLS device view.
    pub fn directory(&self) -> MemoryDirectory {
        MemoryDirectory::new(self.clone())
    }

    /// The `mls-ds` epoch-head directory ([CB-28], [CB-29], Gate 6).
    pub fn ds_directory(&self) -> MemoryDsDirectory {
        MemoryDsDirectory::new(self.clone())
    }

    /// Publishes `did`'s heads to the `mls-ds` directory (`publishEpochHead`).
    pub fn ds_publisher(&self, did: &str) -> MemoryDsPublisher {
        MemoryDsPublisher::new(did, self.clone())
    }

    /// Publishes `did`'s public `mailboxKeys` records.
    pub fn pds_publisher(&self, did: &str) -> MemoryPdsPublisher {
        MemoryPdsPublisher::new(did, self.clone())
    }

    /// Stamp every MEK, batch and owner batch with [`ServerOrder`].
    pub fn enable_server_order(&self) {
        self.lock().stamping = true;
    }

    /// Sets the server clock (ms).
    pub fn set_server_time(&self, ms: u64) {
        self.lock().server_now = ms;
    }

    /// Fault-injection helper for tests modelling an unvalidated store.
    #[doc(hidden)]
    pub fn insert_epoch_unchecked(&self, did: &str, epoch: &Epoch) {
        let mut s = self.lock();
        let m = s.mailboxes.entry(did.to_owned()).or_default();
        m.epochs.insert(space_epoch_id(epoch.seq()), epoch.clone());
    }

    /// Records one MLS chat entry in `thread_id`; returns its seq.
    pub fn append_chat_entry(&self, thread_id: &str) -> u64 {
        let mut s = self.lock();
        let t = s.threads.entry(thread_id.to_owned()).or_default();
        t.chat_seq += 1;
        t.chat_seq
    }

    /// Adds a leaf for `did`'s device `key` to `thread_id`.
    pub fn add_leaf(&self, thread_id: &str, did: &str, key: [u8; 32]) -> u64 {
        let seq = self.append_chat_entry(thread_id);
        let mut s = self.lock();
        let t = s.threads.entry(thread_id.to_owned()).or_default();
        t.leaves
            .get_or_insert_default()
            .entry(did.to_owned())
            .or_default()
            .push(MemberDeviceKey {
                key,
                joined_chat_seq: seq,
                removed_chat_seq: None,
            });
        seq
    }

    /// Removes `did`'s leaf `key` from `thread_id`.
    pub fn remove_leaf(&self, thread_id: &str, did: &str, key: [u8; 32]) -> u64 {
        let seq = self.append_chat_entry(thread_id);
        let mut s = self.lock();
        let t = s.threads.entry(thread_id.to_owned()).or_default();
        for l in t
            .leaves
            .get_or_insert_default()
            .entry(did.to_owned())
            .or_default()
            .iter_mut()
            .filter(|l| l.key == key && l.removed_chat_seq.is_none())
        {
            l.removed_chat_seq = Some(seq);
        }
        seq
    }

    /// Records a chat device of `did` in the MLS view.
    pub fn register_chat_device(&self, did: &str, transport_pub: [u8; 32]) {
        let mut s = self.lock();
        let d = s.chat_devices.entry(did.to_owned()).or_default();
        if !d.current.contains(&transport_pub) {
            d.current.push(transport_pub);
        }
    }

    /// Replaces `did`'s active chat device transport keys.
    pub fn set_chat_devices(&self, did: &str, keys: Vec<[u8; 32]>) {
        let mut s = self.lock();
        let d = s.chat_devices.entry(did.to_owned()).or_default();
        d.current = keys;
    }

    /// Removes a chat device from the current MLS view at `removed_at_ms`.
    pub fn remove_chat_device(&self, did: &str, transport_pub: [u8; 32], removed_at_ms: u64) {
        let mut s = self.lock();
        let d = s.chat_devices.entry(did.to_owned()).or_default();
        d.current.retain(|k| *k != transport_pub);
        if !d.removed.iter().any(|(k, _)| *k == transport_pub) {
            d.removed.push((transport_pub, removed_at_ms));
        }
    }

    /// The conversation space stops serving `did` (Space member removal).
    pub fn revoke_thread_access(&self, thread_id: &str, did: &str) {
        let mut s = self.lock();
        let t = s.threads.entry(thread_id.to_owned()).or_default();
        t.no_read.insert(did.to_owned());
    }

    /// DIDs with at least one leaf recorded in `thread_id`.
    pub fn leaf_dids(&self, thread_id: &str) -> Vec<String> {
        let s = self.lock();
        s.threads
            .get(thread_id)
            .and_then(|t| t.leaves.as_ref())
            .map(|l| l.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Installs the authoritative MLS device leaves for one test conversation.
    pub fn set_member_device_keys(&self, thread_id: &str, did: &str, keys: Vec<MemberDeviceKey>) {
        let mut state = self.lock();
        state
            .threads
            .entry(thread_id.to_owned())
            .or_default()
            .leaves
            .get_or_insert_with(BTreeMap::new)
            .insert(did.to_owned(), keys);
    }

    /// Registers the first receipt key for `thread_id`.
    pub fn set_sequencer_receipt_key(&self, thread_id: &str, key: SequencerReceiptKey) {
        let key_id = labyrinth_protocol::expected_receipt_key_id(&key.did);
        self.try_set_sequencer_receipt_key_with_id(thread_id, &key_id, key)
            .expect("test receipt key must be a fresh method");
    }

    /// Rotates the current receipt key while retaining the exact old method.
    pub fn set_sequencer_receipt_key_with_id(
        &self,
        thread_id: &str,
        key_id: &str,
        key: SequencerReceiptKey,
    ) {
        self.try_set_sequencer_receipt_key_with_id(thread_id, key_id, key)
            .expect("test receipt key must be a fresh method");
    }

    /// Fallible variant used by key-ID reuse tests.
    pub fn try_set_sequencer_receipt_key_with_id(
        &self,
        thread_id: &str,
        key_id: &str,
        key: SequencerReceiptKey,
    ) -> Result<()> {
        labyrinth_protocol::receipt_key_generation(&key.did, key_id)
            .map_err(|_| Error::Malformed("receipt key ID does not name its authority"))?;
        let mut state = self.lock();
        let history = state
            .receipt_key_history
            .entry(thread_id.to_owned())
            .or_default();
        if history.get(key_id).is_some_and(|existing| existing != &key) {
            return Err(Error::Conflict);
        }
        history
            .entry(key_id.to_owned())
            .or_insert_with(|| key.clone());
        state.receipt_keys.insert(thread_id.to_owned(), key);
        Ok(())
    }

    /// Remove every directory copy of a thread's receipt methods.
    pub fn clear_sequencer_receipt_keys(&self, thread_id: &str) {
        let mut state = self.lock();
        state.receipt_keys.remove(thread_id);
        state.receipt_key_history.remove(thread_id);
    }

    pub(super) fn receipt_key(&self, thread_id: &str) -> Option<SequencerReceiptKey> {
        self.lock().receipt_keys.get(thread_id).cloned()
    }

    pub(super) fn receipt_key_by_id(
        &self,
        thread_id: &str,
        key_id: &str,
    ) -> Option<SequencerReceiptKey> {
        self.lock()
            .receipt_key_history
            .get(thread_id)
            .and_then(|history| history.get(key_id))
            .cloned()
    }

    /// Prunes `mls-ds` epoch heads strictly below `floor_seq` (`L-F01`, Gate 6).
    pub fn prune_ds_heads_below(&self, did: &str, floor_seq: u64) {
        let mut s = self.lock();
        if let Some(chain) = s.ds_heads.get_mut(did) {
            chain.retain(|&seq, _| seq >= floor_seq);
        }
        s.ds_floors.insert(did.to_owned(), floor_seq);
    }

    /// Adversarial helper overwriting `did`'s PDS `mailboxKeys/self` without rollback checks (`Gate 6`).
    pub fn tamper_pds_latest(&self, did: &str, record: MailboxKeysRecord) {
        self.lock().public_keys.insert(did.to_owned(), record);
    }

    /// Adversarial helper overriding the `floor_seq` reported by `ds_directory` (`Gate 6`).
    pub fn set_ds_floor_seq_override_for_test(&self, did: &str, floor_seq: u64) {
        self.lock()
            .ds_floor_overrides
            .insert(did.to_owned(), floor_seq);
    }

    /// The server clock (ms).
    pub fn server_time(&self) -> u64 {
        self.lock().server_now
    }

    fn member_keys(&self, thread_id: &str, did: &str) -> Option<Vec<MemberDeviceKey>> {
        let s = self.lock();
        let leaves = s.threads.get(thread_id)?.leaves.as_ref()?;
        Some(leaves.get(did).cloned().unwrap_or_default())
    }

    fn chat_keys(&self, did: &str) -> Vec<ChatDeviceKey> {
        let s = self.lock();
        s.chat_devices
            .get(did)
            .map(|d| {
                d.current
                    .iter()
                    .map(|k| ChatDeviceKey::current(*k))
                    .chain(d.removed.iter().map(|(k, at)| ChatDeviceKey {
                        key: *k,
                        removed_at: Some(*at),
                    }))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// [`MailboxStore`] handle bound to one DID.
pub struct MemoryMailbox {
    did: String,
    backend: MemoryBackend,
    version_floors: Arc<Mutex<BTreeMap<(String, String), u64>>>,
}

impl MemoryMailbox {
    fn with<T>(&self, f: impl FnOnce(&mut Mailbox) -> Result<T>) -> Result<T> {
        let mut s = self.backend.lock();
        f(s.mailboxes.entry(self.did.clone()).or_default())
    }

    fn pinned_version(&self, collection: &str, id: &str) -> u64 {
        self.version_floors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(collection.to_owned(), id.to_owned()))
            .copied()
            .unwrap_or(0)
    }

    fn observe_version(&self, collection: &str, id: &str, ver: u64) -> Result<()> {
        crate::store::validate_owner_state_version_floor(collection, id, ver)?;
        let mut guard = self
            .version_floors
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = (collection.to_owned(), id.to_owned());
        if let Some(&pinned) = guard.get(&key) {
            if ver < pinned {
                return Err(Error::Malformed("owner state version rollback"));
            }
            if ver > pinned {
                guard.insert(key, ver);
            }
            return Ok(());
        }
        if guard.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
            return Err(Error::Malformed("owner state version floor table full"));
        }
        guard.insert(key, ver);
        Ok(())
    }
}

fn create<T: Clone>(map: &mut BTreeMap<String, T>, key: String, value: &T) -> Result<()> {
    if map.contains_key(&key) {
        return Err(Error::Conflict);
    }
    map.insert(key, value.clone());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for MemoryMailbox {
    fn owner(&self) -> &str {
        &self.did
    }

    async fn create_device(&self, device: &Device) -> Result<()> {
        let key = hex::encode(&device.device_key_pubkey.0);
        self.with(|m| create(&mut m.devices, key, device))
    }

    async fn set_device_revoked(&self, device_key: &XVerifyingKey, revoked_at: &str) -> Result<()> {
        self.with(|m| {
            let d = m
                .devices
                .get_mut(&hex::encode(device_key.0))
                .ok_or(Error::NotFound("device"))?;
            if d.revoked_at.is_none() {
                d.revoked_at = Some(revoked_at.to_owned());
            }
            Ok(())
        })
    }

    async fn set_device_revocation(
        &self,
        device_key: &XVerifyingKey,
        revoked_at: &str,
        revocation: &crate::records::DeviceRevocationDef,
    ) -> Result<()> {
        let owner = self.did.clone();
        self.with(|m| {
            let rkey = hex::encode(device_key.0);
            let current = m.devices.get(&rkey).ok_or(Error::NotFound("device"))?;
            let all_devices: Vec<Device> = m.devices.values().cloned().collect();
            if crate::records::should_replace_device_revocation(
                &owner,
                device_key,
                current,
                &all_devices,
                revoked_at,
                revocation,
            ) {
                let d = m.devices.get_mut(&rkey).expect("checked above");
                d.revoked_at = Some(revoked_at.to_owned());
                d.revocation = Some(revocation.clone());
            }
            Ok(())
        })
    }

    async fn get_device(&self, device_key: &XVerifyingKey) -> Result<Option<Device>> {
        self.with(|m| Ok(m.devices.get(&hex::encode(device_key.0)).cloned()))
    }

    async fn list_devices(&self) -> Result<Vec<Device>> {
        self.with(|m| Ok(m.devices.values().cloned().collect()))
    }

    async fn create_epoch(&self, epoch: &Epoch, members: &[EpochMember]) -> Result<String> {
        let seq = epoch.seq();
        let id = space_epoch_id(seq);
        let cur_pub = epoch.public.to_public()?;
        self.with(|m| {
            if m.epochs.contains_key(&id)
                || members
                    .iter()
                    .any(|x| x.epoch_number != seq || m.members.contains_key(&x.rkey()))
            {
                return Err(Error::Conflict);
            }
            if seq > 0 {
                let prev = m
                    .epochs
                    .get(&space_epoch_id(seq - 1))
                    .ok_or(Error::Malformed("InvalidEpochChain"))?;
                let prev_pub = prev.public.to_public()?;
                cur_pub
                    .verify_link(prev_pub.seq, &prev_pub.head, &prev_pub.keys.sig)
                    .map_err(|_| Error::Malformed("InvalidEpochChain"))?;
            }
            m.epochs.insert(id.clone(), epoch.clone());
            for x in members {
                m.members.insert(x.rkey(), x.clone());
            }
            Ok(id)
        })
    }

    async fn atomic_enroll(&self, bundle: &AtomicEnrollBundle) -> Result<String> {
        let seq = bundle.epoch.seq();
        let id = space_epoch_id(seq);
        let cur_pub = bundle.epoch.public.to_public()?;
        let dev_key = hex::encode(&bundle.device.device_key_pubkey.0);
        self.with(|m| {
            if m.devices.contains_key(&dev_key)
                || m.epochs.contains_key(&id)
                || bundle
                    .members
                    .iter()
                    .any(|x| x.epoch_number != seq || m.members.contains_key(&x.rkey()))
            {
                return Err(Error::Conflict);
            }
            if let Some(cleanup) = &bundle.cleanup {
                match cleanup {
                    EnrollCleanup::ConsumeOtcSession { rkey } => {
                        if !m.otc_sessions.contains_key(rkey) {
                            return Err(Error::Conflict);
                        }
                    }
                    EnrollCleanup::TouchVirtualDevice { updated } => {
                        if !m.vdevices.contains_key(&updated.rkey()) {
                            return Err(Error::NotFound("virtual device"));
                        }
                    }
                }
            }
            if seq > 0 {
                let prev = m
                    .epochs
                    .get(&space_epoch_id(seq - 1))
                    .ok_or(Error::Malformed("InvalidEpochChain"))?;
                let prev_pub = prev.public.to_public()?;
                cur_pub
                    .verify_link(prev_pub.seq, &prev_pub.head, &prev_pub.keys.sig)
                    .map_err(|_| Error::Malformed("InvalidEpochChain"))?;
            }
            if let Some(cleanup) = &bundle.cleanup {
                match cleanup {
                    EnrollCleanup::ConsumeOtcSession { rkey } => {
                        m.otc_sessions.remove(rkey);
                    }
                    EnrollCleanup::TouchVirtualDevice { updated } => {
                        m.vdevices.insert(updated.rkey(), updated.clone());
                    }
                }
            }
            m.devices.insert(dev_key, bundle.device.clone());
            m.epochs.insert(id.clone(), bundle.epoch.clone());
            for x in &bundle.members {
                m.members.insert(x.rkey(), x.clone());
            }
            Ok(id)
        })
    }

    async fn get_epoch(&self, seq: u64) -> Result<Option<Stored<Epoch>>> {
        let id = space_epoch_id(seq);
        self.with(|m| {
            Ok(m.epochs.get(&id).map(|e| Stored {
                author: self.did.clone(),
                rkey: id.clone(),
                value: e.clone(),
                order: None,
            }))
        })
    }

    async fn list_epochs(&self) -> Result<Vec<Stored<Epoch>>> {
        self.with(|m| {
            Ok(m.epochs
                .iter()
                .map(|(k, e)| Stored {
                    author: self.did.clone(),
                    rkey: k.clone(),
                    value: e.clone(),
                    order: None,
                })
                .collect())
        })
    }

    async fn create_epoch_member(&self, member: &EpochMember) -> Result<()> {
        self.with(|m| {
            if !m.epochs.contains_key(&space_epoch_id(member.epoch_number)) {
                return Err(Error::NotFound("epoch"));
            }
            create(&mut m.members, member.rkey(), member)
        })
    }

    async fn list_epoch_members(&self, seq: u64) -> Result<Vec<EpochMember>> {
        let prefix = format!("{seq:012}-");
        self.with(|m| {
            Ok(m.members
                .range(prefix.clone()..)
                .take_while(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v.clone())
                .collect())
        })
    }

    async fn create_virtual_device(&self, vdevice: &VirtualDevice) -> Result<()> {
        self.with(|m| create(&mut m.vdevices, vdevice.rkey(), vdevice))
    }

    async fn get_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<Option<VirtualDevice>> {
        self.with(|m| Ok(m.vdevices.get(&hex::encode(vdevice_id)).cloned()))
    }

    async fn list_virtual_devices(&self) -> Result<Vec<VirtualDevice>> {
        self.with(|m| Ok(m.vdevices.values().cloned().collect()))
    }

    async fn put_otc_session(&self, session: &OtcSession) -> Result<()> {
        session.check()?;
        self.with(|m| {
            m.otc_sessions
                .insert(session.rkey().to_owned(), session.clone());
            Ok(())
        })
    }

    async fn get_otc_session(&self, session_id: &str) -> Result<Option<OtcSession>> {
        self.with(|m| Ok(m.otc_sessions.get(session_id).cloned()))
    }

    async fn append_owner_batch(&self, batch: &OwnerBatch) -> Result<String> {
        let mut s = self.backend.lock();
        let tid = s.next_tid();
        let (stamping, now) = (s.stamping, s.server_now);
        let m = s.mailboxes.entry(self.did.clone()).or_default();
        let order = stamping.then(|| {
            m.next_seq += 1;
            ServerOrder {
                labyrinth_seq: m.next_seq,
                chat_seq: None,
                received_at_ms: now,
            }
        });
        create(&mut m.owner_batches, tid.clone(), &(batch.clone(), order))?;
        Ok(tid)
    }

    async fn list_owner_batches(
        &self,
        thread_id: &str,
        range: TimeRange,
    ) -> Result<Vec<Stored<OwnerBatch>>> {
        self.with(|m| {
            Ok(m.owner_batches
                .iter()
                .filter(|(_, (b, _))| {
                    b.thread_id == thread_id && b.items.iter().any(|i| range.contains(i.timestamp))
                })
                .map(|(k, (b, order))| Stored {
                    author: self.did.clone(),
                    rkey: k.clone(),
                    value: b.clone(),
                    order: *order,
                })
                .collect())
        })
    }

    async fn upload_and_commit_owner_attachment(
        &self,
        rkey: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> Result<String> {
        verify_attachment_ciphertext(ciphertext, meta)?;
        let mut s = self.backend.lock();
        let cid = s.store_blob(&self.did, ciphertext);
        let manifest = AttachmentManifest::from_meta(&cid, meta, created_at.to_owned());
        let m = s.mailboxes.entry(self.did.clone()).or_default();
        m.attachments.insert(rkey.to_owned(), manifest);
        Ok(cid)
    }

    async fn get_owner_attachment_verified(&self, rkey: &str) -> Result<Vec<u8>> {
        let s = self.backend.lock();
        let manifest = s
            .mailboxes
            .get(&self.did)
            .and_then(|m| m.attachments.get(rkey))
            .ok_or(Error::NotFound("attachmentManifest"))?;
        let (cid, meta) = manifest.to_meta()?;
        let bytes = s
            .blobs
            .get(&(self.did.clone(), cid))
            .ok_or(Error::NotFound("attachment blob"))?
            .clone();
        verify_attachment_ciphertext(&bytes, &meta)?;
        Ok(bytes)
    }

    async fn list_owner_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Stored<OwnerBatch>>> {
        let target = limit.max(1).saturating_add(1);
        let range = TimeRange {
            from_ms: None,
            until_ms: before_ms,
        };
        self.with(|m| {
            let mut candidates: Vec<Stored<OwnerBatch>> = m
                .owner_batches
                .iter()
                .rev()
                .filter(|(_, (b, _))| {
                    b.thread_id == thread_id && b.items.iter().any(|i| range.contains(i.timestamp))
                })
                .map(|(k, (b, order))| Stored {
                    author: self.did.clone(),
                    rkey: k.clone(),
                    value: b.clone(),
                    order: *order,
                })
                .collect();
            candidates.sort_by_key(|b| core::cmp::Reverse(b.order.map(|o| o.labyrinth_seq)));
            let mut eligible = std::collections::BTreeSet::new();
            for b in &candidates {
                for i in &b.value.items {
                    if before_ms.is_none_or(|u| i.timestamp < u.saturating_sub(1)) {
                        eligible.insert((i.timestamp, i.message_id.clone()));
                    }
                }
                if eligible.len() >= target {
                    break;
                }
            }
            if let Some((floor, _)) = (eligible.len() >= target)
                .then(|| eligible.iter().rev().nth(target - 1))
                .flatten()
            {
                let floor = *floor;
                candidates.retain(|b| {
                    b.value
                        .items
                        .iter()
                        .any(|i| i.timestamp >= floor && before_ms.is_none_or(|u| i.timestamp < u))
                });
            }
            candidates.sort_by_key(|b| {
                core::cmp::Reverse(b.value.items.iter().map(|i| i.timestamp).max())
            });
            Ok(candidates)
        })
    }

    async fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> Result<()> {
        self.backend.lock().publish_pds(&self.did, record)
    }

    async fn list_owner_threads(&self) -> Result<Vec<String>> {
        Ok(self.backend.lock().owner_threads(&self.did))
    }

    async fn touch_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        self.backend.lock().touch_vdevice(&self.did, vdevice_id)
    }

    async fn delete_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        self.backend.lock().delete_vdevice(&self.did, vdevice_id)
    }

    async fn delete_squatted_epoch(&self, seq: u64) -> Result<()> {
        let epoch_rkey = space_epoch_id(seq);
        let prefix = format!("{seq:012}-");
        self.with(|m| {
            m.members.retain(|k, _| !k.starts_with(&prefix));
            m.epochs.remove(&epoch_rkey);
            Ok(())
        })
    }

    async fn get_read_state_versioned(
        &self,
        conversation_id: &str,
    ) -> Result<Option<(ReadStateRecord, Option<String>, u64)>> {
        let row = self.with(|m| {
            Ok(m.read_states
                .get(conversation_id)
                .map(|(rec, cid, ver)| (rec.clone(), Some(cid.clone()), *ver)))
        })?;
        match row {
            Some((rec, cid, ver)) => {
                self.observe_version(crate::records::nsid::READ_STATE, conversation_id, ver)?;
                Ok(Some((rec, cid, ver)))
            }
            None => {
                if self.pinned_version(crate::records::nsid::READ_STATE, conversation_id) > 0 {
                    return Err(Error::Malformed("owner state version rollback"));
                }
                Ok(None)
            }
        }
    }

    async fn get_read_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<(ReadStateRecord, Option<String>)>> {
        Ok(self
            .get_read_state_versioned(conversation_id)
            .await?
            .map(|(rec, cid, _)| (rec, cid)))
    }

    async fn put_read_state(
        &self,
        conversation_id: &str,
        record: &ReadStateRecord,
        expected_cid: Option<&str>,
    ) -> Result<String> {
        record.check()?;
        let cid = record_cid_json(record)?;
        let pinned = self.pinned_version(crate::records::nsid::READ_STATE, conversation_id);
        let next_ver = self.with(|m| {
            let next_ver = match (m.read_states.get(conversation_id), expected_cid) {
                (Some(_), None) => return Err(Error::Conflict),
                (None, Some(_)) => {
                    if pinned > 0 {
                        return Err(Error::Malformed("owner state version rollback"));
                    }
                    return Err(Error::Conflict);
                }
                (None, None) => {
                    if pinned > 0 {
                        return Err(Error::Malformed("owner state version rollback"));
                    }
                    1
                }
                (Some((_, cur_cid, cur_ver)), Some(exp)) => {
                    if *cur_ver < pinned {
                        return Err(Error::Malformed("owner state version rollback"));
                    }
                    if cur_cid != exp {
                        return Err(Error::Conflict);
                    }
                    cur_ver
                        .checked_add(1)
                        .ok_or_else(|| Error::Backend("cas version overflow".into()))?
                }
            };
            m.read_states.insert(
                conversation_id.to_owned(),
                (record.clone(), cid.clone(), next_ver),
            );
            Ok(next_ver)
        })?;
        self.observe_version(crate::records::nsid::READ_STATE, conversation_id, next_ver)?;
        Ok(cid)
    }

    async fn list_read_states_versioned(
        &self,
    ) -> Result<Vec<(String, ReadStateRecord, Option<String>, u64)>> {
        let rows = self.with(|m| {
            Ok(m.read_states
                .iter()
                .map(|(k, (rec, cid, ver))| (k.clone(), rec.clone(), Some(cid.clone()), *ver))
                .collect::<Vec<_>>())
        })?;
        let seen: BTreeMap<&str, u64> = rows
            .iter()
            .map(|(id, _, _, ver)| (id.as_str(), *ver))
            .collect();
        {
            let guard = self
                .version_floors
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for ((col, id), &pinned) in guard.iter() {
                if col == crate::records::nsid::READ_STATE
                    && pinned > 0
                    && seen.get(id.as_str()).is_none_or(|&v| v < pinned)
                {
                    return Err(Error::Malformed("owner state version rollback"));
                }
            }
        }
        for (id, _, _, ver) in &rows {
            self.observe_version(crate::records::nsid::READ_STATE, id, *ver)?;
        }
        Ok(rows)
    }

    async fn list_read_states(&self) -> Result<Vec<(String, ReadStateRecord, Option<String>)>> {
        Ok(self
            .list_read_states_versioned()
            .await?
            .into_iter()
            .map(|(k, rec, cid, _)| (k, rec, cid))
            .collect())
    }

    async fn get_circle_owner_state_versioned(
        &self,
        circle_id: &str,
    ) -> Result<Option<(CircleOwnerStateRecord, Option<String>, u64)>> {
        let row = self.with(|m| {
            Ok(m.circle_owner_states
                .get(circle_id)
                .map(|(rec, cid, ver)| (rec.clone(), Some(cid.clone()), *ver)))
        })?;
        match row {
            Some((rec, cid, ver)) => {
                self.observe_version(crate::records::nsid::CIRCLE_OWNER_STATE, circle_id, ver)?;
                Ok(Some((rec, cid, ver)))
            }
            None => {
                if self.pinned_version(crate::records::nsid::CIRCLE_OWNER_STATE, circle_id) > 0 {
                    return Err(Error::Malformed("owner state version rollback"));
                }
                Ok(None)
            }
        }
    }

    async fn get_circle_owner_state(
        &self,
        circle_id: &str,
    ) -> Result<Option<(CircleOwnerStateRecord, Option<String>)>> {
        Ok(self
            .get_circle_owner_state_versioned(circle_id)
            .await?
            .map(|(rec, cid, _)| (rec, cid)))
    }

    async fn put_circle_owner_state(
        &self,
        circle_id: &str,
        record: &CircleOwnerStateRecord,
        expected_cid: Option<&str>,
    ) -> Result<String> {
        record.check()?;
        let cid = record_cid_json(record)?;
        let pinned = self.pinned_version(crate::records::nsid::CIRCLE_OWNER_STATE, circle_id);
        let next_ver = self.with(|m| {
            let next_ver = match (m.circle_owner_states.get(circle_id), expected_cid) {
                (Some(_), None) => return Err(Error::Conflict),
                (None, Some(_)) => {
                    if pinned > 0 {
                        return Err(Error::Malformed("owner state version rollback"));
                    }
                    return Err(Error::Conflict);
                }
                (None, None) => {
                    if pinned > 0 {
                        return Err(Error::Malformed("owner state version rollback"));
                    }
                    1
                }
                (Some((_, cur_cid, cur_ver)), Some(exp)) => {
                    if *cur_ver < pinned {
                        return Err(Error::Malformed("owner state version rollback"));
                    }
                    if cur_cid != exp {
                        return Err(Error::Conflict);
                    }
                    cur_ver
                        .checked_add(1)
                        .ok_or_else(|| Error::Backend("cas version overflow".into()))?
                }
            };
            m.circle_owner_states.insert(
                circle_id.to_owned(),
                (record.clone(), cid.clone(), next_ver),
            );
            Ok(next_ver)
        })?;
        self.observe_version(
            crate::records::nsid::CIRCLE_OWNER_STATE,
            circle_id,
            next_ver,
        )?;
        Ok(cid)
    }

    async fn list_circle_owner_states_versioned(
        &self,
    ) -> Result<Vec<(String, CircleOwnerStateRecord, Option<String>, u64)>> {
        let rows = self.with(|m| {
            Ok(m.circle_owner_states
                .iter()
                .map(|(k, (rec, cid, ver))| (k.clone(), rec.clone(), Some(cid.clone()), *ver))
                .collect::<Vec<_>>())
        })?;
        let seen: BTreeMap<&str, u64> = rows
            .iter()
            .map(|(id, _, _, ver)| (id.as_str(), *ver))
            .collect();
        {
            let guard = self
                .version_floors
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for ((col, id), &pinned) in guard.iter() {
                if col == crate::records::nsid::CIRCLE_OWNER_STATE
                    && pinned > 0
                    && seen.get(id.as_str()).is_none_or(|&v| v < pinned)
                {
                    return Err(Error::Malformed("owner state version rollback"));
                }
            }
        }
        for (id, _, _, ver) in &rows {
            self.observe_version(crate::records::nsid::CIRCLE_OWNER_STATE, id, *ver)?;
        }
        Ok(rows)
    }

    async fn list_circle_owner_states(
        &self,
    ) -> Result<Vec<(String, CircleOwnerStateRecord, Option<String>)>> {
        Ok(self
            .list_circle_owner_states_versioned()
            .await?
            .into_iter()
            .map(|(k, rec, cid, _)| (k, rec, cid))
            .collect())
    }

    fn seed_owner_state_version_floors(&self, floors: &BTreeMap<(String, String), u64>) {
        let mut guard = self
            .version_floors
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for ((col, id), &ver) in floors {
            if crate::store::validate_owner_state_version_floor(col, id, ver).is_err() {
                continue;
            }
            let key = (col.clone(), id.clone());
            match guard.get(&key) {
                Some(&cur) if cur >= ver => {}
                Some(_) => {
                    guard.insert(key, ver);
                }
                None if guard.len() < crate::store::MAX_WRITER_FLOOR_ENTRIES => {
                    guard.insert(key, ver);
                }
                None => {}
            }
        }
    }

    fn replace_owner_state_version_floors(&self, floors: &BTreeMap<(String, String), u64>) {
        let mut next = BTreeMap::new();
        for ((col, id), &ver) in floors {
            if crate::store::validate_owner_state_version_floor(col, id, ver).is_err() {
                continue;
            }
            let key = (col.clone(), id.clone());
            if next.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES && !next.contains_key(&key) {
                continue;
            }
            next.insert(key, ver);
        }
        *self
            .version_floors
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = next;
    }

    fn export_owner_state_version_floors(&self) -> BTreeMap<(String, String), u64> {
        self.version_floors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    async fn purge_mailbox(&self) -> Result<()> {
        self.backend.lock().purge(&self.did);
        self.version_floors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        Ok(())
    }
}

fn record_cid_json<T: serde::Serialize>(record: &T) -> Result<String> {
    let json = serde_json::to_vec(record).map_err(|e| Error::Backend(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(&json);
    Ok(format!("bafyreimem{}", hex::encode(&h.finalize()[..16])))
}

#[cfg(test)]
mod tests;

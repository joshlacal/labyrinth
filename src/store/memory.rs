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
    AttachmentManifest, Device, Epoch, EpochMember, MailboxKeysRecord, OtcSession, OwnerBatch,
    VirtualDevice,
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
    /// The DS that sequences every thread here: its DID and optional Ed25519 seed ([CB-38]).
    sequencer: Option<(String, Option<[u8; 32]>)>,
    /// Per-thread `I13` ES256 receipt verification keys (`Gate 1`).
    receipt_keys: HashMap<String, SequencerReceiptKey>,
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

    /// Configures the sequencer DS DID and optional Ed25519 redaction signing seed.
    pub fn set_sequencer(&self, did: &str, signing_seed: Option<[u8; 32]>) {
        self.lock().sequencer = Some((did.to_owned(), signing_seed));
    }

    /// Registers the ES256 receipt verification key `{did}#mls-receipt-1` for `thread_id` (`Gate 1`).
    pub fn set_sequencer_receipt_key(&self, thread_id: &str, key: SequencerReceiptKey) {
        self.lock().receipt_keys.insert(thread_id.to_owned(), key);
    }

    pub(super) fn receipt_key(&self, thread_id: &str) -> Option<SequencerReceiptKey> {
        self.lock().receipt_keys.get(thread_id).cloned()
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

    fn sequencer_key(&self) -> Option<super::SequencerKey> {
        let s = self.lock();
        let (did, seed) = s.sequencer.as_ref()?;
        let key = ed25519_dalek::SigningKey::from_bytes(seed.as_ref()?)
            .verifying_key()
            .to_bytes();
        Some(super::SequencerKey {
            did: did.clone(),
            key,
        })
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
}

impl MemoryMailbox {
    fn with<T>(&self, f: impl FnOnce(&mut Mailbox) -> Result<T>) -> Result<T> {
        let mut s = self.backend.lock();
        f(s.mailboxes.entry(self.did.clone()).or_default())
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
        let s = self.backend.lock();
        let now = s.server_now;
        Ok(s.mailboxes
            .get(&self.did)
            .and_then(|m| m.vdevices.get(&hex::encode(vdevice_id)))
            .filter(|vd| !vdevice_expired_at(vd, now))
            .cloned())
    }

    async fn list_virtual_devices(&self) -> Result<Vec<VirtualDevice>> {
        let s = self.backend.lock();
        let now = s.server_now;
        Ok(s.mailboxes
            .get(&self.did)
            .map(|m| {
                m.vdevices
                    .values()
                    .filter(|vd| !vdevice_expired_at(vd, now))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
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

    async fn purge_mailbox(&self) -> Result<()> {
        self.backend.lock().purge(&self.did);
        Ok(())
    }
}

pub(super) fn vdevice_expired_at(vd: &VirtualDevice, now_ms: u64) -> bool {
    let Ok((rec, _)) = vd.to_bundle() else {
        return false;
    };
    let Ok(created_ms) = crate::records::ms_from_datetime(&vd.created_at) else {
        return false;
    };
    let Ok(last_used_ms) = vd
        .last_used_at
        .as_deref()
        .map(crate::records::ms_from_datetime)
        .transpose()
    else {
        return false;
    };
    crate::client::recovery::recovery_expiry(rec.mechanism, created_ms, last_used_ms)
        .is_some_and(|exp| now_ms >= exp)
}

#[cfg(test)]
mod tests;

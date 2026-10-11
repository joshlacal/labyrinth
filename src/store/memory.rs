//! In-memory backend for tests and examples.
//!
//! One [`MemoryBackend`] plays every server at once: each DID's personal
//! mailbox space and public repo, every conversation space, and the MLS
//! device view the [`super::MailboxDirectory`] reports. Handles bound to a DID
//! ([`MemoryBackend::mailbox`], [`MemoryBackend::threads`]) can only write
//! that DID's repos, as Spaces enforce.
//!
//! Conversation spaces have **no read ACL by default**: any handle can read
//! any thread, as a leaky or malicious backend would. Confidentiality must
//! come from the cryptography. [`MemoryBackend::revoke_thread_access`]
//! models a Space removing a member ([CB-22]).
//!
//! By default nothing carries server order, as on a Space.
//! [`MemoryBackend::enable_server_order`] switches to mls-ds behaviour:
//! every MEK, batch and owner batch is stamped with a [`ServerOrder`] from
//! a test-controlled server clock and the thread's chat sequence, and
//! [`MemoryBackend::add_leaf`] / [`MemoryBackend::remove_leaf`] model the
//! per-conversation device view ([CB-27]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use super::{ChatDeviceKey, MailboxStore, MemberDeviceKey, ServerOrder, Stored, TimeRange};
use crate::epoch::space_epoch_id;
use crate::records::{Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice};
use crate::sign::XVerifyingKey;
use crate::{Error, Result};

mod attachments;
mod directory;
mod heads;
mod lifecycle;
mod orf;
mod threads;

pub use directory::MemoryDirectory;
pub use heads::{MemoryDsDirectory, MemoryDsPublisher, MemoryPdsPublisher};
pub use orf::MemoryOrf;
pub use threads::MemoryThreads;

#[derive(Default)]
struct Mailbox {
    devices: BTreeMap<String, Device>,
    epochs: BTreeMap<String, Epoch>,
    members: BTreeMap<String, EpochMember>,
    vdevices: BTreeMap<String, VirtualDevice>,
    owner_batches: BTreeMap<String, (OwnerBatch, Option<ServerOrder>)>,
    next_seq: u64,
}

#[derive(Default)]
struct Repo {
    meks: BTreeMap<String, (crate::records::MekDistribution, Option<ServerOrder>)>,
    batches: BTreeMap<String, (crate::records::Batch, Option<ServerOrder>)>,
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
    public_keys: HashMap<String, MailboxKeysRecord>,
    /// Every published `mailboxKeys`, by DID and epoch number ([CB-29]).
    public_history: HashMap<String, BTreeMap<u64, MailboxKeysRecord>>,
    threads: HashMap<String, ThreadSpace>,
    chat_devices: HashMap<String, ChatDevices>,
    tid: u64,
    /// Stamp writes with [`ServerOrder`] (mls-ds mode).
    stamping: bool,
    /// The server clock for stamps (ms), set by tests.
    server_now: u64,
    /// mls-ds `labyrinth.epoch_heads`, by DID and epoch number.
    ds_heads: HashMap<String, BTreeMap<u64, crate::mailbox::EpochPublic>>,
    /// ORF server states by (owner DID, device key).
    orf: HashMap<(String, [u8; 32]), crate::orf::OrfServerState>,
    /// Attachment references and chat blobs ([CB-33]).
    attach: attachments::AttachState,
    /// The DS that sequences every thread here: its DID and, when it
    /// signs its own redactions, its Ed25519 seed ([CB-38]).
    sequencer: Option<(String, Option<[u8; 32]>)>,
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
        self.public_keys.insert(did.to_owned(), record.clone());
        Ok(())
    }

    /// The server stamp for a write into `thread_id` (`None` unless
    /// stamping).
    fn stamp_thread(&mut self, thread_id: &str) -> Option<ServerOrder> {
        if !self.stamping {
            return None;
        }
        let now = self.server_now;
        let t = self.threads.entry(thread_id.to_owned()).or_default();
        t.next_seq += 1;
        Some(ServerOrder {
            labyrinth_seq: t.next_seq,
            chat_seq: Some(t.chat_seq),
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

    /// The mls-ds epoch-head directory ([CB-28], [CB-29]): heads recorded
    /// by [`ds_publisher`](Self::ds_publisher), plus the MLS device view.
    pub fn ds_directory(&self) -> MemoryDsDirectory {
        MemoryDsDirectory::new(self.clone())
    }

    /// Publishes `did`'s heads to the mls-ds directory, with its
    /// server-side checks (`publishEpochHead`).
    pub fn ds_publisher(&self, did: &str) -> MemoryDsPublisher {
        MemoryDsPublisher::new(did, self.clone())
    }

    /// Publishes `did`'s public `mailboxKeys` records (what a Space
    /// mailbox does in [`MailboxStore::publish_mailbox_keys`]).
    pub fn pds_publisher(&self, did: &str) -> MemoryPdsPublisher {
        MemoryPdsPublisher::new(did, self.clone())
    }

    /// The ORF server, as `did` sees it.
    pub fn orf(&self, did: &str) -> MemoryOrf {
        MemoryOrf::new(did, self.clone())
    }

    /// From now on, stamp every MEK, batch and owner batch with a
    /// [`ServerOrder`] as mls-ds does ([CB-27]). Without this the backend
    /// behaves like a Space: no server order.
    pub fn enable_server_order(&self) {
        self.lock().stamping = true;
    }

    /// Sets the server clock that stamps writes and that
    /// [`remove_chat_device`](Self::remove_chat_device) times are read on.
    pub fn set_server_time(&self, ms: u64) {
        self.lock().server_now = ms;
    }

    /// Records one MLS chat entry in `thread_id`; returns its seq.
    pub fn append_chat_entry(&self, thread_id: &str) -> u64 {
        let mut s = self.lock();
        let t = s.threads.entry(thread_id.to_owned()).or_default();
        t.chat_seq += 1;
        t.chat_seq
    }

    /// An MLS commit adds a leaf for `did`'s device `key` to `thread_id`
    /// (one chat entry). Returns the commit's seq.
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

    /// An MLS commit removes `did`'s leaf `key` from `thread_id`. Returns
    /// the commit's seq.
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

    /// Removes a chat device from the current MLS view at `removed_at_ms`
    /// (it stays historical, valid for history before that time).
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

    /// Every thread is sequenced by DS `did`; with `signing_seed`, its
    /// account-deletion redactions are signed by that Ed25519 key and the
    /// directories report it ([`crate::store::MailboxDirectory::sequencer_key`]).
    /// Without a call, account deletion writes bare `{redactedAt}`
    /// redactions.
    pub fn set_sequencer(&self, did: &str, signing_seed: Option<[u8; 32]>) {
        self.lock().sequencer = Some((did.to_owned(), signing_seed));
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

impl MailboxStore for MemoryMailbox {
    fn owner(&self) -> &str {
        &self.did
    }

    fn create_device(&self, device: &Device) -> Result<()> {
        let key = hex::encode(&device.device_key_pubkey.0);
        self.with(|m| create(&mut m.devices, key, device))
    }

    fn set_device_revoked(&self, device_key: &XVerifyingKey, revoked_at: &str) -> Result<()> {
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

    fn get_device(&self, device_key: &XVerifyingKey) -> Result<Option<Device>> {
        self.with(|m| Ok(m.devices.get(&hex::encode(device_key.0)).cloned()))
    }

    fn list_devices(&self) -> Result<Vec<Device>> {
        self.with(|m| Ok(m.devices.values().cloned().collect()))
    }

    fn create_epoch(&self, epoch: &Epoch, members: &[EpochMember]) -> Result<String> {
        let id = space_epoch_id(epoch.seq());
        self.with(|m| {
            if m.epochs.contains_key(&id)
                || members
                    .iter()
                    .any(|x| x.epoch_number != epoch.seq() || m.members.contains_key(&x.rkey()))
            {
                return Err(Error::Conflict);
            }
            m.epochs.insert(id.clone(), epoch.clone());
            for x in members {
                m.members.insert(x.rkey(), x.clone());
            }
            Ok(id)
        })
    }

    fn get_epoch(&self, seq: u64) -> Result<Option<Stored<Epoch>>> {
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

    fn list_epochs(&self) -> Result<Vec<Stored<Epoch>>> {
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

    fn create_epoch_member(&self, member: &EpochMember) -> Result<()> {
        self.with(|m| {
            if !m.epochs.contains_key(&space_epoch_id(member.epoch_number)) {
                return Err(Error::NotFound("epoch"));
            }
            create(&mut m.members, member.rkey(), member)
        })
    }

    fn list_epoch_members(&self, seq: u64) -> Result<Vec<EpochMember>> {
        let prefix = format!("{seq:012}-");
        self.with(|m| {
            Ok(m.members
                .range(prefix.clone()..)
                .take_while(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v.clone())
                .collect())
        })
    }

    fn create_virtual_device(&self, vdevice: &VirtualDevice) -> Result<()> {
        self.with(|m| create(&mut m.vdevices, vdevice.rkey(), vdevice))
    }

    fn get_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<Option<VirtualDevice>> {
        self.with(|m| Ok(m.vdevices.get(&hex::encode(vdevice_id)).cloned()))
    }

    fn list_virtual_devices(&self) -> Result<Vec<VirtualDevice>> {
        self.with(|m| Ok(m.vdevices.values().cloned().collect()))
    }

    fn append_owner_batch(&self, batch: &OwnerBatch) -> Result<String> {
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

    fn list_owner_batches(
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

    fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> Result<()> {
        self.backend.lock().publish_pds(&self.did, record)
    }

    fn list_owner_threads(&self) -> Result<Vec<String>> {
        Ok(self.backend.lock().owner_threads(&self.did))
    }

    fn touch_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        self.backend.lock().touch_vdevice(&self.did, vdevice_id)
    }

    fn delete_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        self.backend.lock().delete_vdevice(&self.did, vdevice_id)
    }

    fn purge_mailbox(&self) -> Result<()> {
        self.backend.lock().purge(&self.did);
        Ok(())
    }
}

#[cfg(test)]
mod tests;

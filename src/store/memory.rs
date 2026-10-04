//! In-memory backend for tests and examples.
//!
//! One [`MemoryBackend`] plays every server at once: each DID's personal
//! mailbox space and public repo, every conversation space, and the MLS
//! device view the [`MailboxDirectory`] reports. Handles bound to a DID
//! ([`MemoryBackend::mailbox`], [`MemoryBackend::threads`]) can only write
//! that DID's repos, as Spaces enforce.
//!
//! Conversation spaces have **no read ACL by default**: any handle can read
//! any thread, as a leaky or malicious backend would. Confidentiality must
//! come from the cryptography. [`MemoryBackend::revoke_thread_access`]
//! models a Space removing a member ([CB-22]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use super::{MailboxDirectory, MailboxStore, Stored, ThreadStore, TimeRange};
use crate::epoch::space_epoch_id;
use crate::mailbox::EpochPublic;
use crate::records::{
    Batch, Device, Epoch, EpochMember, MailboxKeysRecord, MekDistribution, OwnerBatch,
    VirtualDevice,
};
use crate::sign::XVerifyingKey;
use crate::{Error, Result};

#[derive(Default)]
struct Mailbox {
    devices: BTreeMap<String, Device>,
    epochs: BTreeMap<String, Epoch>,
    members: BTreeMap<String, EpochMember>,
    vdevices: BTreeMap<String, VirtualDevice>,
    owner_batches: BTreeMap<String, OwnerBatch>,
}

#[derive(Default)]
struct Repo {
    meks: BTreeMap<String, MekDistribution>,
    batches: BTreeMap<String, Batch>,
}

#[derive(Default)]
struct ThreadSpace {
    repos: BTreeMap<String, Repo>,
    no_read: BTreeSet<String>,
}

#[derive(Default)]
struct ChatDevices {
    current: Vec<[u8; 32]>,
    removed: Vec<[u8; 32]>,
}

#[derive(Default)]
struct State {
    mailboxes: HashMap<String, Mailbox>,
    public_keys: HashMap<String, MailboxKeysRecord>,
    threads: HashMap<String, ThreadSpace>,
    chat_devices: HashMap<String, ChatDevices>,
    tid: u64,
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
        MemoryThreads {
            did: did.to_owned(),
            backend: self.clone(),
        }
    }

    /// Public `mailboxKeys` records plus the MLS device view.
    pub fn directory(&self) -> MemoryDirectory {
        MemoryDirectory {
            backend: self.clone(),
        }
    }

    /// Records a chat device of `did` in the MLS view.
    pub fn register_chat_device(&self, did: &str, transport_pub: [u8; 32]) {
        let mut s = self.lock();
        let d = s.chat_devices.entry(did.to_owned()).or_default();
        if !d.current.contains(&transport_pub) {
            d.current.push(transport_pub);
        }
    }

    /// Removes a chat device from the current MLS view (it stays historical).
    pub fn remove_chat_device(&self, did: &str, transport_pub: [u8; 32]) {
        let mut s = self.lock();
        let d = s.chat_devices.entry(did.to_owned()).or_default();
        d.current.retain(|k| *k != transport_pub);
        if !d.removed.contains(&transport_pub) {
            d.removed.push(transport_pub);
        }
    }

    /// The conversation space stops serving `did` (Space member removal).
    pub fn revoke_thread_access(&self, thread_id: &str, did: &str) {
        let mut s = self.lock();
        let t = s.threads.entry(thread_id.to_owned()).or_default();
        t.no_read.insert(did.to_owned());
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
        let m = s.mailboxes.entry(self.did.clone()).or_default();
        create(&mut m.owner_batches, tid.clone(), batch)?;
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
                .filter(|(_, b)| {
                    b.thread_id == thread_id && b.items.iter().any(|i| range.contains(i.timestamp))
                })
                .map(|(k, b)| Stored {
                    author: self.did.clone(),
                    rkey: k.clone(),
                    value: b.clone(),
                })
                .collect())
        })
    }

    fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> Result<()> {
        let mut s = self.backend.lock();
        s.public_keys.insert(self.did.clone(), record.clone());
        Ok(())
    }
}

/// [`ThreadStore`] handle bound to one DID.
pub struct MemoryThreads {
    did: String,
    backend: MemoryBackend,
}

impl MemoryThreads {
    fn space<T>(
        &self,
        thread_id: &str,
        f: impl FnOnce(&mut ThreadSpace) -> Result<T>,
    ) -> Result<T> {
        let mut s = self.backend.lock();
        let t = s.threads.entry(thread_id.to_owned()).or_default();
        if t.no_read.contains(&self.did) {
            return Err(Error::Forbidden);
        }
        f(t)
    }
}

impl ThreadStore for MemoryThreads {
    fn author(&self) -> &str {
        &self.did
    }

    fn create_mek(&self, mek: &MekDistribution) -> Result<()> {
        self.space(&mek.thread_id, |t| {
            let repo = t.repos.entry(self.did.clone()).or_default();
            create(&mut repo.meks, mek.rkey(), mek)
        })
    }

    fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> Result<Vec<Stored<MekDistribution>>> {
        let rkey = hex::encode(mek_id);
        self.space(thread_id, |t| {
            Ok(t.repos
                .iter()
                .filter_map(|(did, r)| {
                    r.meks.get(&rkey).map(|m| Stored {
                        author: did.clone(),
                        rkey: rkey.clone(),
                        value: m.clone(),
                    })
                })
                .collect())
        })
    }

    fn append_batch(&self, batch: &Batch) -> Result<String> {
        let mut s = self.backend.lock();
        let tid = s.next_tid();
        let t = s.threads.entry(batch.thread_id.clone()).or_default();
        if t.no_read.contains(&self.did) {
            return Err(Error::Forbidden);
        }
        let repo = t.repos.entry(self.did.clone()).or_default();
        create(&mut repo.batches, tid.clone(), batch)?;
        Ok(tid)
    }

    fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<Stored<Batch>>> {
        self.space(thread_id, |t| {
            Ok(t.repos
                .iter()
                .filter(|(did, _)| sender.is_none_or(|s| s == did.as_str()))
                .flat_map(|(did, r)| {
                    r.batches
                        .iter()
                        .filter(|(_, b)| b.items.iter().any(|i| range.contains(i.timestamp)))
                        .map(|(k, b)| Stored {
                            author: did.clone(),
                            rkey: k.clone(),
                            value: b.clone(),
                        })
                })
                .collect())
        })
    }
}

/// [`MailboxDirectory`] over the backend's public repos and MLS view.
pub struct MemoryDirectory {
    backend: MemoryBackend,
}

impl MailboxDirectory for MemoryDirectory {
    fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        let s = self.backend.lock();
        s.public_keys.get(did).map(|r| r.to_public()).transpose()
    }

    fn device_transport_keys(&self, did: &str) -> Result<Vec<[u8; 32]>> {
        let s = self.backend.lock();
        Ok(s.chat_devices
            .get(did)
            .map(|d| d.current.clone())
            .unwrap_or_default())
    }

    fn historical_transport_keys(&self, did: &str) -> Result<Vec<[u8; 32]>> {
        let s = self.backend.lock();
        Ok(s.chat_devices
            .get(did)
            .map(|d| [d.current.as_slice(), &d.removed].concat())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests;

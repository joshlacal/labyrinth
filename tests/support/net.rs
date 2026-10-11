//! Shared client fixtures for the gap-closing tests: a test clock, chat
//! signers, memory backends, sibling enrollment, and a mailbox wrapper
//! that can tamper with member rows or fail epoch creates.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, Labyrinth};
use labyrinth::records::{
    Bytes, Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryMailbox};
use labyrinth::store::{KeyPublisher, MailboxStore, Stored, TimeRange};

pub const A: &str = "did:plc:alice";
pub const B: &str = "did:plc:bob";
pub const T: &str = "conv-gaps";

#[derive(Clone, Default)]
pub struct TestClock(pub Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        1_791_000_000_000 + self.0.load(Ordering::Relaxed)
    }
}
impl TestClock {
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::Relaxed);
    }
}

pub fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}
pub fn tpub(seed: u8) -> [u8; 32] {
    signer(seed).0.verifying_key().to_bytes()
}

pub fn backends_with(
    net: &MemoryBackend,
    clock: &TestClock,
    did: &str,
    mailbox: Box<dyn MailboxStore + Send>,
    publishers: Vec<Box<dyn KeyPublisher + Send>>,
) -> Backends {
    Backends {
        mailbox,
        threads: Box::new(net.threads(did)),
        directory: Box::new(net.directory()),
        orf: Box::new(net.orf(did)),
        publishers,
        clock: Box::new(clock.clone()),
    }
}

pub fn backends(net: &MemoryBackend, clock: &TestClock, did: &str) -> Backends {
    backends_with(net, clock, did, Box::new(net.mailbox(did)), vec![])
}

/// A fresh mailbox for `did` whose first device signs with chat key `seed`.
pub fn init(net: &MemoryBackend, clock: &TestClock, did: &str, seed: u8) -> Labyrinth {
    net.register_chat_device(did, tpub(seed));
    Labyrinth::initialize(did, Box::new(signer(seed)), backends(net, clock, did)).unwrap()
}

/// Enrolls a sibling of `existing` by one-time code, with chat key `seed`.
pub fn sibling_with(
    net: &MemoryBackend,
    clock: &TestClock,
    existing: &mut Labyrinth,
    seed: u8,
    mailbox: Box<dyn MailboxStore + Send>,
) -> Labyrinth {
    let did = existing.did().to_owned();
    let mut r = existing.otc_offer().unwrap();
    let typed = r.code().as_str().to_owned();
    let (init, hello) = Labyrinth::otc_start(&did, &typed).unwrap();
    let reply = existing.otc_respond(&mut r, &hello).unwrap();
    net.register_chat_device(&did, tpub(seed));
    let b = backends_with(net, clock, &did, mailbox, vec![]);
    Labyrinth::enroll_via_otc(
        &did,
        init,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(seed)),
        b,
    )
    .unwrap()
    .0
}

pub fn sibling(
    net: &MemoryBackend,
    clock: &TestClock,
    existing: &mut Labyrinth,
    seed: u8,
) -> Labyrinth {
    let mb = Box::new(net.mailbox(existing.did()));
    sibling_with(net, clock, existing, seed, mb)
}

/// A mailbox that, when told to, flips one bit of a chosen member's MAC
/// on every read (a store rewriting a row it served intact) and fails
/// every epoch create (an outage mid-revocation).
#[derive(Clone)]
pub struct Faulty {
    pub inner: Arc<MemoryMailbox>,
    pub tamper: Arc<std::sync::Mutex<Option<XVerifyingKey>>>,
    pub fail_epochs: Arc<AtomicBool>,
}

impl Faulty {
    pub fn new(m: MemoryMailbox) -> Self {
        Self {
            inner: Arc::new(m),
            tamper: Arc::default(),
            fail_epochs: Arc::default(),
        }
    }
}

impl MailboxStore for Faulty {
    fn owner(&self) -> &str {
        self.inner.owner()
    }
    fn create_device(&self, d: &Device) -> labyrinth::Result<()> {
        self.inner.create_device(d)
    }
    fn set_device_revoked(&self, k: &XVerifyingKey, at: &str) -> labyrinth::Result<()> {
        self.inner.set_device_revoked(k, at)
    }
    fn get_device(&self, k: &XVerifyingKey) -> labyrinth::Result<Option<Device>> {
        self.inner.get_device(k)
    }
    fn list_devices(&self) -> labyrinth::Result<Vec<Device>> {
        self.inner.list_devices()
    }
    fn create_epoch(&self, e: &Epoch, m: &[EpochMember]) -> labyrinth::Result<String> {
        if self.fail_epochs.load(Ordering::Relaxed) {
            return Err(Error::Backend("injected outage".into()));
        }
        self.inner.create_epoch(e, m)
    }
    fn get_epoch(&self, s: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        self.inner.get_epoch(s)
    }
    fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        self.inner.list_epochs()
    }
    fn create_epoch_member(&self, m: &EpochMember) -> labyrinth::Result<()> {
        self.inner.create_epoch_member(m)
    }
    fn list_epoch_members(&self, s: u64) -> labyrinth::Result<Vec<EpochMember>> {
        let mut v = self.inner.list_epoch_members(s)?;
        if let Some(k) = *self.tamper.lock().unwrap() {
            for m in v.iter_mut().filter(|m| m.device_key_pubkey.0 == k.0) {
                let mut mac = m.device_mac.0.clone();
                mac[0] ^= 1;
                m.device_mac = Bytes(mac);
            }
        }
        Ok(v)
    }
    fn create_virtual_device(&self, v: &VirtualDevice) -> labyrinth::Result<()> {
        self.inner.create_virtual_device(v)
    }
    fn get_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<Option<VirtualDevice>> {
        self.inner.get_virtual_device(id)
    }
    fn list_virtual_devices(&self) -> labyrinth::Result<Vec<VirtualDevice>> {
        self.inner.list_virtual_devices()
    }
    fn append_owner_batch(&self, b: &OwnerBatch) -> labyrinth::Result<String> {
        self.inner.append_owner_batch(b)
    }
    fn list_owner_batches(
        &self,
        t: &str,
        r: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.inner.list_owner_batches(t, r)
    }
    fn publish_mailbox_keys(&self, r: &MailboxKeysRecord) -> labyrinth::Result<()> {
        self.inner.publish_mailbox_keys(r)
    }
}

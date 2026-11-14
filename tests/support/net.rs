//! Shared client fixtures for the gap-closing tests: a test clock, chat
//! signers, memory backends, sibling enrollment, and a mailbox wrapper
//! that can tamper with member rows or fail epoch creates.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, Clock, Labyrinth};
use labyrinth::records::{
    Bytes, Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryMailbox};
use labyrinth::store::{AtomicEnrollBundle, KeyPublisher, MailboxStore, Stored, TimeRange};

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
    mailbox: Box<dyn MailboxStore>,
    publishers: Vec<Box<dyn KeyPublisher>>,
) -> Backends {
    Backends {
        mailbox,
        threads: Box::new(net.threads(did)),
        directory: Box::new(net.directory()),
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
    block_on(Labyrinth::initialize(
        did,
        Box::new(signer(seed)),
        backends(net, clock, did),
    ))
    .unwrap()
}

/// Enrolls a sibling of `existing` by one-time code, with chat key `seed`.
pub fn sibling_with(
    net: &MemoryBackend,
    clock: &TestClock,
    existing: &mut Labyrinth,
    seed: u8,
    mailbox: Box<dyn MailboxStore>,
) -> Labyrinth {
    let did = existing.did().to_owned();
    let mut r = existing.otc_offer().unwrap();
    let typed = r.code().as_str().to_owned();
    let (init, hello) = Labyrinth::otc_start(&did, &typed).unwrap();
    let reply = block_on(existing.otc_respond(&mut r, &hello)).unwrap();
    net.register_chat_device(&did, tpub(seed));
    let b = backends_with(net, clock, &did, mailbox, vec![]);
    block_on(Labyrinth::enroll_via_otc(
        &did,
        init,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(seed)),
        b,
    ))
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
    pub omit: Arc<std::sync::Mutex<Option<XVerifyingKey>>>,
    pub omit_skip: Arc<AtomicU64>,
    pub fail_epochs: Arc<AtomicBool>,
}

impl Faulty {
    pub fn new(m: MemoryMailbox) -> Self {
        Self {
            inner: Arc::new(m),
            tamper: Arc::default(),
            omit: Arc::default(),
            omit_skip: Arc::default(),
            fail_epochs: Arc::default(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for Faulty {
    fn owner(&self) -> &str {
        self.inner.owner()
    }
    async fn create_device(&self, d: &Device) -> labyrinth::Result<()> {
        self.inner.create_device(d).await
    }
    async fn set_device_revoked(&self, k: &XVerifyingKey, at: &str) -> labyrinth::Result<()> {
        self.inner.set_device_revoked(k, at).await
    }
    async fn set_device_revocation(
        &self,
        k: &XVerifyingKey,
        at: &str,
        rev: &labyrinth::records::DeviceRevocationDef,
    ) -> labyrinth::Result<()> {
        self.inner.set_device_revocation(k, at, rev).await
    }
    async fn get_device(&self, k: &XVerifyingKey) -> labyrinth::Result<Option<Device>> {
        self.inner.get_device(k).await
    }
    async fn list_devices(&self) -> labyrinth::Result<Vec<Device>> {
        self.inner.list_devices().await
    }
    async fn create_epoch(&self, e: &Epoch, m: &[EpochMember]) -> labyrinth::Result<String> {
        if self.fail_epochs.load(Ordering::Relaxed) {
            return Err(Error::Backend("injected outage".into()));
        }
        self.inner.create_epoch(e, m).await
    }
    async fn atomic_enroll(&self, bundle: &AtomicEnrollBundle) -> labyrinth::Result<String> {
        if self.fail_epochs.load(Ordering::Relaxed) {
            return Err(Error::Backend("injected outage".into()));
        }
        self.inner.atomic_enroll(bundle).await
    }
    async fn get_epoch(&self, s: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        self.inner.get_epoch(s).await
    }
    async fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        self.inner.list_epochs().await
    }
    async fn create_epoch_member(&self, m: &EpochMember) -> labyrinth::Result<()> {
        self.inner.create_epoch_member(m).await
    }
    async fn list_epoch_members(&self, s: u64) -> labyrinth::Result<Vec<EpochMember>> {
        let mut v = self.inner.list_epoch_members(s).await?;
        if let Some(k) = *self.omit.lock().unwrap() {
            let skipped = loop {
                let cur = self.omit_skip.load(Ordering::SeqCst);
                let Some(next) = cur.checked_sub(1) else {
                    break false;
                };
                if self
                    .omit_skip
                    .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    break true;
                }
            };
            if !skipped {
                v.retain(|m| m.device_key_pubkey.0 != k.0);
            }
        }
        if let Some(k) = *self.tamper.lock().unwrap() {
            for m in v.iter_mut().filter(|m| m.device_key_pubkey.0 == k.0) {
                let mut mac = m.device_mac.0.clone();
                mac[0] ^= 1;
                m.device_mac = Bytes(mac);
            }
        }
        Ok(v)
    }
    async fn create_virtual_device(&self, v: &VirtualDevice) -> labyrinth::Result<()> {
        self.inner.create_virtual_device(v).await
    }
    async fn get_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<Option<VirtualDevice>> {
        self.inner.get_virtual_device(id).await
    }
    async fn list_virtual_devices(&self) -> labyrinth::Result<Vec<VirtualDevice>> {
        self.inner.list_virtual_devices().await
    }
    async fn list_virtual_device_records(
        &self,
    ) -> labyrinth::Result<Vec<labyrinth::Result<VirtualDevice>>> {
        self.inner.list_virtual_device_records().await
    }
    async fn touch_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<()> {
        self.inner.touch_virtual_device(id).await
    }
    async fn delete_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<()> {
        self.inner.delete_virtual_device(id).await
    }
    async fn append_owner_batch(&self, b: &OwnerBatch) -> labyrinth::Result<String> {
        self.inner.append_owner_batch(b).await
    }
    async fn list_owner_batches(
        &self,
        t: &str,
        r: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.inner.list_owner_batches(t, r).await
    }
    async fn publish_mailbox_keys(&self, r: &MailboxKeysRecord) -> labyrinth::Result<()> {
        self.inner.publish_mailbox_keys(r).await
    }
    async fn delete_squatted_epoch(&self, seq: u64) -> labyrinth::Result<()> {
        self.inner.delete_squatted_epoch(seq).await
    }
    async fn get_read_state(
        &self,
        conversation_id: &str,
    ) -> labyrinth::Result<Option<(labyrinth::records::ReadStateRecord, Option<String>)>> {
        self.inner.get_read_state(conversation_id).await
    }
    async fn put_read_state(
        &self,
        conversation_id: &str,
        record: &labyrinth::records::ReadStateRecord,
        expected_cid: Option<&str>,
    ) -> labyrinth::Result<String> {
        self.inner
            .put_read_state(conversation_id, record, expected_cid)
            .await
    }
    async fn list_read_states(
        &self,
    ) -> labyrinth::Result<Vec<(String, labyrinth::records::ReadStateRecord, Option<String>)>> {
        self.inner.list_read_states().await
    }
    async fn get_circle_owner_state(
        &self,
        circle_id: &str,
    ) -> labyrinth::Result<Option<(labyrinth::records::CircleOwnerStateRecord, Option<String>)>>
    {
        self.inner.get_circle_owner_state(circle_id).await
    }
    async fn put_circle_owner_state(
        &self,
        circle_id: &str,
        record: &labyrinth::records::CircleOwnerStateRecord,
        expected_cid: Option<&str>,
    ) -> labyrinth::Result<String> {
        self.inner
            .put_circle_owner_state(circle_id, record, expected_cid)
            .await
    }
    async fn list_circle_owner_states(
        &self,
    ) -> labyrinth::Result<
        Vec<(
            String,
            labyrinth::records::CircleOwnerStateRecord,
            Option<String>,
        )>,
    > {
        self.inner.list_circle_owner_states().await
    }
}

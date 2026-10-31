//! Initialization never strands a mailbox: once epoch 0 exists, a failed
//! primary or secondary `mailboxKeys` publish keeps the client (and with it
//! the only copy of the genesis keys) and can be retried cleanly.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, Clock, Labyrinth};
use labyrinth::records::{
    Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryMailbox};
use labyrinth::store::{
    AtomicEnrollBundle, KeyPublisher, MailboxDirectory, MailboxStore, Stored, TimeRange,
};
use labyrinth::virtual_device::Mechanism;

const ALICE: &str = "did:plc:alice";

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        1_791_000_000_000 + self.0.fetch_add(1, Ordering::Relaxed)
    }
}

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

/// A switch shared between a test and a store wrapper.
#[derive(Clone, Default)]
struct Down(Arc<AtomicBool>);
impl Down {
    fn set(&self, v: bool) {
        self.0.store(v, Ordering::Relaxed)
    }
    fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

struct FlakyMailboxPublish {
    inner: MemoryMailbox,
    down: Down,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for FlakyMailboxPublish {
    fn owner(&self) -> &str {
        self.inner.owner()
    }
    async fn create_device(&self, d: &Device) -> labyrinth::Result<()> {
        self.inner.create_device(d).await
    }
    async fn set_device_revoked(&self, k: &XVerifyingKey, at: &str) -> labyrinth::Result<()> {
        self.inner.set_device_revoked(k, at).await
    }
    async fn get_device(&self, k: &XVerifyingKey) -> labyrinth::Result<Option<Device>> {
        self.inner.get_device(k).await
    }
    async fn list_devices(&self) -> labyrinth::Result<Vec<Device>> {
        self.inner.list_devices().await
    }
    async fn create_epoch(&self, e: &Epoch, m: &[EpochMember]) -> labyrinth::Result<String> {
        self.inner.create_epoch(e, m).await
    }
    async fn atomic_enroll(&self, bundle: &AtomicEnrollBundle) -> labyrinth::Result<String> {
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
        self.inner.list_epoch_members(s).await
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
        if self.down.get() {
            return Err(Error::Backend("primary mailboxKeys publish down".into()));
        }
        self.inner.publish_mailbox_keys(r).await
    }
}

struct FlakyPublisher {
    inner: Box<dyn KeyPublisher>,
    down: Down,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyPublisher for FlakyPublisher {
    async fn publish(&self, record: &MailboxKeysRecord) -> labyrinth::Result<()> {
        if self.down.get() {
            return Err(Error::Backend("publisher down".into()));
        }
        self.inner.publish(record).await
    }
}

fn backends(net: &MemoryBackend, primary_down: &Down, pub_down: &Down) -> Backends {
    Backends {
        mailbox: Box::new(FlakyMailboxPublish {
            inner: net.mailbox(ALICE),
            down: primary_down.clone(),
        }),
        threads: Box::new(net.threads(ALICE)),
        directory: Box::new(net.directory()),
        publishers: vec![Box::new(FlakyPublisher {
            inner: Box::new(net.ds_publisher(ALICE)),
            down: pub_down.clone(),
        })],
        clock: Box::new(TestClock::default()),
    }
}

#[test]
fn primary_publish_failure_after_epoch_zero_keeps_the_client() {
    let net = MemoryBackend::new();
    net.register_chat_device(ALICE, signer(1).0.verifying_key().to_bytes());
    let (primary_down, pub_down) = (Down::default(), Down::default());
    primary_down.set(true);
    let (mut lab, unfinished) = block_on(Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(1)),
        backends(&net, &primary_down, &pub_down),
    ))
    .unwrap();
    assert!(matches!(unfinished, Some(Error::Backend(_))));
    assert!(block_on(net.directory().latest(ALICE)).unwrap().is_none());

    // The retry publishes both primary and secondary directories; repeating is idempotent.
    primary_down.set(false);
    block_on(lab.finish_initialize()).unwrap();
    block_on(lab.finish_initialize()).unwrap();
    assert_eq!(
        block_on(net.directory().latest(ALICE))
            .unwrap()
            .unwrap()
            .seq,
        0
    );
    assert_eq!(
        block_on(net.ds_directory().latest(ALICE))
            .unwrap()
            .unwrap()
            .seq,
        0
    );
    block_on(lab.create_recovery_code(Mechanism::Code)).unwrap();
}

#[test]
fn publish_failure_after_epoch_zero_keeps_the_client() {
    let net = MemoryBackend::new();
    net.register_chat_device(ALICE, signer(1).0.verifying_key().to_bytes());
    let (primary_down, pub_down) = (Down::default(), Down::default());
    pub_down.set(true);
    let (mut lab, published) = block_on(Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(1)),
        backends(&net, &primary_down, &pub_down),
    ))
    .unwrap();
    assert!(matches!(published, Some(Error::Backend(_))));
    assert!(
        block_on(net.ds_directory().latest(ALICE))
            .unwrap()
            .is_none()
    );
    // The mailbox's own publish still went through.
    assert_eq!(
        block_on(net.directory().latest(ALICE))
            .unwrap()
            .unwrap()
            .seq,
        0
    );

    // The client is whole: retry the publish and keep going.
    pub_down.set(false);
    block_on(lab.finish_initialize()).unwrap();
    assert_eq!(
        block_on(net.ds_directory().latest(ALICE))
            .unwrap()
            .unwrap()
            .seq,
        0
    );
    block_on(lab.create_recovery_code(Mechanism::Code)).unwrap();
}

#[test]
fn rotation_before_the_retry_still_publishes_epoch_zero_first() {
    let net = MemoryBackend::new();
    net.register_chat_device(ALICE, signer(1).0.verifying_key().to_bytes());
    net.register_chat_device(ALICE, signer(2).0.verifying_key().to_bytes());
    let (primary_down, pub_down) = (Down::default(), Down::default());
    pub_down.set(true);
    let (mut phone, unfinished) = block_on(Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(1)),
        backends(&net, &primary_down, &pub_down),
    ))
    .unwrap();
    assert!(unfinished.is_some());
    block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    // Rotate (revoke the recovery bundle) while the publisher is down.
    let vkey = block_on(phone.list_recovery_methods()).unwrap()[0].device_key;
    assert!(block_on(phone.revoke_device(&vkey)).is_err());
    assert_eq!(phone.latest_epoch(), 1);
    assert!(
        block_on(net.ds_directory().latest(ALICE))
            .unwrap()
            .is_none()
    );

    // The retry replays epoch 0 before epoch 1, so the head chain takes both.
    pub_down.set(false);
    block_on(phone.finish_initialize()).unwrap();
    let ds = net.ds_directory();
    assert_eq!(block_on(ds.epoch(ALICE, 0)).unwrap().unwrap().seq, 0);
    assert_eq!(block_on(ds.latest(ALICE)).unwrap().unwrap().seq, 1);
    assert_eq!(
        block_on(net.directory().latest(ALICE))
            .unwrap()
            .unwrap()
            .seq,
        1
    );
}

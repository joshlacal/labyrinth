//! Initialization never strands a mailbox: once epoch 0 exists, a failed
//! ORF registration or publish keeps the client (and with it the only copy
//! of the genesis keys) and can be retried.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, Labyrinth};
use labyrinth::orf::{EvolveToken, ObliviousId};
use labyrinth::records::MailboxKeysRecord;
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryOrf};
use labyrinth::store::{KeyPublisher, MailboxDirectory, OrfServer};
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

struct FlakyOrf {
    inner: MemoryOrf,
    down: Down,
}

impl OrfServer for FlakyOrf {
    fn register(
        &self,
        device_key: &XVerifyingKey,
        parent: Option<(&XVerifyingKey, &EvolveToken)>,
    ) -> labyrinth::Result<()> {
        if self.down.get() {
            return Err(Error::Backend("orf down".into()));
        }
        self.inner.register(device_key, parent)
    }
    fn map(
        &self,
        device_key: &XVerifyingKey,
        domain: &[u8],
        id: &ObliviousId,
    ) -> labyrinth::Result<[u8; 32]> {
        self.inner.map(device_key, domain, id)
    }
    fn delete(&self, device_key: &XVerifyingKey) -> labyrinth::Result<()> {
        self.inner.delete(device_key)
    }
}

struct FlakyPublisher {
    inner: Box<dyn KeyPublisher + Send>,
    down: Down,
}

impl KeyPublisher for FlakyPublisher {
    fn publish(&self, record: &MailboxKeysRecord) -> labyrinth::Result<()> {
        if self.down.get() {
            return Err(Error::Backend("publisher down".into()));
        }
        self.inner.publish(record)
    }
}

fn backends(net: &MemoryBackend, orf_down: &Down, pub_down: &Down) -> Backends {
    Backends {
        mailbox: Box::new(net.mailbox(ALICE)),
        threads: Box::new(net.threads(ALICE)),
        directory: Box::new(net.directory()),
        orf: Box::new(FlakyOrf {
            inner: net.orf(ALICE),
            down: orf_down.clone(),
        }),
        publishers: vec![Box::new(FlakyPublisher {
            inner: Box::new(net.ds_publisher(ALICE)),
            down: pub_down.clone(),
        })],
        clock: Box::new(TestClock::default()),
    }
}

#[test]
fn orf_failure_after_epoch_zero_keeps_the_client() {
    let net = MemoryBackend::new();
    net.register_chat_device(ALICE, signer(1).0.verifying_key().to_bytes());
    let (orf_down, pub_down) = (Down::default(), Down::default());
    orf_down.set(true);
    let (mut lab, unfinished) = Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(1)),
        backends(&net, &orf_down, &pub_down),
    )
    .unwrap();
    assert!(matches!(unfinished, Some(Error::Backend(_))));
    // Publishing did not wait for the ORF.
    assert_eq!(net.ds_directory().latest(ALICE).unwrap().unwrap().seq, 0);
    let key = lab.device_public().device_key_pub;
    assert!(!net.orf(ALICE).has_state(&key));

    // The retry registers the state; repeating it is harmless.
    orf_down.set(false);
    lab.finish_initialize().unwrap();
    lab.finish_initialize().unwrap();
    assert!(net.orf(ALICE).has_state(&key));
    lab.create_recovery_code(Mechanism::Code).unwrap();
}

#[test]
fn publish_failure_after_epoch_zero_keeps_the_client() {
    let net = MemoryBackend::new();
    net.register_chat_device(ALICE, signer(1).0.verifying_key().to_bytes());
    let (orf_down, pub_down) = (Down::default(), Down::default());
    pub_down.set(true);
    let (mut lab, published) = Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(1)),
        backends(&net, &orf_down, &pub_down),
    )
    .unwrap();
    assert!(matches!(published, Some(Error::Backend(_))));
    assert!(net.ds_directory().latest(ALICE).unwrap().is_none());
    // The mailbox's own publish still went through.
    assert_eq!(net.directory().latest(ALICE).unwrap().unwrap().seq, 0);

    // The client is whole: retry the publish and keep going.
    pub_down.set(false);
    lab.finish_initialize().unwrap();
    assert_eq!(net.ds_directory().latest(ALICE).unwrap().unwrap().seq, 0);
    lab.create_recovery_code(Mechanism::Code).unwrap();
}

#[test]
fn rotation_before_the_retry_still_publishes_epoch_zero_first() {
    let net = MemoryBackend::new();
    net.register_chat_device(ALICE, signer(1).0.verifying_key().to_bytes());
    net.register_chat_device(ALICE, signer(2).0.verifying_key().to_bytes());
    let (orf_down, pub_down) = (Down::default(), Down::default());
    pub_down.set(true);
    let (mut phone, unfinished) = Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(1)),
        backends(&net, &orf_down, &pub_down),
    )
    .unwrap();
    assert!(unfinished.is_some());
    phone.create_recovery_code(Mechanism::Code).unwrap();
    // Rotate (revoke the recovery bundle) while the publisher is down.
    let vkey = phone.list_recovery_methods().unwrap()[0].device_key;
    assert!(phone.revoke_device(&vkey).is_err());
    assert_eq!(phone.latest_epoch(), 1);
    assert!(net.ds_directory().latest(ALICE).unwrap().is_none());

    // The retry replays epoch 0 before epoch 1, so the head chain takes both.
    pub_down.set(false);
    phone.finish_initialize().unwrap();
    let ds = net.ds_directory();
    assert_eq!(ds.epoch(ALICE, 0).unwrap().unwrap().seq, 0);
    assert_eq!(ds.latest(ALICE).unwrap().unwrap().seq, 1);
    assert_eq!(net.directory().latest(ALICE).unwrap().unwrap().seq, 1);
}

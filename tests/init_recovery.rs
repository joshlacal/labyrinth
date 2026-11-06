//! Initialization never strands a mailbox: once epoch 0 exists, a failed
//! primary or secondary `mailboxKeys` publish keeps the client (and with it
//! the only copy of the genesis keys) and can be retried cleanly.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth};
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

fn strict_backends(net: &MemoryBackend, primary_down: &Down, pub_down: &Down) -> Backends {
    let mut backends = backends(net, primary_down, pub_down);
    backends.directory = Box::new(CompositeDirectory::new(
        Box::new(net.directory()),
        Box::new(net.ds_directory()),
    ));
    backends
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
    assert_eq!(lab.pending_directory_epoch(), Some(0));

    // The retry publishes both primary and secondary directories; repeating is idempotent.
    primary_down.set(false);
    block_on(lab.finish_initialize()).unwrap();
    block_on(lab.finish_initialize()).unwrap();
    assert_eq!(lab.pending_directory_epoch(), None);
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
        strict_backends(&net, &primary_down, &pub_down),
    ))
    .unwrap();
    assert_eq!(
        published,
        Some(Error::DirectoryIncomplete {
            pds_present: true,
            ds_present: false,
        })
    );
    assert!(
        block_on(net.ds_directory().latest(ALICE))
            .unwrap()
            .is_none()
    );
    assert_eq!(lab.pending_directory_epoch(), Some(0));
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
    assert_eq!(lab.pending_directory_epoch(), None);
    assert_eq!(
        block_on(net.ds_directory().latest(ALICE))
            .unwrap()
            .unwrap()
            .seq,
        0
    );
    assert_eq!(
        block_on(net.directory().latest(ALICE))
            .unwrap()
            .unwrap()
            .head,
        block_on(net.ds_directory().latest(ALICE))
            .unwrap()
            .unwrap()
            .head
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
    assert_eq!(phone.pending_directory_epoch(), Some(1));
    let state = phone.export_state().unwrap();
    let mut phone = block_on(Labyrinth::from_state(
        &state,
        ALICE,
        Box::new(signer(1)),
        backends(&net, &primary_down, &pub_down),
    ))
    .unwrap();
    assert_eq!(phone.pending_directory_epoch(), Some(1));

    // The retry replays epoch 0 before epoch 1, so the head chain takes both.
    pub_down.set(false);
    block_on(phone.finish_initialize()).unwrap();
    assert_eq!(phone.pending_directory_epoch(), None);
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

#[test]
fn one_source_or_mismatched_head_never_clears_pending_publication() {
    let pds_only = MemoryBackend::new();
    pds_only.register_chat_device(ALICE, signer(1).0.verifying_key().to_bytes());
    let (primary_down, pub_down) = (Down::default(), Down::default());
    pub_down.set(true);
    let (mut client, _) = block_on(Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(1)),
        strict_backends(&pds_only, &primary_down, &pub_down),
    ))
    .unwrap();
    assert_eq!(
        block_on(client.retry_pending_directory_publication()),
        Err(Error::DirectoryIncomplete {
            pds_present: true,
            ds_present: false,
        })
    );
    assert_eq!(client.pending_directory_epoch(), Some(0));

    let ds_only = MemoryBackend::new();
    ds_only.register_chat_device(ALICE, signer(2).0.verifying_key().to_bytes());
    let (primary_down, pub_down) = (Down::default(), Down::default());
    primary_down.set(true);
    let (mut client, _) = block_on(Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(2)),
        strict_backends(&ds_only, &primary_down, &pub_down),
    ))
    .unwrap();
    assert_eq!(
        block_on(client.retry_pending_directory_publication()),
        Err(Error::DirectoryIncomplete {
            pds_present: false,
            ds_present: true,
        })
    );
    assert_eq!(client.pending_directory_epoch(), Some(0));

    let mismatched = MemoryBackend::new();
    mismatched.register_chat_device(ALICE, signer(3).0.verifying_key().to_bytes());
    let (primary_down, pub_down) = (Down::default(), Down::default());
    pub_down.set(true);
    let (mut client, _) = block_on(Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(3)),
        strict_backends(&mismatched, &primary_down, &pub_down),
    ))
    .unwrap();
    let original = client.latest_public().unwrap();
    block_on(
        mismatched
            .ds_publisher(ALICE)
            .publish(&MailboxKeysRecord::from_public(
                &original,
                None,
                "2026-11-06T00:00:00Z".into(),
            )),
    )
    .unwrap();

    let fork = MemoryBackend::new();
    fork.register_chat_device(ALICE, signer(4).0.verifying_key().to_bytes());
    let forked = block_on(Labyrinth::initialize(
        ALICE,
        Box::new(signer(4)),
        backends(&fork, &Down::default(), &Down::default()),
    ))
    .unwrap()
    .latest_public()
    .unwrap();
    mismatched.tamper_pds_latest(
        ALICE,
        MailboxKeysRecord::from_public(&forked, None, "2026-11-06T00:00:00Z".into()),
    );
    primary_down.set(true);
    pub_down.set(false);
    assert_eq!(
        block_on(client.retry_pending_directory_publication()),
        Err(Error::DirectoryFork { pds: 0, ds: 0 })
    );
    assert_eq!(client.pending_directory_epoch(), Some(0));
}

#[test]
fn two_source_newer_head_supersedes_pending_before_revocation_sync() {
    let net = MemoryBackend::new();
    net.register_chat_device(ALICE, signer(1).0.verifying_key().to_bytes());
    let (primary_down, pub_down) = (Down::default(), Down::default());
    pub_down.set(true);
    let (mut stale, _) = block_on(Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(1)),
        strict_backends(&net, &primary_down, &pub_down),
    ))
    .unwrap();
    let epoch_zero = stale.latest_public().unwrap();
    block_on(
        net.ds_publisher(ALICE)
            .publish(&MailboxKeysRecord::from_public(
                &epoch_zero,
                None,
                "2026-11-06T00:00:00Z".into(),
            )),
    )
    .unwrap();

    let stale_key = stale.device_public().device_key_pub;
    let mut responder = stale.otc_offer().unwrap();
    let typed = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(ALICE, &typed).unwrap();
    let reply = block_on(stale.otc_respond(&mut responder, &hello)).unwrap();
    net.register_chat_device(ALICE, signer(2).0.verifying_key().to_bytes());
    pub_down.set(false);
    let (mut replacement, _) = block_on(Labyrinth::enroll_via_otc(
        ALICE,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(2)),
        strict_backends(&net, &primary_down, &pub_down),
    ))
    .unwrap();
    block_on(replacement.revoke_device(&stale_key)).unwrap();

    assert!(block_on(stale.retry_pending_directory_publication()).unwrap());
    assert_eq!(stale.pending_directory_epoch(), None);
    assert_eq!(block_on(stale.sync_epochs()), Err(Error::NotEpochMember));
}

#[test]
fn two_source_agreed_newer_fork_does_not_clear_pending_publication() {
    let net = MemoryBackend::new();
    net.register_chat_device(ALICE, signer(1).0.verifying_key().to_bytes());
    let (primary_down, pub_down) = (Down::default(), Down::default());
    pub_down.set(true);
    let (mut stale, _) = block_on(Labyrinth::initialize_with_report(
        ALICE,
        Box::new(signer(1)),
        strict_backends(&net, &primary_down, &pub_down),
    ))
    .unwrap();
    let epoch_zero = stale.latest_public().unwrap();
    block_on(
        net.ds_publisher(ALICE)
            .publish(&MailboxKeysRecord::from_public(
                &epoch_zero,
                None,
                "2026-11-06T00:00:00Z".into(),
            )),
    )
    .unwrap();

    let mut responder = stale.otc_offer().unwrap();
    let typed = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(ALICE, &typed).unwrap();
    let reply = block_on(stale.otc_respond(&mut responder, &hello)).unwrap();
    net.register_chat_device(ALICE, signer(2).0.verifying_key().to_bytes());
    pub_down.set(false);
    block_on(Labyrinth::enroll_via_otc(
        ALICE,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(2)),
        strict_backends(&net, &primary_down, &pub_down),
    ))
    .unwrap();

    let fork = MemoryBackend::new();
    fork.register_chat_device(ALICE, signer(9).0.verifying_key().to_bytes());
    let mut fork_owner = block_on(Labyrinth::initialize(
        ALICE,
        Box::new(signer(9)),
        backends(&fork, &Down::default(), &Down::default()),
    ))
    .unwrap();
    block_on(fork_owner.create_recovery_code(Mechanism::Code)).unwrap();
    let virtual_key = block_on(fork_owner.list_recovery_methods()).unwrap()[0].device_key;
    block_on(fork_owner.revoke_device(&virtual_key)).unwrap();
    let fork_zero = block_on(fork.ds_directory().epoch(ALICE, 0))
        .unwrap()
        .unwrap();
    let fork_one = fork_owner.latest_public().unwrap();

    block_on(net.ds_publisher(ALICE).retract()).unwrap();
    net.register_chat_device(ALICE, signer(9).0.verifying_key().to_bytes());
    for head in [&fork_zero, &fork_one] {
        block_on(
            net.ds_publisher(ALICE)
                .publish(&MailboxKeysRecord::from_public(
                    head,
                    None,
                    "2026-11-06T00:00:00Z".into(),
                )),
        )
        .unwrap();
    }
    net.tamper_pds_latest(
        ALICE,
        MailboxKeysRecord::from_public(&fork_one, None, "2026-11-06T00:00:00Z".into()),
    );

    assert_eq!(
        block_on(stale.retry_pending_directory_publication()),
        Err(Error::Malformed(
            "superseding directory head forks from mailbox"
        ))
    );
    assert_eq!(stale.pending_directory_epoch(), Some(0));
}

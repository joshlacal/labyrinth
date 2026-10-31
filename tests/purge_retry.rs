//! Review 2: account deletion never strands the user. A failed remote
//! `deleteAccountData` still clears the client and reports the error; the
//! remote half is retried later without any client state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, Labyrinth, SystemClock, delete_account_remote};
use labyrinth::records::{
    Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryMailbox};
use labyrinth::store::{
    AtomicEnrollBundle, MailboxDirectory as _, MailboxStore, Stored, TimeRange,
};

const A: &str = "did:plc:alice";
const B: &str = "did:plc:bob";

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

/// Fails `delete_account` while `down` is set.
#[derive(Clone)]
struct FlakyMailbox {
    inner: Arc<MemoryMailbox>,
    down: Arc<AtomicBool>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for FlakyMailbox {
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
        self.inner.publish_mailbox_keys(r).await
    }
    async fn purge_mailbox(&self) -> labyrinth::Result<()> {
        if self.down.load(Ordering::SeqCst) {
            return Err(Error::Backend("connection reset".into()));
        }
        self.inner.purge_mailbox().await
    }
    async fn delete_account_data(&self) -> labyrinth::Result<()> {
        if self.down.load(Ordering::SeqCst) {
            return Err(Error::Backend("connection reset".into()));
        }
        self.inner.delete_account_data().await
    }
}

fn backends(net: &MemoryBackend, mailbox: Box<dyn MailboxStore>, did: &str) -> Backends {
    Backends {
        mailbox,
        threads: Box::new(net.threads(did)),
        directory: Box::new(net.directory()),
        publishers: vec![],
        clock: Box::new(SystemClock),
    }
}

#[test]
fn remote_failure_still_purges_locally_and_the_retry_finishes_the_job() {
    let net = MemoryBackend::new();
    let down = Arc::new(AtomicBool::new(true));
    let key = signer(1).0.verifying_key().to_bytes();
    net.register_chat_device(A, key);
    let flaky = FlakyMailbox {
        inner: Arc::new(net.mailbox(A)),
        down: down.clone(),
    };
    let mut alice = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, Box::new(flaky.clone()), A),
    ))
    .unwrap();
    // Initial publish happened while down=true? Wait: `publish_mailbox_keys` does not check `down`, so A's keys ARE published!
    net.register_chat_device(B, signer(2).0.verifying_key().to_bytes());
    let _bob = block_on(Labyrinth::initialize(
        B,
        Box::new(signer(2)),
        backends(&net, Box::new(net.mailbox(B)), B),
    ))
    .unwrap();
    block_on(alice.resolve_roster(&[A, B])).unwrap();
    assert!(alice.peer_pin(B).is_some());

    let report = block_on(alice.purge_account()).unwrap();
    let pending = report.remote_pending.expect("remote failure is reported");
    assert!(matches!(pending, Error::Backend(_)));
    assert!(!report.server_side);
    // Local state is cleared regardless.
    assert!(alice.peer_pin(B).is_none());
    // The server still holds the mailbox.
    let dir = net.directory();
    assert!(block_on(dir.latest(A)).unwrap().is_some());

    // Still down: the retry fails, and says so.
    assert!(block_on(delete_account_remote(&flaky, &[])).is_err());
    // Back up: the retry (no client state needed) deletes the account.
    down.store(false, Ordering::SeqCst);
    block_on(delete_account_remote(&flaky, &[])).unwrap();
    assert!(block_on(dir.latest(A)).unwrap().is_none());
    assert!(block_on(flaky.list_devices()).unwrap().is_empty());
    // Idempotent.
    block_on(delete_account_remote(&flaky, &[])).unwrap();
}

//! Hardening integration and property tests covering:
//! - virtual-member recovery bundle cross-checking and tolerant recovery listing;
//! - atomic recovery-method re-keying on physical device revocation;
//! - `membersHash` verification across epoch adoption, sync, state reload, OTC, and restore;
//! - signed `deviceRevocation` (`0x35`), signed `epoch.revocations` (`0x36`), and
//!   virtual-bundle metadata/AAD binding (`0x37`);
//! - create-if-absent / CAS semantics, unanchored publication handling, fork
//!   recovery, and non-wedging multi-device revocation;
//! - per-author restore quarantine and bounded MEK lookup budgets;
//! - per-flush directory caching with pre-commit roster re-validation.

#[path = "support/net.rs"]
mod net;

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{
    AUTO_RECOVERY_TTL_MS, Backends, Clock as _, ExclusionReason, Labyrinth, QuarantineReason,
};
use labyrinth::device::{DeviceRevocation, DeviceSecrets};
use labyrinth::epoch::{EpochSecret, space_epoch_id};
use labyrinth::mailbox::EpochPublic;
use labyrinth::records::{
    Batch, Bytes, Device, DeviceRevocationDef, Epoch, EpochMember, MailboxKeysRecord,
    MekDistribution, OtcSession, OwnerBatch, SealedMessageDef, VirtualDevice, datetime_from_ms,
    nsid,
};
use labyrinth::recovery_code::RecoveryCode;
use labyrinth::sign::XVerifyingKey;
use labyrinth::store::memory::{MemoryBackend, MemoryDirectory, MemoryMailbox};
use labyrinth::store::pds::{PdsRecords, PublicRepoBackend};
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef, SpaceThreadStore};
use labyrinth::store::{
    AtomicEnrollBundle, AuthorQuarantine, ChatDeviceKey, MailboxDirectory, MailboxStore,
    MemberDeviceKey, SequencerReceiptKey, Stored, ThreadListing, ThreadStore, TimeRange,
};
use labyrinth::virtual_device::{self, Mechanism};
use net::{A, B, Faulty, T, TestClock, backends, backends_with, init, sibling, signer, tpub};
use proptest::prelude::*;
use serde_json::json;

const C: &str = "did:plc:carol";
const D: &str = "did:plc:dave";
const E: &str = "did:plc:erin";
const M: &str = "did:plc:mallory";

fn queue_outgoing(
    client: &mut Labyrinth,
    thread_id: &str,
    dids: &[&str],
    message_id: &str,
    ts: u64,
    plaintext: &[u8],
) {
    let resolved = block_on(client.resolve_roster(dids)).unwrap();
    block_on(client.archive_outgoing(thread_id, &resolved, message_id, ts, plaintext)).unwrap();
}

// ---------------------------------------------------------------------------
// Test store / directory wrappers
// ---------------------------------------------------------------------------

type OmittedMemberSet = BTreeSet<(u64, [u8; 32])>;

/// Wraps a `MemoryMailbox` and omits an arbitrary set of `(seq, device_key)` member rows.
#[derive(Clone)]
struct OmitMembersMailbox {
    inner: Arc<MemoryMailbox>,
    omitted: Arc<Mutex<OmittedMemberSet>>,
}

impl OmitMembersMailbox {
    fn new(inner: MemoryMailbox) -> Self {
        Self {
            inner: Arc::new(inner),
            omitted: Arc::default(),
        }
    }

    fn omit(&self, seq: u64, key: XVerifyingKey) {
        self.omitted.lock().unwrap().insert((seq, key.0));
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for OmitMembersMailbox {
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
        rev: &DeviceRevocationDef,
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
        self.inner.create_epoch(e, m).await
    }
    async fn atomic_enroll(&self, b: &AtomicEnrollBundle) -> labyrinth::Result<String> {
        self.inner.atomic_enroll(b).await
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
        let omitted = self.omitted.lock().unwrap().clone();
        let mut rows = self.inner.list_epoch_members(s).await?;
        rows.retain(|m| {
            <[u8; 32]>::try_from(m.device_key_pubkey.0.as_slice())
                .map(|k| !omitted.contains(&(s, k)))
                .unwrap_or(true)
        });
        Ok(rows)
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
    async fn put_otc_session(&self, s: &OtcSession) -> labyrinth::Result<()> {
        self.inner.put_otc_session(s).await
    }
    async fn get_otc_session(&self, id: &str) -> labyrinth::Result<Option<OtcSession>> {
        self.inner.get_otc_session(id).await
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
    async fn touch_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<()> {
        self.inner.touch_virtual_device(id).await
    }
    async fn delete_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<()> {
        self.inner.delete_virtual_device(id).await
    }
    async fn delete_squatted_epoch(&self, seq: u64) -> labyrinth::Result<()> {
        self.inner.delete_squatted_epoch(seq).await
    }
}

/// Mailbox wrapper that can fail `publish_mailbox_keys` on demand.
#[derive(Clone)]
struct FailPublishMailbox {
    inner: Arc<MemoryMailbox>,
    fail_publish: Arc<AtomicBool>,
}

impl FailPublishMailbox {
    fn new(inner: MemoryMailbox, fail_publish: Arc<AtomicBool>) -> Self {
        Self {
            inner: Arc::new(inner),
            fail_publish,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for FailPublishMailbox {
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
        rev: &DeviceRevocationDef,
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
        self.inner.create_epoch(e, m).await
    }
    async fn atomic_enroll(&self, b: &AtomicEnrollBundle) -> labyrinth::Result<String> {
        self.inner.atomic_enroll(b).await
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
    async fn list_virtual_device_records(
        &self,
    ) -> labyrinth::Result<Vec<labyrinth::Result<VirtualDevice>>> {
        self.inner.list_virtual_device_records().await
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
        if self.fail_publish.load(Ordering::SeqCst) {
            return Err(Error::Backend("simulated directory publish failure".into()));
        }
        self.inner.publish_mailbox_keys(r).await
    }
    async fn touch_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<()> {
        self.inner.touch_virtual_device(id).await
    }
    async fn delete_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<()> {
        self.inner.delete_virtual_device(id).await
    }
    async fn delete_squatted_epoch(&self, seq: u64) -> labyrinth::Result<()> {
        self.inner.delete_squatted_epoch(seq).await
    }
}

/// Counts `find_meks` invocations on the underlying `ThreadStore`.
struct CountingThreads {
    inner: Box<dyn ThreadStore>,
    find_mek_calls: Arc<AtomicUsize>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ThreadStore for CountingThreads {
    fn author(&self) -> &str {
        self.inner.author()
    }
    async fn create_mek(&self, mek: &MekDistribution) -> labyrinth::Result<()> {
        self.inner.create_mek(mek).await
    }
    async fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> labyrinth::Result<Vec<Stored<MekDistribution>>> {
        self.find_mek_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.find_meks(thread_id, mek_id).await
    }
    async fn append_batch(&self, batch: &Batch) -> labyrinth::Result<String> {
        self.inner.append_batch(batch).await
    }
    async fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<Batch>>> {
        self.inner.list_batches(thread_id, sender, range).await
    }
    async fn list_batches_quarantined(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> labyrinth::Result<(Vec<Stored<Batch>>, Vec<AuthorQuarantine>)> {
        self.inner
            .list_batches_quarantined(thread_id, sender, range)
            .await
    }
    async fn list_threads(&self) -> labyrinth::Result<Vec<String>> {
        self.inner.list_threads().await
    }
    async fn list_threads_report(&self) -> labyrinth::Result<ThreadListing> {
        self.inner.list_threads_report().await
    }
}

/// Counts per-DID `latest` and `device_transport_keys` lookups on `MailboxDirectory`.
#[derive(Clone)]
struct CountingDirectory {
    inner: Arc<MemoryDirectory>,
    latest_calls: Arc<Mutex<HashMap<String, usize>>>,
    transport_calls: Arc<Mutex<HashMap<String, usize>>>,
}

impl CountingDirectory {
    fn new(inner: MemoryDirectory) -> Self {
        Self {
            inner: Arc::new(inner),
            latest_calls: Arc::default(),
            transport_calls: Arc::default(),
        }
    }

    fn reset(&self) {
        self.latest_calls.lock().unwrap().clear();
        self.transport_calls.lock().unwrap().clear();
    }

    fn peer_latest_calls(&self, did: &str) -> usize {
        self.latest_calls
            .lock()
            .unwrap()
            .get(did)
            .copied()
            .unwrap_or(0)
    }

    fn peer_transport_calls(&self, did: &str) -> usize {
        self.transport_calls
            .lock()
            .unwrap()
            .get(did)
            .copied()
            .unwrap_or(0)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for CountingDirectory {
    async fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        *self
            .latest_calls
            .lock()
            .unwrap()
            .entry(did.to_owned())
            .or_insert(0) += 1;
        self.inner.latest(did).await
    }
    async fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        self.inner.epoch(did, seq).await
    }
    async fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        *self
            .transport_calls
            .lock()
            .unwrap()
            .entry(did.to_owned())
            .or_insert(0) += 1;
        self.inner.device_transport_keys(did).await
    }
    async fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> labyrinth::Result<Option<Vec<MemberDeviceKey>>> {
        self.inner.member_device_keys(thread_id, did).await
    }
    async fn sequencer_receipt_key(
        &self,
        thread_id: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        self.inner.sequencer_receipt_key(thread_id).await
    }
}

type PublicRepoMap = HashMap<(String, String), (Vec<u8>, String)>;

/// Minimal in-memory `PublicRepoBackend` verifying create-if-absent and `swapRecord` CAS.
#[derive(Default)]
struct MemoryPublicRepo {
    rows: Mutex<PublicRepoMap>,
    seq: AtomicUsize,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl PublicRepoBackend for MemoryPublicRepo {
    async fn put_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
        record: &[u8],
        swap_cid: Option<&str>,
    ) -> labyrinth::Result<String> {
        let mut rows = self.rows.lock().unwrap();
        let key = (did.to_owned(), rkey.to_owned());
        match (swap_cid, rows.get(&key)) {
            (None, Some(_)) => return Err(Error::Conflict),
            (Some(_), None) => return Err(Error::Conflict),
            (Some(expected), Some((_, actual))) if expected != actual => {
                return Err(Error::Conflict);
            }
            _ => {}
        }
        let n = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let cid = format!("bafyreicas{n:08}");
        rows.insert(key, (record.to_vec(), cid.clone()));
        Ok(cid)
    }

    async fn get_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
    ) -> labyrinth::Result<Option<(Vec<u8>, String)>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .get(&(did.to_owned(), rkey.to_owned()))
            .cloned())
    }

    async fn delete_all_mailbox_keys(&self, did: &str) -> labyrinth::Result<()> {
        self.rows.lock().unwrap().retain(|(d, _), _| d != did);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 1. Virtual-member bundle validation & tolerant recovery method listing
// ---------------------------------------------------------------------------

#[test]
fn virtual_member_without_recovery_bundle_is_excluded_from_rotation() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let setup = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();

    // Remove the `virtualDevice` bundle while leaving the virtual `Device` and
    // `EpochMember` rows in place.
    let mb = net.mailbox(A);
    block_on(mb.delete_virtual_device(&setup.vdevice_id)).unwrap();

    let rot = block_on(phone.rotate_epoch()).unwrap();
    assert_eq!(rot.new_epoch, 1);
    assert!(
        rot.excluded
            .iter()
            .any(|e| e.reason == ExclusionReason::MissingRecoveryBundle),
        "expected MissingRecoveryBundle exclusion, got {:?}",
        rot.excluded
    );
    let e1_members = block_on(mb.list_epoch_members(1)).unwrap();
    assert_eq!(e1_members.len(), 1);
    assert_eq!(
        e1_members[0].device_key_pubkey.0,
        phone.device_public().device_key_pub.0
    );
}

#[test]
fn virtual_member_with_malformed_or_mismatched_bundle_is_excluded() {
    let space_host = MemorySpaceHost::new();
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let space = SpaceRef::mailbox(A);
    net.register_chat_device(A, tpub(1));

    let make_mb =
        || SpaceMailboxStore::for_owner(A, space_host.client(A), Box::new(net.pds_publisher(A)));
    let mut phone = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(make_mb()), vec![]),
    ))
    .unwrap();

    let good = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    // Snapshot `phone` before `bad_suite` / `bad_json` exist so we can test both:
    // (a) `[CB-25]` fail-closed tamper detection when an already-verified virtual
    //     member's bundle is rewritten in place; and
    // (b) `ExclusionReason::InvalidRecoveryBundle` when a rotating device sees
    //     newly added virtual members whose bundles are malformed or mismatched.
    let pre_bad_snapshot = phone.export_state().unwrap();
    let bad_suite = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let bad_json = block_on(phone.create_recovery_code(Mechanism::Keychain)).unwrap();

    // Flip the AEAD suite byte on `bad_suite`'s ciphertext to v1.0 (`0x01`).
    let rkey_suite = hex::encode(bad_suite.vdevice_id);
    let mut raw_suite: VirtualDevice = serde_json::from_value(
        space_host
            .record(&space, A, nsid::VIRTUAL_DEVICE, &rkey_suite)
            .unwrap(),
    )
    .unwrap();
    raw_suite.encrypted_epoch_root_key.0[0] = 0x01;
    space_host.tamper(
        &space,
        A,
        nsid::VIRTUAL_DEVICE,
        &rkey_suite,
        serde_json::to_value(&raw_suite).unwrap(),
    );

    // Corrupt `bad_json` directly in the Space host so record deserialization fails.
    space_host.tamper(
        &space,
        A,
        nsid::VIRTUAL_DEVICE,
        &hex::encode(bad_json.vdevice_id),
        json!({ "$type": nsid::VIRTUAL_DEVICE, "broken": true }),
    );

    // `list_recovery_methods` tolerates both corruptions and returns only `good`.
    let methods = block_on(phone.list_recovery_methods()).unwrap();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0].vdevice_id, good.vdevice_id);

    // `phone` already verified `bad_suite` during `create_recovery_code(bad_json)`,
    // so `[CB-25]` detects the in-place rewrite as `MemberTampered { seq: 0 }`.
    assert_eq!(
        block_on(phone.rotate_epoch()).unwrap_err(),
        Error::MemberTampered { seq: 0 }
    );

    // A client loaded from `pre_bad_snapshot` (which has not cached `bad_suite` /
    // `bad_json`) excludes both invalid virtual members with `InvalidRecoveryBundle`
    // and carries `phone` + `good` into epoch 1.
    let mut phone_unseen = block_on(Labyrinth::from_state(
        &pre_bad_snapshot,
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(make_mb()), vec![]),
    ))
    .unwrap();
    let rot = block_on(phone_unseen.rotate_epoch()).unwrap();
    assert_eq!(rot.new_epoch, 1);
    let invalid_count = rot
        .excluded
        .iter()
        .filter(|e| e.reason == ExclusionReason::InvalidRecoveryBundle)
        .count();
    assert_eq!(
        invalid_count, 2,
        "expected 2 InvalidRecoveryBundle exclusions, got {:?}",
        rot.excluded
    );
    let methods_after = block_on(phone_unseen.list_recovery_methods()).unwrap();
    assert_eq!(methods_after.len(), 1);
    assert_eq!(methods_after[0].vdevice_id, good.vdevice_id);
}

#[test]
fn list_recovery_methods_ignores_unauthenticated_and_forged_bundles() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let honest = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();

    // Plant an unauthenticated `virtualDevice` + `Device` record forged for an
    // unrelated epoch secret without a valid `EpochMember` MAC in `phone`'s epoch.
    let fake_opener = DeviceSecrets::generate().unwrap();
    let fake_epoch = EpochSecret::from_parts(0, space_epoch_id(0), [9u8; 32]);
    let fake_code = RecoveryCode::generate().unwrap();
    let now = datetime_from_ms(clock.now_ms());
    let (forged_rec, _) = virtual_device::create_at(
        A,
        &fake_code,
        &fake_opener,
        &fake_epoch,
        Mechanism::Passkey,
        &now,
    )
    .unwrap();
    let mb = net.mailbox(A);
    block_on(mb.create_device(&Device::from_public(&forged_rec.public, now.clone()))).unwrap();
    block_on(mb.create_virtual_device(&VirtualDevice::from_bundle(&forged_rec, None, now)))
        .unwrap();

    let listed = block_on(phone.list_recovery_methods()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].vdevice_id, honest.vdevice_id);
    assert_eq!(listed[0].mechanism, Mechanism::Code);
}

// ---------------------------------------------------------------------------
// 2. Atomic recovery re-keying on physical device revocation
// ---------------------------------------------------------------------------

#[test]
fn physical_device_revocation_atomically_rekeys_all_recovery_methods() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);

    let old_code = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let prf = [0x42u8; 32];
    let cred_id = b"cred-alice-1";
    let old_passkey = block_on(phone.create_passkey_recovery(&prf, cred_id)).unwrap();

    let mut laptop = sibling(&net, &clock, &mut phone, 3);
    block_on(phone.sync_epochs()).unwrap();

    // Archive pre-revocation messages across epochs.
    queue_outgoing(&mut phone, T, &[A, B], "m-pre", 100, b"before revoke");
    block_on(phone.flush()).unwrap();
    queue_outgoing(&mut bob, T, &[A, B], "m-bob", 200, b"from bob");
    block_on(bob.flush()).unwrap();

    // Remove `phone` from MLS chat devices and revoke `phone` on `laptop`.
    net.remove_chat_device(A, tpub(1), clock.now_ms() + 1);
    clock.advance(10);
    let phone_key = phone.device_public().device_key_pub;
    let rot = block_on(laptop.revoke_device(&phone_key)).unwrap();

    assert_eq!(rot.invalidated_recovery_methods.len(), 2);
    let invalidated_ids: BTreeSet<[u8; 16]> = rot
        .invalidated_recovery_methods
        .iter()
        .map(|m| m.vdevice_id)
        .collect();
    assert!(invalidated_ids.contains(&old_code.vdevice_id));
    assert!(invalidated_ids.contains(&old_passkey.vdevice_id));
    let replacement = rot
        .rekeyed_recovery
        .expect("physical device revocation must issue a replacement recovery code");

    // Post-revocation message.
    queue_outgoing(&mut laptop, T, &[A, B], "m-post", 300, b"after revoke");
    block_on(laptop.flush()).unwrap();

    // Both pre-revocation recovery methods must fail closed.
    net.register_chat_device(A, tpub(4));
    assert!(matches!(
        block_on(Labyrinth::restore_with_recovery_code(
            A,
            old_code.code.as_str(),
            Box::new(signer(4)),
            backends(&net, &clock, A),
        )),
        Err(Error::BadRecoveryCode)
    ));
    assert!(matches!(
        block_on(Labyrinth::restore_with_passkey(
            A,
            &prf,
            cred_id,
            Box::new(signer(4)),
            backends(&net, &clock, A),
        )),
        Err(Error::NotFound(_)) | Err(Error::NotEpochMember) | Err(Error::BadRecoveryCode)
    ));

    // Restoring with the replacement code succeeds and decrypts all pre- and post-revoke history.
    let (mut restored, _) = block_on(Labyrinth::restore_with_recovery_code(
        A,
        replacement.code.as_str(),
        Box::new(signer(4)),
        backends(&net, &clock, A),
    ))
    .unwrap();
    let history = block_on(restored.load_thread(T, TimeRange::ALL)).unwrap();
    let texts: Vec<&[u8]> = history
        .messages
        .iter()
        .map(|m| m.frame.as_slice())
        .collect();
    assert_eq!(
        texts,
        vec![
            b"before revoke".as_slice(),
            b"from bob".as_slice(),
            b"after revoke".as_slice()
        ]
    );
}

#[test]
fn virtual_device_removal_preserves_other_active_recovery_methods() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let first = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let second = block_on(phone.create_recovery_code(Mechanism::Keychain)).unwrap();

    let rot = block_on(phone.remove_recovery_method(&first.vdevice_id)).unwrap();
    assert!(rot.rekeyed_recovery.is_none());
    assert!(rot.invalidated_recovery_methods.is_empty());

    let remaining = block_on(phone.list_recovery_methods()).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].vdevice_id, second.vdevice_id);
}

// ---------------------------------------------------------------------------
// 3. `membersHash` verification on epoch adoption
// ---------------------------------------------------------------------------

#[test]
fn withheld_initial_epoch_member_is_rejected_across_restore_otc_state_and_sync() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let laptop = sibling(&net, &clock, &mut phone, 2);
    block_on(phone.sync_epochs()).unwrap();

    // Mid-epoch virtual addition in epoch 1 (not in epoch 1's initial `members_hash`).
    let recovery = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let phone_state_e1 = phone.export_state().unwrap();

    let omit_mb = OmitMembersMailbox::new(net.mailbox(A));
    let laptop_key = laptop.device_public().device_key_pub;
    omit_mb.omit(1, laptop_key);

    // 1) `restore_with_recovery_code` rejects epoch 1 when initial member `laptop` is omitted.
    net.register_chat_device(A, tpub(5));
    let err_restore = block_on(Labyrinth::restore_with_recovery_code(
        A,
        recovery.code.as_str(),
        Box::new(signer(5)),
        backends_with(&net, &clock, A, Box::new(omit_mb.clone()), vec![]),
    ))
    .map(|_| ())
    .unwrap_err();
    assert_eq!(err_restore, Error::MemberTampered { seq: 1 });

    // 2) `enroll_via_otc` rejects epoch 1 when initial member `laptop` is omitted.
    let mut responder = phone.otc_offer().unwrap();
    let code_str = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(A, &code_str).unwrap();
    let reply = block_on(phone.otc_respond(&mut responder, &hello)).unwrap();
    net.register_chat_device(A, tpub(6));
    let err_otc = block_on(Labyrinth::enroll_via_otc(
        A,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(6)),
        backends_with(&net, &clock, A, Box::new(omit_mb.clone()), vec![]),
    ))
    .map(|_| ())
    .unwrap_err();
    assert_eq!(err_otc, Error::MemberTampered { seq: 1 });

    // 3) `from_state` rejects startup verification when `laptop`'s row in `latest` is omitted.
    let err_state = block_on(Labyrinth::from_state(
        &phone_state_e1,
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(omit_mb.clone()), vec![]),
    ))
    .map(|_| ())
    .unwrap_err();
    assert_eq!(err_state, Error::MemberTampered { seq: 1 });

    // 4) `sync_epochs` rejects advancing into epoch 2 when a sibling row in epoch 2 is omitted.
    let mut laptop_full = laptop;
    let rot = block_on(laptop_full.rotate_epoch()).unwrap();
    assert_eq!(rot.new_epoch, 2);

    let omit_e2 = OmitMembersMailbox::new(net.mailbox(A));
    omit_e2.omit(2, laptop_key);
    let mut phone_reloaded = block_on(Labyrinth::from_state(
        &phone_state_e1,
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(omit_e2), vec![]),
    ))
    .unwrap();
    assert_eq!(
        block_on(phone_reloaded.sync_epochs()).unwrap_err(),
        Error::MemberTampered { seq: 2 }
    );

    // Positive check: with intact store (including mid-epoch virtual device), `sync_epochs` succeeds.
    let mut phone_intact = block_on(Labyrinth::from_state(
        &phone_state_e1,
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A),
    ))
    .unwrap();
    assert_eq!(block_on(phone_intact.sync_epochs()).unwrap().to, 2);
}

// ---------------------------------------------------------------------------
// 4. Signed revocations & virtual bundle AAD / metadata binding
// ---------------------------------------------------------------------------

#[test]
fn unsigned_or_forged_revoked_at_is_rejected_without_dropping_sibling() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let laptop = sibling(&net, &clock, &mut phone, 2);
    block_on(phone.sync_epochs()).unwrap();
    let recovery = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();

    // Host stamps an unsigned `revokedAt` on `laptop`'s device record.
    let mb = net.mailbox(A);
    let laptop_key = laptop.device_public().device_key_pub;
    block_on(mb.set_device_revoked(&laptop_key, "2026-11-13T00:00:00.000Z")).unwrap();

    // `phone` already verified `laptop` at epoch 1 (`[CB-25]` -> `MemberTampered`),
    // and a fresh restoring client rejects the unsigned revocation with `DeviceTampered`.
    assert_eq!(
        block_on(phone.rotate_epoch()).unwrap_err(),
        Error::MemberTampered { seq: 1 }
    );

    net.register_chat_device(A, tpub(7));
    assert_eq!(
        block_on(Labyrinth::restore_with_recovery_code(
            A,
            recovery.code.as_str(),
            Box::new(signer(7)),
            backends(&net, &clock, A),
        ))
        .map(|_| ())
        .unwrap_err(),
        Error::DeviceTampered
    );

    // Forged signature by an unattested outsider device key also fails closed.
    let outsider = DeviceSecrets::generate().unwrap();
    let forged_rev = DeviceRevocation::sign(
        A,
        &laptop_key,
        "2026-11-13T00:00:00.000Z",
        &outsider.device_key,
    )
    .unwrap();
    block_on(mb.set_device_revocation(
        &laptop_key,
        "2026-11-13T00:00:00.000Z",
        &DeviceRevocationDef::from_revocation(&forged_rev),
    ))
    .unwrap();
    assert_eq!(
        block_on(phone.rotate_epoch()).unwrap_err(),
        Error::MemberTampered { seq: 1 }
    );
    assert_eq!(
        block_on(Labyrinth::restore_with_recovery_code(
            A,
            recovery.code.as_str(),
            Box::new(signer(7)),
            backends(&net, &clock, A),
        ))
        .map(|_| ())
        .unwrap_err(),
        Error::DeviceTampered
    );
}

#[test]
fn signed_device_revocation_and_epoch_revocation_set_verify_and_carry_forward() {
    let space_host = MemorySpaceHost::new();
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let space = SpaceRef::mailbox(A);
    let make_backends = |seed_net: &MemoryBackend| {
        let mb = SpaceMailboxStore::for_owner(
            A,
            space_host.client(A),
            Box::new(seed_net.pds_publisher(A)),
        );
        backends_with(seed_net, &clock, A, Box::new(mb), vec![])
    };

    net.register_chat_device(A, tpub(1));
    let mut phone = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        make_backends(&net),
    ))
    .unwrap();

    let mut r1 = phone.otc_offer().unwrap();
    let c1 = r1.code().as_str().to_owned();
    let (i1, h1) = Labyrinth::otc_start(A, &c1).unwrap();
    let rep1 = block_on(phone.otc_respond(&mut r1, &h1)).unwrap();
    net.register_chat_device(A, tpub(2));
    let (laptop, _) = block_on(Labyrinth::enroll_via_otc(
        A,
        i1,
        &rep1.message,
        &rep1.sealed_payload,
        Box::new(signer(2)),
        make_backends(&net),
    ))
    .unwrap();
    block_on(phone.sync_epochs()).unwrap();

    let mut r2 = phone.otc_offer().unwrap();
    let c2 = r2.code().as_str().to_owned();
    let (i2, h2) = Labyrinth::otc_start(A, &c2).unwrap();
    let rep2 = block_on(phone.otc_respond(&mut r2, &h2)).unwrap();
    net.register_chat_device(A, tpub(3));
    let (mut tablet, _) = block_on(Labyrinth::enroll_via_otc(
        A,
        i2,
        &rep2.message,
        &rep2.sealed_payload,
        Box::new(signer(3)),
        make_backends(&net),
    ))
    .unwrap();
    block_on(phone.sync_epochs()).unwrap();

    // Revoke `laptop` from `phone`.
    net.remove_chat_device(A, tpub(2), clock.now_ms() + 1);
    clock.advance(10);
    let laptop_key = laptop.device_public().device_key_pub;
    let rot = block_on(phone.revoke_device(&laptop_key)).unwrap();
    assert_eq!(rot.new_epoch, 3);

    // Inspect stored `device` revocation signature and `epoch/000000000003` signed `revocations`.
    let dev_json = space_host
        .record(&space, A, nsid::DEVICE, &hex::encode(laptop_key.0))
        .unwrap();
    assert!(dev_json["revocation"]["sig"]["$bytes"].is_string());
    let e3_json = space_host
        .record(&space, A, nsid::EPOCH, &space_epoch_id(3))
        .unwrap();
    let e3: Epoch = serde_json::from_value(e3_json).unwrap();
    let e3_rec = e3.to_record().unwrap();
    e3_rec.verify_revocations(A).unwrap();
    assert_eq!(e3_rec.revocations, vec![laptop_key]);

    // Subsequent ordinary rotation on `tablet` carries cumulative signed `revocations` forward.
    block_on(tablet.sync_epochs()).unwrap();
    let rot4 = block_on(tablet.rotate_epoch()).unwrap();
    assert_eq!(rot4.new_epoch, 4);
    let e4: Epoch = serde_json::from_value(
        space_host
            .record(&space, A, nsid::EPOCH, &space_epoch_id(4))
            .unwrap(),
    )
    .unwrap();
    let e4_rec = e4.to_record().unwrap();
    e4_rec.verify_revocations(A).unwrap();
    assert_eq!(e4_rec.revocations, vec![laptop_key]);

    // Tampering with `revocationsSig` on epoch 4 fails `verify_revocations` directly
    // and causes `phone.sync_epochs()` to reject epoch 4.
    let mut bad_e4 = e4;
    bad_e4.revocations_sig.as_mut().unwrap().0[0] ^= 1;
    assert_eq!(
        bad_e4.to_record().unwrap().verify_revocations(A),
        Err(Error::BadSignature)
    );
    space_host.tamper(
        &space,
        A,
        nsid::EPOCH,
        &space_epoch_id(4),
        serde_json::to_value(&bad_e4).unwrap(),
    );
    assert_eq!(
        block_on(phone.sync_epochs()).unwrap_err(),
        Error::EpochSquatted {
            seq: 4,
            reason: "its revocation list signature is invalid",
        }
    );
}

#[test]
fn virtual_device_bundle_binds_did_mechanism_and_clamps_future_last_used_at() {
    let space_host = MemorySpaceHost::new();
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let space = SpaceRef::mailbox(A);
    net.register_chat_device(A, tpub(1));
    let mb = SpaceMailboxStore::for_owner(A, space_host.client(A), Box::new(net.pds_publisher(A)));
    let mut phone = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(mb), vec![]),
    ))
    .unwrap();

    let keychain = block_on(phone.create_recovery_code(Mechanism::Keychain)).unwrap();
    let rkey = hex::encode(keychain.vdevice_id);
    let orig: VirtualDevice = serde_json::from_value(
        space_host
            .record(&space, A, nsid::VIRTUAL_DEVICE, &rkey)
            .unwrap(),
    )
    .unwrap();

    // 1) Rewriting `mechanism` from `"keychain"` to `"code"` fails metadata signature verification.
    let mut swapped_mech = orig.clone();
    swapped_mech.mechanism = "code".into();
    assert!(swapped_mech.to_bundle_for_did(A).is_err());

    // 2) Rewriting `createdAt` fails metadata signature / AAD verification.
    let mut swapped_created = orig.clone();
    swapped_created.created_at = "2099-01-01T00:00:00.000Z".into();
    assert!(swapped_created.to_bundle_for_did(A).is_err());

    // 3) Binding to a different DID fails closed.
    assert!(orig.to_bundle_for_did(B).is_err());

    // 4) Stamping a far-future `lastUsedAt` cannot extend automatic TTL past `now + AUTO_RECOVERY_TTL_MS`.
    let mut future_used = orig;
    future_used.last_used_at = Some("2099-01-01T00:00:00.000Z".into());
    space_host.tamper(
        &space,
        A,
        nsid::VIRTUAL_DEVICE,
        &rkey,
        serde_json::to_value(&future_used).unwrap(),
    );

    let methods = block_on(phone.list_recovery_methods()).unwrap();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0].last_used_at_ms, None);
    assert_eq!(
        methods[0].stale_at_ms,
        Some(clock.now_ms() + AUTO_RECOVERY_TTL_MS)
    );

    // Advancing past `AUTO_RECOVERY_TTL_MS` expires the bundle on ordinary rotation despite `2099` `lastUsedAt`.
    clock.advance(AUTO_RECOVERY_TTL_MS + 1);
    let rot = block_on(phone.rotate_epoch()).unwrap();
    assert!(
        rot.excluded
            .iter()
            .any(|e| e.reason == ExclusionReason::RecoveryExpired)
    );
}

// ---------------------------------------------------------------------------
// 5. CAS, pre-marked revocation guard, squatted epochs, unanchored fork recovery,
//    and non-wedging multi-device revocation
// ---------------------------------------------------------------------------

#[test]
fn epoch_member_and_mailbox_keys_enforce_create_if_absent_and_cas() {
    let space_host = MemorySpaceHost::new();
    let net = MemoryBackend::new();
    let mb = SpaceMailboxStore::for_owner(A, space_host.client(A), Box::new(net.pds_publisher(A)));
    let dev = DeviceSecrets::generate().unwrap();
    let (pending, genesis) = labyrinth::epoch::open::open_genesis(A, &dev, &signer(1)).unwrap();
    let now = "2026-11-13T00:00:00.000Z".to_owned();
    let ep = Epoch::from_record(&genesis.record, now.clone());
    let mems: Vec<EpochMember> = genesis
        .members
        .iter()
        .map(|m| EpochMember::from_record(m, now.clone()))
        .collect();

    block_on(mb.create_epoch(&ep, &mems)).unwrap();
    assert_eq!(
        block_on(mb.create_epoch(&ep, &mems)).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        block_on(mb.create_epoch_member(&mems[0])).unwrap_err(),
        Error::Conflict
    );
    let _ = pending.assign_id(space_epoch_id(0));

    // Public repo `PdsRecords` enforces create-if-absent (`None`) and `swapRecord` CAS (`Some`).
    let pub_repo = MemoryPublicRepo::default();
    let pds = PdsRecords::new(&pub_repo);
    let mk = MailboxKeysRecord::from_public(&genesis.record.public, None, now);
    let cid1 = block_on(pds.put_mailbox_keys_cas(A, "self", &mk, None)).unwrap();
    assert_eq!(
        block_on(pds.put_mailbox_keys_cas(A, "self", &mk, None)).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        block_on(pds.put_mailbox_keys_cas(A, "self", &mk, Some("bafyreiwrong"))).unwrap_err(),
        Error::Conflict
    );
    let _cid2 = block_on(pds.put_mailbox_keys_cas(A, "self", &mk, Some(&cid1))).unwrap();
}

#[test]
fn premarked_revoked_at_never_bypasses_revoke_chat_device_rotation() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let mut laptop = sibling(&net, &clock, &mut phone, 2);
    block_on(phone.sync_epochs()).unwrap();

    // Even if `laptop` already carries `revokedAt` on its `Device` record while
    // still an active `epochMember` of epoch 1, `revoke_chat_device(&tpub(2))`
    // MUST still rotate `laptop` out rather than returning an empty report list.
    let laptop_key = laptop.device_public().device_key_pub;
    let now = datetime_from_ms(clock.now_ms());
    let mb = net.mailbox(A);
    block_on(mb.set_device_revoked(&laptop_key, &now)).unwrap();
    net.remove_chat_device(A, tpub(2), clock.now_ms() + 1);
    clock.advance(5);

    let reports = block_on(phone.revoke_chat_device(&tpub(2))).unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].new_epoch, 2);
    assert_eq!(
        block_on(laptop.sync_epochs()).unwrap_err(),
        Error::NotEpochMember
    );
}

#[test]
fn clear_squatted_epoch_preserves_valid_sibling_epoch() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);

    // Enroll `laptop` with a failing directory publisher so `epoch 1` is written to
    // the mailbox by a valid sibling (`laptop`) but NOT yet anchored in the directory.
    let fail_publish = Arc::new(AtomicBool::new(true));
    let laptop_mb = FailPublishMailbox::new(net.mailbox(A), fail_publish);
    let mut responder = phone.otc_offer().unwrap();
    let typed = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(A, &typed).unwrap();
    let reply = block_on(phone.otc_respond(&mut responder, &hello)).unwrap();
    net.register_chat_device(A, tpub(2));
    let (_laptop, enrollment) = block_on(Labyrinth::enroll_via_otc(
        A,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(2)),
        backends_with(&net, &clock, A, Box::new(laptop_mb), vec![]),
    ))
    .unwrap();
    assert!(enrollment.unfinished.is_some());

    // `phone.clear_squatted_epoch(1)` must NOT delete `laptop`'s valid sibling epoch 1;
    // instead it adopts epoch 1 and returns `Ok(false)`.
    assert!(!block_on(phone.clear_squatted_epoch(1)).unwrap());
    assert_eq!(phone.latest_epoch(), 1);
    assert!(block_on(net.mailbox(A).get_epoch(1)).unwrap().is_some());
}

#[test]
fn unanchored_revocation_reports_error_and_recovers_losing_fork() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let laptop = sibling(&net, &clock, &mut phone, 2);
    let mut tablet = sibling(&net, &clock, &mut phone, 3);
    block_on(phone.sync_epochs()).unwrap();
    let mut laptop = laptop;
    block_on(laptop.sync_epochs()).unwrap();

    // Isolate `laptop` onto a temporary local mailbox buffer whose directory
    // publish fails, simulating an unanchored local rotation `2 -> 3` that loses
    // the directory race to `tablet` anchoring `2 -> 3` on the shared mailbox.
    let local_fork_net = MemoryBackend::new();
    let shared_mb = net.mailbox(A);
    let fork_mb = local_fork_net.mailbox(A);
    for dev in block_on(shared_mb.list_devices()).unwrap() {
        block_on(fork_mb.create_device(&dev)).unwrap();
    }
    for ep in block_on(shared_mb.list_epochs()).unwrap() {
        let mems = block_on(shared_mb.list_epoch_members(ep.value.seq())).unwrap();
        block_on(fork_mb.create_epoch(&ep.value, &mems)).unwrap();
    }

    let laptop_state = laptop.export_state().unwrap();
    let fail_pub = Arc::new(AtomicBool::new(true));
    let mut laptop_fork = block_on(Labyrinth::from_state(
        &laptop_state,
        A,
        Box::new(signer(2)),
        backends_with(
            &net,
            &clock,
            A,
            Box::new(FailPublishMailbox::new(fork_mb, fail_pub)),
            vec![],
        ),
    ))
    .unwrap();

    // Remove `phone`'s chat device so revocation is permitted, then revoke `phone`
    // on `laptop_fork`: mailbox write commits to `fork_mb`, directory publish fails -> `EpochUnanchored`.
    net.remove_chat_device(A, tpub(1), clock.now_ms() + 1);
    clock.advance(5);
    let phone_key = phone.device_public().device_key_pub;
    let err = block_on(laptop_fork.revoke_device(&phone_key)).unwrap_err();
    assert!(matches!(err, Error::EpochUnanchored { seq: 3, .. }));
    assert_eq!(laptop_fork.last_unanchored_rotation().unwrap().new_epoch, 3);
    assert!(block_on(laptop_fork.retry_pending_directory_publication()).is_err());

    // Meanwhile on the shared mailbox, `tablet` opens and anchors a competing epoch 3
    // that still carries `phone`, then `tpub(1)` is removed again.
    net.register_chat_device(A, tpub(1));
    let tablet_rot = block_on(tablet.rotate_epoch()).unwrap();
    assert_eq!(tablet_rot.new_epoch, 3);
    net.remove_chat_device(A, tpub(1), clock.now_ms() + 1);
    clock.advance(5);

    // Reconnect `laptop` (from its persisted unanchored state) to the shared mailbox
    // and call `recover_unanchored_fork()`: it rolls back unanchored local epoch 3,
    // adopts `tablet`'s anchored epoch 3, sees `phone_key` is still present, and
    // immediately rotates to epoch 4 evicting `phone_key`!
    let unanchored_state = laptop_fork.export_state().unwrap();
    let mut laptop_recovered = block_on(Labyrinth::from_state(
        &unanchored_state,
        A,
        Box::new(signer(2)),
        backends(&net, &clock, A),
    ))
    .unwrap();
    let recovery_rot = block_on(laptop_recovered.recover_unanchored_fork())
        .unwrap()
        .expect("must rotate immediately to evict locally revoked phone on winning fork");
    assert_eq!(recovery_rot.new_epoch, 4);
    assert_eq!(laptop_recovered.latest_epoch(), 4);
    assert!(!block_on(laptop_recovered.retry_pending_directory_publication()).unwrap());
    assert_eq!(
        block_on(phone.sync_epochs()).unwrap_err(),
        Error::NotEpochMember
    );
    assert_eq!(block_on(tablet.sync_epochs()).unwrap().to, 4);
}

#[test]
fn pending_revocation_keeps_archiving_available_supports_multi_revoke_and_cancel() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let faulty = Faulty::new(net.mailbox(A));
    net.register_chat_device(A, tpub(1));
    let mut laptop = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(faulty.clone()), vec![]),
    ))
    .unwrap();
    let phone = sibling(&net, &clock, &mut laptop, 2);
    let tablet = sibling(&net, &clock, &mut laptop, 3);
    let watch = sibling(&net, &clock, &mut laptop, 4);

    net.remove_chat_device(A, tpub(2), clock.now_ms() + 1);
    net.remove_chat_device(A, tpub(3), clock.now_ms() + 1);
    net.remove_chat_device(A, tpub(4), clock.now_ms() + 1);
    clock.advance(10);

    // Outage blocks epoch creation during `revoke_device(phone)`.
    faulty.fail_epochs.store(true, Ordering::SeqCst);
    let phone_key = phone.device_public().device_key_pub;
    let tablet_key = tablet.device_public().device_key_pub;
    let watch_key = watch.device_public().device_key_pub;

    assert!(matches!(
        block_on(laptop.revoke_device(&phone_key)),
        Err(Error::Backend(_))
    ));
    let pending: Vec<XVerifyingKey> = laptop.pending_revocation_devices().collect();
    assert_eq!(pending, vec![phone_key]);

    // Cancel check on a second pending revocation (`watch_key`).
    assert!(matches!(
        block_on(laptop.revoke_device(&watch_key)),
        Err(Error::Backend(_))
    ));
    assert!(laptop.cancel_pending_revocation(&watch_key).unwrap());
    assert!(!laptop.cancel_pending_revocation(&watch_key).unwrap());

    // Archiving owner & outgoing messages remains non-wedging while `phone_key` is pending!
    block_on(laptop.archive_owner(T, "own-1", 100, b"owner archive works")).unwrap();
    queue_outgoing(
        &mut laptop,
        T,
        &[A],
        "out-1",
        101,
        b"outgoing archive works",
    );
    block_on(laptop.flush()).unwrap();

    // Once storage recovers, revoking `tablet_key` evicts BOTH `phone_key` and `tablet_key` in one rotation!
    faulty.fail_epochs.store(false, Ordering::SeqCst);
    let rot = block_on(laptop.revoke_device(&tablet_key)).unwrap();
    assert_eq!(rot.new_epoch, 4);
    assert!(rot.evicted_revoked.contains(&phone_key));
    assert_eq!(laptop.pending_revocation_devices().count(), 0);

    let e4_members = block_on(net.mailbox(A).list_epoch_members(4)).unwrap();
    let member_keys: BTreeSet<[u8; 32]> = e4_members
        .iter()
        .map(|m| m.device_key_pubkey.0.as_slice().try_into().unwrap())
        .collect();
    assert!(member_keys.contains(&laptop.device_public().device_key_pub.0));
    assert!(!member_keys.contains(&phone_key.0));
    assert!(!member_keys.contains(&tablet_key.0));
}

// ---------------------------------------------------------------------------
// 6. Per-author restore quarantine & bounded MEK lookup budget
// ---------------------------------------------------------------------------

#[test]
fn per_author_quarantine_isolates_corrupt_repos_timestamps_non_participants_and_mek_misses() {
    let space_host = MemorySpaceHost::new();
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let conv_space = SpaceRef::conversation("did:plc:alice", T);

    for did in [A, B, C, D, E, M] {
        space_host.grant_space_member(&conv_space, did);
    }

    let make_space_client = |did: &str, seed: u8, count_meks: Option<Arc<AtomicUsize>>| {
        net.register_chat_device(did, tpub(seed));
        let mb = SpaceMailboxStore::for_owner(
            did,
            space_host.client(did),
            Box::new(net.pds_publisher(did)),
        );
        let st =
            SpaceThreadStore::new(space_host.client(did), did).with_authority_did("did:plc:alice");
        let threads: Box<dyn ThreadStore> = match count_meks {
            Some(counter) => Box::new(CountingThreads {
                inner: Box::new(st),
                find_mek_calls: counter,
            }),
            None => Box::new(st),
        };
        let b = Backends {
            mailbox: Box::new(mb),
            threads,
            directory: Box::new(net.directory()),
            publishers: vec![],
            clock: Box::new(clock.clone()),
        };
        block_on(Labyrinth::initialize(did, Box::new(signer(seed)), b)).unwrap()
    };

    let find_calls = Arc::new(AtomicUsize::new(0));
    let mut alice = make_space_client(A, 1, Some(find_calls.clone()));
    let mut bob = make_space_client(B, 2, None);
    let mut carol = make_space_client(C, 3, None);
    let mut dave = make_space_client(D, 4, None);
    let mut erin = make_space_client(E, 5, None);
    let mut mallory = make_space_client(M, 6, None);

    // Register MLS leaves for `[A, B, C, D, E]` ONLY (`M` is a non-participant in MLS).
    for (did, seed) in [(A, 1), (B, 2), (C, 3), (D, 4), (E, 5)] {
        net.add_leaf(T, did, tpub(seed));
    }

    let participants = [A, B, C, D, E];
    queue_outgoing(
        &mut alice,
        T,
        &participants,
        "a-honest",
        100,
        b"hello from alice",
    );
    block_on(alice.flush()).unwrap();
    queue_outgoing(
        &mut bob,
        T,
        &participants,
        "b-honest",
        200,
        b"hello from bob",
    );
    block_on(bob.flush()).unwrap();

    // 1) Non-participant `Mallory` writes a batch into the Space.
    queue_outgoing(&mut mallory, T, &[M, A], "m-intruder", 250, b"intruder");
    block_on(mallory.flush()).unwrap();

    // 2) `Carol`'s Space repo gets a corrupt `batch` record that fails schema parsing.
    space_host.tamper(
        &conv_space,
        C,
        nsid::BATCH,
        "0000000000000099-corrupt",
        json!({ "$type": nsid::BATCH, "threadId": 12345 }),
    );
    let _ = &mut carol;

    // 3) `Dave` writes a batch containing an out-of-range timestamp (`(i64::MAX as u64) + 1`).
    let dave_threads =
        SpaceThreadStore::new(space_host.client(D), D).with_authority_did("did:plc:alice");
    block_on(dave_threads.append_batch(&Batch {
        type_: nsid::BATCH.into(),
        thread_id: T.into(),
        items: vec![SealedMessageDef {
            message_id: "d-overflow-ts".into(),
            seq: None,
            timestamp: (i64::MAX as u64) + 1,
            mek_id: Bytes(vec![0xAA; 12]),
            sender_transport_pubkey: Bytes::from_slice(&tpub(4)),
            signed_enc_message: Bytes(vec![1, 2, 3]),
            sequencer_receipt: None,
            redaction: None,
        }],
        created_at: "2026-11-13T00:00:00.000Z".into(),
    }))
    .unwrap();
    let _ = &mut dave;

    // 4) `Erin` writes 20 items repeating the SAME missing `mek_id` plus 25 items with
    //    distinct missing `mek_id`s (45 items total). Negative caching deduplicates the
    //    20 repeated items into 1 lookup, and the per-author budget caps total misses at 16!
    let erin_threads =
        SpaceThreadStore::new(space_host.client(E), E).with_authority_did("did:plc:alice");
    let mut spam_items = Vec::new();
    for i in 0..20u32 {
        spam_items.push(SealedMessageDef {
            message_id: format!("e-repeat-{i}"),
            seq: None,
            timestamp: 300 + u64::from(i),
            mek_id: Bytes(vec![0xFE; 12]),
            sender_transport_pubkey: Bytes::from_slice(&tpub(5)),
            signed_enc_message: Bytes(vec![9, 9, 9]),
            sequencer_receipt: None,
            redaction: None,
        });
    }
    for i in 0..25u8 {
        let mut id = [0x80u8; 12];
        id[0] = i;
        spam_items.push(SealedMessageDef {
            message_id: format!("e-distinct-{i}"),
            seq: None,
            timestamp: 400 + u64::from(i),
            mek_id: Bytes(id.to_vec()),
            sender_transport_pubkey: Bytes::from_slice(&tpub(5)),
            signed_enc_message: Bytes(vec![9, 9, 9]),
            sequencer_receipt: None,
            redaction: None,
        });
    }
    block_on(erin_threads.append_batch(&Batch {
        type_: nsid::BATCH.into(),
        thread_id: T.into(),
        items: spam_items,
        created_at: "2026-11-13T00:00:00.000Z".into(),
    }))
    .unwrap();
    let _ = &mut erin;

    find_calls.store(0, Ordering::SeqCst);
    let h = block_on(alice.load_thread(T, TimeRange::ALL)).unwrap();

    // Honest messages from Alice and Bob restore 100% intact!
    let honest_ids: Vec<&str> = h.messages.iter().map(|m| m.message_id.as_str()).collect();
    assert_eq!(honest_ids, vec!["a-honest", "b-honest"]);

    // Every misbehaving repository was isolated with its exact `QuarantineReason`.
    let has_q = |author: &str, reason: QuarantineReason| {
        h.quarantined
            .iter()
            .any(|q| q.author == author && q.reason == reason)
    };
    assert!(has_q(M, QuarantineReason::NonParticipant));
    assert!(has_q(C, QuarantineReason::MalformedRecord));
    assert!(has_q(D, QuarantineReason::TimestampOutOfRange));
    assert!(has_q(E, QuarantineReason::ExcessiveMekMisses));

    // Total `find_meks` calls: 1 for Bob's valid MEK + 16 capped misses for Erin = 17!
    let total_mek_queries = find_calls.load(Ordering::SeqCst);
    assert!(
        total_mek_queries <= 17,
        "expected <= 17 find_meks queries (1 valid + 16 capped misses), got {total_mek_queries}"
    );
}

// ---------------------------------------------------------------------------
// 7. Per-flush directory cache & pre-commit roster re-validation
// ---------------------------------------------------------------------------

#[test]
fn per_flush_directory_cache_batches_message_queuing_and_revalidates_on_flush() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let counting_dir = CountingDirectory::new(net.directory());

    net.register_chat_device(A, tpub(1));
    let mut alice = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        Backends {
            mailbox: Box::new(net.mailbox(A)),
            threads: Box::new(net.threads(A)),
            directory: Box::new(counting_dir.clone()),
            publishers: vec![],
            clock: Box::new(clock.clone()),
        },
    ))
    .unwrap();

    let mut bob = init(&net, &clock, B, 2);
    let _carol = init(&net, &clock, C, 3);
    let _dave = init(&net, &clock, D, 4);
    let _erin = init(&net, &clock, E, 5);

    let group = [A, B, C, D, E];
    counting_dir.reset();

    // Resolve the 5-member roster once for the batch, then queue 25 outgoing
    // messages across 2 conversations (`T` and `"thread-2"`) before flushing.
    let roster = block_on(alice.resolve_roster(&group)).unwrap();
    for i in 0..25u64 {
        let target_thread = if i % 2 == 0 { T } else { "thread-2" };
        block_on(alice.archive_outgoing(
            target_thread,
            &roster,
            &format!("msg-{i}"),
            1_000 + i,
            b"cached roster send",
        ))
        .unwrap();
    }

    // Before `flush()`, each peer was queried at most once (`O(N)` total, independent of M=25).
    for peer in [B, C, D, E] {
        assert_eq!(
            counting_dir.peer_latest_calls(peer),
            1,
            "peer {peer} latest_calls during 25 queued messages should be 1"
        );
        assert_eq!(
            counting_dir.peer_transport_calls(peer),
            1,
            "peer {peer} transport_calls during 25 queued messages should be 1"
        );
    }

    block_on(alice.flush()).unwrap();

    // `flush()` performs one fresh directory re-validation per peer (`1 + 1 = 2` total, never 25+).
    for peer in [B, C, D, E] {
        assert_eq!(counting_dir.peer_latest_calls(peer), 2);
        assert_eq!(counting_dir.peer_transport_calls(peer), 2);
    }

    // Verify that if a peer rotates AFTER `archive_outgoing` and BEFORE `flush()`,
    // `flush()` bypasses the cache, detects the fresh epoch change, and returns `RosterMismatch`!
    queue_outgoing(
        &mut alice,
        T,
        &group,
        "stale-roster",
        2_000,
        b"before bob rotates",
    );
    block_on(bob.rotate_epoch()).unwrap();
    assert_eq!(block_on(alice.flush()).unwrap_err(), Error::RosterMismatch);
}

// ---------------------------------------------------------------------------
// 8. Property tests (`proptest`)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn prop_virtual_device_and_revocation_mutations_fail_closed(
        field_idx in 0usize..4,
        byte_offset in 0usize..256,
        flip_mask in 1u8..=255u8,
        sig_byte in 0usize..64,
    ) {
        let did = "did:plc:prop";
        let opener = DeviceSecrets::generate().unwrap();
        let target = DeviceSecrets::generate().unwrap();
        let epoch = EpochSecret::from_parts(3, space_epoch_id(3), [0x5Au8; 32]);
        let code = RecoveryCode::generate().unwrap();
        let ts = "2026-11-13T12:00:00.000Z";

        // 1) VirtualDeviceRecord mutations fail closed on `validate_shape` or `open`.
        let (rec, _) = virtual_device::create_at(
            did,
            &code,
            &opener,
            &epoch,
            Mechanism::Passkey,
            ts,
        ).unwrap();
        rec.validate_shape(Some(did)).unwrap();
        prop_assert!(virtual_device::open(&rec, &code, did).is_ok());

        let mut mutated = rec.clone();
        {
            let buf = match field_idx {
                0 => &mut mutated.encrypted_device_key_priv,
                1 => &mut mutated.encrypted_epoch_storage_key_priv,
                2 => &mut mutated.encrypted_epoch_root_key,
                _ => &mut mutated.encrypted_epoch_number,
            };
            let idx = byte_offset % buf.len();
            buf[idx] ^= flip_mask;
        }
        prop_assert!(virtual_device::open(&mutated, &code, did).is_err());

        let mut bad_sig = rec;
        bad_sig.metadata_sig.as_mut().unwrap()[sig_byte] ^= flip_mask;
        prop_assert!(bad_sig.validate_shape(Some(did)).is_err());
        prop_assert!(virtual_device::open(&bad_sig, &code, did).is_err());

        // 2) DeviceRevocation mutations fail closed on `verify`.
        let rev = DeviceRevocation::sign(
            did,
            &target.public().device_key_pub,
            ts,
            &opener.device_key,
        ).unwrap();
        rev.verify(did, &target.public().device_key_pub, ts).unwrap();

        let mut tampered_rev = rev;
        tampered_rev.sig[sig_byte] ^= flip_mask;
        prop_assert!(tampered_rev.verify(did, &target.public().device_key_pub, ts).is_err());
        prop_assert!(rev.verify("did:plc:wrong", &target.public().device_key_pub, ts).is_err());
        prop_assert!(rev.verify(did, &opener.public().device_key_pub, ts).is_err());
        prop_assert!(rev.verify(did, &target.public().device_key_pub, "2026-11-13T12:00:00.001Z").is_err());
    }

    #[test]
    fn prop_omitted_initial_members_fail_members_hash_while_virtual_additions_verify(
        n_siblings in 1usize..=4,
        omit_bits in 1u8..16u8,
        n_virtual in 0usize..=2,
    ) {
        let net = MemoryBackend::new();
        let clock = TestClock::default();
        let mut primary = init(&net, &clock, A, 1);
        let mut sib_keys = Vec::new();
        for i in 0..n_siblings {
            let s = sibling(&net, &clock, &mut primary, (i as u8) + 2);
            sib_keys.push(s.device_public().device_key_pub);
        }
        block_on(primary.sync_epochs()).unwrap();
        let latest_seq = primary.latest_epoch();

        let mut last_code = None;
        for _ in 0..n_virtual {
            last_code = Some(block_on(primary.create_recovery_code(Mechanism::Code)).unwrap());
        }
        let state = primary.export_state().unwrap();

        // Intact store (including `n_virtual` mid-epoch virtual additions) verifies cleanly.
        let reloaded = block_on(Labyrinth::from_state(
            &state,
            A,
            Box::new(signer(1)),
            backends(&net, &clock, A),
        ));
        prop_assert!(reloaded.is_ok());

        // Omit at least one initial sibling according to `omit_bits`.
        let omit_mb = OmitMembersMailbox::new(net.mailbox(A));
        let mut any_omitted = false;
        for (idx, key) in sib_keys.iter().enumerate() {
            if (omit_bits & (1 << idx)) != 0 {
                omit_mb.omit(latest_seq, *key);
                any_omitted = true;
            }
        }
        if !any_omitted {
            omit_mb.omit(latest_seq, sib_keys[0]);
        }

        let err = block_on(Labyrinth::from_state(
            &state,
            A,
            Box::new(signer(1)),
            backends_with(&net, &clock, A, Box::new(omit_mb.clone()), vec![]),
        ))
        .map(|_| ())
        .unwrap_err();
        prop_assert_eq!(err, Error::MemberTampered { seq: latest_seq });

        if let Some(code) = last_code {
            net.register_chat_device(A, tpub(20));
            let r_err = block_on(Labyrinth::restore_with_recovery_code(
                A,
                code.code.as_str(),
                Box::new(signer(20)),
                backends_with(&net, &clock, A, Box::new(omit_mb), vec![]),
            ))
            .map(|_| ())
            .unwrap_err();
            prop_assert_eq!(r_err, Error::MemberTampered { seq: latest_seq });
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn prop_quarantine_preserves_honest_messages_and_bounds_mek_lookups(
        n_alice in 1usize..=5,
        n_bob in 1usize..=5,
        n_missing_meks in 0usize..=30,
        inject_overflow_ts in any::<bool>(),
    ) {
        let net = MemoryBackend::new();
        let clock = TestClock::default();
        let find_calls = Arc::new(AtomicUsize::new(0));

        net.register_chat_device(A, tpub(1));
        let mut alice = block_on(Labyrinth::initialize(
            A,
            Box::new(signer(1)),
            Backends {
                mailbox: Box::new(net.mailbox(A)),
                threads: Box::new(CountingThreads {
                    inner: Box::new(net.threads(A)),
                    find_mek_calls: find_calls.clone(),
                }),
                directory: Box::new(net.directory()),
                publishers: vec![],
                clock: Box::new(clock.clone()),
            },
        ))
        .unwrap();
        let mut bob = init(&net, &clock, B, 2);
        let _carol = init(&net, &clock, C, 3);

        for (did, seed) in [(A, 1), (B, 2), (C, 3)] {
            net.add_leaf(T, did, tpub(seed));
        }
        let group = [A, B, C];
        let mut expected_ids = Vec::new();
        let mut ts = 1_000u64;

        for i in 0..n_alice {
            let id = format!("a-{i}");
            ts += 10;
            queue_outgoing(&mut alice, T, &group, &id, ts, b"honest-a");
            expected_ids.push(id);
        }
        block_on(alice.flush()).unwrap();

        for i in 0..n_bob {
            let id = format!("b-{i}");
            ts += 10;
            queue_outgoing(&mut bob, T, &group, &id, ts, b"honest-b");
            expected_ids.push(id);
        }
        block_on(bob.flush()).unwrap();

        if inject_overflow_ts || n_missing_meks > 0 {
            let carol_threads = net.threads(C);
            let mut items = Vec::new();
            if inject_overflow_ts {
                items.push(SealedMessageDef {
                    message_id: "c-bad-ts".into(),
                    seq: None,
                    timestamp: (i64::MAX as u64) + 42,
                    mek_id: Bytes(vec![0xAA; 12]),
                    sender_transport_pubkey: Bytes::from_slice(&tpub(3)),
                    signed_enc_message: Bytes(vec![1, 2, 3]),
                    sequencer_receipt: None,
                    redaction: None,
                });
            }
            for i in 0..n_missing_meks {
                let mut mid = [0xCCu8; 12];
                mid[0] = i as u8;
                ts += 1;
                items.push(SealedMessageDef {
                    message_id: format!("c-miss-{i}"),
                    seq: None,
                    timestamp: ts,
                    mek_id: Bytes(mid.to_vec()),
                    sender_transport_pubkey: Bytes::from_slice(&tpub(3)),
                    signed_enc_message: Bytes(vec![4, 5, 6]),
                    sequencer_receipt: None,
                    redaction: None,
                });
            }
            block_on(carol_threads.append_batch(&Batch {
                type_: nsid::BATCH.into(),
                thread_id: T.into(),
                items,
                created_at: "2026-11-13T00:00:00.000Z".into(),
            }))
            .unwrap();
        }

        find_calls.store(0, Ordering::SeqCst);
        let h = block_on(alice.load_thread(T, TimeRange::ALL)).unwrap();
        let got_ids: Vec<String> = h.messages.iter().map(|m| m.message_id.clone()).collect();
        prop_assert_eq!(got_ids, expected_ids);

        // `find_meks` calls: at most 1 for Bob's valid MEK + min(n_missing_meks, 16) for Carol.
        let calls = find_calls.load(Ordering::SeqCst);
        prop_assert!(calls <= 1 + n_missing_meks.min(16));
        if n_missing_meks > 16 {
            prop_assert!(
                h.quarantined
                    .iter()
                    .any(|q| q.author == C && q.reason == QuarantineReason::ExcessiveMekMisses)
            );
        }
        if inject_overflow_ts {
            prop_assert!(
                h.quarantined
                    .iter()
                    .any(|q| q.author == C && q.reason == QuarantineReason::TimestampOutOfRange)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 9. Multi-device conflict / transient failure during physical revocation rekey,
//    signed self-revocation check in `clear_squatted_epoch`, and `set_device_revocation`
//    replacement of forged or malformed pre-populated revocations
// ---------------------------------------------------------------------------

type ConflictHook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

/// Mailbox wrapper whose first `create_epoch` call runs an interleaved sibling
/// operation (such as a concurrent sibling `rotate_epoch`) and returns `Error::Conflict`.
#[derive(Clone)]
struct ConflictOnceEpochMailbox {
    inner: Arc<MemoryMailbox>,
    on_first_create_epoch: ConflictHook,
}

impl ConflictOnceEpochMailbox {
    fn new(inner: MemoryMailbox, hook: impl FnOnce() + Send + 'static) -> Self {
        Self {
            inner: Arc::new(inner),
            on_first_create_epoch: Arc::new(Mutex::new(Some(Box::new(hook)))),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for ConflictOnceEpochMailbox {
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
        rev: &DeviceRevocationDef,
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
        let hook = self.on_first_create_epoch.lock().unwrap().take();
        if let Some(f) = hook {
            f();
            return Err(Error::Conflict);
        }
        self.inner.create_epoch(e, m).await
    }
    async fn atomic_enroll(&self, b: &AtomicEnrollBundle) -> labyrinth::Result<String> {
        self.inner.atomic_enroll(b).await
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
    async fn delete_squatted_epoch(&self, s: u64) -> labyrinth::Result<()> {
        self.inner.delete_squatted_epoch(s).await
    }
}

#[test]
fn physical_revocation_rekey_survives_conflict_and_transient_epoch_write_failure() {
    // Part A: Transient `create_epoch` failure does not prematurely mark existing
    // virtual recovery methods revoked or leak orphaned `virtualDevice` bundles.
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let faulty = Faulty::new(net.mailbox(A));
    net.register_chat_device(A, tpub(1));
    let mut phone = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(faulty.clone()), vec![]),
    ))
    .unwrap();
    let laptop = sibling(&net, &clock, &mut phone, 2);
    block_on(phone.sync_epochs()).unwrap();

    let old_code = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let old_keychain = block_on(phone.create_recovery_code(Mechanism::Keychain)).unwrap();
    assert_eq!(block_on(phone.list_recovery_methods()).unwrap().len(), 2);

    net.remove_chat_device(A, tpub(2), clock.now_ms() + 1);
    clock.advance(10);
    let laptop_key = laptop.device_public().device_key_pub;

    faulty.fail_epochs.store(true, Ordering::SeqCst);
    assert!(matches!(
        block_on(phone.revoke_device(&laptop_key)),
        Err(Error::Backend(_))
    ));
    // Existing virtual recovery bundles remain intact and unrevoked before epoch commit.
    let mid_methods = block_on(phone.list_recovery_methods()).unwrap();
    assert_eq!(mid_methods.len(), 2);
    assert!(mid_methods.iter().all(|m| !m.revoked));
    assert_eq!(
        block_on(net.mailbox(A).list_virtual_devices())
            .unwrap()
            .len(),
        2
    );

    faulty.fail_epochs.store(false, Ordering::SeqCst);
    let rot_a = block_on(phone.revoke_device(&laptop_key)).unwrap();
    assert_eq!(rot_a.invalidated_recovery_methods.len(), 2);
    let repl_a = rot_a
        .rekeyed_recovery
        .as_ref()
        .expect("retry after transient failure must still mint replacement recovery method");
    let after_a = block_on(phone.list_recovery_methods()).unwrap();
    assert_eq!(after_a.len(), 1);
    assert_eq!(after_a[0].vdevice_id, repl_a.vdevice_id);

    for stale in [old_code.code.as_str(), old_keychain.code.as_str()] {
        net.register_chat_device(A, tpub(8));
        assert_eq!(
            block_on(Labyrinth::restore_with_recovery_code(
                A,
                stale,
                Box::new(signer(8)),
                backends(&net, &clock, A),
            ))
            .map(|_| ())
            .unwrap_err(),
            Error::BadRecoveryCode
        );
    }
    net.register_chat_device(A, tpub(9));
    let (_restored_a, _) = block_on(Labyrinth::restore_with_recovery_code(
        A,
        repl_a.code.as_str(),
        Box::new(signer(9)),
        backends(&net, &clock, A),
    ))
    .unwrap();

    // Part B: Multi-device `Error::Conflict` on `create_epoch` (sibling `tablet` wins
    // `epoch 3` while `phone` is revoking `laptop` with `rekey_virtual_methods == true`).
    let net2 = MemoryBackend::new();
    let clock2 = TestClock::default();
    let mut phone2 = init(&net2, &clock2, A, 1);
    let laptop2 = sibling(&net2, &clock2, &mut phone2, 2);
    let mut tablet2 = sibling(&net2, &clock2, &mut phone2, 3);
    block_on(phone2.sync_epochs()).unwrap();
    block_on(tablet2.sync_epochs()).unwrap();

    let _c1 = block_on(phone2.create_recovery_code(Mechanism::Code)).unwrap();
    let _c2 = block_on(phone2.create_recovery_code(Mechanism::Keychain)).unwrap();
    let phone2_state = phone2.export_state().unwrap();

    let conflict_mb = ConflictOnceEpochMailbox::new(net2.mailbox(A), move || {
        // Concurrent sibling `tablet2` wins epoch 3 while carrying the active virtual methods.
        std::thread::spawn(move || {
            let r = block_on(tablet2.rotate_epoch()).unwrap();
            assert_eq!(r.new_epoch, 3);
        })
        .join()
        .unwrap();
    });
    let mut phone2_racing = block_on(Labyrinth::from_state(
        &phone2_state,
        A,
        Box::new(signer(1)),
        backends_with(&net2, &clock2, A, Box::new(conflict_mb), vec![]),
    ))
    .unwrap();

    net2.remove_chat_device(A, tpub(2), clock2.now_ms() + 1);
    clock2.advance(10);
    let laptop2_key = laptop2.device_public().device_key_pub;
    let rot_b = block_on(phone2_racing.revoke_device(&laptop2_key)).unwrap();
    assert_eq!(rot_b.new_epoch, 4);
    assert_eq!(rot_b.invalidated_recovery_methods.len(), 2);
    let repl_b = rot_b
        .rekeyed_recovery
        .as_ref()
        .expect("Conflict retry must preserve recovery methods by minting replacement code");
    let after_b = block_on(phone2_racing.list_recovery_methods()).unwrap();
    assert_eq!(after_b.len(), 1);
    assert_eq!(after_b[0].vdevice_id, repl_b.vdevice_id);
    assert_eq!(
        block_on(net2.mailbox(A).list_virtual_devices())
            .unwrap()
            .len(),
        1
    );

    net2.register_chat_device(A, tpub(10));
    let (_restored_b, _) = block_on(Labyrinth::restore_with_recovery_code(
        A,
        repl_b.code.as_str(),
        Box::new(signer(10)),
        backends(&net2, &clock2, A),
    ))
    .unwrap();
}

#[test]
fn clear_squatted_epoch_ignores_unsigned_or_forged_self_revocation_and_honors_signed() {
    let space_host = MemorySpaceHost::new();
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let space = SpaceRef::mailbox(A);
    let make_backends = |seed_net: &MemoryBackend| {
        let mb = SpaceMailboxStore::for_owner(
            A,
            space_host.client(A),
            Box::new(seed_net.pds_publisher(A)),
        );
        backends_with(seed_net, &clock, A, Box::new(mb), vec![])
    };

    net.register_chat_device(A, tpub(1));
    let mut phone = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        make_backends(&net),
    ))
    .unwrap();

    // Enroll `laptop` (`tpub(2)`) so we also have a second bound physical device.
    let mut r1 = phone.otc_offer().unwrap();
    let c1 = r1.code().as_str().to_owned();
    let (i1, h1) = Labyrinth::otc_start(A, &c1).unwrap();
    let rep1 = block_on(phone.otc_respond(&mut r1, &h1)).unwrap();
    net.register_chat_device(A, tpub(2));
    let (mut laptop, _) = block_on(Labyrinth::enroll_via_otc(
        A,
        i1,
        &rep1.message,
        &rep1.sealed_payload,
        Box::new(signer(2)),
        make_backends(&net),
    ))
    .unwrap();
    block_on(phone.sync_epochs()).unwrap();
    assert_eq!(phone.latest_epoch(), 1);

    let phone_key = phone.device_public().device_key_pub;
    let phone_rkey = hex::encode(phone_key.0);
    let orig_phone_dev = space_host
        .record(&space, A, nsid::DEVICE, &phone_rkey)
        .unwrap();

    let plant_squatted_epoch_2 = |host: &MemorySpaceHost| {
        let squatter = DeviceSecrets::generate().unwrap();
        let (_, fake_gen) =
            labyrinth::epoch::open::open_genesis(A, &squatter, &signer(99)).unwrap();
        let mut fake_rec = fake_gen.record;
        fake_rec.public.seq = 2;
        fake_rec.public.prev_head = Some([0x77; 32]);
        let ep = Epoch::from_record(&fake_rec, "2026-11-13T00:00:00.000Z".into());
        let mb = SpaceMailboxStore::for_owner(A, host.client(A), Box::new(net.pds_publisher(A)));
        block_on(mb.create_epoch(&ep, &[])).unwrap();
    };

    // 1) Unsigned `revokedAt` stamped on `phone`'s own `Device` record must NOT block `clear_squatted_epoch(2)`.
    plant_squatted_epoch_2(&space_host);
    let mut unsigned_dev: Device = serde_json::from_value(orig_phone_dev.clone()).unwrap();
    unsigned_dev.revoked_at = Some("2026-11-13T01:00:00.000Z".into());
    unsigned_dev.revocation = None;
    space_host.tamper(
        &space,
        A,
        nsid::DEVICE,
        &phone_rkey,
        serde_json::to_value(&unsigned_dev).unwrap(),
    );
    assert!(block_on(phone.clear_squatted_epoch(2)).unwrap());

    // 2) Forged outsider `revocation` stamped on `phone`'s own `Device` record must NOT block `clear_squatted_epoch(2)`.
    plant_squatted_epoch_2(&space_host);
    let outsider = DeviceSecrets::generate().unwrap();
    let forged_rev = DeviceRevocation::sign(
        A,
        &phone_key,
        "2026-11-13T01:00:00.000Z",
        &outsider.device_key,
    )
    .unwrap();
    let mut forged_dev: Device = serde_json::from_value(orig_phone_dev.clone()).unwrap();
    forged_dev.revoked_at = Some("2026-11-13T01:00:00.000Z".into());
    forged_dev.revocation = Some(DeviceRevocationDef::from_revocation(&forged_rev));
    space_host.tamper(
        &space,
        A,
        nsid::DEVICE,
        &phone_rkey,
        serde_json::to_value(&forged_dev).unwrap(),
    );
    assert!(block_on(phone.clear_squatted_epoch(2)).unwrap());

    // 3) Restore `phone`'s clean device record, then have attested `laptop` genuinely
    //    revoke `phone` (while `phone`'s directory view still shows `tpub(1)` current).
    //    Now `phone`'s device record carries a valid `DeviceRevocation` signed by `laptop`,
    //    so `phone.clear_squatted_epoch(2)` refuses deletion with `Error::NotEpochMember`.
    space_host.tamper(&space, A, nsid::DEVICE, &phone_rkey, orig_phone_dev);
    clock.advance(10);
    let _ = block_on(laptop.revoke_device(&phone_key)).unwrap();
    assert_eq!(
        block_on(phone.clear_squatted_epoch(2)).unwrap_err(),
        Error::NotEpochMember
    );
}

#[test]
fn set_device_revocation_replaces_forged_or_garbage_prepopulated_revocation() {
    // 1) Verify on `MemoryMailbox`
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let laptop = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    block_on(phone.sync_epochs()).unwrap();

    let phone_key = phone.device_public().device_key_pub;
    let laptop_key = laptop.device_public().device_key_pub;
    let tablet_key = tablet.device_public().device_key_pub;
    let mb = net.mailbox(A);

    // Pre-populate `laptop` with a malformed/bit-flipped signature and `tablet` with an outsider signature.
    let outsider = DeviceSecrets::generate().unwrap();
    let ts_bad = "2026-11-13T00:00:00.000Z";
    let mut bad_sig_rev =
        DeviceRevocation::sign(A, &laptop_key, ts_bad, &outsider.device_key).unwrap();
    bad_sig_rev.sig[0] ^= 0xFF;
    block_on(mb.set_device_revocation(
        &laptop_key,
        ts_bad,
        &DeviceRevocationDef::from_revocation(&bad_sig_rev),
    ))
    .unwrap();

    let outsider_rev =
        DeviceRevocation::sign(A, &tablet_key, ts_bad, &outsider.device_key).unwrap();
    block_on(mb.set_device_revocation(
        &tablet_key,
        ts_bad,
        &DeviceRevocationDef::from_revocation(&outsider_rev),
    ))
    .unwrap();

    net.remove_chat_device(A, tpub(2), clock.now_ms() + 1);
    net.remove_chat_device(A, tpub(3), clock.now_ms() + 1);
    clock.advance(20);

    block_on(phone.revoke_device(&laptop_key)).unwrap();
    block_on(phone.revoke_device(&tablet_key)).unwrap();

    for key in [laptop_key, tablet_key] {
        let stored = block_on(mb.get_device(&key)).unwrap().unwrap();
        let stored_ts = stored.revoked_at.as_deref().unwrap();
        let stored_rev = stored.revocation().unwrap().unwrap();
        assert_eq!(stored_rev.revoked_by, phone_key);
        stored_rev.verify(A, &key, stored_ts).unwrap();

        // An outsider cannot clobber `phone`'s valid revocation afterwards.
        block_on(mb.set_device_revocation(
            &key,
            ts_bad,
            &DeviceRevocationDef::from_revocation(&outsider_rev),
        ))
        .unwrap();
        let after = block_on(mb.get_device(&key)).unwrap().unwrap();
        assert_eq!(after.revocation().unwrap().unwrap().revoked_by, phone_key);
    }

    // 2) Verify on `SpaceMailboxStore` as well.
    let space_host = MemorySpaceHost::new();
    let net_s = MemoryBackend::new();
    let clock_s = TestClock::default();
    let make_space_mb =
        || SpaceMailboxStore::for_owner(A, space_host.client(A), Box::new(net_s.pds_publisher(A)));
    net_s.register_chat_device(A, tpub(1));
    let mut phone_s = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net_s, &clock_s, A, Box::new(make_space_mb()), vec![]),
    ))
    .unwrap();
    let mut r = phone_s.otc_offer().unwrap();
    let code = r.code().as_str().to_owned();
    let (init_otc, hello) = Labyrinth::otc_start(A, &code).unwrap();
    let rep = block_on(phone_s.otc_respond(&mut r, &hello)).unwrap();
    net_s.register_chat_device(A, tpub(2));
    let (laptop_s, _) = block_on(Labyrinth::enroll_via_otc(
        A,
        init_otc,
        &rep.message,
        &rep.sealed_payload,
        Box::new(signer(2)),
        backends_with(&net_s, &clock_s, A, Box::new(make_space_mb()), vec![]),
    ))
    .unwrap();
    block_on(phone_s.sync_epochs()).unwrap();

    let laptop_s_key = laptop_s.device_public().device_key_pub;
    let outsider_s_rev =
        DeviceRevocation::sign(A, &laptop_s_key, ts_bad, &outsider.device_key).unwrap();
    let space_mb = make_space_mb();
    block_on(space_mb.set_device_revocation(
        &laptop_s_key,
        ts_bad,
        &DeviceRevocationDef::from_revocation(&outsider_s_rev),
    ))
    .unwrap();

    net_s.remove_chat_device(A, tpub(2), clock_s.now_ms() + 1);
    clock_s.advance(20);
    block_on(phone_s.revoke_device(&laptop_s_key)).unwrap();

    let stored_s = block_on(space_mb.get_device(&laptop_s_key))
        .unwrap()
        .unwrap();
    let rev_s = stored_s.revocation().unwrap().unwrap();
    assert_eq!(rev_s.revoked_by, phone_s.device_public().device_key_pub);
    rev_s
        .verify(A, &laptop_s_key, stored_s.revoked_at.as_deref().unwrap())
        .unwrap();
}

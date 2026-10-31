//! Regression tests for the 2026-10-04 security review (DECISIONS.md,
//! "security review fixes"). Each test asserts the *secure* behaviour.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, Labyrinth};
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::records::{
    Bytes, Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryDirectory, MemoryMailbox};
use labyrinth::store::{ChatDeviceKey, MailboxDirectory, MailboxStore, Stored, TimeRange};
use labyrinth::virtual_device::Mechanism;

const A: &str = "did:plc:alice";
const B: &str = "did:plc:bob";

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
fn tpub(seed: u8) -> [u8; 32] {
    signer(seed).0.verifying_key().to_bytes()
}

/// Mailbox that silently ignores revocation (malicious / buggy backend),
/// and fails every epoch create while `fail_epochs` is set (a crash or
/// outage in the middle of a revocation).
struct IgnoresRevoke(
    MemoryMailbox,
    Arc<AtomicBool>,
    Arc<Mutex<Option<(XVerifyingKey, bool)>>>,
    Arc<AtomicBool>,
);
impl IgnoresRevoke {
    fn new(m: MemoryMailbox) -> Self {
        Self(
            m,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicBool::new(false)),
        )
    }
}
impl MailboxStore for IgnoresRevoke {
    fn owner(&self) -> &str {
        self.0.owner()
    }
    fn create_device(&self, d: &Device) -> labyrinth::Result<()> {
        self.0.create_device(d)
    }
    fn set_device_revoked(&self, _k: &XVerifyingKey, _at: &str) -> labyrinth::Result<()> {
        Ok(())
    }
    fn get_device(&self, k: &XVerifyingKey) -> labyrinth::Result<Option<Device>> {
        self.0.get_device(k)
    }
    fn list_devices(&self) -> labyrinth::Result<Vec<Device>> {
        self.0.list_devices()
    }
    fn create_epoch(&self, e: &Epoch, m: &[EpochMember]) -> labyrinth::Result<String> {
        if self.1.load(Ordering::Relaxed) {
            return Err(Error::Backend("injected outage".into()));
        }
        let created = self.0.create_epoch(e, m);
        if self.3.swap(false, Ordering::Relaxed) {
            created?;
            return Err(Error::Backend("committed epoch response lost".into()));
        }
        created
    }
    fn get_epoch(&self, s: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        self.0.get_epoch(s)
    }
    fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        self.0.list_epochs()
    }
    fn create_epoch_member(&self, m: &EpochMember) -> labyrinth::Result<()> {
        self.0.create_epoch_member(m)
    }
    fn list_epoch_members(&self, s: u64) -> labyrinth::Result<Vec<EpochMember>> {
        let mut members = self.0.list_epoch_members(s)?;
        if let Some((key, hide)) = *self.2.lock().unwrap() {
            if hide {
                members.retain(|member| member.device_key_pubkey.0 != key.0);
            } else if let Some(member) = members
                .iter_mut()
                .find(|member| member.device_key_pubkey.0 == key.0)
            {
                let mut mac = member.device_mac.0.clone();
                mac[0] ^= 1;
                member.device_mac = Bytes(mac);
            }
        }
        Ok(members)
    }
    fn create_virtual_device(&self, v: &VirtualDevice) -> labyrinth::Result<()> {
        self.0.create_virtual_device(v)
    }
    fn get_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<Option<VirtualDevice>> {
        self.0.get_virtual_device(id)
    }
    fn list_virtual_devices(&self) -> labyrinth::Result<Vec<VirtualDevice>> {
        self.0.list_virtual_devices()
    }
    fn append_owner_batch(&self, b: &OwnerBatch) -> labyrinth::Result<String> {
        self.0.append_owner_batch(b)
    }
    fn list_owner_batches(
        &self,
        t: &str,
        r: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.0.list_owner_batches(t, r)
    }
    fn publish_mailbox_keys(&self, r: &MailboxKeysRecord) -> labyrinth::Result<()> {
        self.0.publish_mailbox_keys(r)
    }
}

fn backends(
    net: &MemoryBackend,
    clock: &TestClock,
    did: &str,
    mb: Box<dyn MailboxStore + Send>,
) -> Backends {
    Backends {
        mailbox: mb,
        threads: Box::new(net.threads(did)),
        directory: Box::new(net.directory()),
        orf: Box::new(net.orf(did)),
        publishers: vec![],
        clock: Box::new(clock.clone()),
    }
}

#[derive(Clone, Default)]
struct DirectoryControls {
    latest: Arc<Mutex<Option<EpochPublic>>>,
    keys: Arc<Mutex<Option<Vec<ChatDeviceKey>>>>,
    key_calls: Arc<AtomicU64>,
    fail_key_call: Arc<AtomicU64>,
}

struct ControlledDirectory {
    inner: MemoryDirectory,
    controls: DirectoryControls,
}

impl MailboxDirectory for ControlledDirectory {
    fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        if let Some(epoch) = self.controls.latest.lock().unwrap().clone() {
            Ok(Some(epoch))
        } else {
            self.inner.latest(did)
        }
    }

    fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        self.inner.epoch(did, seq)
    }

    fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        let call = self.controls.key_calls.fetch_add(1, Ordering::Relaxed) + 1;
        if self.controls.fail_key_call.load(Ordering::Relaxed) == call {
            return Err(Error::Backend("injected member-audit outage".into()));
        }
        if let Some(keys) = self.controls.keys.lock().unwrap().clone() {
            Ok(keys)
        } else {
            self.inner.device_transport_keys(did)
        }
    }
}

fn controlled_backends(
    net: &MemoryBackend,
    clock: &TestClock,
    did: &str,
) -> (Backends, DirectoryControls) {
    let controls = DirectoryControls::default();
    let mut b = backends(net, clock, did, Box::new(net.mailbox(did)));
    b.directory = Box::new(ControlledDirectory {
        inner: net.directory(),
        controls: controls.clone(),
    });
    (b, controls)
}

fn candidate_epoch_fixture() -> (
    MemoryBackend,
    TestClock,
    Labyrinth,
    DirectoryControls,
    EpochPublic,
) {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let (b, controls) = controlled_backends(&net, &clock, A);
    let mut phone = Labyrinth::initialize(A, Box::new(signer(1)), b).unwrap();
    let mut laptop = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(net.mailbox(A)));
    let tablet = enroll_sibling(&net, &clock, &mut phone, 3, Box::new(net.mailbox(A)));
    laptop
        .revoke_device(&tablet.device_public().device_key_pub)
        .unwrap();
    let candidate = laptop.latest_public().unwrap();
    assert_eq!((phone.latest_epoch(), candidate.seq), (0, 1));
    (net, clock, phone, controls, candidate)
}

fn assert_unchanged(client: &Labyrinth, latest: u64, state: &[u8]) {
    assert_eq!(client.latest_epoch(), latest);
    assert_eq!(client.export_state().unwrap().as_slice(), state);
}

#[test]
fn committed_epoch_with_lost_response_is_reconciled_before_keys_are_dropped() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let uncertain = IgnoresRevoke::new(net.mailbox(A));
    uncertain.3.store(true, Ordering::Relaxed);

    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(uncertain)),
    )
    .unwrap();

    assert_eq!(phone.latest_epoch(), 0);
    phone.create_recovery_code(Mechanism::Code).unwrap();
}

#[test]
fn failed_integrity_check_does_not_activate_candidate_epoch() {
    let (_net, _clock, mut phone, controls, candidate) = candidate_epoch_fixture();
    let previous = MailboxKeys::derive(&[8; 32], 1);
    let published = EpochPublic::sign(
        A,
        2,
        &MailboxKeys::derive(&[9; 32], 2),
        Some(candidate.head),
        Some(&previous.sig_secret),
        &signer(1),
    )
    .unwrap();
    *controls.latest.lock().unwrap() = Some(published);
    let latest = phone.latest_epoch();
    let state = phone.export_state().unwrap();

    assert_eq!(
        phone.sync_epochs().unwrap_err(),
        Error::EpochTruncated {
            published: 2,
            reached: 1
        }
    );
    assert_unchanged(&phone, latest, &state);
}

#[test]
fn foreign_attested_ahead_head_cannot_block_sync_as_truncation() {
    let (_net, _clock, mut phone, controls, candidate) = candidate_epoch_fixture();
    let previous = MailboxKeys::derive(&[8; 32], 1);
    let published = EpochPublic::sign(
        A,
        2,
        &MailboxKeys::derive(&[9; 32], 2),
        Some(candidate.head),
        Some(&previous.sig_secret),
        &signer(99),
    )
    .unwrap();
    *controls.latest.lock().unwrap() = Some(published);
    let latest = phone.latest_epoch();
    let state = phone.export_state().unwrap();

    assert_eq!(phone.sync_epochs().unwrap_err(), Error::Unattested);
    assert_unchanged(&phone, latest, &state);
}

#[test]
fn removed_attester_cannot_publish_an_ahead_head() {
    let (_net, _clock, mut phone, controls, candidate) = candidate_epoch_fixture();
    let removed = signer(98);
    *controls.keys.lock().unwrap() = Some(vec![
        ChatDeviceKey::current(candidate.attestation.transport_public_key),
        ChatDeviceKey {
            key: removed.0.verifying_key().to_bytes(),
            removed_at: Some(1),
        },
    ]);
    let previous = MailboxKeys::derive(&[8; 32], 1);
    let published = EpochPublic::sign(
        A,
        2,
        &MailboxKeys::derive(&[9; 32], 2),
        Some(candidate.head),
        Some(&previous.sig_secret),
        &removed,
    )
    .unwrap();
    *controls.latest.lock().unwrap() = Some(published);
    let latest = phone.latest_epoch();
    let state = phone.export_state().unwrap();

    assert_eq!(phone.sync_epochs().unwrap_err(), Error::Unattested);
    assert_unchanged(&phone, latest, &state);
}

#[test]
fn failed_attester_check_does_not_activate_candidate_epoch() {
    let (_net, _clock, mut phone, controls, _candidate) = candidate_epoch_fixture();
    *controls.keys.lock().unwrap() = Some(vec![ChatDeviceKey::current(tpub(1))]);
    let latest = phone.latest_epoch();
    let state = phone.export_state().unwrap();

    assert_eq!(phone.sync_epochs().unwrap_err(), Error::Unattested);
    assert_unchanged(&phone, latest, &state);
}

#[test]
fn failed_member_audit_does_not_activate_candidate_epoch() {
    let (_net, _clock, mut phone, controls, _candidate) = candidate_epoch_fixture();
    controls.key_calls.store(0, Ordering::Relaxed);
    controls.fail_key_call.store(2, Ordering::Relaxed);
    let latest = phone.latest_epoch();
    let state = phone.export_state().unwrap();

    assert_eq!(
        phone.sync_epochs().unwrap_err(),
        Error::Backend("injected member-audit outage".into())
    );
    assert_unchanged(&phone, latest, &state);
}

#[test]
fn older_published_head_must_be_an_ancestor_of_the_candidate() {
    let (_net, _clock, mut phone, controls, _candidate) = candidate_epoch_fixture();
    let fork = EpochPublic::sign(
        A,
        0,
        &MailboxKeys::derive(&[7; 32], 0),
        None,
        None,
        &signer(1),
    )
    .unwrap();
    *controls.latest.lock().unwrap() = Some(fork);
    let latest = phone.latest_epoch();
    let state = phone.export_state().unwrap();

    assert_eq!(
        phone.sync_epochs().unwrap_err(),
        Error::Malformed("published epoch head forks from mailbox")
    );
    assert_unchanged(&phone, latest, &state);
}

#[test]
fn older_published_ancestor_allows_candidate_activation() {
    let (net, _clock, mut phone, controls, _candidate) = candidate_epoch_fixture();
    let published = net
        .mailbox(A)
        .get_epoch(0)
        .unwrap()
        .unwrap()
        .value
        .public
        .to_public()
        .unwrap();
    *controls.latest.lock().unwrap() = Some(published);

    assert_eq!(phone.sync_epochs().unwrap().to, 1);
    assert_eq!(phone.latest_epoch(), 1);
}

#[test]
fn recovery_rejects_an_older_published_head_from_another_branch() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let recovery = phone.create_recovery_code(Mechanism::Code).unwrap();
    let sibling = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(net.mailbox(A)));
    phone
        .revoke_device(&sibling.device_public().device_key_pub)
        .unwrap();
    assert_eq!(phone.latest_epoch(), 1);

    let controls = DirectoryControls::default();
    *controls.latest.lock().unwrap() = Some(
        EpochPublic::sign(
            A,
            0,
            &MailboxKeys::derive(&[7; 32], 0),
            None,
            None,
            &signer(1),
        )
        .unwrap(),
    );
    let mut b = backends(&net, &clock, A, Box::new(net.mailbox(A)));
    b.directory = Box::new(ControlledDirectory {
        inner: net.directory(),
        controls,
    });
    net.register_chat_device(A, tpub(6));

    let restored =
        Labyrinth::restore_with_recovery_code(A, recovery.code.as_str(), Box::new(signer(6)), b);
    assert_eq!(
        restored.map(|_| ()).unwrap_err(),
        Error::Malformed("published epoch head forks from mailbox")
    );
}

#[test]
fn removed_historical_attester_still_allows_candidate_activation() {
    let (net, _clock, mut phone, _controls, _candidate) = candidate_epoch_fixture();
    net.remove_chat_device(A, tpub(2), 1);

    assert_eq!(phone.sync_epochs().unwrap().to, 1);
    assert_eq!(phone.latest_epoch(), 1);
}

/// Enrolls a second device of `existing`'s account via one-time code.
fn enroll_sibling(
    net: &MemoryBackend,
    clock: &TestClock,
    existing: &mut Labyrinth,
    seed: u8,
    mb: Box<dyn MailboxStore + Send>,
) -> Labyrinth {
    let did = existing.did().to_owned();
    let mut r = existing.otc_offer().unwrap();
    let typed = r.code().as_str().to_owned();
    let (init, hello) = Labyrinth::otc_start(&did, &typed).unwrap();
    let reply = existing.otc_respond(&mut r, &hello).unwrap();
    net.register_chat_device(&did, tpub(seed));
    Labyrinth::enroll_via_otc(
        &did,
        init,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(seed)),
        backends(net, clock, &did, mb),
    )
    .unwrap()
    .0
}

// ---- Finding 1: revocation must not trust the store's `revokedAt` ----

#[test]
fn revoked_device_is_excluded_even_when_store_drops_revoked_at() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let mut laptop = enroll_sibling(
        &net,
        &clock,
        &mut phone,
        2,
        Box::new(IgnoresRevoke::new(net.mailbox(A))),
    );
    let phone_key = phone.device_public().device_key_pub;
    let rot = laptop.revoke_device(&phone_key).unwrap();
    assert_eq!(rot.new_epoch, 1);
    assert_eq!(phone.sync_epochs().unwrap_err(), Error::NotEpochMember);
}

// ---- Finding 3: insider messageId collision ----

#[test]
fn insider_message_id_collision_keeps_both_copies() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    const M: &str = "did:plc:aaa-mallory"; // sorts before alice in this backend
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(M, tpub(2));
    net.register_chat_device(C, tpub(3));
    let mk = |did: &str, seed: u8| {
        Labyrinth::initialize(
            did,
            Box::new(signer(seed)),
            backends(&net, &clock, did, Box::new(net.mailbox(did))),
        )
        .unwrap()
    };
    let mut alice = mk(A, 1);
    let mut mal = mk(M, 2);
    let mut carol = mk(C, 3);
    let group = [A, M, C];
    let roster = alice.resolve_roster(&group).unwrap();
    alice
        .archive_outgoing("t", &roster, "msg-42", 1000, b"genuine from alice")
        .unwrap();
    alice.flush().unwrap();
    // Mallory sees msg-42 via MLS and re-uses its id.
    let roster = mal.resolve_roster(&group).unwrap();
    mal.archive_outgoing("t", &roster, "msg-42", 1001, b"spoof")
        .unwrap();
    mal.flush().unwrap();
    let h = carol.load_thread("t", TimeRange::ALL).unwrap();
    assert!(
        h.messages
            .iter()
            .any(|m| m.frame == b"genuine from alice" && m.sender.as_deref() == Some(A)),
        "Alice's message was dropped"
    );
    let copies: Vec<_> = h
        .messages
        .iter()
        .filter(|m| m.message_id == "msg-42")
        .collect();
    assert_eq!(copies.len(), 2);
    assert!(copies.iter().all(|m| m.conflict));

    // Re-archiving before leaving keeps both distinct copies, and the owner
    // archive alone still shows both.
    assert_eq!(carol.rearchive_thread_before_leave("t").unwrap(), 2);
    assert_eq!(carol.rearchive_thread_before_leave("t").unwrap(), 0);
    net.revoke_thread_access("t", C);
    let h = carol.load_thread("t", TimeRange::ALL).unwrap();
    assert!(!h.space_readable);
    let frames: Vec<_> = h.messages.iter().map(|m| m.frame.as_slice()).collect();
    assert!(frames.contains(&&b"genuine from alice"[..]) && frames.contains(&&b"spoof"[..]));
    assert!(h.messages.iter().all(|m| m.conflict));
}

// ---- Finding 2: stale epoch head replay ----

/// Directory that, once `active`, replays an old `mailboxKeys` for `victim`.
struct Stale {
    inner: MemoryDirectory,
    victim: String,
    old: EpochPublic,
    active: Arc<AtomicBool>,
}
impl MailboxDirectory for Stale {
    fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        if did == self.victim && self.active.load(Ordering::Relaxed) {
            return Ok(Some(self.old.clone()));
        }
        self.inner.latest(did)
    }
    fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        self.inner.epoch(did, seq)
    }
    fn device_transport_keys(&self, d: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        self.inner.device_transport_keys(d)
    }
}

#[test]
fn stale_head_replay_after_contact_is_rejected() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(B, tpub(3));
    let mut laptop = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let mut phone = enroll_sibling(&net, &clock, &mut laptop, 2, Box::new(net.mailbox(A)));
    let old = laptop.latest_public().unwrap();
    let active = Arc::new(AtomicBool::new(false));
    let bb = Backends {
        mailbox: Box::new(net.mailbox(B)),
        threads: Box::new(net.threads(B)),
        directory: Box::new(Stale {
            inner: net.directory(),
            victim: A.into(),
            old: old.clone(),
            active: active.clone(),
        }),
        orf: Box::new(net.orf(B)),
        publishers: vec![],
        clock: Box::new(clock.clone()),
    };
    let mut bob = Labyrinth::initialize(B, Box::new(signer(3)), bb).unwrap();
    // Bob talks to Alice while she is at epoch 0 ...
    let roster = bob.resolve_roster(&[A, B]).unwrap();
    bob.archive_outgoing("t", &roster, "before", 4000, b"hello")
        .unwrap();
    bob.flush().unwrap();
    // ... then Alice's phone is stolen and revoked (epoch 1) ...
    net.remove_chat_device(A, tpub(2), 4400);
    laptop
        .revoke_device(&phone.device_public().device_key_pub)
        .unwrap();
    assert!(phone.sync_epochs().is_err());
    // ... Bob sees epoch 1 ...
    let roster = bob.resolve_roster(&[A, B]).unwrap();
    bob.archive_outgoing("t", &roster, "after-1", 4500, b"post revoke")
        .unwrap();
    // ... and then Alice's PDS replays her epoch-0 keys.
    active.store(true, Ordering::Relaxed);
    let replay = bob.resolve_roster(&[A, B]);
    let forced = vec![
        (A.to_owned(), old),
        (B.to_owned(), bob.latest_public().unwrap()),
    ];
    let sent = bob.archive_outgoing(
        "t",
        &forced,
        "after-revoke",
        5000,
        b"secret after revocation",
    );
    assert!(matches!(
        bob.flush(),
        Err(Error::EpochRollback {
            pinned: 1,
            offered: 0
        })
    ));
    // The safe epoch-1 message remains queued. Once the directory stops
    // replaying epoch 0, it can be published under its original roster.
    active.store(false, Ordering::Relaxed);
    bob.flush().unwrap();
    let h = phone.load_thread("t", TimeRange::ALL).unwrap();
    assert!(
        !h.messages
            .iter()
            .any(|m| m.frame == b"secret after revocation"),
        "revoked phone read a message sent after revocation"
    );
    assert!(replay.is_err(), "stale roster accepted");
    assert!(sent.is_err(), "stale epoch accepted for addressing");
}

// ---- Finding 4: an invalid continuing member aborts rotation ([CB-25]) ----

#[test]
fn rotation_excludes_and_reports_an_invalid_member() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let mut laptop = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(net.mailbox(A)));
    let mut tablet = enroll_sibling(&net, &clock, &mut phone, 4, Box::new(net.mailbox(A)));
    // The store (or anyone with write access) plants a member record with a
    // bad MAC for a third device in epoch 0.
    let tablet_key = tablet.device_public().device_key_pub;
    let mb = net.mailbox(A);
    let mut m = mb.get_epoch_member(0, &tablet_key).unwrap().unwrap();
    let forged_key = labyrinth::device::DeviceSecrets::generate().unwrap();
    mb.create_device(&Device::from_public(
        forged_key.public(),
        "2026-10-04T00:00:00.000Z".into(),
    ))
    .unwrap();
    m.device_key_pubkey =
        labyrinth::records::Bytes::from_slice(&forged_key.public().device_key_pub.0);
    mb.create_epoch_member(&m).unwrap();
    // [CB-25] as amended: the planted row neither blocks the revocation
    // (a DoS) nor disappears silently; it is dropped and reported.
    let report = laptop
        .revoke_device(&phone.device_public().device_key_pub)
        .unwrap();
    assert_eq!(report.new_epoch, 1);
    let forged = forged_key.public().device_key_pub;
    assert_eq!(
        report.excluded,
        vec![labyrinth::client::ExcludedMember {
            device_key: Some(forged),
            reason: labyrinth::client::ExclusionReason::InvalidMac,
        }]
    );
    // The tablet is carried over; the forged device is not a member.
    assert_eq!(tablet.sync_epochs().unwrap().to, 1);
    assert!(mb.get_epoch_member(1, &forged).unwrap().is_none());
    assert!(mb.get_epoch_member(1, &tablet_key).unwrap().is_some());
}

/// Directory that refuses to serve one historical epoch.
struct HidesEpoch {
    inner: MemoryDirectory,
    hidden: Arc<AtomicU64>,
}
impl MailboxDirectory for HidesEpoch {
    fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        self.inner.latest(did)
    }
    fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        if seq == self.hidden.load(Ordering::Relaxed) {
            return Ok(None);
        }
        self.inner.epoch(did, seq)
    }
    fn device_transport_keys(&self, d: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        self.inner.device_transport_keys(d)
    }
}

#[test]
fn pins_reject_rollback_and_advance_only_through_a_verified_chain() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(B, tpub(3));
    let mut laptop = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let phone = enroll_sibling(&net, &clock, &mut laptop, 2, Box::new(net.mailbox(A)));
    let tablet = enroll_sibling(&net, &clock, &mut laptop, 4, Box::new(net.mailbox(A)));
    let e0 = laptop.latest_public().unwrap();
    let hidden = Arc::new(AtomicU64::new(u64::MAX));
    let bob_backends = |hidden: &Arc<AtomicU64>| Backends {
        mailbox: Box::new(net.mailbox(B)),
        threads: Box::new(net.threads(B)),
        directory: Box::new(HidesEpoch {
            inner: net.directory(),
            hidden: hidden.clone(),
        }),
        orf: Box::new(net.orf(B)),
        publishers: vec![],
        clock: Box::new(clock.clone()),
    };
    let mut bob = Labyrinth::initialize(B, Box::new(signer(3)), bob_backends(&hidden)).unwrap();
    bob.resolve_roster(&[A, B]).unwrap();
    assert_eq!(bob.peer_pin(A).unwrap().seq, 0);

    // Alice rotates twice (epochs 1 and 2) while Bob is away.
    laptop
        .revoke_device(&phone.device_public().device_key_pub)
        .unwrap();
    laptop
        .revoke_device(&tablet.device_public().device_key_pub)
        .unwrap();

    // Without epoch 1 the chain from Bob's pin cannot be verified.
    hidden.store(1, Ordering::Relaxed);
    assert_eq!(
        bob.resolve_roster(&[A, B]).unwrap_err(),
        Error::NotFound("intermediate peer epoch")
    );
    assert_eq!(bob.peer_pin(A).unwrap().seq, 0);

    // With it, Bob advances 0 -> 2 through epoch 1.
    hidden.store(u64::MAX, Ordering::Relaxed);
    let roster = bob.resolve_roster(&[A, B]).unwrap();
    assert_eq!(bob.peer_pin(A).unwrap().seq, 2);
    assert_eq!(roster.iter().find(|(d, _)| d == A).unwrap().1.seq, 2);

    // Offering epoch 0 again is a rollback.
    let forced = vec![
        (A.to_owned(), e0),
        (B.to_owned(), bob.latest_public().unwrap()),
    ];
    assert_eq!(
        bob.archive_outgoing("t", &forced, "m", 1, b"x")
            .unwrap_err(),
        Error::Malformed("roster epoch is not the directory head")
    );
}

// ---- Design note [CB-27]: removed chat keys only vouch for older history ----

/// Phone (Alice) and Carol on `net`; returns `(phone, carol)`.
fn phone_and_carol(net: &MemoryBackend, clock: &TestClock) -> (Labyrinth, Labyrinth) {
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(C, tpub(3));
    let mk = |did: &str, seed: u8| {
        Labyrinth::initialize(
            did,
            Box::new(signer(seed)),
            backends(net, clock, did, Box::new(net.mailbox(did))),
        )
        .unwrap()
    };
    (mk(A, 1), mk(C, 3))
}

const C: &str = "did:plc:carol";

/// Fallback without server order (the Space backend): the bound uses the
/// sender's timestamp, so a removed device can still backdate. This is
/// the residual risk SPEC §10 keeps for Space-stored threads.
#[test]
fn without_server_order_a_removed_key_is_bounded_by_sender_timestamps() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let (mut phone, mut carol) = phone_and_carol(&net, &clock);
    let roster = phone.resolve_roster(&[A, C]).unwrap();
    phone
        .archive_outgoing("t", &roster, "early", 1000, b"early")
        .unwrap();
    net.remove_chat_device(A, tpub(1), 2000);
    phone
        .archive_outgoing("t", &roster, "late", 3000, b"late")
        .unwrap();
    // Residual risk: the timestamp is the sender's claim.
    phone
        .archive_outgoing("t", &roster, "backdated", 1500, b"backdated")
        .unwrap();
    phone.flush().unwrap();
    let h = carol.load_thread("t", TimeRange::ALL).unwrap();
    let ids: Vec<_> = h.messages.iter().map(|m| m.message_id.as_str()).collect();
    assert_eq!(ids, ["early", "backdated"]);
    assert_eq!(h.undecryptable.len(), 1);
    assert_eq!(h.undecryptable[0].message_id, "late");
    assert_eq!(h.undecryptable[0].error, Error::BadPublicKey);
}

/// With server order (mls-ds), the bound uses the server's receive time:
/// the backdated message was received after the revocation and fails.
#[test]
fn with_server_order_a_removed_device_cannot_backdate() {
    let net = MemoryBackend::new();
    net.enable_server_order();
    let clock = TestClock::default();
    let (mut phone, mut carol) = phone_and_carol(&net, &clock);
    let roster = phone.resolve_roster(&[A, C]).unwrap();
    net.set_server_time(1000);
    phone
        .archive_outgoing("t", &roster, "early", 1000, b"early")
        .unwrap();
    phone.flush().unwrap();
    net.remove_chat_device(A, tpub(1), 2000);
    net.set_server_time(3000);
    phone
        .archive_outgoing("t", &roster, "late", 3000, b"late")
        .unwrap();
    phone
        .archive_outgoing("t", &roster, "backdated", 1500, b"backdated")
        .unwrap();
    phone.flush().unwrap();
    let h = carol.load_thread("t", TimeRange::ALL).unwrap();
    let ids: Vec<_> = h.messages.iter().map(|m| m.message_id.as_str()).collect();
    assert_eq!(ids, ["early"]);
    let bad: Vec<_> = h
        .undecryptable
        .iter()
        .map(|u| (u.message_id.as_str(), u.error.clone()))
        .collect();
    assert_eq!(
        bad,
        [
            ("backdated", Error::BadPublicKey),
            ("late", Error::BadPublicKey)
        ]
    );
}

/// A device removed from one conversation's MLS group (but not revoked
/// account-wide) stops vouching there at the removal commit's chat seq.
#[test]
fn with_server_order_a_removed_leaf_stops_vouching_at_its_removal_commit() {
    let net = MemoryBackend::new();
    net.enable_server_order();
    let clock = TestClock::default();
    let (mut phone, mut carol) = phone_and_carol(&net, &clock);
    for t in ["t", "u"] {
        net.add_leaf(t, A, tpub(1));
        net.add_leaf(t, C, tpub(3));
    }
    let roster = phone.resolve_roster(&[A, C]).unwrap();
    for (t, id) in [("t", "in-group"), ("u", "other-thread")] {
        phone.archive_outgoing(t, &roster, id, 10, b"x").unwrap();
    }
    phone.flush().unwrap();
    net.remove_leaf("t", A, tpub(1));
    for (t, id) in [("t", "after-removal"), ("u", "still-member")] {
        phone.archive_outgoing(t, &roster, id, 5, b"y").unwrap();
    }
    phone.flush().unwrap();
    let ids = |h: &labyrinth::client::ThreadHistory| -> Vec<String> {
        h.messages.iter().map(|m| m.message_id.clone()).collect()
    };
    let h = carol.load_thread("t", TimeRange::ALL).unwrap();
    assert_eq!(ids(&h), ["in-group"]);
    assert_eq!(h.undecryptable.len(), 1);
    assert_eq!(h.undecryptable[0].message_id, "after-removal");
    assert_eq!(h.undecryptable[0].error, Error::BadPublicKey);
    // The account-wide key is still current; another conversation is fine.
    let h = carol.load_thread("u", TimeRange::ALL).unwrap();
    assert_eq!(ids(&h), ["still-member", "other-thread"]);
    // A device that never had a leaf in the conversation vouches for nothing.
    net.add_leaf("v", C, tpub(3));
    phone
        .archive_outgoing("v", &roster, "no-leaf", 1, b"z")
        .unwrap();
    phone.flush().unwrap();
    let h = carol.load_thread("v", TimeRange::ALL).unwrap();
    assert!(h.messages.is_empty());
    assert_eq!(h.undecryptable[0].error, Error::BadPublicKey);

    // An unsequenced batch (`chat_seq: None`, written before leaf tracking was
    // enabled on `"w"`) is rejected fail-closed once leaves are tracked on `"w"`.
    phone
        .archive_outgoing("w", &roster, "unsequenced-pre-leaf", 1, b"u")
        .unwrap();
    phone.flush().unwrap();
    net.add_leaf("w", A, tpub(1));
    net.add_leaf("w", C, tpub(3));
    let h = carol.load_thread("w", TimeRange::ALL).unwrap();
    assert!(h.messages.is_empty());
    assert_eq!(h.undecryptable.len(), 1);
    assert_eq!(h.undecryptable[0].error, Error::BadPublicKey);
}

// ---- Finding 7: client state persistence ----

#[test]
fn state_round_trips_and_a_restarted_client_keeps_working() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(B, tpub(3));
    let mut alice = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let mut bob = Labyrinth::initialize(
        B,
        Box::new(signer(3)),
        backends(&net, &clock, B, Box::new(net.mailbox(B))),
    )
    .unwrap();
    let roster = alice.resolve_roster(&[A, B]).unwrap();
    alice
        .archive_outgoing("t", &roster, "a1", 10, b"one")
        .unwrap();
    alice.flush().unwrap();
    let state = alice.export_state().unwrap();
    drop(alice);

    let mut alice = Labyrinth::from_state(
        &state,
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    assert_eq!(*alice.export_state().unwrap(), *state);
    assert_eq!(alice.peer_pin(B).unwrap().seq, 0);
    // The MEK cache survived: the next message reuses the MEK.
    let roster = alice.resolve_roster(&[A, B]).unwrap();
    let out = alice
        .archive_outgoing("t", &roster, "a2", 20, b"two")
        .unwrap();
    assert!(out.mek_written.is_none());
    alice.flush().unwrap();
    let h = bob.load_thread("t", TimeRange::ALL).unwrap();
    assert_eq!(h.messages.len(), 2);
    assert_eq!(
        alice
            .load_thread("t", TimeRange::ALL)
            .unwrap()
            .messages
            .len(),
        2
    );

    // Wrong identity, corruption and trailing bytes are refused.
    let restore = |bytes: &[u8], did: &str, seed: u8| {
        Labyrinth::from_state(
            bytes,
            did,
            Box::new(signer(seed)),
            backends(&net, &clock, did, Box::new(net.mailbox(did))),
        )
        .map(|_| ())
    };
    assert!(restore(&state, B, 1).is_err());
    assert!(restore(&state, A, 9).is_err());
    assert!(restore(&state[..state.len() - 1], A, 1).is_err());
    let mut long = state.to_vec();
    long.push(0);
    assert!(restore(&long, A, 1).is_err());
    let mut v3 = state.to_vec();
    v3[4] = 3;
    assert_eq!(restore(&v3, A, 1), Err(Error::Unsupported(3)));
    let mut bad_key = state.to_vec();
    let at = 4 + 1 + 2 + A.len() + 32 + 1; // second byte of deviceKey (byte 0 is clamped)
    bad_key[at] ^= 1;
    assert!(restore(&bad_key, A, 1).is_err());
}

#[test]
fn reached_epoch_readmitting_a_revoked_device_is_not_activated() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let flaky = IgnoresRevoke::new(net.mailbox(A));
    let outage = flaky.1.clone();
    let mut laptop = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(flaky));
    let mut tablet = enroll_sibling(&net, &clock, &mut phone, 4, Box::new(net.mailbox(A)));
    let spare = enroll_sibling(&net, &clock, &mut phone, 5, Box::new(net.mailbox(A)));

    // The revocation is recorded locally, but its rotation never happens.
    outage.store(true, Ordering::Relaxed);
    let phone_key = phone.device_public().device_key_pub;
    assert!(matches!(
        laptop.revoke_device(&phone_key),
        Err(Error::Backend(_))
    ));
    let blocked = Error::EpochSquatted {
        seq: 0,
        reason: "it re-admits a device this client revoked",
    };
    assert_eq!(
        laptop
            .archive_owner("blocked", "m", 1, b"must not encrypt")
            .unwrap_err(),
        blocked
    );
    assert_eq!(laptop.resolve_roster(&[A]).unwrap_err(), blocked);
    assert_eq!(
        laptop
            .archive_outgoing("blocked", &[], "m", 1, b"must not encrypt")
            .unwrap_err(),
        blocked
    );
    assert_eq!(laptop.publish_latest_keys().unwrap_err(), blocked);
    let latest = laptop.latest_epoch();
    let before_same_epoch = laptop.export_state().unwrap();
    assert_eq!(
        laptop.sync_epochs().unwrap_err(),
        Error::EpochSquatted {
            seq: 0,
            reason: "it re-admits a device this client revoked"
        }
    );
    assert_unchanged(&laptop, latest, &before_same_epoch);
    let state = laptop.export_state().unwrap();
    drop(laptop);

    // An unaware sibling advances the chain from the still-inclusive epoch.
    // Because the store discarded revokedAt, it carries the phone forward.
    tablet
        .revoke_device(&spare.device_public().device_key_pub)
        .unwrap();

    // After a restart (on a store that never recorded revokedAt), the
    // laptop still knows the phone is revoked ...
    let mut laptop = Labyrinth::from_state(
        &state,
        A,
        Box::new(signer(2)),
        backends(
            &net,
            &clock,
            A,
            Box::new(IgnoresRevoke::new(net.mailbox(A))),
        ),
    )
    .unwrap();
    assert_eq!(
        laptop.revoked_devices().collect::<Vec<_>>(),
        vec![phone_key]
    );
    let latest = laptop.latest_epoch();
    let state = laptop.export_state().unwrap();
    assert_eq!(
        laptop.sync_epochs().unwrap_err(),
        Error::EpochSquatted {
            seq: 0,
            reason: "it re-admits a device this client revoked"
        }
    );
    assert_unchanged(&laptop, latest, &state);
}

#[test]
fn revocation_refuses_to_cross_pending_ciphertext() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    phone.create_recovery_code(Mechanism::Code).unwrap();
    let target = phone.list_recovery_methods().unwrap()[0].device_key;
    let roster = phone.resolve_roster(&[A]).unwrap();
    phone
        .archive_outgoing("queued", &roster, "m", 1, b"before revocation")
        .unwrap();

    assert_eq!(
        phone.revoke_device(&target).unwrap_err(),
        Error::PendingWrites
    );
    assert_eq!(phone.latest_epoch(), 0);
    assert!(phone.revoked_devices().next().is_none());
    assert_eq!(phone.pending("queued"), 1);

    assert_eq!(phone.discard_pending("queued"), 1);
    assert_eq!(phone.revoke_device(&target).unwrap().new_epoch, 1);
}

#[test]
fn flush_rejects_ciphertext_buffered_under_an_old_epoch() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let mut laptop = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(net.mailbox(A)));
    let spare = enroll_sibling(&net, &clock, &mut phone, 3, Box::new(net.mailbox(A)));
    let roster = phone.resolve_roster(&[A]).unwrap();
    phone
        .archive_outgoing("queued", &roster, "m", 1, b"before sibling rotation")
        .unwrap();
    phone
        .archive_owner("owner-queued", "o", 1, b"before sibling rotation")
        .unwrap();

    laptop
        .revoke_device(&spare.device_public().device_key_pub)
        .unwrap();

    assert_eq!(phone.flush().unwrap_err(), Error::RosterMismatch);
    assert_eq!(phone.pending("queued"), 1);
    assert_eq!(phone.pending("owner-queued"), 1);
}

#[test]
fn flush_revalidates_a_peers_epoch_before_publishing() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(B, tpub(4));
    let mut alice = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let mut bob = Labyrinth::initialize(
        B,
        Box::new(signer(4)),
        backends(&net, &clock, B, Box::new(net.mailbox(B))),
    )
    .unwrap();
    bob.create_recovery_code(Mechanism::Code).unwrap();
    let recovery = bob.list_recovery_methods().unwrap()[0].device_key;
    let roster = alice.resolve_roster(&[A, B]).unwrap();
    alice
        .archive_outgoing("peer-queued", &roster, "m", 1, b"before peer rotation")
        .unwrap();

    bob.revoke_device(&recovery).unwrap();

    assert_eq!(alice.flush().unwrap_err(), Error::RosterMismatch);
    assert_eq!(alice.pending("peer-queued"), 1);
}

#[test]
fn removed_chat_binding_does_not_hide_a_failed_revocation_membership() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let flaky = IgnoresRevoke::new(net.mailbox(A));
    let outage = flaky.1.clone();
    let mut laptop = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(flaky));

    net.remove_chat_device(A, tpub(1), 1);
    outage.store(true, Ordering::Relaxed);
    assert!(matches!(
        laptop.revoke_chat_device(&tpub(1)),
        Err(Error::Backend(_))
    ));
    assert_eq!(
        laptop.sync_epochs().unwrap_err(),
        Error::EpochSquatted {
            seq: 0,
            reason: "it re-admits a device this client revoked"
        }
    );
}

#[test]
fn store_cannot_hide_a_previously_verified_revoked_member() {
    for hide in [false, true] {
        let net = MemoryBackend::new();
        let clock = TestClock::default();
        net.register_chat_device(A, tpub(1));
        let mut phone = Labyrinth::initialize(
            A,
            Box::new(signer(1)),
            backends(&net, &clock, A, Box::new(net.mailbox(A))),
        )
        .unwrap();
        let hostile = IgnoresRevoke::new(net.mailbox(A));
        let outage = hostile.1.clone();
        let membership_fault = hostile.2.clone();
        let mut laptop = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(hostile));
        let phone_key = phone.device_public().device_key_pub;

        // The preparatory audit verifies and remembers the target, but the
        // rotation fails after the local revocation decision.
        outage.store(true, Ordering::Relaxed);
        assert!(matches!(
            laptop.revoke_device(&phone_key),
            Err(Error::Backend(_))
        ));
        *membership_fault.lock().unwrap() = Some((phone_key, hide));

        assert_eq!(
            laptop.sync_epochs().unwrap_err(),
            Error::EpochSquatted {
                seq: 0,
                reason: "it re-admits a device this client revoked",
            }
        );
    }
}

#[test]
fn revocation_catches_up_through_an_epoch_previously_opened_by_its_target() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let mut laptop = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(net.mailbox(A)));
    let spare = enroll_sibling(&net, &clock, &mut phone, 3, Box::new(net.mailbox(A)));

    // While the laptop is offline at epoch 0, the phone legitimately opens
    // epoch 1. The later decision to revoke that phone must be allowed to
    // catch up in quarantine and immediately rotate again; it must not use
    // epoch 1 for ordinary archiving in between.
    phone
        .revoke_device(&spare.device_public().device_key_pub)
        .unwrap();
    assert_eq!((laptop.latest_epoch(), phone.latest_epoch()), (0, 1));

    let phone_key = phone.device_public().device_key_pub;
    let report = laptop.revoke_device(&phone_key).unwrap();
    assert_eq!(report.new_epoch, 2);
    assert_eq!(phone.sync_epochs().unwrap_err(), Error::NotEpochMember);
}

#[test]
fn intermediate_epoch_readmitting_a_revoked_device_is_not_activated() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let flaky = IgnoresRevoke::new(net.mailbox(A));
    let outage = flaky.1.clone();
    let mut laptop = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(flaky));
    let mut tablet = enroll_sibling(&net, &clock, &mut phone, 4, Box::new(net.mailbox(A)));
    let spare = enroll_sibling(&net, &clock, &mut phone, 5, Box::new(net.mailbox(A)));

    outage.store(true, Ordering::Relaxed);
    let phone_key = phone.device_public().device_key_pub;
    assert!(matches!(
        laptop.revoke_device(&phone_key),
        Err(Error::Backend(_))
    ));
    let state = laptop.export_state().unwrap();
    drop(laptop);

    // Epoch 1 incorrectly carries the locally revoked phone. Epoch 2 is
    // clean again, so auditing only the final reached epoch misses the
    // compromise already present at the starting epoch and carried through
    // the intermediate epoch.
    tablet
        .revoke_device(&spare.device_public().device_key_pub)
        .unwrap();
    tablet.revoke_device(&phone_key).unwrap();
    assert_eq!(tablet.latest_epoch(), 2);

    let mut laptop = Labyrinth::from_state(
        &state,
        A,
        Box::new(signer(2)),
        backends(
            &net,
            &clock,
            A,
            Box::new(IgnoresRevoke::new(net.mailbox(A))),
        ),
    )
    .unwrap();
    let latest = laptop.latest_epoch();
    let before = laptop.export_state().unwrap();
    assert_eq!(
        laptop.sync_epochs().unwrap_err(),
        Error::EpochSquatted {
            seq: 0,
            reason: "it re-admits a device this client revoked"
        }
    );
    assert_unchanged(&laptop, latest, &before);
}

#[test]
fn restarted_client_still_enforces_peer_pins() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(B, tpub(3));
    let mut laptop = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let phone = enroll_sibling(&net, &clock, &mut laptop, 2, Box::new(net.mailbox(A)));
    let old = laptop.latest_public().unwrap();
    laptop
        .revoke_device(&phone.device_public().device_key_pub)
        .unwrap();
    let active = Arc::new(AtomicBool::new(false));
    let bob_backends = || Backends {
        mailbox: Box::new(net.mailbox(B)),
        threads: Box::new(net.threads(B)),
        directory: Box::new(Stale {
            inner: net.directory(),
            victim: A.into(),
            old: old.clone(),
            active: active.clone(),
        }),
        orf: Box::new(net.orf(B)),
        publishers: vec![],
        clock: Box::new(clock.clone()),
    };
    let mut bob = Labyrinth::initialize(B, Box::new(signer(3)), bob_backends()).unwrap();
    bob.resolve_roster(&[A, B]).unwrap();
    assert_eq!(bob.peer_pin(A).unwrap().seq, 1);
    let state = bob.export_state().unwrap();
    drop(bob);

    active.store(true, Ordering::Relaxed);
    let mut bob = Labyrinth::from_state(&state, B, Box::new(signer(3)), bob_backends()).unwrap();
    assert_eq!(
        bob.resolve_roster(&[A, B]).unwrap_err(),
        Error::EpochRollback {
            pinned: 1,
            offered: 0
        }
    );
}

// ---- 2026-10-13 review, I2: peer-minted MEKs are not reused ----

/// Mallory's thread handle: every MEK she distributes carries a corrupted
/// ciphertext for Bob, which only Bob can detect.
struct BlackholesBob(labyrinth::store::memory::MemoryThreads);
impl labyrinth::store::ThreadStore for BlackholesBob {
    fn author(&self) -> &str {
        self.0.author()
    }
    fn create_mek(&self, mek: &labyrinth::records::MekDistribution) -> labyrinth::Result<()> {
        let mut mek = mek.clone();
        for r in mek.recipients.iter_mut().filter(|r| r.did == B) {
            r.ciphertext.0[0] ^= 1;
        }
        self.0.create_mek(&mek)
    }
    fn find_meks(
        &self,
        t: &str,
        id: &[u8; 12],
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::MekDistribution>>> {
        self.0.find_meks(t, id)
    }
    fn append_batch(&self, b: &labyrinth::records::Batch) -> labyrinth::Result<String> {
        self.0.append_batch(b)
    }
    fn list_batches(
        &self,
        t: &str,
        s: Option<&str>,
        r: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::Batch>>> {
        self.0.list_batches(t, s, r)
    }
}

#[test]
fn a_peer_minted_mek_is_never_reused_for_outgoing() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    const M: &str = "did:plc:mallory";
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(B, tpub(3));
    net.register_chat_device(M, tpub(2));
    let mk = |did: &str, seed: u8| {
        Labyrinth::initialize(
            did,
            Box::new(signer(seed)),
            backends(&net, &clock, did, Box::new(net.mailbox(did))),
        )
        .unwrap()
    };
    let mut alice = mk(A, 1);
    let mut bob = mk(B, 3);
    let mut mal = Labyrinth::initialize(
        M,
        Box::new(signer(2)),
        Backends {
            threads: Box::new(BlackholesBob(net.threads(M))),
            ..backends(&net, &clock, M, Box::new(net.mailbox(M)))
        },
    )
    .unwrap();
    let group = [A, B, M];

    let roster = mal.resolve_roster(&group).unwrap();
    mal.archive_outgoing("t", &roster, "m1", 1000, b"from mallory")
        .unwrap();
    mal.flush().unwrap();
    // Alice opens Mallory's MEK through her own (intact) entry.
    let h = alice.load_thread("t", TimeRange::ALL).unwrap();
    assert!(h.messages.iter().any(|m| m.frame == b"from mallory"));

    // Alice's next message must not ride on Mallory's MEK.
    let roster = alice.resolve_roster(&group).unwrap();
    let out = alice
        .archive_outgoing("t", &roster, "a1", 2000, b"from alice")
        .unwrap();
    assert!(out.mek_written.is_some(), "reused a peer-minted MEK");
    alice.flush().unwrap();
    let h = bob.load_thread("t", TimeRange::ALL).unwrap();
    assert!(
        h.messages.iter().any(|m| m.frame == b"from alice"),
        "Bob was blackholed from Alice's message"
    );

    // Alice still reuses the MEK she minted herself.
    let out = alice
        .archive_outgoing("t", &roster, "a2", 3000, b"again")
        .unwrap();
    assert!(out.mek_written.is_none());
}

// ---- 2026-10-13 review, I3: the starting epoch record's signatures ----

/// What [`Tampered`] does to every epoch record it returns (head and keys
/// are always left intact).
const CLEAN: u8 = 0;
/// Corrupt `selfSig`.
const SELF_SIG: u8 = 1;
/// Replace the attestation with a validly signed one from a key that is
/// not one of the account's chat devices.
const FOREIGN_ATTESTATION: u8 = 2;
/// Corrupt `prevSig` (epochs above 0).
const PREV_SIG: u8 = 3;

fn attacker() -> Ed25519Transport {
    signer(99)
}

/// Mailbox whose stored epoch records come back tampered as its mode says.
struct Tampered(MemoryMailbox, Arc<AtomicU8>);
impl MailboxStore for Tampered {
    fn owner(&self) -> &str {
        self.0.owner()
    }
    fn create_device(&self, d: &Device) -> labyrinth::Result<()> {
        self.0.create_device(d)
    }
    fn set_device_revoked(&self, k: &XVerifyingKey, at: &str) -> labyrinth::Result<()> {
        self.0.set_device_revoked(k, at)
    }
    fn get_device(&self, k: &XVerifyingKey) -> labyrinth::Result<Option<Device>> {
        self.0.get_device(k)
    }
    fn list_devices(&self) -> labyrinth::Result<Vec<Device>> {
        self.0.list_devices()
    }
    fn create_epoch(&self, e: &Epoch, m: &[EpochMember]) -> labyrinth::Result<String> {
        self.0.create_epoch(e, m)
    }
    fn get_epoch(&self, s: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        let mut e = self.0.get_epoch(s)?;
        if let Some(e) = e.as_mut() {
            let p = &mut e.value.public;
            match self.1.load(Ordering::Relaxed) {
                SELF_SIG => p.self_sig.0[0] ^= 1,
                FOREIGN_ATTESTATION => {
                    use labyrinth::sign::TransportSigner as _;
                    let msg = [
                        format!("catbird.labyrinth.epoch_head_attest:{}:", self.owner()).as_bytes(),
                        p.epoch_head.0.as_slice(),
                    ]
                    .concat();
                    p.attestation.transport_pubkey.0 = attacker().transport_public_key().to_vec();
                    p.attestation.sig.0 = attacker().sign_transport(&msg).to_vec();
                }
                PREV_SIG => {
                    if let Some(sig) = p.prev_sig.as_mut() {
                        sig.0[0] ^= 1;
                    }
                }
                _ => {}
            }
        }
        Ok(e)
    }
    fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        self.0.list_epochs()
    }
    fn create_epoch_member(&self, m: &EpochMember) -> labyrinth::Result<()> {
        self.0.create_epoch_member(m)
    }
    fn list_epoch_members(&self, s: u64) -> labyrinth::Result<Vec<EpochMember>> {
        self.0.list_epoch_members(s)
    }
    fn create_virtual_device(&self, v: &VirtualDevice) -> labyrinth::Result<()> {
        self.0.create_virtual_device(v)
    }
    fn get_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<Option<VirtualDevice>> {
        self.0.get_virtual_device(id)
    }
    fn list_virtual_devices(&self) -> labyrinth::Result<Vec<VirtualDevice>> {
        self.0.list_virtual_devices()
    }
    fn append_owner_batch(&self, b: &OwnerBatch) -> labyrinth::Result<String> {
        self.0.append_owner_batch(b)
    }
    fn list_owner_batches(
        &self,
        t: &str,
        r: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.0.list_owner_batches(t, r)
    }
    fn publish_mailbox_keys(&self, r: &MailboxKeysRecord) -> labyrinth::Result<()> {
        self.0.publish_mailbox_keys(r)
    }
}

#[test]
fn a_tampered_starting_epoch_record_is_not_adopted() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    let mut alice = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let state = alice.export_state().unwrap();
    let tamper = Arc::new(AtomicU8::new(SELF_SIG));
    let tampered = || Box::new(Tampered(net.mailbox(A), tamper.clone()));

    // Restart: the stored latest epoch record must verify.
    let restored = Labyrinth::from_state(
        &state,
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, tampered()),
    );
    assert!(restored.is_err(), "restart adopted a tampered epoch record");

    // OTC enrollment: no forward epochs, so only the starting record.
    let mut r = alice.otc_offer().unwrap();
    let typed = r.code().as_str().to_owned();
    let (init, hello) = Labyrinth::otc_start(A, &typed).unwrap();
    let reply = alice.otc_respond(&mut r, &hello).unwrap();
    net.register_chat_device(A, tpub(5));
    let enrolled = Labyrinth::enroll_via_otc(
        A,
        init,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(5)),
        backends(&net, &clock, A, tampered()),
    );
    assert!(
        enrolled.is_err(),
        "enrollment adopted a tampered epoch record"
    );

    // Untampered, both succeed.
    tamper.store(CLEAN, Ordering::Relaxed);
    Labyrinth::from_state(
        &state,
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, tampered()),
    )
    .unwrap();
}

// ---- 2026-10-13 review, labyrinth #5 follow-up: [CB-43] ----

/// Alice's phone and laptop, with the laptop revoked so that the newest
/// epoch is 1 (opened and attested by the phone).
fn alice_at_epoch_one(net: &MemoryBackend, clock: &TestClock) -> Labyrinth {
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(net, clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let laptop = enroll_sibling(net, clock, &mut phone, 2, Box::new(net.mailbox(A)));
    let rot = phone
        .revoke_device(&laptop.device_public().device_key_pub)
        .unwrap();
    assert_eq!(rot.new_epoch, 1);
    phone
}

#[test]
fn a_foreign_attestation_or_broken_link_on_my_own_epoch_is_not_adopted() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = alice_at_epoch_one(&net, &clock);
    let state = phone.export_state().unwrap();
    let tamper = Arc::new(AtomicU8::new(CLEAN));
    let tampered = || Box::new(Tampered(net.mailbox(A), tamper.clone()));

    for mode in [FOREIGN_ATTESTATION, PREV_SIG] {
        tamper.store(mode, Ordering::Relaxed);
        let restored = Labyrinth::from_state(
            &state,
            A,
            Box::new(signer(1)),
            backends(&net, &clock, A, tampered()),
        );
        assert!(
            restored.is_err(),
            "restart adopted epoch 1 under mode {mode}"
        );

        let mut r = phone.otc_offer().unwrap();
        let typed = r.code().as_str().to_owned();
        let (init, hello) = Labyrinth::otc_start(A, &typed).unwrap();
        let reply = phone.otc_respond(&mut r, &hello).unwrap();
        net.register_chat_device(A, tpub(5));
        let enrolled = Labyrinth::enroll_via_otc(
            A,
            init,
            &reply.message,
            &reply.sealed_payload,
            Box::new(signer(5)),
            backends(&net, &clock, A, tampered()),
        );
        assert!(
            enrolled.is_err(),
            "enrollment adopted epoch 1 under mode {mode}"
        );
    }

    tamper.store(CLEAN, Ordering::Relaxed);
    let restored = Labyrinth::from_state(
        &state,
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, tampered()),
    )
    .unwrap();
    assert_eq!(restored.latest_epoch(), 1);
}

#[test]
fn my_latest_epoch_is_the_verified_copy_not_a_fresh_mailbox_read() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let phone = alice_at_epoch_one(&net, &clock);
    let state = phone.export_state().unwrap();
    let tamper = Arc::new(AtomicU8::new(CLEAN));
    let mut restored = Labyrinth::from_state(
        &state,
        A,
        Box::new(signer(1)),
        backends(
            &net,
            &clock,
            A,
            Box::new(Tampered(net.mailbox(A), tamper.clone())),
        ),
    )
    .unwrap();
    let verified = restored.latest_public().unwrap();
    assert_eq!(verified.attestation.transport_public_key, tpub(1));

    // The host swaps the record after the restart checked it.
    tamper.store(FOREIGN_ATTESTATION, Ordering::Relaxed);
    assert_eq!(restored.latest_public().unwrap(), verified);
    restored.sync_epochs().unwrap();
    assert_eq!(restored.latest_public().unwrap(), verified);
    restored.check_epoch_integrity().unwrap();
}

/// Directory that fails every lookup while the flag is set.
struct Flaky(MemoryDirectory, Arc<AtomicBool>);
impl Flaky {
    fn check(&self) -> labyrinth::Result<()> {
        if self.1.load(Ordering::Relaxed) {
            Err(Error::Backend("directory unreachable".into()))
        } else {
            Ok(())
        }
    }
}
impl MailboxDirectory for Flaky {
    fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        self.check()?;
        self.0.latest(did)
    }
    fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        self.check()?;
        self.0.epoch(did, seq)
    }
    fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        self.check()?;
        self.0.device_transport_keys(did)
    }
}

#[test]
fn an_offline_restart_defers_the_attester_check_until_the_roster_needs_it() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let phone = alice_at_epoch_one(&net, &clock);
    let state = phone.export_state().unwrap();
    let tamper = Arc::new(AtomicU8::new(FOREIGN_ATTESTATION));
    let down = Arc::new(AtomicBool::new(true));
    let mut b = backends(
        &net,
        &clock,
        A,
        Box::new(Tampered(net.mailbox(A), tamper.clone())),
    );
    b.directory = Box::new(Flaky(net.directory(), down.clone()));

    // Offline, the restart works: the signatures and link verify.
    let mut restored = Labyrinth::from_state(&state, A, Box::new(signer(1)), b).unwrap();
    // Back online, the foreign attester is caught before anything is
    // addressed to this epoch, and keeps being caught.
    down.store(false, Ordering::Relaxed);
    assert_eq!(
        restored.resolve_roster(&[A]).unwrap_err(),
        Error::Unattested
    );
    assert_eq!(restored.sync_epochs().unwrap_err(), Error::Unattested);
    assert_eq!(
        restored.resolve_roster(&[A]).unwrap_err(),
        Error::Unattested
    );
}

#[test]
fn owner_archive_and_rearchive_fail_closed_when_outbox_holds_stale_epoch_items() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(B, tpub(4));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let mut laptop = enroll_sibling(&net, &clock, &mut phone, 2, Box::new(net.mailbox(A)));
    let spare = enroll_sibling(&net, &clock, &mut phone, 3, Box::new(net.mailbox(A)));
    let mut bob = Labyrinth::initialize(
        B,
        Box::new(signer(4)),
        backends(&net, &clock, B, Box::new(net.mailbox(B))),
    )
    .unwrap();
    let roster_ab = bob.resolve_roster(&[A, B]).unwrap();
    bob.archive_outgoing("t-leave", &roster_ab, "m-bob", 5, b"hello")
        .unwrap();
    bob.flush().unwrap();

    phone
        .archive_owner("owner-queued", "o1", 1, b"epoch-0")
        .unwrap();
    assert_eq!(phone.pending("owner-queued"), 1);

    laptop
        .revoke_device(&spare.device_public().device_key_pub)
        .unwrap();

    assert_eq!(
        phone
            .archive_owner("owner-queued", "o2", 2, b"epoch-1")
            .unwrap_err(),
        Error::WrongEpoch
    );
    assert_eq!(phone.pending("owner-queued"), 1);
    assert_eq!(
        phone
            .archive_owner("other-thread", "o3", 3, b"epoch-1")
            .unwrap_err(),
        Error::WrongEpoch
    );
    assert_eq!(phone.pending("other-thread"), 0);
    assert_eq!(
        phone.rearchive_thread_before_leave("t-empty").unwrap_err(),
        Error::WrongEpoch
    );
    assert_eq!(
        phone.rearchive_thread_before_leave("t-leave").unwrap_err(),
        Error::WrongEpoch
    );

    assert_eq!(phone.discard_pending("owner-queued"), 1);
    assert_eq!(phone.rearchive_thread_before_leave("t-leave").unwrap(), 1);
}

struct TrackMeksAndFailAppend {
    inner: labyrinth::store::memory::MemoryThreads,
    created_meks: Arc<std::sync::atomic::AtomicUsize>,
    fail_append: Arc<AtomicBool>,
}

impl labyrinth::store::ThreadStore for TrackMeksAndFailAppend {
    fn author(&self) -> &str {
        self.inner.author()
    }
    fn create_mek(&self, mek: &labyrinth::records::MekDistribution) -> labyrinth::Result<()> {
        self.created_meks.fetch_add(1, Ordering::Relaxed);
        self.inner.create_mek(mek)
    }
    fn find_meks(
        &self,
        t: &str,
        id: &[u8; 12],
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::MekDistribution>>> {
        self.inner.find_meks(t, id)
    }
    fn append_batch(&self, b: &labyrinth::records::Batch) -> labyrinth::Result<String> {
        if self.fail_append.load(Ordering::Relaxed) {
            return Err(Error::Backend("append down".into()));
        }
        self.inner.append_batch(b)
    }
    fn list_batches(
        &self,
        t: &str,
        s: Option<&str>,
        r: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<labyrinth::records::Batch>>> {
        self.inner.list_batches(t, s, r)
    }
}

#[test]
fn archive_outgoing_flushes_prior_roster_before_publishing_new_mek() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    const C: &str = "did:plc:carol";
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(B, tpub(2));
    net.register_chat_device(C, tpub(3));
    let created_meks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let fail_append = Arc::new(AtomicBool::new(false));
    let mut alice = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        Backends {
            threads: Box::new(TrackMeksAndFailAppend {
                inner: net.threads(A),
                created_meks: created_meks.clone(),
                fail_append: fail_append.clone(),
            }),
            ..backends(&net, &clock, A, Box::new(net.mailbox(A)))
        },
    )
    .unwrap();
    let mut bob = Labyrinth::initialize(
        B,
        Box::new(signer(2)),
        backends(&net, &clock, B, Box::new(net.mailbox(B))),
    )
    .unwrap();
    let _carol = Labyrinth::initialize(
        C,
        Box::new(signer(3)),
        backends(&net, &clock, C, Box::new(net.mailbox(C))),
    )
    .unwrap();

    let roster_ab = alice.resolve_roster(&[A, B]).unwrap();
    alice
        .archive_outgoing("t", &roster_ab, "m1", 10, b"first")
        .unwrap();
    assert_eq!(created_meks.load(Ordering::Relaxed), 1);
    assert_eq!(alice.pending("t"), 1);

    // If flushing the buffered [A, B] batch fails, the new [A, B, C] MEK must
    // not be published beforehand and orphaned on the thread store.
    fail_append.store(true, Ordering::Relaxed);
    let roster_abc = alice.resolve_roster(&[A, B, C]).unwrap();
    assert!(matches!(
        alice.archive_outgoing("t", &roster_abc, "m2", 20, b"second"),
        Err(Error::Backend(_))
    ));
    assert_eq!(created_meks.load(Ordering::Relaxed), 1);
    assert_eq!(alice.pending("t"), 1);

    // Likewise, if Bob rotated while m1 was buffered, flushing m1 fails with
    // RosterMismatch before any new MEK for Bob's new epoch is published.
    fail_append.store(false, Ordering::Relaxed);
    bob.create_recovery_code(Mechanism::Code).unwrap();
    let bob_recovery = bob.list_recovery_methods().unwrap()[0].device_key;
    bob.revoke_device(&bob_recovery).unwrap();
    let roster_ab_v2 = alice.resolve_roster(&[A, B]).unwrap();
    assert_eq!(
        alice
            .archive_outgoing("t", &roster_ab_v2, "m2", 20, b"after bob rotate")
            .unwrap_err(),
        Error::RosterMismatch
    );
    assert_eq!(created_meks.load(Ordering::Relaxed), 1);
    assert_eq!(alice.pending("t"), 1);

    assert_eq!(alice.discard_pending("t"), 1);
    alice
        .archive_outgoing("t", &roster_ab_v2, "m2", 20, b"after discard")
        .unwrap();
    assert_eq!(created_meks.load(Ordering::Relaxed), 2);
}

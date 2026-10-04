//! Regression tests for the 2026-10-04 security review (DECISIONS.md,
//! "security review fixes"). Each test asserts the *secure* behaviour.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, Labyrinth};
use labyrinth::mailbox::EpochPublic;
use labyrinth::records::{
    Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryDirectory, MemoryMailbox};
use labyrinth::store::{ChatDeviceKey, MailboxDirectory, MailboxStore, Stored, TimeRange};

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
struct IgnoresRevoke(MemoryMailbox, Arc<AtomicBool>);
impl IgnoresRevoke {
    fn new(m: MemoryMailbox) -> Self {
        Self(m, Arc::new(AtomicBool::new(false)))
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
        self.0.create_epoch(e, m)
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
        clock: Box::new(clock.clone()),
    }
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
    const C: &str = "did:plc:carol";
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
fn rotation_with_invalid_member_mac_fails() {
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
    let err = laptop
        .revoke_device(&phone.device_public().device_key_pub)
        .unwrap_err();
    assert!(matches!(err, Error::Malformed(_)), "{err:?}");
    // Nothing was rotated: the tablet is still current.
    assert_eq!(tablet.sync_epochs().unwrap().to, 0);
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
        Error::EpochRollback {
            pinned: 2,
            offered: 0
        }
    );
}

// ---- Design note [CB-27]: removed chat keys only vouch for older history ----

#[test]
fn removed_chat_key_is_accepted_only_before_its_removal() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    const C: &str = "did:plc:carol";
    net.register_chat_device(A, tpub(1));
    net.register_chat_device(C, tpub(3));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A, Box::new(net.mailbox(A))),
    )
    .unwrap();
    let mut carol = Labyrinth::initialize(
        C,
        Box::new(signer(3)),
        backends(&net, &clock, C, Box::new(net.mailbox(C))),
    )
    .unwrap();
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
    let mut v2 = state.to_vec();
    v2[4] = 2;
    assert_eq!(restore(&v2, A, 1), Err(Error::Unsupported(2)));
    let mut bad_key = state.to_vec();
    let at = 4 + 1 + 2 + A.len() + 32 + 1; // second byte of deviceKey (byte 0 is clamped)
    bad_key[at] ^= 1;
    assert!(restore(&bad_key, A, 1).is_err());
}

#[test]
fn restarted_client_still_enforces_the_revoked_set() {
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
    let tablet = enroll_sibling(&net, &clock, &mut phone, 4, Box::new(net.mailbox(A)));

    // The revocation is recorded locally, but its rotation never happens.
    outage.store(true, Ordering::Relaxed);
    let phone_key = phone.device_public().device_key_pub;
    assert!(matches!(
        laptop.revoke_device(&phone_key),
        Err(Error::Backend(_))
    ));
    let state = laptop.export_state().unwrap();
    drop(laptop);

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
    assert_eq!(laptop.sync_epochs().unwrap().readmitted, vec![phone_key]);
    // ... and its next rotation, for another device, excludes it too.
    laptop
        .revoke_device(&tablet.device_public().device_key_pub)
        .unwrap();
    assert_eq!(phone.sync_epochs().unwrap_err(), Error::NotEpochMember);
    assert!(laptop.sync_epochs().unwrap().readmitted.is_empty());
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

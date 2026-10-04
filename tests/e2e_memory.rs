//! Full client lifecycle on the in-memory backend: enrollment, MEK
//! distribution, revocation, recovery, leaving and joining, and the
//! malicious-backend checks ([CB-18], SPEC §10).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, Labyrinth, MessageSource};
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::records::{
    Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use labyrinth::recovery_code::ALPHABET;
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryDirectory, MemoryMailbox};
use labyrinth::store::{MailboxDirectory, MailboxStore, Stored, TimeRange};
use labyrinth::virtual_device::Mechanism;

const ALICE: &str = "did:plc:alice";
const BOB: &str = "did:plc:bob";
const CAROL: &str = "did:plc:carol";
const DAVE: &str = "did:plc:dave";
const THREAD: &str = "conv-e2e";

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        1_791_000_000_000 + self.0.fetch_add(1, Ordering::Relaxed)
    }
}

struct World {
    net: MemoryBackend,
    clock: TestClock,
    /// Expected `(messageId, sender, frame)` in send order.
    sent: Vec<(String, String, Vec<u8>)>,
    ts: u64,
}

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

fn transport_pub(seed: u8) -> [u8; 32] {
    signer(seed).0.verifying_key().to_bytes()
}

impl World {
    fn new() -> Self {
        Self {
            net: MemoryBackend::new(),
            clock: TestClock::default(),
            sent: Vec::new(),
            ts: 1_000,
        }
    }

    fn backends(&self, did: &str) -> Backends {
        self.with_stores(
            did,
            Box::new(self.net.mailbox(did)),
            Box::new(self.net.directory()),
        )
    }

    fn with_stores(
        &self,
        did: &str,
        mailbox: Box<dyn MailboxStore + Send>,
        directory: Box<dyn MailboxDirectory + Send>,
    ) -> Backends {
        Backends {
            mailbox,
            threads: Box::new(self.net.threads(did)),
            directory,
            clock: Box::new(self.clock.clone()),
        }
    }

    /// A chat device `seed` of `did` joins MLS; returns its transport.
    fn chat_device(&self, did: &str, seed: u8) -> Box<Ed25519Transport> {
        self.net.register_chat_device(did, transport_pub(seed));
        Box::new(signer(seed))
    }

    fn init(&self, did: &str, seed: u8) -> Labyrinth {
        Labyrinth::initialize(did, self.chat_device(did, seed), self.backends(did)).unwrap()
    }

    /// `lab` sends `id` to the MLS group `members`; returns whether a new
    /// MEK record was written.
    fn send(&mut self, lab: &mut Labyrinth, members: &[&str], id: &str) -> bool {
        self.ts += 10;
        let frame = format!("frame {id} from {}", lab.did()).into_bytes();
        let roster = lab.resolve_roster(members).unwrap();
        let out = lab
            .archive_outgoing(THREAD, &roster, id, self.ts, &frame)
            .unwrap();
        self.sent.push((id.to_owned(), lab.did().to_owned(), frame));
        out.mek_written.is_some()
    }

    fn expected(&self, ids: &[&str]) -> Vec<(String, Option<String>, Vec<u8>)> {
        ids.iter()
            .map(|id| {
                let (i, s, f) = self.sent.iter().find(|(i, ..)| i == id).unwrap();
                (i.clone(), Some(s.clone()), f.clone())
            })
            .collect()
    }
}

fn read(lab: &mut Labyrinth) -> labyrinth::client::ThreadHistory {
    lab.load_thread(THREAD, TimeRange::ALL).unwrap()
}

fn got(h: &labyrinth::client::ThreadHistory) -> Vec<(String, Option<String>, Vec<u8>)> {
    h.messages
        .iter()
        .map(|m| (m.message_id.clone(), m.sender.clone(), m.frame.clone()))
        .collect()
}

fn ids(h: &labyrinth::client::ThreadHistory) -> Vec<&str> {
    h.messages.iter().map(|m| m.message_id.as_str()).collect()
}

/// Change one entropy character of the code to another alphabet character.
fn one_typo(code: &str) -> String {
    let mut s = code.as_bytes().to_vec();
    let i = ALPHABET.iter().position(|&c| c == s[11]).unwrap();
    s[11] = ALPHABET[(i + 7) % 32];
    String::from_utf8(s).unwrap()
}

/// A personal mailbox that hides every epoch after `max_seq` (SPEC §10).
struct Truncating {
    inner: MemoryMailbox,
    max_seq: u64,
}

impl MailboxStore for Truncating {
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
        self.inner.create_epoch(e, m)
    }
    fn get_epoch(&self, seq: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        if seq > self.max_seq {
            return Ok(None);
        }
        self.inner.get_epoch(seq)
    }
    fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        let mut v = self.inner.list_epochs()?;
        v.retain(|e| e.value.seq() <= self.max_seq);
        Ok(v)
    }
    fn create_epoch_member(&self, m: &EpochMember) -> labyrinth::Result<()> {
        self.inner.create_epoch_member(m)
    }
    fn list_epoch_members(&self, seq: u64) -> labyrinth::Result<Vec<EpochMember>> {
        self.inner.list_epoch_members(seq)
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

/// A directory that serves `fake` as `victim`'s latest epoch.
struct Substituting {
    inner: MemoryDirectory,
    victim: String,
    fake: EpochPublic,
}

impl MailboxDirectory for Substituting {
    fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        if did == self.victim {
            return Ok(Some(self.fake.clone()));
        }
        self.inner.latest(did)
    }
    fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        self.inner.epoch(did, seq)
    }
    fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<[u8; 32]>> {
        self.inner.device_transport_keys(did)
    }
    fn historical_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<[u8; 32]>> {
        self.inner.historical_transport_keys(did)
    }
}

#[test]
fn full_lifecycle() {
    let mut w = World::new();

    // Alice: phone (genesis), laptop via one-time code, recovery code.
    let mut phone = w.init(ALICE, 1);
    let mut responder = phone.otc_offer().unwrap();
    let typed = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(ALICE, &typed).unwrap();
    let reply = phone.otc_respond(&mut responder, &hello).unwrap();
    let (mut laptop, _) = Labyrinth::enroll_via_otc(
        ALICE,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        w.chat_device(ALICE, 2),
        w.backends(ALICE),
    )
    .unwrap();
    assert_eq!(laptop.latest_epoch(), 0);
    let recovery = phone.create_recovery_code(Mechanism::Code).unwrap();
    let code = recovery.code.as_str().to_owned();

    let mut bob = w.init(BOB, 3);
    let mut carol = w.init(CAROL, 4);
    let group = [ALICE, BOB, CAROL];

    // Everyone talks. Bob's second message reuses his MEK.
    assert!(w.send(&mut phone, &group, "a1"));
    assert!(w.send(&mut bob, &group, "b1"));
    assert!(w.send(&mut carol, &group, "c1"));
    assert!(w.send(&mut laptop, &group, "a2"));
    assert!(!w.send(&mut bob, &group, "b2"));
    for lab in [&mut phone, &mut laptop, &mut bob, &mut carol] {
        lab.flush().unwrap();
    }
    let before = ["a1", "b1", "c1", "a2", "b2"];
    assert_eq!(got(&read(&mut carol)), w.expected(&before));

    // Alice's phone is lost: the laptop revokes it and rotates.
    w.net.remove_chat_device(ALICE, transport_pub(1));
    let phone_key = phone.device_public().device_key_pub;
    let rot = laptop.revoke_device(&phone_key).unwrap();
    assert_eq!(rot.new_epoch, 1);
    assert_eq!(phone.sync_epochs().unwrap_err(), Error::NotEpochMember);
    assert_eq!(w.net.directory().latest(ALICE).unwrap().unwrap().seq, 1);

    // Alice's new epoch changes the roster: everyone mints a fresh MEK.
    assert!(w.send(&mut laptop, &group, "a3"));
    assert!(w.send(&mut bob, &group, "b3"));
    assert!(w.send(&mut carol, &group, "c2"));
    for lab in [&mut laptop, &mut bob, &mut carol] {
        lab.flush().unwrap();
    }

    // A second bundle made in epoch 1: restoring from it needs backward
    // chaining to read epoch-0 MEKs.
    let keychain = laptop.create_recovery_code(Mechanism::Keychain).unwrap();
    let (mut tablet, _) = Labyrinth::restore_with_recovery_code(
        ALICE,
        keychain.code.as_str(),
        w.chat_device(ALICE, 8),
        w.backends(ALICE),
    )
    .unwrap();

    // A NEW Alice device restores from the recovery code with one typo and
    // reads the whole thread, before and after the revocation.
    let (mut alice, _) = Labyrinth::restore_with_recovery_code(
        ALICE,
        &one_typo(&code),
        w.chat_device(ALICE, 5),
        w.backends(ALICE),
    )
    .unwrap();
    assert_eq!(alice.latest_epoch(), 1);
    let all = ["a1", "b1", "c1", "a2", "b2", "a3", "b3", "c2"];
    let h = read(&mut alice);
    assert_eq!(got(&h), w.expected(&all));
    assert!(h.undecryptable.is_empty());
    assert!(h.messages.iter().all(|m| m.source == MessageSource::Sender));
    assert_eq!(got(&read(&mut tablet)), w.expected(&all));

    // Carol re-archives, then MLS removes her and Bob talks without her.
    assert_eq!(
        carol.rearchive_thread_before_leave(THREAD).unwrap(),
        all.len()
    );
    let group = [ALICE, BOB];
    assert!(w.send(&mut bob, &group, "b4"));
    bob.flush().unwrap();
    // Space removal lags: Carol still sees the records but cannot open b4.
    let h = read(&mut carol);
    assert_eq!(ids(&h), all);
    assert_eq!(h.undecryptable.len(), 1);
    assert_eq!(h.undecryptable[0].message_id, "b4");
    assert_eq!(h.undecryptable[0].error, Error::NotRecipient);
    // Once the space drops her, her own archive still holds the history.
    w.net.revoke_thread_access(THREAD, CAROL);
    let h = read(&mut carol);
    assert!(!h.space_readable);
    assert_eq!(ids(&h), all);
    assert!(h.messages.iter().all(|m| m.source == MessageSource::Owner));
    let frames: Vec<_> = h.messages.iter().map(|m| m.frame.clone()).collect();
    let want: Vec<_> = w.expected(&all).into_iter().map(|x| x.2).collect();
    assert_eq!(frames, want);

    // Dave joins later and sees only what was sent after he joined.
    let mut dave = w.init(DAVE, 6);
    let group = [ALICE, BOB, DAVE];
    assert!(w.send(&mut bob, &group, "b5"));
    assert!(w.send(&mut dave, &group, "d1"));
    bob.flush().unwrap();
    dave.flush().unwrap();
    let h = read(&mut dave);
    assert_eq!(got(&h), w.expected(&["b5", "d1"]));
    assert_eq!(h.undecryptable.len(), all.len() + 1);
    assert!(
        h.undecryptable
            .iter()
            .all(|u| u.error == Error::NotRecipient)
    );

    // Alice's restored device reads everything, including after Carol left.
    let everything = [&all[..], &["b4", "b5", "d1"]].concat();
    assert_eq!(got(&read(&mut alice)), w.expected(&everything));
    // Time ranges filter.
    let h = alice
        .load_thread(
            THREAD,
            TimeRange {
                from_ms: Some(w.ts),
                until_ms: None,
            },
        )
        .unwrap();
    assert_eq!(ids(&h), ["d1"]);

    // A backend that hides epoch 1 from a restoring device is detected.
    let truncated = w.with_stores(
        ALICE,
        Box::new(Truncating {
            inner: w.net.mailbox(ALICE),
            max_seq: 0,
        }),
        Box::new(w.net.directory()),
    );
    let err =
        Labyrinth::restore_with_recovery_code(ALICE, &code, w.chat_device(ALICE, 7), truncated)
            .unwrap_err();
    assert_eq!(
        err,
        Error::EpochTruncated {
            published: 1,
            reached: 0
        }
    );
}

#[test]
fn substituted_mailbox_keys_are_rejected() {
    let w = World::new();
    let bob = w.init(BOB, 3);
    let real = bob.latest_public().unwrap();

    // A key set signed by a transport key that is not one of Bob's devices.
    let attacker = signer(66);
    let keys = MailboxKeys::derive(&[66u8; 32], 0);
    let forged = EpochPublic::sign(BOB, 0, &keys, None, None, &attacker).unwrap();
    // Bob's real record with swapped keys (head no longer matches).
    let mut tampered = real.clone();
    tampered.keys = keys.public();

    let cases = [
        ("did:plc:erin1", forged.clone(), Error::Unattested),
        (
            "did:plc:erin2",
            tampered,
            Error::Malformed("epoch head mismatch"),
        ),
    ];
    for (erin_did, fake, want) in cases {
        let dir = Substituting {
            inner: w.net.directory(),
            victim: BOB.into(),
            fake,
        };
        w.net.register_chat_device(erin_did, transport_pub(9));
        let b = w.with_stores(erin_did, Box::new(w.net.mailbox(erin_did)), Box::new(dir));
        let mut erin = Labyrinth::initialize(erin_did, Box::new(signer(9)), b).unwrap();
        assert_eq!(erin.resolve_roster(&[BOB]).unwrap_err(), want);
        let roster = vec![(BOB.to_owned(), forged.clone())];
        assert_eq!(
            erin.archive_outgoing(THREAD, &roster, "m", 1, b"x")
                .unwrap_err(),
            Error::Unattested
        );
        // The genuine record passes.
        let roster = vec![(BOB.to_owned(), real.clone())];
        assert!(erin.archive_outgoing(THREAD, &roster, "m", 1, b"x").is_ok());
    }
}

#[test]
fn passkey_restore_and_batch_limits() {
    let mut w = World::new();
    let mut phone = w.init(ALICE, 1);
    phone
        .create_passkey_recovery(&[42u8; 32], b"credential-1")
        .unwrap();
    assert_eq!(
        Labyrinth::restore_with_passkey(
            ALICE,
            &[43u8; 32],
            b"credential-1",
            w.chat_device(ALICE, 2),
            w.backends(ALICE)
        )
        .unwrap_err(),
        Error::Decrypt
    );
    let (mut tablet, _) = Labyrinth::restore_with_passkey(
        ALICE,
        &[42u8; 32],
        b"credential-1",
        w.chat_device(ALICE, 3),
        w.backends(ALICE),
    )
    .unwrap();

    // 300 messages: one batch flushes itself at 256, flush() writes 44.
    let mut bob = w.init(BOB, 4);
    let group = [ALICE, BOB];
    let mut auto = Vec::new();
    for i in 0..300 {
        w.ts += 1;
        let roster = bob.resolve_roster(&group).unwrap();
        let out = bob
            .archive_outgoing(THREAD, &roster, &format!("m{i:03}"), w.ts, b"hi")
            .unwrap();
        auto.extend(out.flushed);
    }
    assert_eq!(auto.len(), 1);
    assert_eq!(auto[0].count, 256);
    assert_eq!(bob.pending(THREAD), 44);
    let rest = bob.flush().unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].count, 44);
    let h = read(&mut tablet);
    assert_eq!(h.messages.len(), 300);

    // Owner archive round trip on the restored device.
    tablet.archive_owner(THREAD, "own-1", 5, b"note").unwrap();
    tablet.flush().unwrap();
    let h = read(&mut tablet);
    let own: Vec<_> = h
        .messages
        .iter()
        .filter(|m| m.source == MessageSource::Owner)
        .collect();
    assert_eq!(own.len(), 1);
    assert_eq!(own[0].frame, b"note");
    // Initializing an existing mailbox conflicts.
    assert_eq!(
        Labyrinth::initialize(ALICE, w.chat_device(ALICE, 8), w.backends(ALICE)).unwrap_err(),
        Error::Conflict
    );
}

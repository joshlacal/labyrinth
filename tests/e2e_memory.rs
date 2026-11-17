//! Full client lifecycle on the in-memory backend: enrollment, MEK
//! distribution, revocation, recovery, leaving and joining, and the
//! malicious-backend checks ([CB-18], SPEC §10).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{
    Backends, Clock, Labyrinth, MessageSource, enroll::passkey_recovery_requires_share,
};
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::records::{
    Device, Epoch, EpochMember, MailboxKeysRecord, OtcSession, OwnerBatch, VirtualDevice,
};
use labyrinth::recovery_code::ALPHABET;
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryDirectory, MemoryMailbox};
use labyrinth::store::{
    AtomicEnrollBundle, ChatDeviceKey, MailboxDirectory, MailboxStore, MemberDeviceKey,
    SequencerReceiptKey, Stored, TimeRange,
};
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

fn earlier_vdevice_id(id: [u8; 16]) -> [u8; 16] {
    let mut earlier = id;
    let first_nonzero = earlier
        .iter()
        .position(|b| *b != 0)
        .expect("generated vdevice id is not the minimum 128-bit value");
    earlier[first_nonzero] -= 1;
    earlier[first_nonzero + 1..].fill(u8::MAX);
    assert!(earlier < id);
    earlier
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
        mailbox: Box<dyn MailboxStore>,
        directory: Box<dyn MailboxDirectory>,
    ) -> Backends {
        Backends {
            mailbox,
            threads: Box::new(self.net.threads(did)),
            directory,
            publishers: vec![],
            clock: Box::new(self.clock.clone()),
        }
    }

    /// A chat device `seed` of `did` joins MLS; returns its transport.
    fn chat_device(&self, did: &str, seed: u8) -> Box<Ed25519Transport> {
        self.net.register_chat_device(did, transport_pub(seed));
        Box::new(signer(seed))
    }

    fn init(&self, did: &str, seed: u8) -> Labyrinth {
        block_on(Labyrinth::initialize(
            did,
            self.chat_device(did, seed),
            self.backends(did),
        ))
        .unwrap()
    }

    /// `lab` sends `id` to the MLS group `members`; returns whether a new
    /// MEK record was written.
    fn send(&mut self, lab: &mut Labyrinth, members: &[&str], id: &str) -> bool {
        self.ts += 10;
        let frame = format!("frame {id} from {}", lab.did()).into_bytes();
        let roster = block_on(lab.resolve_roster(members)).unwrap();
        let out = block_on(lab.archive_outgoing(THREAD, &roster, id, self.ts, &frame)).unwrap();
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
    block_on(lab.load_thread(THREAD, TimeRange::ALL)).unwrap()
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

/// A mailbox view that returns a caller-controlled virtual-device list.
/// The underlying records remain available for the rest of enrollment.
struct BundleView {
    inner: MemoryMailbox,
    bundles: Vec<VirtualDevice>,
    epoch_calls: AtomicU64,
    fail_epoch_call: Option<u64>,
    fail_member_key: Option<XVerifyingKey>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for BundleView {
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
        self.inner.create_epoch(e, m).await
    }
    async fn atomic_enroll(&self, bundle: &AtomicEnrollBundle) -> labyrinth::Result<String> {
        self.inner.atomic_enroll(bundle).await
    }
    async fn get_epoch(&self, seq: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        let call = self.epoch_calls.fetch_add(1, Ordering::Relaxed) + 1;
        if self.fail_epoch_call == Some(call) {
            return Err(Error::Backend("injected passkey preflight outage".into()));
        }
        self.inner.get_epoch(seq).await
    }
    async fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        self.inner.list_epochs().await
    }
    async fn create_epoch_member(&self, m: &EpochMember) -> labyrinth::Result<()> {
        self.inner.create_epoch_member(m).await
    }
    async fn list_epoch_members(&self, seq: u64) -> labyrinth::Result<Vec<EpochMember>> {
        self.inner.list_epoch_members(seq).await
    }
    async fn get_epoch_member(
        &self,
        seq: u64,
        key: &XVerifyingKey,
    ) -> labyrinth::Result<Option<EpochMember>> {
        if self.fail_member_key.as_ref() == Some(key) {
            return Err(Error::Backend("injected passkey membership outage".into()));
        }
        self.inner.get_epoch_member(seq, key).await
    }
    async fn create_virtual_device(&self, v: &VirtualDevice) -> labyrinth::Result<()> {
        self.inner.create_virtual_device(v).await
    }
    async fn get_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<Option<VirtualDevice>> {
        self.inner.get_virtual_device(id).await
    }
    async fn list_virtual_devices(&self) -> labyrinth::Result<Vec<VirtualDevice>> {
        Ok(self.bundles.clone())
    }
    async fn list_virtual_device_records(
        &self,
    ) -> labyrinth::Result<Vec<labyrinth::Result<VirtualDevice>>> {
        Ok(self.bundles.iter().cloned().map(Ok).collect())
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
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for Truncating {
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
        self.inner.create_epoch(e, m).await
    }
    async fn atomic_enroll(&self, bundle: &AtomicEnrollBundle) -> labyrinth::Result<String> {
        self.inner.atomic_enroll(bundle).await
    }
    async fn get_epoch(&self, seq: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        if seq > self.max_seq {
            return Ok(None);
        }
        self.inner.get_epoch(seq).await
    }
    async fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        let mut v = self.inner.list_epochs().await?;
        v.retain(|e| e.value.seq() <= self.max_seq);
        Ok(v)
    }
    async fn create_epoch_member(&self, m: &EpochMember) -> labyrinth::Result<()> {
        self.inner.create_epoch_member(m).await
    }
    async fn list_epoch_members(&self, seq: u64) -> labyrinth::Result<Vec<EpochMember>> {
        self.inner.list_epoch_members(seq).await
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
    async fn list_virtual_device_records(
        &self,
    ) -> labyrinth::Result<Vec<labyrinth::Result<VirtualDevice>>> {
        self.inner.list_virtual_device_records().await
    }
}

/// A directory that serves `fake` as `victim`'s latest epoch.
struct Substituting {
    inner: MemoryDirectory,
    victim: String,
    fake: EpochPublic,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for Substituting {
    async fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        if did == self.victim {
            return Ok(Some(self.fake.clone()));
        }
        self.inner.latest(did).await
    }
    async fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        self.inner.epoch(did, seq).await
    }
    async fn epoch_chain(
        &self,
        did: &str,
    ) -> labyrinth::Result<Option<(Vec<labyrinth_protocol::EpochPublicHeader>, u64)>> {
        self.inner.epoch_chain(did).await
    }
    async fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
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

#[test]
fn full_lifecycle() {
    let mut w = World::new();

    // Alice: phone (genesis = 0), laptop via one-time code (Gate 3 opens 1), recovery code.
    let mut phone = w.init(ALICE, 1);
    let mut responder = phone.otc_offer().unwrap();
    let typed = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(ALICE, &typed).unwrap();
    let reply = block_on(phone.otc_respond(&mut responder, &hello)).unwrap();
    let (mut laptop, _) = block_on(Labyrinth::enroll_via_otc(
        ALICE,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        w.chat_device(ALICE, 2),
        w.backends(ALICE),
    ))
    .unwrap();
    assert_eq!(laptop.latest_epoch(), 1);
    let recovery = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
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
        block_on(lab.flush()).unwrap();
    }
    let before = ["a1", "b1", "c1", "a2", "b2"];
    assert_eq!(got(&read(&mut carol)), w.expected(&before));

    // Alice's phone is lost: the laptop revokes it and rotates (1 -> 2),
    // atomically invalidating pre-revocation recovery methods and issuing a replacement.
    w.net.remove_chat_device(ALICE, transport_pub(1), w.ts + 1);
    let phone_key = phone.device_public().device_key_pub;
    let rot = block_on(laptop.revoke_device(&phone_key)).unwrap();
    assert_eq!(rot.new_epoch, 2);
    let replacement = rot
        .rekeyed_recovery
        .expect("physical revocation re-keys recovery methods");
    assert!(matches!(
        block_on(Labyrinth::restore_with_recovery_code(
            ALICE,
            &code,
            w.chat_device(ALICE, 9),
            w.backends(ALICE),
        )),
        Err(Error::BadRecoveryCode)
    ));
    assert_eq!(
        block_on(phone.sync_epochs()).unwrap_err(),
        Error::NotEpochMember
    );
    assert_eq!(
        block_on(w.net.directory().latest(ALICE))
            .unwrap()
            .unwrap()
            .seq,
        2
    );

    // Alice's new epoch changes the roster: everyone mints a fresh MEK.
    assert!(w.send(&mut laptop, &group, "a3"));
    assert!(w.send(&mut bob, &group, "b3"));
    assert!(w.send(&mut carol, &group, "c2"));
    for lab in [&mut laptop, &mut bob, &mut carol] {
        block_on(lab.flush()).unwrap();
    }

    // A second bundle made in epoch 2: restoring from it needs backward
    // chaining to read earlier-epoch MEKs, and Gate 3 opens epoch 3.
    let keychain = block_on(laptop.create_recovery_code(Mechanism::Keychain)).unwrap();
    let (mut tablet, _) = block_on(Labyrinth::restore_with_recovery_code(
        ALICE,
        keychain.code.as_str(),
        w.chat_device(ALICE, 8),
        w.backends(ALICE),
    ))
    .unwrap();
    assert_eq!(tablet.latest_epoch(), 3);

    // A NEW Alice device restores from the replacement recovery code with one typo,
    // opens epoch 4 (Gate 3), and reads the whole thread before and after revocation.
    let (mut alice, _) = block_on(Labyrinth::restore_with_recovery_code(
        ALICE,
        &one_typo(replacement.code.as_str()),
        w.chat_device(ALICE, 5),
        w.backends(ALICE),
    ))
    .unwrap();
    assert_eq!(alice.latest_epoch(), 4);
    let all = ["a1", "b1", "c1", "a2", "b2", "a3", "b3", "c2"];
    let h = read(&mut alice);
    assert_eq!(got(&h), w.expected(&all));
    assert!(h.undecryptable.is_empty());
    assert!(h.messages.iter().all(|m| m.source == MessageSource::Sender));
    assert_eq!(got(&read(&mut tablet)), w.expected(&all));

    // Carol re-archives, then MLS removes her and Bob talks without her.
    assert_eq!(
        block_on(carol.rearchive_thread_before_leave(THREAD)).unwrap(),
        all.len()
    );
    let group = [ALICE, BOB];
    assert!(w.send(&mut bob, &group, "b4"));
    block_on(bob.flush()).unwrap();
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
    block_on(bob.flush()).unwrap();
    block_on(dave.flush()).unwrap();
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
    let h = block_on(alice.load_thread(
        THREAD,
        TimeRange {
            from_ms: Some(w.ts),
            until_ms: None,
        },
    ))
    .unwrap();
    assert_eq!(ids(&h), ["d1"]);

    // A backend that hides epochs > 2 from a restoring device (bundle minted in epoch 2) is detected.
    let truncated = w.with_stores(
        ALICE,
        Box::new(Truncating {
            inner: w.net.mailbox(ALICE),
            max_seq: 2,
        }),
        Box::new(w.net.directory()),
    );
    let err = block_on(Labyrinth::restore_with_recovery_code(
        ALICE,
        replacement.code.as_str(),
        w.chat_device(ALICE, 7),
        truncated,
    ))
    .unwrap_err();
    assert_eq!(
        err,
        Error::EpochTruncated {
            published: 4,
            reached: 2
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
    let forged = EpochPublic::sign(BOB, 0, &keys, [0u8; 32], None, None, &attacker).unwrap();
    // Bob's real record with swapped keys (head no longer matches).
    let mut tampered = real.clone();
    tampered.keys = keys.public();

    let cases = [
        (
            "did:plc:erin1",
            forged.clone(),
            Error::Unattested,
            Error::Unattested,
            Error::Unattested,
        ),
        (
            "did:plc:erin2",
            tampered,
            Error::Malformed("epoch head mismatch"),
            Error::Malformed("epoch head mismatch"),
            Error::Malformed("epoch head mismatch"),
        ),
    ];
    for (erin_did, fake, want, supplied_want, direct_want) in cases {
        let dir = Substituting {
            inner: w.net.directory(),
            victim: BOB.into(),
            fake,
        };
        w.net.register_chat_device(erin_did, transport_pub(9));
        let b = w.with_stores(erin_did, Box::new(w.net.mailbox(erin_did)), Box::new(dir));
        let mut erin = block_on(Labyrinth::initialize(erin_did, Box::new(signer(9)), b)).unwrap();
        assert_eq!(block_on(erin.resolve_roster(&[BOB])).unwrap_err(), want);
        let roster = vec![(BOB.to_owned(), forged.clone())];
        assert_eq!(
            block_on(erin.archive_outgoing(THREAD, &roster, "m", 1, b"x")).unwrap_err(),
            supplied_want
        );
        // Supplying a genuine record directly must not bypass the live
        // directory check while that directory is serving a substitution.
        let roster = vec![(BOB.to_owned(), real.clone())];
        assert_eq!(
            block_on(erin.archive_outgoing(THREAD, &roster, "m", 1, b"x")).unwrap_err(),
            direct_want
        );
    }
}

#[test]
fn passkey_creation_rejects_invalid_prf_without_storing_bundle() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    for len in [0, 1, 31, 33, 64] {
        let prf_output = vec![7u8; len];
        let credential = format!("credential-{len}");
        let result = block_on(phone.create_passkey_recovery(&prf_output, credential.as_bytes()));
        let stored = block_on(w.net.mailbox(ALICE).list_virtual_devices())
            .unwrap()
            .len();
        assert_eq!(
            (result.err(), stored),
            (
                Some(Error::Malformed("passkey PRF output must be 32 bytes")),
                0
            ),
            "length {len}"
        );
    }
}

#[test]
fn version_two_passkey_preflight_needs_no_recovery_share_service() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let bundles = block_on(w.net.mailbox(ALICE).list_virtual_devices()).unwrap();

    assert!(
        !passkey_recovery_requires_share(
            ALICE,
            &[42u8; 32],
            b"credential-1",
            &bundles,
        )
        .unwrap()
    );
}

#[test]
fn passkey_restore_skips_earlier_duplicate_with_invalid_wrap() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    let setup = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let mailbox = w.net.mailbox(ALICE);
    let mut poison = block_on(mailbox.get_virtual_device(&setup.vdevice_id))
        .unwrap()
        .unwrap();
    poison.vdevice_id.0 = earlier_vdevice_id(setup.vdevice_id).to_vec();
    *poison
        .passkey_wrapped_code
        .as_mut()
        .unwrap()
        .0
        .last_mut()
        .unwrap() ^= 1;
    block_on(mailbox.create_virtual_device(&poison)).unwrap();

    block_on(Labyrinth::restore_with_passkey(
        ALICE,
        &[42u8; 32],
        b"credential-1",
        w.chat_device(ALICE, 2),
        w.backends(ALICE),
    ))
    .unwrap();
}

#[test]
fn passkey_restore_uses_canonical_id_for_copied_wrap() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    let setup = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let mailbox = w.net.mailbox(ALICE);
    let mut poison = block_on(mailbox.get_virtual_device(&setup.vdevice_id))
        .unwrap()
        .unwrap();
    poison.vdevice_id.0 = earlier_vdevice_id(setup.vdevice_id).to_vec();
    block_on(mailbox.create_virtual_device(&poison)).unwrap();

    block_on(Labyrinth::restore_with_passkey(
        ALICE,
        &[42u8; 32],
        b"credential-1",
        w.chat_device(ALICE, 2),
        w.backends(ALICE),
    ))
    .unwrap();
}

#[test]
fn passkey_restore_rejects_invalid_prf_length_before_credential_selection() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();

    for credential in [b"credential-1".as_slice(), b"unknown".as_slice()] {
        assert_eq!(
            block_on(Labyrinth::restore_with_passkey(
                ALICE,
                &[7u8; 31],
                credential,
                w.chat_device(ALICE, 2),
                w.backends(ALICE),
            ))
            .unwrap_err(),
            Error::Malformed("passkey PRF output must be 32 bytes")
        );
    }
}

#[test]
fn wrong_passkey_prf_error_is_not_shadowed_by_malformed_candidates() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    let setup = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let mailbox = w.net.mailbox(ALICE);
    let original = block_on(mailbox.get_virtual_device(&setup.vdevice_id))
        .unwrap()
        .unwrap();
    let mut missing_wrap = original.clone();
    missing_wrap.vdevice_id.0 = earlier_vdevice_id(setup.vdevice_id).to_vec();
    missing_wrap.passkey_wrapped_code = None;
    let mut empty_wrap = missing_wrap.clone();
    empty_wrap.passkey_wrapped_code = original.passkey_wrapped_code.clone();
    empty_wrap.passkey_wrapped_code.as_mut().unwrap().0.clear();
    let mut unsupported_wrap = empty_wrap.clone();
    unsupported_wrap.passkey_wrapped_code = original.passkey_wrapped_code.clone();
    unsupported_wrap.passkey_wrapped_code.as_mut().unwrap().0[0] = 0x01;
    let b = w.with_stores(
        ALICE,
        Box::new(BundleView {
            inner: mailbox,
            bundles: vec![missing_wrap, empty_wrap, unsupported_wrap, original],
            epoch_calls: AtomicU64::new(0),
            fail_epoch_call: None,
            fail_member_key: None,
        }),
        Box::new(w.net.directory()),
    );

    assert_eq!(
        block_on(Labyrinth::restore_with_passkey(
            ALICE,
            &[43u8; 32],
            b"credential-1",
            w.chat_device(ALICE, 2),
            b,
        ))
        .unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn retained_revoked_passkey_bundle_does_not_shadow_active_replacement() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    let old = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let mailbox = w.net.mailbox(ALICE);
    let old_bundle = block_on(mailbox.get_virtual_device(&old.vdevice_id))
        .unwrap()
        .unwrap();
    let old_key = old_bundle.to_bundle().unwrap().0.public.device_key_pub;
    block_on(phone.revoke_device(&old_key)).unwrap();

    let active = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let active_bundle = block_on(mailbox.get_virtual_device(&active.vdevice_id))
        .unwrap()
        .unwrap();
    let b = w.with_stores(
        ALICE,
        Box::new(BundleView {
            inner: mailbox,
            bundles: vec![old_bundle, active_bundle],
            epoch_calls: AtomicU64::new(0),
            fail_epoch_call: None,
            fail_member_key: None,
        }),
        Box::new(w.net.directory()),
    );

    block_on(Labyrinth::restore_with_passkey(
        ALICE,
        &[42u8; 32],
        b"credential-1",
        w.chat_device(ALICE, 2),
        b,
    ))
    .unwrap();
}

#[test]
fn multiple_active_passkey_bundles_are_ambiguous_and_write_nothing() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    let one = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let two = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let mailbox = w.net.mailbox(ALICE);
    let bundles = [one.vdevice_id, two.vdevice_id]
        .map(|id| block_on(mailbox.get_virtual_device(&id)).unwrap().unwrap())
        .to_vec();
    let devices_before = block_on(mailbox.list_devices()).unwrap().len();
    let epochs_before = block_on(mailbox.list_epochs()).unwrap().len();
    let members_before = block_on(mailbox.list_epoch_members(phone.latest_epoch()))
        .unwrap()
        .len();
    let b = w.with_stores(
        ALICE,
        Box::new(BundleView {
            inner: w.net.mailbox(ALICE),
            bundles,
            epoch_calls: AtomicU64::new(0),
            fail_epoch_call: None,
            fail_member_key: None,
        }),
        Box::new(w.net.directory()),
    );

    assert_eq!(
        block_on(Labyrinth::restore_with_passkey(
            ALICE,
            &[42u8; 32],
            b"credential-1",
            w.chat_device(ALICE, 2),
            b,
        ))
        .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        block_on(mailbox.list_devices()).unwrap().len(),
        devices_before
    );
    assert_eq!(
        block_on(mailbox.list_epochs()).unwrap().len(),
        epochs_before
    );
    assert_eq!(
        block_on(mailbox.list_epoch_members(phone.latest_epoch()))
            .unwrap()
            .len(),
        members_before
    );
    assert!(bundles_last_used_are_none(&mailbox));
}

#[test]
fn duplicate_canonical_passkey_records_fail_closed_in_any_order() {
    for reverse in [false, true] {
        let w = World::new();
        let mut phone = w.init(ALICE, 1);
        let setup = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
        let mailbox = w.net.mailbox(ALICE);
        let original = block_on(mailbox.get_virtual_device(&setup.vdevice_id))
            .unwrap()
            .unwrap();
        let mut altered = original.clone();
        altered.created_at = "2026-01-01T00:00:00.000Z".into();
        let bundles = if reverse {
            vec![original, altered]
        } else {
            vec![altered, original]
        };
        let b = w.with_stores(
            ALICE,
            Box::new(BundleView {
                inner: mailbox,
                bundles,
                epoch_calls: AtomicU64::new(0),
                fail_epoch_call: None,
                fail_member_key: None,
            }),
            Box::new(w.net.directory()),
        );
        assert_eq!(
            block_on(Labyrinth::restore_with_passkey(
                ALICE,
                &[42u8; 32],
                b"credential-1",
                w.chat_device(ALICE, 2),
                b,
            ))
            .unwrap_err(),
            Error::Conflict
        );
    }
}

#[test]
fn passkey_preflight_uncertainty_is_not_hidden_by_an_active_candidate() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    let one = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let two = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let mailbox = w.net.mailbox(ALICE);
    let bundles = [one.vdevice_id, two.vdevice_id]
        .map(|id| block_on(mailbox.get_virtual_device(&id)).unwrap().unwrap())
        .to_vec();
    let devices_before = block_on(mailbox.list_devices()).unwrap().len();
    let epochs_before = block_on(mailbox.list_epochs()).unwrap().len();
    let members_before = block_on(mailbox.list_epoch_members(phone.latest_epoch()))
        .unwrap()
        .len();
    let b = w.with_stores(
        ALICE,
        Box::new(BundleView {
            inner: w.net.mailbox(ALICE),
            bundles,
            epoch_calls: AtomicU64::new(0),
            fail_epoch_call: Some(1),
            fail_member_key: None,
        }),
        Box::new(w.net.directory()),
    );

    assert_eq!(
        block_on(Labyrinth::restore_with_passkey(
            ALICE,
            &[42u8; 32],
            b"credential-1",
            w.chat_device(ALICE, 2),
            b,
        ))
        .unwrap_err(),
        Error::Backend("injected passkey preflight outage".into())
    );
    assert_eq!(
        block_on(mailbox.list_devices()).unwrap().len(),
        devices_before
    );
    assert_eq!(
        block_on(mailbox.list_epochs()).unwrap().len(),
        epochs_before
    );
    assert_eq!(
        block_on(mailbox.list_epoch_members(phone.latest_epoch()))
            .unwrap()
            .len(),
        members_before
    );
    assert!(bundles_last_used_are_none(&mailbox));
}

#[test]
fn passkey_membership_uncertainty_is_not_treated_as_revocation() {
    let w = World::new();
    let mut phone = w.init(ALICE, 1);
    let old = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let mailbox = w.net.mailbox(ALICE);
    let old_bundle = block_on(mailbox.get_virtual_device(&old.vdevice_id))
        .unwrap()
        .unwrap();
    let old_key = old_bundle.to_bundle().unwrap().0.public.device_key_pub;
    block_on(phone.revoke_device(&old_key)).unwrap();
    let active = block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    let active_bundle = block_on(mailbox.get_virtual_device(&active.vdevice_id))
        .unwrap()
        .unwrap();
    let bundles = vec![old_bundle, active_bundle];
    let devices_before = block_on(mailbox.list_devices()).unwrap().len();
    let epochs_before = block_on(mailbox.list_epochs()).unwrap().len();
    let members_before = block_on(mailbox.list_epoch_members(phone.latest_epoch()))
        .unwrap()
        .len();
    let b = w.with_stores(
        ALICE,
        Box::new(BundleView {
            inner: w.net.mailbox(ALICE),
            bundles,
            epoch_calls: AtomicU64::new(0),
            fail_epoch_call: None,
            fail_member_key: Some(old_key),
        }),
        Box::new(w.net.directory()),
    );

    assert_eq!(
        block_on(Labyrinth::restore_with_passkey(
            ALICE,
            &[42u8; 32],
            b"credential-1",
            w.chat_device(ALICE, 2),
            b,
        ))
        .unwrap_err(),
        Error::Backend("injected passkey membership outage".into())
    );
    assert_eq!(
        block_on(mailbox.list_devices()).unwrap().len(),
        devices_before
    );
    assert_eq!(
        block_on(mailbox.list_epochs()).unwrap().len(),
        epochs_before
    );
    assert_eq!(
        block_on(mailbox.list_epoch_members(phone.latest_epoch()))
            .unwrap()
            .len(),
        members_before
    );
    assert!(bundles_last_used_are_none(&mailbox));
}

fn bundles_last_used_are_none(mailbox: &MemoryMailbox) -> bool {
    block_on(mailbox.list_virtual_devices())
        .unwrap()
        .iter()
        .all(|bundle| bundle.last_used_at.is_none())
}

#[test]
fn passkey_restore_and_batch_limits() {
    let mut w = World::new();
    let mut phone = w.init(ALICE, 1);
    block_on(phone.create_passkey_recovery(&[42u8; 32], b"credential-1")).unwrap();
    assert_eq!(
        block_on(Labyrinth::restore_with_passkey(
            ALICE,
            &[43u8; 32],
            b"credential-1",
            w.chat_device(ALICE, 2),
            w.backends(ALICE)
        ))
        .unwrap_err(),
        Error::Decrypt
    );
    let (mut tablet, _) = block_on(Labyrinth::restore_with_passkey(
        ALICE,
        &[42u8; 32],
        b"credential-1",
        w.chat_device(ALICE, 3),
        w.backends(ALICE),
    ))
    .unwrap();

    // 300 messages: one batch flushes itself at 256, flush() writes 44.
    let mut bob = w.init(BOB, 4);
    let group = [ALICE, BOB];
    let mut auto = Vec::new();
    for i in 0..300 {
        w.ts += 1;
        let roster = block_on(bob.resolve_roster(&group)).unwrap();
        let out = block_on(bob.archive_outgoing(THREAD, &roster, &format!("m{i:03}"), w.ts, b"hi"))
            .unwrap();
        auto.extend(out.flushed);
    }
    assert_eq!(auto.len(), 1);
    assert_eq!(auto[0].count, 256);
    assert_eq!(bob.pending(THREAD), 44);
    let rest = block_on(bob.flush()).unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].count, 44);
    let h = read(&mut tablet);
    assert_eq!(h.messages.len(), 300);

    // Owner archive round trip on the restored device.
    block_on(tablet.archive_owner(THREAD, "own-1", 5, b"note")).unwrap();
    block_on(tablet.flush()).unwrap();
    let h = block_on(tablet.load_owner_thread(THREAD)).unwrap();
    let own: Vec<_> = h
        .messages
        .iter()
        .filter(|m| m.source == MessageSource::Owner)
        .collect();
    assert_eq!(own.len(), 1);
    assert_eq!(own[0].frame, b"note");
    // Initializing an existing mailbox conflicts.
    assert_eq!(
        block_on(Labyrinth::initialize(
            ALICE,
            w.chat_device(ALICE, 8),
            w.backends(ALICE)
        ))
        .unwrap_err(),
        Error::Conflict
    );
}

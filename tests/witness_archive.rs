//! Witness archives (sim O6): a member that received and verified another
//! member's receipt-committed frame archives that exact frame in its own
//! conversation-space repo. The copy is attributed to the receipt's sender,
//! merges with the sender's own copy and keeps unsend/deletion semantics, so
//! pre-removal history survives a sender removed before it flushed. A copy
//! that contradicts an accepted one is rejected (ruling 3); pages and
//! account deletion treat every copy of a message alike.

#[path = "support/net.rs"]
mod net;

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{
    Labyrinth, LoadedMessage, MessageSource, Rejection, ThreadCursor, ThreadHistory,
};
use labyrinth::message::{ArchivedReceipt, OriginalSenderArchiveAttestation};
use labyrinth::protocol::receipt::{
    SequencerReceiptPayload, compute_archive_commitment, expected_receipt_key_id,
    sign_sequencer_receipt,
};
use labyrinth::records::{Batch, MekDistribution};
use labyrinth::store::memory::{MemoryBackend, MemoryThreads};
use labyrinth::store::{SequencerReceiptKey, Stored, ThreadStore as _, TimeRange};
use labyrinth::virtual_device::Mechanism;
use net::{A, B, TestClock, backends, init, signer, tpub};
use p256::ecdsa::SigningKey;

const C: &str = "did:plc:carol";
const THREAD: &str = "conv-witness";
const SEQUENCER: &str = "did:web:ds.example";
const DEVICE: &str = "6f1d2c3b-4a59-4687-8796-a5b4c3d2e1f0";

struct World {
    net: MemoryBackend,
    clock: TestClock,
    sequencer: SigningKey,
}

/// One application message as the sequencer receipted it.
struct Sent {
    id: String,
    sender: &'static str,
    frame: Vec<u8>,
    nonce: [u8; 32],
    receipt: ArchivedReceipt,
}

/// A hostile conversation store that changes only the original sender's
/// attestation signature after a valid batch has been committed.
struct SignatureBitFlipThreads(MemoryThreads);

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl labyrinth::store::ThreadStore for SignatureBitFlipThreads {
    fn author(&self) -> &str {
        self.0.author()
    }

    async fn create_mek(&self, mek: &MekDistribution) -> labyrinth::Result<()> {
        self.0.create_mek(mek).await
    }

    async fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> labyrinth::Result<Vec<Stored<MekDistribution>>> {
        self.0.find_meks(thread_id, mek_id).await
    }

    async fn append_batch(&self, batch: &Batch) -> labyrinth::Result<String> {
        self.0.append_batch(batch).await
    }

    async fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<Batch>>> {
        let mut batches = self.0.list_batches(thread_id, sender, range).await?;
        for batch in &mut batches {
            for item in &mut batch.value.items {
                if let Some(receipt) = &mut item.sequencer_receipt {
                    receipt.original_sender_attestation.signature.0[0] ^= 1;
                }
            }
        }
        Ok(batches)
    }
}

impl World {
    fn new() -> Self {
        let net = MemoryBackend::new();
        net.enable_server_order();
        let sequencer = SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let public_key_sec1 = sequencer
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        net.set_sequencer_receipt_key(
            THREAD,
            SequencerReceiptKey {
                did: SEQUENCER.to_owned(),
                public_key_sec1,
            },
        );
        Self {
            net,
            clock: TestClock::default(),
            sequencer,
        }
    }

    /// An enrolled member whose chat device `seed` has a leaf in the thread.
    fn join(&self, did: &str, seed: u8) -> Labyrinth {
        let lab = init(&self.net, &self.clock, did, seed);
        self.net.add_leaf(THREAD, did, tpub(seed));
        lab
    }

    /// The sequencer orders `sender`'s message `id` and receipts it for `thread`.
    fn sequence_in(&self, thread: &str, sender: &'static str, id: &str) -> Sent {
        let frame = format!(r#"{{"text":"{id} from {sender}"}}"#).into_bytes();
        let mut nonce = [0u8; 32];
        for (n, b) in nonce.iter_mut().zip(id.bytes().cycle()) {
            *n = b;
        }
        let seq = self.net.append_chat_entry(THREAD);
        let payload = SequencerReceiptPayload {
            sequencer_did: SEQUENCER.to_owned(),
            conversation_id: thread.to_owned(),
            group_id: vec![0x99; 32],
            epoch: 1,
            sender_device_did_url: format!("{sender}#{DEVICE}"),
            entry_id: format!("entry-{id}"),
            archive_commitment: compute_archive_commitment(&nonce, &frame),
            seq,
            issued_at_ms: 1_791_000_000_000 + seq as i64,
        };
        let key_id = expected_receipt_key_id(SEQUENCER);
        let signed = sign_sequencer_receipt(&self.sequencer, &key_id, &payload).unwrap();
        let sender_seed = match sender {
            A => 1,
            B => 2,
            _ => panic!("sender fixture has no enrolled device key"),
        };
        let original_sender_attestation = OriginalSenderArchiveAttestation::sign(
            sender.to_owned(),
            DEVICE.to_owned(),
            thread,
            id,
            &payload.archive_commitment,
            &signer(sender_seed),
        );
        Sent {
            id: id.to_owned(),
            sender,
            frame,
            nonce,
            receipt: ArchivedReceipt::new(signed, original_sender_attestation),
        }
    }

    fn sequence(&self, sender: &'static str, id: &str) -> Sent {
        self.sequence_in(THREAD, sender, id)
    }
}

/// `lab` archives `m` at `ts` under the MLS roster `members`: its own send,
/// or a witness copy of a message it received and verified.
fn archive(lab: &mut Labyrinth, members: &[&str], m: &Sent, ts: u64) {
    let roster = block_on(lab.resolve_roster(members)).unwrap();
    block_on(
        lab.archive_outgoing_committed(THREAD, &roster, &m.id, ts, &m.nonce, &m.frame, &m.receipt),
    )
    .unwrap();
}

fn load(lab: &mut Labyrinth) -> ThreadHistory {
    block_on(lab.load_thread(THREAD, TimeRange::ALL)).unwrap()
}

/// `(messageId, sender, source, timestamp, conflict)` of each loaded message.
fn summary(h: &ThreadHistory) -> Vec<(&str, Option<&str>, MessageSource, u64, bool)> {
    h.messages
        .iter()
        .map(|m| {
            (
                m.message_id.as_str(),
                m.sender.as_deref(),
                m.source,
                m.timestamp,
                m.conflict,
            )
        })
        .collect()
}

/// `(messageId, reason)` of each rejected witness copy.
fn rejected(h: &ThreadHistory) -> Vec<(&str, Rejection)> {
    h.rejected
        .iter()
        .map(|r| (r.message_id.as_str(), r.reason))
        .collect()
}

/// `loaded` is `m` exactly: id, sender, canonical frame and its I13 evidence.
fn assert_exact(loaded: &LoadedMessage, m: &Sent) {
    assert_eq!(loaded.message_id, m.id);
    assert_eq!(loaded.sender.as_deref(), Some(m.sender));
    assert_eq!(loaded.frame, m.frame);
    assert_eq!(loaded.frame_nonce, Some(m.nonce));
    assert_eq!(loaded.archived_receipt.as_ref(), Some(&m.receipt));
}

#[test]
fn witness_copy_is_attributed_to_the_receipt_sender() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let mut carol = w.join(C, 3);
    let m = w.sequence(A, "m1");
    archive(&mut bob, &[A, B, C], &m, 200);
    block_on(bob.flush()).unwrap();

    for lab in [&mut alice, &mut bob, &mut carol] {
        let h = load(lab);
        assert!(h.undecryptable.is_empty(), "{:?}", h.undecryptable);
        assert_eq!(
            summary(&h),
            [("m1", Some(A), MessageSource::Witness, 200, false)]
        );
        assert_exact(&h.messages[0], &m);
    }
}

#[test]
fn sender_and_witness_copies_merge_without_conflict() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let mut carol = w.join(C, 3);
    let all = [A, B, C];
    let m = w.sequence(A, "m1");
    archive(&mut alice, &all, &m, 100);
    archive(&mut bob, &all, &m, 300);
    archive(&mut carol, &all, &m, 200);
    block_on(bob.flush()).unwrap();
    block_on(carol.flush()).unwrap();

    // Witness copies alone: one copy, at the earliest witness timestamp.
    let h = load(&mut bob);
    assert_eq!(
        summary(&h),
        [("m1", Some(A), MessageSource::Witness, 200, false)]
    );

    // The sender's own copy, once flushed, is the representative everywhere.
    block_on(alice.flush()).unwrap();
    for lab in [&mut alice, &mut bob, &mut carol] {
        let h = load(lab);
        assert!(h.undecryptable.is_empty(), "{:?}", h.undecryptable);
        assert_eq!(
            summary(&h),
            [("m1", Some(A), MessageSource::Sender, 100, false)]
        );
        assert_exact(&h.messages[0], &m);
        let one = block_on(lab.load_message(THREAD, "m1")).unwrap();
        assert_eq!(
            summary(&one),
            [("m1", Some(A), MessageSource::Sender, 100, false)]
        );
    }
}

#[test]
fn tampered_witness_copies_are_never_attributed() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let mut carol = w.join(C, 3);
    let all = [A, B, C];
    let m = w.sequence(A, "m1");
    archive(&mut alice, &all, &m, 100);
    block_on(alice.flush()).unwrap();

    // Carol is a malicious witness: every copy pairs a genuine receipt with
    // something it does not commit to.
    let roster = block_on(carol.resolve_roster(&all)).unwrap();
    let forged_frame = br#"{"text":"forged"}"#;
    let other_thread = w.sequence_in("conv-other", A, "m1");
    assert_eq!(
        block_on(carol.archive_outgoing_committed(
            THREAD,
            &roster,
            "m1",
            150,
            &m.nonce,
            forged_frame,
            &m.receipt,
        ))
        .unwrap_err(),
        Error::ReceiptCommitmentMismatch
    );
    assert_eq!(
        block_on(carol.archive_outgoing_committed(
            THREAD,
            &roster,
            "m1",
            150,
            &other_thread.nonce,
            &other_thread.frame,
            &other_thread.receipt,
        ))
        .unwrap_err(),
        Error::Malformed("receipt conversation_id mismatch")
    );
    let mut nonce = m.nonce;
    nonce[0] ^= 1;
    let mut signature = m.receipt.clone();
    signature.signed.signature[0] ^= 1;
    let mut reattributed = m.receipt.clone();
    reattributed.signed.payload.sender_device_did_url = format!("{C}#{DEVICE}");
    let tampered: [(&[u8], &[u8; 32], &ArchivedReceipt); 2] = [
        (forged_frame, &m.nonce, &m.receipt),
        (&m.frame, &nonce, &m.receipt),
    ];
    for (frame, nonce, receipt) in tampered {
        block_on(carol.archive_outgoing_committed_unchecked_for_test(
            THREAD, &roster, "m1", 150, nonce, frame, receipt,
        ))
        .unwrap();
    }
    assert!(
        block_on(carol.archive_outgoing_committed_unchecked_for_test(
            THREAD, &roster, "m1", 150, &m.nonce, &m.frame, &signature,
        ))
        .is_err()
    );
    assert!(
        block_on(carol.archive_outgoing_committed_unchecked_for_test(
            THREAD,
            &roster,
            "m1",
            150,
            &m.nonce,
            &m.frame,
            &reattributed,
        ))
        .is_err()
    );
    // A genuine copy replayed under another message id is rejected before it
    // enters any member repo.
    archive(&mut carol, &all, &w.sequence(A, "m2"), 160);
    assert!(
        block_on(carol.archive_outgoing_committed(
            THREAD,
            &roster,
            "m2-replay",
            170,
            &m.nonce,
            &m.frame,
            &m.receipt,
        ))
        .is_err()
    );
    block_on(carol.flush()).unwrap();

    let h = load(&mut bob);
    assert_eq!(
        summary(&h),
        [
            ("m1", Some(A), MessageSource::Sender, 100, false),
            ("m2", Some(A), MessageSource::Witness, 160, false),
        ]
    );
    assert!(rejected(&h).is_empty());
    assert_exact(&h.messages[0], &m);
    let mut errors: Vec<String> = h
        .undecryptable
        .iter()
        .map(|u| {
            assert_eq!(u.message_id, "m1");
            assert_eq!(u.sender.as_deref(), Some(C), "never attributed to Alice");
            format!("{:?}", u.error)
        })
        .collect();
    errors.sort();
    assert_eq!(
        errors,
        ["ReceiptCommitmentMismatch", "ReceiptCommitmentMismatch"]
    );
}

#[test]
fn original_sender_attestation_signature_bit_flip_is_rejected_on_read() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);

    w.net.register_chat_device(C, tpub(3));
    let mut reader_backends = backends(&w.net, &w.clock, C);
    reader_backends.threads = Box::new(SignatureBitFlipThreads(w.net.threads(C)));
    let mut carol = block_on(Labyrinth::initialize(
        C,
        Box::new(signer(3)),
        reader_backends,
    ))
    .unwrap();
    w.net.add_leaf(THREAD, C, tpub(3));

    let m = w.sequence(A, "m1");
    archive(&mut bob, &[A, B, C], &m, 100);
    block_on(bob.flush()).unwrap();

    let intact = load(&mut alice);
    assert_eq!(
        summary(&intact),
        [("m1", Some(A), MessageSource::Witness, 100, false)]
    );
    assert_exact(&intact.messages[0], &m);

    let tampered = load(&mut carol);
    assert!(
        tampered.messages.is_empty(),
        "a signature-bit-flipped attestation must never attribute a message"
    );
    assert_eq!(tampered.undecryptable.len(), 1);
    assert_eq!(tampered.undecryptable[0].message_id, "m1");
    assert_eq!(tampered.undecryptable[0].error, Error::BadSignature);
}

#[test]
fn redactions_and_tombstones_suppress_witness_copies() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let mut carol = w.join(C, 3);
    let all = [A, B, C];
    let sent: Vec<Sent> = ["a1", "a2", "a3", "a4"]
        .into_iter()
        .map(|id| w.sequence(A, id))
        .collect();
    // Alice flushes a1 and a3 only; Bob witnesses all four.
    for (i, m) in sent.iter().enumerate() {
        if i % 2 == 0 {
            archive(&mut alice, &all, m, 100 + i as u64);
        }
        archive(&mut bob, &all, m, 200 + i as u64);
    }
    block_on(alice.flush()).unwrap();
    block_on(bob.flush()).unwrap();

    // Alice unsends a1; Carol deletes a2 (by Alice) for herself.
    assert_eq!(block_on(alice.unsend(THREAD, "a1")).unwrap(), 1);
    block_on(carol.delete_for_me(THREAD, "a2", 201, Some(A), &[])).unwrap();
    let h = load(&mut carol);
    assert!(h.undecryptable.is_empty(), "{:?}", h.undecryptable);
    assert_eq!(
        summary(&h),
        [
            ("a3", Some(A), MessageSource::Sender, 102, false),
            ("a4", Some(A), MessageSource::Witness, 203, false),
        ]
    );
    let unsent: Vec<_> = h
        .redacted
        .iter()
        .map(|r| (r.message_id.as_str(), r.sender.as_str()))
        .collect();
    assert_eq!(unsent, [("a1", A)]);
    assert_eq!(h.deleted_for_me, ["a2"]);

    // Re-archiving before a leave keeps the same view: witness copies stay
    // attributed to Alice, and neither unsent nor deleted copies come back.
    assert_eq!(
        block_on(carol.rearchive_thread_before_leave(THREAD)).unwrap(),
        2
    );
    w.net.revoke_thread_access(THREAD, C);
    let h = load(&mut carol);
    assert!(!h.space_readable);
    let owner: Vec<_> = h
        .messages
        .iter()
        .map(|m| (m.message_id.as_str(), m.sender.as_deref(), m.source))
        .collect();
    assert_eq!(
        owner,
        [
            ("a3", Some(A), MessageSource::Owner),
            ("a4", Some(A), MessageSource::Owner),
        ]
    );
}

/// Sim O6 regression: Alice's last messages never left her outbox before an
/// admin removed her. Without any pre-removal flush, the witness copies Bob
/// and Carol archived on receipt let a fresh device of Bob restore them.
#[test]
fn unflushed_pre_kick_history_survives_removal_through_witness_copies() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let mut carol = w.join(C, 3);
    let all = [A, B, C];

    let a0 = w.sequence(A, "a0");
    archive(&mut alice, &all, &a0, 100);
    block_on(alice.flush()).unwrap();
    let a1 = w.sequence(A, "a1");
    let a2 = w.sequence(A, "a2");
    archive(&mut alice, &all, &a1, 110);
    archive(&mut alice, &all, &a2, 120);
    let b1 = w.sequence(B, "b1");
    archive(&mut bob, &all, &b1, 130);
    // Receivers archive what they verified, under their receive-time roster.
    for m in [&a0, &a1, &a2] {
        archive(&mut bob, &all, m, 200);
    }
    for m in [&a0, &a1, &a2, &b1] {
        archive(&mut carol, &all, m, 300);
    }
    block_on(bob.flush()).unwrap();
    block_on(carol.flush()).unwrap();
    let recovery = block_on(bob.create_recovery_code(Mechanism::Code)).unwrap();

    // The removal lands while a1 and a2 are still in Alice's outbox.
    let removal_seq = w.net.remove_leaf(THREAD, A, tpub(1));
    w.net.revoke_thread_access(THREAD, A);
    assert_eq!(alice.pending(THREAD), 2);
    assert_eq!(block_on(alice.flush()).unwrap_err(), Error::Forbidden);
    let b2 = w.sequence(B, "b2");
    archive(&mut bob, &[B, C], &b2, 400);
    block_on(bob.flush()).unwrap();

    // The removed device is denied the conversation space after removal...
    let h = load(&mut alice);
    assert!(!h.space_readable);
    assert!(h.messages.is_empty());
    assert_eq!(
        block_on(w.net.threads(A).list_batches(THREAD, None, TimeRange::ALL)).unwrap_err(),
        Error::Forbidden
    );
    // ...and no MEK covering a post-removal item is wrapped to it.
    let space = w.net.threads(B);
    let batches = block_on(space.list_batches(THREAD, None, TimeRange::ALL)).unwrap();
    let mut post_removal = 0;
    for item in batches.iter().flat_map(|b| &b.value.items) {
        if item.seq.is_some_and(|seq| seq > removal_seq) {
            post_removal += 1;
            let mek_id = item.mek_id.array::<12>("mekId").unwrap();
            let meks = block_on(space.find_meks(THREAD, &mek_id)).unwrap();
            assert!(!meks.is_empty());
            for mek in meks {
                assert!(mek.value.recipients.iter().all(|r| r.did != A));
            }
        }
    }
    assert_eq!(post_removal, 1);

    // A fresh device of Bob holds only the recovery code and the spaces.
    w.net.register_chat_device(B, tpub(9));
    let (mut fresh, _) = block_on(Labyrinth::restore_with_recovery_code(
        B,
        recovery.code.as_str(),
        Box::new(signer(9)),
        backends(&w.net, &w.clock, B),
    ))
    .unwrap();
    let h = load(&mut fresh);
    assert!(h.space_readable);
    assert!(h.undecryptable.is_empty(), "{:?}", h.undecryptable);
    assert_eq!(
        summary(&h),
        [
            ("a0", Some(A), MessageSource::Sender, 100, false),
            ("b1", Some(B), MessageSource::Sender, 130, false),
            ("a1", Some(A), MessageSource::Witness, 200, false),
            ("a2", Some(A), MessageSource::Witness, 200, false),
            ("b2", Some(B), MessageSource::Sender, 400, false),
        ]
    );
    for (loaded, m) in h.messages.iter().zip([&a0, &b1, &a1, &a2, &b2]) {
        assert_exact(loaded, m);
    }
}

/// A malicious sequencer/member cannot file a genuine sender-attested frame
/// under another message id.
fn relabel(
    lab: &mut Labyrinth,
    members: &[&str],
    id: &str,
    m: &Sent,
    ts: u64,
) -> labyrinth::Result<()> {
    let roster = block_on(lab.resolve_roster(members)).unwrap();
    block_on(
        lab.archive_outgoing_committed(THREAD, &roster, id, ts, &m.nonce, &m.frame, &m.receipt),
    )
    .map(|_| ())
}

/// Ruling 3: a witness copy that contradicts the sender's own copy or an
/// earlier admitted witness copy, or that reuses an accepted copy's
/// receipt, is rejected; it never flags, replaces or re-attributes the
/// genuine copy, and re-archiving never launders it into the owner archive.
#[test]
fn original_sender_attestation_rejects_relabelled_witness_copies() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let mut carol = w.join(C, 3);
    let all = [A, B, C];
    let m1 = w.sequence(A, "m1");
    let m2 = w.sequence(A, "m2");
    archive(&mut alice, &all, &m1, 100);
    block_on(alice.flush()).unwrap();
    // Alice never flushes m2; Bob's witness copy is the first one admitted.
    archive(&mut bob, &all, &m2, 210);
    block_on(bob.flush()).unwrap();
    // Carol controls a member repo and colludes with the sequencer, but does not
    // possess Alice's historical device key. Exact sender attestations reject
    // every changed message id before any witness record is written.
    assert!(relabel(&mut carol, &all, "m1", &m2, 120).is_err());
    assert!(relabel(&mut carol, &all, "m2", &m1, 50).is_err());
    assert!(relabel(&mut carol, &all, "m9", &m2, 230).is_err());
    archive(&mut carol, &all, &m2, 205);
    block_on(carol.flush()).unwrap();

    for lab in [&mut alice, &mut bob, &mut carol] {
        let h = load(lab);
        assert!(h.undecryptable.is_empty(), "{:?}", h.undecryptable);
        assert_eq!(
            summary(&h),
            [
                ("m1", Some(A), MessageSource::Sender, 100, false),
                ("m2", Some(A), MessageSource::Witness, 205, false),
            ]
        );
        assert_exact(&h.messages[0], &m1);
        assert_exact(&h.messages[1], &m2);
        assert!(rejected(&h).is_empty());
        let one = block_on(lab.load_message(THREAD, "m1")).unwrap();
        assert_eq!(
            summary(&one),
            [("m1", Some(A), MessageSource::Sender, 100, false)]
        );
        let alias = block_on(lab.load_message(THREAD, "m9")).unwrap();
        assert!(alias.messages.is_empty());
        assert!(alias.rejected.is_empty());
        let mut cursor: Option<ThreadCursor> = None;
        let mut paged_messages = Vec::new();
        let mut paged_rejections = Vec::new();
        loop {
            let page = block_on(lab.load_thread_page(THREAD, cursor.as_ref(), 1)).unwrap();
            paged_messages.extend(page.history.messages.iter().map(|m| m.message_id.clone()));
            paged_rejections.extend(
                page.history
                    .rejected
                    .iter()
                    .map(|r| (r.message_id.clone(), r.reason)),
            );
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        paged_messages.sort();
        assert_eq!(paged_messages, ["m1", "m2"]);
        assert!(paged_rejections.is_empty());
    }

    // Re-archiving keeps exactly the accepted copies.
    assert_eq!(
        block_on(bob.rearchive_thread_before_leave(THREAD)).unwrap(),
        2
    );
    w.net.revoke_thread_access(THREAD, B);
    let h = load(&mut bob);
    assert!(!h.space_readable);
    assert_eq!(
        summary(&h),
        [
            ("m1", Some(A), MessageSource::Owner, 100, false),
            ("m2", Some(A), MessageSource::Owner, 205, false),
        ]
    );
    assert_exact(&h.messages[0], &m1);
    assert_exact(&h.messages[1], &m2);
}

/// A sender copy and a later witness copy of one message sit at different
/// timestamps. Pages position each message once, by its sender copy, so it
/// is neither repeated on the next page nor skipped, at any page size.
#[test]
fn pages_show_each_message_once_with_all_its_copies() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let all = [A, B];
    let a0 = w.sequence(A, "a0");
    let a1 = w.sequence(A, "a1");
    let b1 = w.sequence(B, "b1");
    archive(&mut alice, &all, &a0, 100);
    archive(&mut alice, &all, &a1, 110);
    block_on(alice.flush()).unwrap();
    archive(&mut bob, &all, &b1, 200);
    archive(&mut bob, &all, &a0, 300);
    block_on(bob.flush()).unwrap();

    for limit in 1..=4 {
        let mut seen = Vec::new();
        let mut cursor: Option<ThreadCursor> = None;
        for _ in 0..10 {
            let page = block_on(bob.load_thread_page(THREAD, cursor.as_ref(), limit)).unwrap();
            assert!(page.history.messages.len() <= limit);
            seen.extend(
                page.history
                    .messages
                    .iter()
                    .map(|m| (m.message_id.clone(), m.source, m.timestamp)),
            );
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none(), "limit {limit}: paging did not end");
        assert_eq!(
            seen,
            [
                ("b1".to_owned(), MessageSource::Sender, 200),
                ("a1".to_owned(), MessageSource::Sender, 110),
                ("a0".to_owned(), MessageSource::Sender, 100),
            ],
            "limit {limit}"
        );
    }
}

#[test]
fn queued_only_unsend_publishes_a_witness_suppressing_redaction() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let mut carol = w.join(C, 3);
    let all = [A, B, C];
    let message = w.sequence(A, "queued");

    archive(&mut alice, &all, &message, 100);
    archive(&mut bob, &all, &message, 200);
    block_on(bob.flush()).unwrap();
    assert_eq!(alice.pending(THREAD), 1);

    assert_eq!(block_on(alice.unsend(THREAD, "queued")).unwrap(), 1);
    assert_eq!(alice.pending(THREAD), 0);
    let h = load(&mut carol);
    assert!(h.messages.is_empty(), "{:?}", summary(&h));
    assert_eq!(
        h.redacted
            .iter()
            .map(|r| (r.message_id.as_str(), r.sender.as_str()))
            .collect::<Vec<_>>(),
        [("queued", A)]
    );
}

#[test]
fn queued_only_unsend_keeps_the_journal_when_redaction_cannot_publish() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let all = [A];
    let message = w.sequence(A, "still-queued");

    archive(&mut alice, &all, &message, 100);
    w.net.revoke_thread_access(THREAD, A);
    assert_eq!(
        block_on(alice.unsend(THREAD, "still-queued")).unwrap_err(),
        labyrinth::Error::Forbidden
    );
    assert_eq!(alice.pending(THREAD), 1);
}

#[test]
fn evidence_outside_a_display_window_still_hides_selected_copies() {
    let w = World::new();
    let mut alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let mut carol = w.join(C, 3);
    let all = [A, B, C];
    let unsent = w.sequence(A, "unsent");
    let private = w.sequence(B, "private");

    archive(&mut alice, &all, &unsent, 100);
    archive(&mut bob, &all, &unsent, 200);
    archive(&mut bob, &all, &private, 210);
    block_on(alice.flush()).unwrap();
    block_on(bob.flush()).unwrap();
    assert_eq!(block_on(alice.unsend(THREAD, "unsent")).unwrap(), 1);
    block_on(carol.delete_for_me(THREAD, "private", 90, Some(B), &[])).unwrap();

    let h = block_on(carol.load_thread(
        THREAD,
        TimeRange {
            from_ms: Some(150),
            until_ms: Some(250),
        },
    ))
    .unwrap();
    assert!(h.messages.is_empty(), "{:?}", summary(&h));
    assert_eq!(h.deleted_for_me, ["private"]);
    assert!(h.redacted.iter().any(|r| r.message_id == "unsent"));
}

#[test]
fn active_space_deconfliction_ignores_owner_alias_but_keeps_tombstones() {
    let w = World::new();
    let _alice = w.join(A, 1);
    let mut bob = w.join(B, 2);
    let mut carol = w.join(C, 3);
    let all = [A, B, C];
    let message = w.sequence(A, "m1");

    assert!(relabel(&mut bob, &all, "m9", &message, 100).is_err());
    assert!(block_on(bob.flush()).unwrap().is_empty());
    assert_eq!(
        block_on(bob.rearchive_thread_before_leave(THREAD)).unwrap(),
        0
    );
    block_on(w.net.threads(B).clear_records(THREAD)).unwrap();
    archive(&mut carol, &all, &message, 200);
    block_on(carol.flush()).unwrap();

    let h = load(&mut bob);
    assert!(h.space_readable);
    assert_eq!(
        summary(&h),
        [("m1", Some(A), MessageSource::Witness, 200, false)]
    );
    assert!(h.rejected.is_empty(), "{:?}", h.rejected);

    block_on(bob.delete_for_me(THREAD, "m1", 50, Some(A), &[])).unwrap();
    let hidden = load(&mut bob);
    assert!(hidden.messages.is_empty());
    assert_eq!(hidden.deleted_for_me, ["m1"]);
}

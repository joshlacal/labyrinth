//! Gate 5: Ciphertext-only Space attachments (`.staged` -> `.space`), in-place
//! author batch redaction preserving sibling `I13` receipts, and re-archive before leave.

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::attachment::AttachmentCiphertextMeta;
use labyrinth::client::{Backends, CompositeDirectory, Labyrinth, MessageSource, SystemClock};
use labyrinth::message::OriginalSenderArchiveAttestation;
use labyrinth::protocol::receipt::{
    SequencerReceiptPayload, compute_archive_commitment, expected_receipt_key_id,
    sign_sequencer_receipt,
};
use labyrinth::sign::{Ed25519Transport, TransportSigner as _};
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef, SpaceThreadStore};
use labyrinth::store::{
    MailboxStore as _, MemberDeviceKey, MemoryBackend, SequencerReceiptKey, ThreadStore as _,
    TimeRange,
};
use p256::ecdsa::SigningKey;

const CONVO_ID: &str = "22222222-3333-4444-5555-666666666666";
const SEQUENCER_DID: &str = "did:web:mls.catbird.blue";
const ALICE_DID: &str = "did:plc:alicegate5";
const BOB_DID: &str = "did:plc:bobgate5";
const ALICE_DEV_ID: &str = "12121212-3434-5656-7878-909090909090";

fn transport(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

fn sequencer_keys() -> (SigningKey, SequencerReceiptKey) {
    let sk = SigningKey::from_bytes((&[0x55u8; 32]).into()).expect("valid p256 sk");
    let pk_sec1 = sk
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    (
        sk,
        SequencerReceiptKey {
            did: SEQUENCER_DID.to_owned(),
            public_key_sec1: pk_sec1,
        },
    )
}

fn make_client(
    did: &str,
    seed: u8,
    net: &MemoryBackend,
    host: &MemorySpaceHost,
    convo_space: &SpaceRef,
) -> Labyrinth {
    let t = transport(seed);
    net.set_chat_devices(did, vec![t.transport_public_key()]);
    net.set_member_device_keys(
        CONVO_ID,
        did,
        vec![MemberDeviceKey {
            key: t.transport_public_key(),
            joined_chat_seq: 1,
            removed_chat_seq: None,
        }],
    );
    let mb_space = SpaceRef::parse(&format!(
        "at://{did}/space/blue.catbird.labyrinth.mailbox/self"
    ))
    .unwrap();
    let mailbox = SpaceMailboxStore::new(host.client(did), mb_space, did.to_owned())
        .with_key_publisher(Box::new(net.pds_publisher(did)));
    let mut threads = SpaceThreadStore::new(host.client(did), did.to_owned());
    threads.register_thread_space(CONVO_ID, convo_space.clone());
    let directory =
        CompositeDirectory::new(Box::new(net.directory()), Box::new(net.ds_directory()));
    let backends = Backends {
        mailbox: Box::new(mailbox),
        threads: Box::new(threads),
        directory: Box::new(directory),
        publishers: vec![Box::new(net.ds_publisher(did))],
        clock: Box::new(SystemClock),
    };
    block_on(Labyrinth::initialize(did, Box::new(t), backends)).expect("init")
}

#[test]
fn gate5_attachments_redact_siblings_intact_and_rearchive_before_leave() {
    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let (seq_sk, seq_rk) = sequencer_keys();
    net.set_sequencer_receipt_key(CONVO_ID, seq_rk);

    let convo_space = SpaceRef::parse(&format!(
        "at://{SEQUENCER_DID}/space/blue.catbird.labyrinth.conversation/{CONVO_ID}"
    ))
    .unwrap();
    // Grant Alice and Bob Space read membership on the reference host.
    host.grant_space_member(&convo_space, ALICE_DID);
    host.grant_space_member(&convo_space, BOB_DID);

    let mut alice = make_client(ALICE_DID, 1, &net, &host, &convo_space);
    let mut bob = make_client(BOB_DID, 2, &net, &host, &convo_space);

    // 1. Attachment upload -> `.staged` -> `attachmentManifest` commit promotes to `.space`.
    let mut alice_threads = SpaceThreadStore::new(host.client(ALICE_DID), ALICE_DID.to_owned());
    alice_threads.register_thread_space(CONVO_ID, convo_space.clone());
    let mut bob_threads = SpaceThreadStore::new(host.client(BOB_DID), BOB_DID.to_owned());
    bob_threads.register_thread_space(CONVO_ID, convo_space.clone());

    let encrypted_blob = b"aes-256-gcm-opaque-attachment-ciphertext-bytes";
    let meta = AttachmentCiphertextMeta::from_ciphertext(
        encrypted_blob,
        Some("application/octet-stream".into()),
    )
    .unwrap();
    let manifest_rkey = block_on(alice_threads.upload_and_commit_attachment(
        CONVO_ID,
        encrypted_blob,
        &meta,
        "2026-10-31T12:00:00.000Z",
    ))
    .expect("upload + commit attachmentManifest");

    // Public `com.atproto.sync.getBlob` MUST fail (blob promoted to `.space`, not public!).
    let manifest =
        block_on(bob_threads.get_attachment_manifest(CONVO_ID, ALICE_DID, &manifest_rkey))
            .unwrap()
            .expect("manifest readable in Space");
    assert!(
        host.public_sync_get_blob(ALICE_DID, manifest.blob.cid_link())
            .is_err(),
        "promoted .space blob must return 404 on public sync.getBlob"
    );

    // Space member Bob fetches & verifies SHA-256 via `com.atproto.space.getBlob`.
    let fetched =
        block_on(bob_threads.get_attachment_verified(CONVO_ID, ALICE_DID, &manifest_rkey))
            .expect("space.getBlob + sha256 verified");
    assert_eq!(fetched, encrypted_blob);

    // 2. Multi-item batch with 3 `I13`-receipted messages (seq 10, 11, 12); unsend middle item!
    let roster = block_on(alice.resolve_roster(&[ALICE_DID, BOB_DID])).unwrap();
    for (seq, msg_id, body) in [
        (10u64, "m-10", b"first message".as_slice()),
        (11u64, "m-11", b"middle message to unsend".as_slice()),
        (12u64, "m-12", b"third message".as_slice()),
    ] {
        let nonce = [seq as u8; 32];
        let commitment = compute_archive_commitment(&nonce, body);
        let rp = SequencerReceiptPayload {
            sequencer_did: SEQUENCER_DID.to_owned(),
            conversation_id: CONVO_ID.to_owned(),
            group_id: vec![0x44u8; 32],
            epoch: 1,
            sender_device_did_url: format!("{ALICE_DID}#{ALICE_DEV_ID}"),
            entry_id: format!("00000000-0000-0000-0000-{seq:012}"),
            archive_commitment: commitment,
            seq,
            issued_at_ms: 1_791_181_720_000 + seq as i64,
        };
        let receipt =
            sign_sequencer_receipt(&seq_sk, &expected_receipt_key_id(SEQUENCER_DID), &rp).unwrap();
        block_on(alice.archive_outgoing_committed(
            CONVO_ID,
            &roster,
            msg_id,
            1_791_181_720_000 + seq,
            &nonce,
            body,
            &labyrinth::message::ArchivedReceipt::new(
                receipt.clone(),
                OriginalSenderArchiveAttestation::sign(
                    ALICE_DID.to_owned(),
                    ALICE_DEV_ID.to_owned(),
                    CONVO_ID,
                    msg_id,
                    &commitment,
                    &transport(1),
                ),
            ),
        ))
        .unwrap();
    }
    let flushed = block_on(alice.flush()).unwrap();
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].count, 3);

    // Alice unsends middle item `m-11`: creates one immutable message-scoped redaction,
    // preserving `m-10` and `m-12` plus every original receipt.
    let redacted_count = block_on(alice.unsend(CONVO_ID, "m-11")).expect("unsend m-11");
    assert_eq!(redacted_count, 1);

    let bob_view =
        block_on(bob.load_thread(CONVO_ID, TimeRange::ALL)).expect("bob load after unsend");
    assert_eq!(bob_view.messages.len(), 2);
    assert_eq!(bob_view.messages[0].message_id, "m-10");
    assert_eq!(bob_view.messages[0].frame, b"first message");
    assert_eq!(bob_view.messages[1].message_id, "m-12");
    assert_eq!(bob_view.messages[1].frame, b"third message");
    assert_eq!(bob_view.redacted.len(), 1);
    assert_eq!(bob_view.redacted[0].message_id, "m-11");
    assert_eq!(bob_view.redacted[0].sender, ALICE_DID);
    assert!(bob_view.undecryptable.is_empty());

    // 3. Alice leaves conversation: readable messages and attachments reach
    // Alice's personal mailbox. Nothing in the conversation Space is deleted:
    // her batch, MEK and attachment manifest may be the only copies remaining
    // members can restore from (G11).
    let leave_report =
        block_on(alice.rearchive_before_leave(CONVO_ID)).expect("rearchive_before_leave");
    assert_eq!(leave_report.messages_archived, 2);
    assert_eq!(leave_report.attachments_archived, 1);
    for collection in [
        labyrinth::records::nsid::BATCH,
        labyrinth::records::nsid::MEK,
        labyrinth::records::nsid::ATTACHMENT_MANIFEST,
        labyrinth::records::nsid::AUTHOR_REDACTION,
    ] {
        assert_eq!(
            host.record_count(&convo_space, ALICE_DID, Some(collection)),
            1,
            "leave must retain the leaver's {collection} records"
        );
    }
    assert_eq!(
        block_on(bob_threads.get_attachment_verified(CONVO_ID, ALICE_DID, &manifest_rkey))
            .expect("remaining member still reads the leaver's attachment"),
        encrypted_blob
    );

    // Revoke Alice's read membership on the conversation Space and confirm she still reads
    // both messages AND the re-archived attachment from her personal mailbox Space!
    host.revoke_space_member(&convo_space, ALICE_DID);
    let alice_after_leave =
        block_on(alice.load_thread(CONVO_ID, TimeRange::ALL)).expect("alice load after leave");
    assert!(!alice_after_leave.space_readable);
    assert_eq!(alice_after_leave.messages.len(), 2);
    assert!(
        alice_after_leave
            .messages
            .iter()
            .all(|m| m.source == MessageSource::Owner)
    );

    let alice_mb_space = SpaceRef::parse(&format!(
        "at://{ALICE_DID}/space/blue.catbird.labyrinth.mailbox/self"
    ))
    .unwrap();
    let alice_mb =
        SpaceMailboxStore::new(host.client(ALICE_DID), alice_mb_space, ALICE_DID.to_owned());
    let rearchived_att = block_on(alice_mb.get_owner_attachment_verified(&manifest_rkey))
        .expect("rearchived attachment in personal mailbox Space");
    assert_eq!(rearchived_att, encrypted_blob);

    // Tampering with the blob bytes in the host is caught by SHA-256 verification.
    host.tamper_blob(
        ALICE_DID,
        &leave_report.rearchived_blob_cids[0],
        b"corrupted",
    );
    assert_eq!(
        block_on(alice_mb.get_owner_attachment_verified(&manifest_rkey)).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn concurrent_unsends_are_independent_and_cleanup_retains_durable_redactions() {
    use std::sync::{Arc, Barrier};

    use labyrinth::deletion::Redaction;

    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let convo_space = SpaceRef::parse(&format!(
        "at://{SEQUENCER_DID}/space/blue.catbird.labyrinth.conversation/{CONVO_ID}"
    ))
    .unwrap();
    host.grant_space_member(&convo_space, ALICE_DID);
    host.grant_space_member(&convo_space, BOB_DID);
    let mut alice = make_client(ALICE_DID, 1, &net, &host, &convo_space);
    let mut bob = make_client(BOB_DID, 2, &net, &host, &convo_space);
    let roster = block_on(alice.resolve_roster(&[ALICE_DID, BOB_DID])).unwrap();
    for (id, timestamp) in [("race-a", 10), ("race-b", 20), ("kept", 30)] {
        block_on(alice.archive_outgoing(CONVO_ID, &roster, id, timestamp, id.as_bytes())).unwrap();
    }
    block_on(alice.flush()).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let redact = |message_id: &'static str, host: MemorySpaceHost, barrier: Arc<Barrier>| {
        let space = convo_space.clone();
        std::thread::spawn(move || {
            let mut store = SpaceThreadStore::new(host.client(ALICE_DID), ALICE_DID.to_owned());
            store.register_thread_space(CONVO_ID, space);
            let redaction = Redaction::sign(ALICE_DID, CONVO_ID, message_id, &transport(1));
            barrier.wait();
            block_on(store.redact_item(CONVO_ID, message_id, &redaction)).unwrap();
        })
    };
    let first = redact("race-a", host.clone(), barrier.clone());
    let second = redact("race-b", host.clone(), barrier);
    first.join().unwrap();
    second.join().unwrap();

    let after_race = block_on(bob.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert_eq!(
        after_race
            .messages
            .iter()
            .map(|message| message.message_id.as_str())
            .collect::<Vec<_>>(),
        ["kept"]
    );
    assert_eq!(
        after_race
            .redacted
            .iter()
            .map(|message| message.message_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        ["race-a", "race-b"].into_iter().collect()
    );

    // Account cleanup removes ciphertext batches, but never the separate
    // immutable author-redaction records.
    let mut cleanup = SpaceThreadStore::new(host.client(ALICE_DID), ALICE_DID.to_owned());
    cleanup.register_thread_space(CONVO_ID, convo_space);
    block_on(cleanup.clear_records(CONVO_ID)).unwrap();
    let after_cleanup = block_on(bob.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert!(after_cleanup.messages.is_empty());
    assert_eq!(
        after_cleanup
            .redacted
            .iter()
            .map(|message| message.message_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        ["race-a", "race-b"].into_iter().collect()
    );
}

/// G10: a member owner-archived Alice's messages (an earlier kick rescue)
/// before Alice unsent one. Once that member leaves and can read only its own
/// mailbox, the unsent message must stay hidden.
#[test]
fn leave_tombstones_owner_copies_of_messages_unsent_in_the_space() {
    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let (seq_sk, seq_rk) = sequencer_keys();
    net.set_sequencer_receipt_key(CONVO_ID, seq_rk);
    let convo_space = SpaceRef::parse(&format!(
        "at://{SEQUENCER_DID}/space/blue.catbird.labyrinth.conversation/{CONVO_ID}"
    ))
    .unwrap();
    host.grant_space_member(&convo_space, ALICE_DID);
    host.grant_space_member(&convo_space, BOB_DID);
    let mut alice = make_client(ALICE_DID, 1, &net, &host, &convo_space);
    let mut bob = make_client(BOB_DID, 2, &net, &host, &convo_space);

    let roster = block_on(alice.resolve_roster(&[ALICE_DID, BOB_DID])).unwrap();
    let mut sent = Vec::new();
    for (seq, message_id) in [(20u64, "kept"), (21u64, "unsent")] {
        let nonce = [seq as u8; 32];
        let commitment = compute_archive_commitment(&nonce, message_id.as_bytes());
        let payload = SequencerReceiptPayload {
            sequencer_did: SEQUENCER_DID.to_owned(),
            conversation_id: CONVO_ID.to_owned(),
            group_id: vec![0x44u8; 32],
            epoch: 1,
            sender_device_did_url: format!("{ALICE_DID}#{ALICE_DEV_ID}"),
            entry_id: format!("00000000-0000-0000-0000-{seq:012}"),
            archive_commitment: commitment,
            seq,
            issued_at_ms: 1_791_181_720_000 + seq as i64,
        };
        let receipt = labyrinth::message::ArchivedReceipt::new(
            sign_sequencer_receipt(&seq_sk, &expected_receipt_key_id(SEQUENCER_DID), &payload)
                .unwrap(),
            OriginalSenderArchiveAttestation::sign(
                ALICE_DID.to_owned(),
                ALICE_DEV_ID.to_owned(),
                CONVO_ID,
                message_id,
                &commitment,
                &transport(1),
            ),
        );
        let timestamp = 1_791_181_720_000 + seq;
        block_on(alice.archive_outgoing_committed(
            CONVO_ID,
            &roster,
            message_id,
            timestamp,
            &nonce,
            message_id.as_bytes(),
            &receipt,
        ))
        .unwrap();
        sent.push((message_id, timestamp, nonce, receipt));
    }
    block_on(alice.flush()).unwrap();
    for (message_id, timestamp, nonce, receipt) in &sent {
        block_on(bob.archive_owner_committed(
            CONVO_ID,
            message_id,
            *timestamp,
            nonce,
            message_id.as_bytes(),
            receipt,
        ))
        .unwrap();
    }
    block_on(bob.flush_owner(CONVO_ID)).unwrap();
    assert_eq!(block_on(alice.unsend(CONVO_ID, "unsent")).unwrap(), 1);

    block_on(bob.rearchive_before_leave(CONVO_ID)).expect("bob leaves");
    host.revoke_space_member(&convo_space, BOB_DID);
    let ids = |h: labyrinth::client::ThreadHistory| {
        assert!(h.undecryptable.is_empty(), "{:?}", h.undecryptable);
        h.messages
            .into_iter()
            .map(|m| m.message_id)
            .collect::<Vec<_>>()
    };
    let after_leave = block_on(bob.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert!(!after_leave.space_readable);
    assert_eq!(ids(after_leave), ["kept"]);
    assert_eq!(
        ids(block_on(bob.load_owner_thread(CONVO_ID)).unwrap()),
        ["kept"]
    );
}

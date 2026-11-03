//! Gate 5: Ciphertext-only Space attachments (`.staged` -> `.space`), in-place
//! author batch redaction preserving sibling `I13` receipts, and re-archive before leave.

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::attachment::AttachmentCiphertextMeta;
use labyrinth::client::{Backends, CompositeDirectory, Labyrinth, MessageSource, SystemClock};
use labyrinth::protocol::receipt::{
    SequencerReceiptPayload, compute_archive_commitment, expected_receipt_key_id,
    sign_sequencer_receipt,
};
use labyrinth::sign::{Ed25519Transport, TransportSigner as _};
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef, SpaceThreadStore};
use labyrinth::store::{
    MailboxStore as _, MemoryBackend, SequencerReceiptKey, ThreadStore as _, TimeRange,
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
            &labyrinth::message::ArchivedReceipt::new(receipt.clone()),
        ))
        .unwrap();
    }
    let flushed = block_on(alice.flush()).unwrap();
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].count, 3);

    // Alice unsends middle item `m-11`: rewrites ONLY `m-11` in-place, preserving `m-10` & `m-12` + receipts!
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
    assert!(bob_view.redacted[0].by_author);
    assert!(bob_view.undecryptable.is_empty());

    // 3. Alice leaves conversation: `rearchive_before_leave` copies messages + attachments
    // into Alice's personal mailbox Space BEFORE `clear_records` purges Alice's conversation Space repo!
    let leave_report = block_on(alice.rearchive_and_clear_before_leave(CONVO_ID))
        .expect("rearchive_and_clear_before_leave");
    assert_eq!(leave_report.messages_archived, 2);
    assert_eq!(leave_report.attachments_archived, 1);
    assert_eq!(
        host.record_count(&convo_space, ALICE_DID, None),
        0,
        "Alice's conversation Space repo must be cleared on leave"
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

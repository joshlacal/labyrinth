//! Gate 1 (`I13`): Sequencer receipt & blinded `archiveCommitment` verification.

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, CompositeDirectory, Labyrinth, SystemClock};
use labyrinth::protocol::receipt::{
    SequencerReceiptPayload, compute_archive_commitment, expected_receipt_key_id,
    sign_sequencer_receipt,
};
use labyrinth::records::defs::SequencerReceiptDef;
use labyrinth::records::nsid;
use labyrinth::sign::{Ed25519Transport, TransportSigner as _};
use labyrinth::store::space::SpaceRef;
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceThreadStore};
use labyrinth::store::{MemoryBackend, SequencerReceiptKey, TimeRange};
use p256::ecdsa::SigningKey;

const CONVO_ID: &str = "11111111-2222-3333-4444-555555555555";
const SEQUENCER_DID: &str = "did:web:mls.catbird.blue";
const ALICE_DID: &str = "did:plc:alicegate1";
const BOB_DID: &str = "did:plc:bobgate1";
const ALICE_DEV_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

fn transport(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

fn sequencer_keys() -> (SigningKey, SequencerReceiptKey) {
    let sk = SigningKey::from_bytes((&[0x42u8; 32]).into()).expect("valid p256 sk");
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

fn make_space_client(
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
    block_on(Labyrinth::initialize(did, Box::new(t), backends)).expect("initialize")
}

#[test]
fn gate1_receipt_commitment_accepts_genuine_and_rejects_substitution() {
    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let (seq_sk, seq_rk) = sequencer_keys();
    net.set_sequencer_receipt_key(CONVO_ID, seq_rk);

    let convo_space = SpaceRef::parse(&format!(
        "at://{SEQUENCER_DID}/space/blue.catbird.labyrinth.conversation/{CONVO_ID}"
    ))
    .unwrap();

    let mut alice = make_space_client(ALICE_DID, 1, &net, &host, &convo_space);
    let mut bob = make_space_client(BOB_DID, 2, &net, &host, &convo_space);

    let frame_nonce = [0x77u8; 32];
    let payload_bytes = b"canonical-mls-application-payload-seq-42";
    let commitment = compute_archive_commitment(&frame_nonce, payload_bytes);
    let receipt_payload = SequencerReceiptPayload {
        sequencer_did: SEQUENCER_DID.to_owned(),
        conversation_id: CONVO_ID.to_owned(),
        group_id: vec![0x99u8; 32],
        epoch: 3,
        sender_device_did_url: format!("{ALICE_DID}#{ALICE_DEV_ID}"),
        entry_id: "99999999-8888-7777-6666-555555555555".to_owned(),
        archive_commitment: commitment,
        seq: 42,
        issued_at_ms: 1_791_181_727_000,
    };
    let receipt = sign_sequencer_receipt(
        &seq_sk,
        &expected_receipt_key_id(SEQUENCER_DID),
        &receipt_payload,
    )
    .expect("sign receipt");

    let roster = block_on(alice.resolve_roster(&[ALICE_DID, BOB_DID])).expect("roster");
    block_on(alice.archive_outgoing_committed(
        CONVO_ID,
        &roster,
        "msg-42",
        1_791_181_727_000,
        &frame_nonce,
        payload_bytes,
        &receipt,
    ))
    .expect("archive committed");
    let flushed = block_on(alice.flush()).expect("flush");
    assert_eq!(flushed.len(), 1);
    assert!(
        flushed[0].rkey.starts_with("000000000000002a-"),
        "batch rkey must carry 16-hex first seq prefix, got {}",
        flushed[0].rkey
    );

    // Confirm frameNonce is NEVER stored in cleartext JSON on the Space host.
    let raw_batch = host
        .record(&convo_space, ALICE_DID, nsid::BATCH, &flushed[0].rkey)
        .expect("stored batch");
    let raw_str = raw_batch.to_string();
    assert!(
        !raw_str.contains("frameNonce"),
        "frameNonce must live strictly inside AEAD ciphertext"
    );
    let _parsed_receipt: SequencerReceiptDef =
        serde_json::from_value(raw_batch["items"][0]["sequencerReceipt"].clone())
            .expect("sequencerReceipt present in batch item");

    // Happy path: Bob loads and verifies I13 receipt + commitment.
    let loaded = block_on(bob.load_thread(CONVO_ID, TimeRange::ALL)).expect("bob load");
    assert_eq!(loaded.messages.len(), 1);
    assert_eq!(loaded.messages[0].frame, payload_bytes);
    assert!(loaded.undecryptable.is_empty());

    // Substitution attack #1: sender re-encrypts & re-signs DIFFERENT payload bytes with
    // the SAME genuine `receipt` from seq = 42.
    block_on(alice.archive_outgoing_committed_unchecked_for_test(
        CONVO_ID,
        &roster,
        "msg-42-sub-payload",
        1_791_181_727_001,
        &frame_nonce,
        b"evil-substituted-payload-bytes",
        &receipt,
    ))
    .expect("archive substituted payload");
    block_on(alice.flush()).expect("flush substituted payload");

    // Substitution attack #2: sender mutates `frame_nonce` while keeping payload_bytes and
    // genuine `receipt` from seq = 42.
    let mut bad_nonce = frame_nonce;
    bad_nonce[0] ^= 0xff;
    block_on(alice.archive_outgoing_committed_unchecked_for_test(
        CONVO_ID,
        &roster,
        "msg-42-sub-nonce",
        1_791_181_727_002,
        &bad_nonce,
        payload_bytes,
        &receipt,
    ))
    .expect("archive substituted nonce");
    block_on(alice.flush()).expect("flush substituted nonce");

    let after_attack = block_on(bob.load_thread(CONVO_ID, TimeRange::ALL)).expect("bob reload");
    assert_eq!(
        after_attack.messages.len(),
        1,
        "substituted items must never be accepted into messages"
    );
    assert_eq!(after_attack.undecryptable.len(), 2);
    for u in &after_attack.undecryptable {
        assert_eq!(u.error, Error::ReceiptCommitmentMismatch);
    }
}

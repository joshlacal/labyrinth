//! Gate 1 (`I13`): Sequencer receipt & blinded `archiveCommitment` verification.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, CompositeDirectory, Labyrinth, SystemClock};
use labyrinth::message::ArchivedReceipt;
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
use labyrinth::store::{MailboxDirectory, MemoryBackend, SequencerReceiptKey, TimeRange};
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

/// A removed device has no live thread authority, but can resolve an issuer
/// authenticated inside owner ciphertext. Public receipt fields alone do not
/// authorize this lookup.
struct OwnerAuthorityDirectory {
    inner: Box<dyn MailboxDirectory>,
    receipt_key: Option<SequencerReceiptKey>,
    lookups: Arc<AtomicUsize>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for OwnerAuthorityDirectory {
    async fn latest(
        &self,
        did: &str,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        self.inner.latest(did).await
    }
    async fn epoch(
        &self,
        did: &str,
        seq: u64,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        self.inner.epoch(did, seq).await
    }
    async fn device_transport_keys(
        &self,
        did: &str,
    ) -> labyrinth::Result<Vec<labyrinth::store::ChatDeviceKey>> {
        self.inner.device_transport_keys(did).await
    }
    async fn sequencer_receipt_key_for_authority(
        &self,
        thread_id: &str,
        expected_authority: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        assert_eq!(thread_id, CONVO_ID);
        assert_eq!(expected_authority, SEQUENCER_DID);
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self.receipt_key.clone())
    }
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
    let archived = ArchivedReceipt {
        signed: receipt.clone(),
        generation: 7,
    };

    let roster = block_on(alice.resolve_roster(&[ALICE_DID, BOB_DID])).expect("roster");
    block_on(alice.archive_outgoing_committed(
        CONVO_ID,
        &roster,
        "msg-42",
        1_791_181_727_000,
        &frame_nonce,
        payload_bytes,
        &archived,
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
    assert_eq!(loaded.messages[0].frame_nonce, Some(frame_nonce));
    assert_eq!(
        loaded.messages[0].archived_receipt.as_ref().unwrap().signed,
        receipt
    );
    assert_eq!(
        loaded.messages[0].archived_receipt.as_ref(),
        Some(&archived)
    );
    assert!(loaded.undecryptable.is_empty());

    // Owner frames carry the same verified metadata, but cannot be trusted
    // without the directory's sequencer receipt key.
    let owner_net = MemoryBackend::new();
    let owner_host = MemorySpaceHost::new();
    let mut owner = make_space_client(ALICE_DID, 1, &owner_net, &owner_host, &convo_space);
    block_on(owner.archive_owner_committed(
        CONVO_ID,
        "msg-42",
        1_791_181_727_000,
        &frame_nonce,
        payload_bytes,
        &archived,
    ))
    .expect("archive owner committed");
    let owner_batch = block_on(owner.flush_owner(CONVO_ID))
        .expect("flush owner committed")
        .expect("owner batch");
    let untrusted = block_on(owner.load_owner_thread(CONVO_ID)).expect("load without key");
    assert!(untrusted.messages.is_empty());
    assert_eq!(untrusted.undecryptable.len(), 1);
    assert_eq!(untrusted.undecryptable[0].error, Error::Unattested);

    owner_net.set_sequencer_receipt_key(CONVO_ID, sequencer_keys().1);
    let trusted = block_on(owner.load_owner_thread(CONVO_ID)).expect("load with key");
    assert!(trusted.undecryptable.is_empty());
    assert_eq!(trusted.messages.len(), 1);
    assert_eq!(trusted.messages[0].frame, payload_bytes);
    assert_eq!(trusted.messages[0].sender.as_deref(), Some(ALICE_DID));
    assert_eq!(trusted.messages[0].frame_nonce, Some(frame_nonce));
    assert_eq!(
        trusted.messages[0]
            .archived_receipt
            .as_ref()
            .unwrap()
            .signed,
        receipt
    );
    assert_eq!(
        trusted.messages[0].archived_receipt.as_ref(),
        Some(&archived)
    );

    // A genuinely fresh device restores mailbox keys through its recovery code,
    // without live conversation authority or saved placement. The retained
    // issuer is usable only because owner AEAD authenticated the entire receipt.
    let recovery = block_on(owner.create_recovery_code(labyrinth::virtual_device::Mechanism::Code))
        .expect("create recovery code");
    owner_net.register_chat_device(ALICE_DID, transport(9).transport_public_key());
    let mailbox_space = SpaceRef::parse(&format!(
        "at://{ALICE_DID}/space/blue.catbird.labyrinth.mailbox/self",
    ))
    .unwrap();
    let lookups = Arc::new(AtomicUsize::new(0));
    let restored_backends = Backends {
        mailbox: Box::new(
            SpaceMailboxStore::new(
                owner_host.client(ALICE_DID),
                mailbox_space.clone(),
                ALICE_DID.to_owned(),
            )
            .with_key_publisher(Box::new(owner_net.pds_publisher(ALICE_DID))),
        ),
        threads: Box::new(owner_net.threads(ALICE_DID)),
        directory: Box::new(CompositeDirectory::new(
            Box::new(OwnerAuthorityDirectory {
                inner: Box::new(owner_net.directory()),
                receipt_key: None,
                lookups: lookups.clone(),
            }),
            Box::new(OwnerAuthorityDirectory {
                inner: Box::new(owner_net.ds_directory()),
                receipt_key: Some(sequencer_keys().1),
                lookups: lookups.clone(),
            }),
        )),
        publishers: vec![Box::new(owner_net.ds_publisher(ALICE_DID))],
        clock: Box::new(SystemClock),
    };
    let (mut fresh, _) = block_on(Labyrinth::restore_with_recovery_code(
        ALICE_DID,
        recovery.code.as_str(),
        Box::new(transport(9)),
        restored_backends,
    ))
    .expect("restore fresh device");
    let recovered = block_on(fresh.load_owner_thread(CONVO_ID)).expect("recover owner history");
    assert!(recovered.undecryptable.is_empty());
    assert_eq!(recovered.messages.len(), 1);
    assert_eq!(recovered.messages[0].frame, payload_bytes);
    assert_eq!(
        recovered.messages[0].archived_receipt.as_ref(),
        Some(&archived)
    );
    assert_eq!(recovered.messages[0].frame_nonce, Some(frame_nonce));
    assert!(lookups.load(Ordering::SeqCst) > 0);

    let stored: labyrinth::records::OwnerBatch = serde_json::from_value(
        owner_host
            .record(
                &mailbox_space,
                ALICE_DID,
                nsid::OWNER_BATCH,
                &owner_batch.rkey,
            )
            .unwrap(),
    )
    .unwrap();
    lookups.store(0, Ordering::SeqCst);
    for mutation in 0..4 {
        let mut messages = stored.to_messages().unwrap();
        let retained = messages[0].sequencer_receipt.as_mut().unwrap();
        match mutation {
            0 => retained.generation += 1,
            1 => {
                retained.signed.payload.sequencer_did = "did:web:attacker.example".into();
                retained.signed.key_id = expected_receipt_key_id("did:web:attacker.example");
            }
            2 => retained.signed.signature[0] ^= 1,
            _ => messages[0].sequencer_receipt = None,
        }
        let substituted =
            labyrinth::records::OwnerBatch::from_messages(&messages, stored.created_at.clone())
                .unwrap();
        let rejected = block_on(fresh.open_owner_record(substituted)).expect("reject substitution");
        assert!(rejected.messages.is_empty());
        assert_eq!(rejected.undecryptable.len(), 1);
        assert_eq!(rejected.undecryptable[0].error, Error::Decrypt);
    }
    assert_eq!(
        lookups.load(Ordering::SeqCst),
        0,
        "unauthenticated issuer must never be resolved"
    );

    // An earlier legacy copy must not discard verified receipt metadata when
    // the equivalent committed owner copy is merged into it.
    block_on(owner.archive_owner_attributed(
        CONVO_ID,
        "dedupe-42",
        1_791_181_727_000,
        ALICE_DID,
        payload_bytes,
    ))
    .expect("archive attributed owner");
    block_on(owner.archive_owner_committed(
        CONVO_ID,
        "dedupe-42",
        1_791_181_727_000,
        &frame_nonce,
        payload_bytes,
        &archived,
    ))
    .expect("archive committed duplicate");
    block_on(owner.flush_owner(CONVO_ID)).expect("flush duplicates");
    let merged = block_on(owner.load_owner_thread(CONVO_ID)).expect("load duplicates");
    assert_eq!(merged.messages.len(), 2);
    let duplicate = merged
        .messages
        .iter()
        .find(|m| m.message_id == "dedupe-42")
        .unwrap();
    assert!(!duplicate.conflict);
    assert_eq!(duplicate.archived_receipt.as_ref().unwrap().signed, receipt);
    assert_eq!(duplicate.frame_nonce, Some(frame_nonce));

    // The same frame with a different verified receipt/nonce pair is not an
    // identical archive copy; retain both and flag the conflict.
    let other_nonce = [0x78; 32];
    let mut other_payload = receipt_payload.clone();
    other_payload.seq = 43;
    other_payload.archive_commitment = compute_archive_commitment(&other_nonce, payload_bytes);
    let other_receipt = sign_sequencer_receipt(
        &seq_sk,
        &expected_receipt_key_id(SEQUENCER_DID),
        &other_payload,
    )
    .unwrap();
    block_on(owner.archive_owner_committed(
        CONVO_ID,
        "dedupe-42",
        1_791_181_727_000,
        &other_nonce,
        payload_bytes,
        &ArchivedReceipt::new(other_receipt.clone()),
    ))
    .expect("archive conflicting commitment");
    block_on(owner.flush_owner(CONVO_ID)).expect("flush conflicting commitment");
    let conflicts =
        block_on(owner.load_owner_thread(CONVO_ID)).expect("load conflicting commitment");
    let duplicates: Vec<_> = conflicts
        .messages
        .iter()
        .filter(|message| message.message_id == "dedupe-42")
        .collect();
    assert_eq!(duplicates.len(), 2);
    for message in duplicates {
        assert!(message.conflict);
        let signed = &message.archived_receipt.as_ref().unwrap().signed;
        assert!(
            (signed == &receipt && message.frame_nonce == Some(frame_nonce))
                || (signed == &other_receipt && message.frame_nonce == Some(other_nonce)),
            "receipt and nonce must remain paired",
        );
    }

    // Substitution attack #1: sender re-encrypts & re-signs DIFFERENT payload bytes with
    // the SAME genuine `receipt` from seq = 42.
    block_on(alice.archive_outgoing_committed_unchecked_for_test(
        CONVO_ID,
        &roster,
        "msg-42-sub-payload",
        1_791_181_727_001,
        &frame_nonce,
        b"evil-substituted-payload-bytes",
        &archived,
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
        &archived,
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

//! Gate 1 (`I13`): Sequencer receipt & blinded `archiveCommitment` verification.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, CompositeDirectory, Labyrinth, SystemClock};
use labyrinth::message::{ArchivedReceipt, OriginalSenderArchiveAttestation};
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
use labyrinth::store::{
    MailboxDirectory, MemberDeviceKey, MemoryBackend, SequencerReceiptKey, TimeRange,
};
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

fn archived_receipt(
    signed: labyrinth::protocol::receipt::SignedSequencerReceipt,
    message_id: &str,
) -> ArchivedReceipt {
    let attestation = OriginalSenderArchiveAttestation::sign(
        ALICE_DID.to_owned(),
        ALICE_DEV_ID.to_owned(),
        CONVO_ID,
        message_id,
        &signed.payload.archive_commitment,
        &transport(1),
    );
    ArchivedReceipt {
        signed,
        generation: 7,
        original_sender_attestation: attestation,
    }
}

fn space_backends(
    did: &str,
    net: &MemoryBackend,
    host: &MemorySpaceHost,
    convo_space: &SpaceRef,
) -> Backends {
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
    Backends {
        mailbox: Box::new(mailbox),
        threads: Box::new(threads),
        directory: Box::new(directory),
        publishers: vec![Box::new(net.ds_publisher(did))],
        clock: Box::new(SystemClock),
    }
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
    net.set_member_device_keys(
        CONVO_ID,
        did,
        vec![MemberDeviceKey {
            key: t.transport_public_key(),
            joined_chat_seq: 1,
            removed_chat_seq: None,
        }],
    );
    block_on(Labyrinth::initialize(
        did,
        Box::new(t),
        space_backends(did, net, host, convo_space),
    ))
    .expect("initialize")
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
    async fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> labyrinth::Result<Option<Vec<MemberDeviceKey>>> {
        self.inner.member_device_keys(thread_id, did).await
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

struct MissingRosterDirectory(Box<dyn MailboxDirectory>);

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for MissingRosterDirectory {
    async fn latest(
        &self,
        did: &str,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        self.0.latest(did).await
    }

    async fn epoch(
        &self,
        did: &str,
        seq: u64,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        self.0.epoch(did, seq).await
    }

    async fn device_transport_keys(
        &self,
        did: &str,
    ) -> labyrinth::Result<Vec<labyrinth::store::ChatDeviceKey>> {
        self.0.device_transport_keys(did).await
    }

    async fn member_device_keys(
        &self,
        _thread_id: &str,
        _did: &str,
    ) -> labyrinth::Result<Option<Vec<MemberDeviceKey>>> {
        Ok(None)
    }

    async fn sequencer_receipt_key(
        &self,
        thread_id: &str,
    ) -> labyrinth::Result<Option<SequencerReceiptKey>> {
        self.0.sequencer_receipt_key(thread_id).await
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
    let archived = archived_receipt(receipt.clone(), "msg-42");

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

    // First valid owner receipt durably latches the exact key bytes. Removing
    // the current DID method and reconstructing the client cannot re-enable
    // receiptless/timestamp fallback.
    let owner_net = MemoryBackend::new();
    owner_net.set_sequencer_receipt_key(CONVO_ID, sequencer_keys().1);
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
    let state = owner.export_state().expect("state with receipt trust");
    owner_net.clear_sequencer_receipt_keys(CONVO_ID);
    let mut owner = block_on(Labyrinth::from_state(
        &state,
        ALICE_DID,
        Box::new(transport(1)),
        space_backends(ALICE_DID, &owner_net, &owner_host, &convo_space),
    ))
    .expect("reconstruct after DID method removal");
    let trusted =
        block_on(owner.load_owner_thread(CONVO_ID)).expect("load from pinned key history");
    assert!(trusted.undecryptable.is_empty());
    assert_eq!(trusted.messages.len(), 1);
    assert_eq!(trusted.messages[0].frame, payload_bytes);
    assert_eq!(trusted.messages[0].sender.as_deref(), Some(ALICE_DID));
    assert_eq!(trusted.messages[0].frame_nonce, Some(frame_nonce));
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

    // Once any valid receipt was observed, a missing current DID method can
    // never make an older receiptless write acceptable.
    assert_eq!(
        block_on(owner.archive_owner_attributed(
            CONVO_ID,
            "backdated-plain",
            1,
            ALICE_DID,
            payload_bytes,
        ))
        .unwrap_err(),
        Error::ReceiptCommitmentMismatch
    );

    // Substitution attack #1: sender re-encrypts & re-signs DIFFERENT payload bytes with
    // the SAME genuine `receipt` from seq = 42.
    let substituted_payload_receipt = archived_receipt(receipt.clone(), "msg-42-sub-payload");
    block_on(alice.archive_outgoing_committed_unchecked_for_test(
        CONVO_ID,
        &roster,
        "msg-42-sub-payload",
        1_791_181_727_001,
        &frame_nonce,
        b"evil-substituted-payload-bytes",
        &substituted_payload_receipt,
    ))
    .expect("archive substituted payload");
    block_on(alice.flush()).expect("flush substituted payload");

    // Substitution attack #2: sender mutates `frame_nonce` while keeping payload_bytes and
    // genuine `receipt` from seq = 42.
    let mut bad_nonce = frame_nonce;
    bad_nonce[0] ^= 0xff;
    let substituted_nonce_receipt = archived_receipt(receipt.clone(), "msg-42-sub-nonce");
    block_on(alice.archive_outgoing_committed_unchecked_for_test(
        CONVO_ID,
        &roster,
        "msg-42-sub-nonce",
        1_791_181_727_002,
        &bad_nonce,
        payload_bytes,
        &substituted_nonce_receipt,
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
#[test]
fn gate14_nonmember_space_repo_is_ignored_by_independent_mls_roster() {
    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let (sequencer, receipt_key) = sequencer_keys();
    net.set_sequencer_receipt_key(CONVO_ID, receipt_key);
    let convo_space = SpaceRef::parse(&format!(
        "at://{SEQUENCER_DID}/space/blue.catbird.labyrinth.conversation/{CONVO_ID}"
    ))
    .unwrap();
    host.grant_space_member(&convo_space, ALICE_DID);
    host.grant_space_member(&convo_space, BOB_DID);

    // Bob is in the authoritative MLS roster. Alice can write a Space repo,
    // but deliberately has no MLS leaf for this conversation.
    let mut bob = make_space_client(BOB_DID, 2, &net, &host, &convo_space);
    let alice_transport = transport(1);
    net.set_chat_devices(ALICE_DID, vec![alice_transport.transport_public_key()]);
    let mut alice = block_on(Labyrinth::initialize(
        ALICE_DID,
        Box::new(alice_transport),
        space_backends(ALICE_DID, &net, &host, &convo_space),
    ))
    .unwrap();

    let message_id = "nonmember-injected-message";
    let frame_nonce = [0x61; 32];
    let frame = b"must not surface";
    let payload = SequencerReceiptPayload {
        sequencer_did: SEQUENCER_DID.to_owned(),
        conversation_id: CONVO_ID.to_owned(),
        group_id: vec![0x99; 32],
        epoch: 1,
        sender_device_did_url: format!("{ALICE_DID}#{ALICE_DEV_ID}"),
        entry_id: "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb".to_owned(),
        archive_commitment: compute_archive_commitment(&frame_nonce, frame),
        seq: 51,
        issued_at_ms: 1_791_181_727_051,
    };
    let signed = sign_sequencer_receipt(
        &sequencer,
        &expected_receipt_key_id(SEQUENCER_DID),
        &payload,
    )
    .unwrap();
    let roster = block_on(alice.resolve_roster(&[ALICE_DID, BOB_DID])).unwrap();
    block_on(alice.archive_outgoing_committed(
        CONVO_ID,
        &roster,
        message_id,
        payload.issued_at_ms as u64,
        &frame_nonce,
        frame,
        &archived_receipt(signed, message_id),
    ))
    .unwrap();
    block_on(alice.flush()).unwrap();
    assert_eq!(
        host.record_count(&convo_space, ALICE_DID, Some(nsid::BATCH)),
        1,
        "fixture must prove listRepos exposes the injected repo"
    );

    let history = block_on(bob.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert!(history.messages.is_empty());
    assert!(history.undecryptable.is_empty());
    assert!(history.redacted.is_empty());
    let state = bob.export_state().unwrap();
    let mut missing_roster_backends = space_backends(BOB_DID, &net, &host, &convo_space);
    missing_roster_backends.directory =
        Box::new(MissingRosterDirectory(missing_roster_backends.directory));
    let mut missing_roster = block_on(Labyrinth::from_state(
        &state,
        BOB_DID,
        Box::new(transport(2)),
        missing_roster_backends,
    ))
    .unwrap();
    assert_eq!(
        block_on(missing_roster.load_thread(CONVO_ID, TimeRange::ALL)).unwrap_err(),
        Error::DirectoryIncomplete {
            pds_present: true,
            ds_present: false,
        }
    );
}

#[test]
fn receipt_rotation_retains_exact_keys_across_directory_removal_and_restart() {
    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let convo_space = SpaceRef::parse(&format!(
        "at://{SEQUENCER_DID}/space/blue.catbird.labyrinth.conversation/{CONVO_ID}"
    ))
    .unwrap();
    let (key1, public1) = sequencer_keys();
    let key1_id = expected_receipt_key_id(SEQUENCER_DID);
    net.set_sequencer_receipt_key_with_id(CONVO_ID, &key1_id, public1.clone());

    let mut alice = make_space_client(ALICE_DID, 1, &net, &host, &convo_space);
    let mut bob = make_space_client(BOB_DID, 2, &net, &host, &convo_space);
    let roster = block_on(alice.resolve_roster(&[ALICE_DID, BOB_DID])).unwrap();
    let nonce1 = [0x51; 32];
    let frame1 = b"receipt key one";
    let payload1 = SequencerReceiptPayload {
        sequencer_did: SEQUENCER_DID.to_owned(),
        conversation_id: CONVO_ID.to_owned(),
        group_id: vec![0x11; 32],
        epoch: 1,
        sender_device_did_url: format!("{ALICE_DID}#{ALICE_DEV_ID}"),
        entry_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        archive_commitment: compute_archive_commitment(&nonce1, frame1),
        seq: 1,
        issued_at_ms: 1_791_181_727_001,
    };
    let receipt1 = archived_receipt(
        sign_sequencer_receipt(&key1, &key1_id, &payload1).unwrap(),
        "rotation-k1",
    );
    block_on(alice.archive_outgoing_committed(
        CONVO_ID,
        &roster,
        "rotation-k1",
        payload1.issued_at_ms as u64,
        &nonce1,
        frame1,
        &receipt1,
    ))
    .unwrap();
    block_on(alice.flush()).unwrap();
    assert_eq!(
        block_on(bob.load_thread(CONVO_ID, TimeRange::ALL))
            .unwrap()
            .messages
            .len(),
        1
    );

    let key2 = SigningKey::from_bytes((&[0x43u8; 32]).into()).unwrap();
    let key2_id = format!("{SEQUENCER_DID}#mls-receipt-2");
    let public2 = SequencerReceiptKey {
        did: SEQUENCER_DID.to_owned(),
        public_key_sec1: key2
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    };
    net.set_sequencer_receipt_key_with_id(CONVO_ID, &key2_id, public2);
    let nonce2 = [0x52; 32];
    let frame2 = b"receipt key two";
    let payload2 = SequencerReceiptPayload {
        archive_commitment: compute_archive_commitment(&nonce2, frame2),
        entry_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        seq: 2,
        issued_at_ms: 1_791_181_727_002,
        ..payload1.clone()
    };
    let receipt2 = archived_receipt(
        sign_sequencer_receipt(&key2, &key2_id, &payload2).unwrap(),
        "rotation-k2",
    );
    block_on(alice.archive_outgoing_committed(
        CONVO_ID,
        &roster,
        "rotation-k2",
        payload2.issued_at_ms as u64,
        &nonce2,
        frame2,
        &receipt2,
    ))
    .unwrap();
    block_on(alice.flush()).unwrap();
    let rotated = block_on(bob.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert_eq!(rotated.messages.len(), 2);

    let replacement = SigningKey::from_bytes((&[0x44u8; 32]).into()).unwrap();
    assert_eq!(
        net.try_set_sequencer_receipt_key_with_id(
            CONVO_ID,
            &key1_id,
            SequencerReceiptKey {
                did: SEQUENCER_DID.to_owned(),
                public_key_sec1: replacement
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec(),
            },
        ),
        Err(Error::Conflict)
    );

    let state = bob.export_state().unwrap();
    net.clear_sequencer_receipt_keys(CONVO_ID);
    let mut restarted = block_on(Labyrinth::from_state(
        &state,
        BOB_DID,
        Box::new(transport(2)),
        space_backends(BOB_DID, &net, &host, &convo_space),
    ))
    .unwrap();
    let history = block_on(restarted.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert_eq!(history.messages.len(), 2);
    assert!(history.undecryptable.is_empty());
    assert_eq!(
        block_on(restarted.archive_owner(CONVO_ID, "backdated-after-rotation", 1, b"receiptless",))
            .unwrap_err(),
        Error::ReceiptCommitmentMismatch
    );
}

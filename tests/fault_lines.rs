//! Fault-line verification suite covering:
//! 1. Immediate `[CB-30]` `StateSink` persistence on `MEK`, `[CB-29]` pin, `revoked`,
//!    and `EpochSecret` mutations before network flush/publish errors.
//! 2. Safe `[CB-40]` `clear_squatted_epoch` cleanup in `SpaceMailboxStore` gated by
//!    `CompositeDirectory` anchoring and `step_forward` re-verification.
//! 3. Owner-mode (`v5` `[CB-37]`) authenticated sender attribution (`0x03` + `0x02`
//!    `I13` receipts), `rearchive_thread_before_leave` peer attribution, `dedupe`
//!    conflict detection, and author-scoped `delete_for_me` tombstones.

#[path = "support/net.rs"]
mod net;

use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{
    Backends, CompositeDirectory, Labyrinth, MessageSource, StateSink, SystemClock,
};
use labyrinth::message::OriginalSenderArchiveAttestation;
use labyrinth::protocol::receipt::{
    SequencerReceiptPayload, compute_archive_commitment, expected_receipt_key_id,
    sign_sequencer_receipt,
};
use labyrinth::records::{
    Batch, Bytes, Epoch, EpochMember, MailboxKeysRecord, MekDistribution, nsid,
};
use labyrinth::sign::{Ed25519Transport, TransportSigner as _};
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef, SpaceRpc as _, SpaceThreadStore};
use labyrinth::store::{
    KeyPublisher, MailboxStore, MemberDeviceKey, SequencerReceiptKey, Stored, ThreadStore,
    TimeRange,
};
use net::*;
use p256::ecdsa::SigningKey;

const CONVO_ID: &str = "33333333-4444-5555-6666-777777777777";
const SEQUENCER_DID: &str = "did:web:mls.catbird.blue";
const ALICE_DID: &str = "did:plc:alicefault";
const BOB_DID: &str = "did:plc:bobfault";
const ALICE_DEV_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const BOB_DEV_ID: &str = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff";

#[derive(Clone, Default)]
struct RecordingSink {
    snapshots: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl RecordingSink {
    fn latest(&self) -> Option<Vec<u8>> {
        self.snapshots.lock().unwrap().last().cloned()
    }
    fn count(&self) -> usize {
        self.snapshots.lock().unwrap().len()
    }
}

impl StateSink for RecordingSink {
    fn save_state(&self, exported_state: &[u8]) -> labyrinth::Result<()> {
        self.snapshots.lock().unwrap().push(exported_state.to_vec());
        Ok(())
    }
}

struct FailingThreadStore {
    inner: Box<dyn ThreadStore>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ThreadStore for FailingThreadStore {
    fn author(&self) -> &str {
        self.inner.author()
    }
    async fn create_mek(&self, mek: &MekDistribution) -> labyrinth::Result<()> {
        self.inner.create_mek(mek).await
    }
    async fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> labyrinth::Result<Vec<Stored<MekDistribution>>> {
        self.inner.find_meks(thread_id, mek_id).await
    }
    async fn append_batch(&self, _batch: &Batch) -> labyrinth::Result<String> {
        Err(Error::Backend("simulated flush network failure".into()))
    }
    async fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<Batch>>> {
        self.inner.list_batches(thread_id, sender, range).await
    }
}

struct FailingPublisher;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyPublisher for FailingPublisher {
    async fn publish(&self, _record: &MailboxKeysRecord) -> labyrinth::Result<()> {
        Err(Error::Backend("simulated publish outage".into()))
    }
    async fn retract(&self) -> labyrinth::Result<()> {
        Ok(())
    }
}

fn transport(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

fn original_sender_attestation(
    seed: u8,
    did: &str,
    device_id: &str,
    thread_id: &str,
    message_id: &str,
    commitment: &[u8; 32],
) -> OriginalSenderArchiveAttestation {
    OriginalSenderArchiveAttestation::sign(
        did.to_owned(),
        device_id.to_owned(),
        thread_id,
        message_id,
        commitment,
        &transport(seed),
    )
}

fn sequencer_keys() -> (SigningKey, SequencerReceiptKey) {
    let sk = SigningKey::from_bytes((&[0x66u8; 32]).into()).expect("valid p256 sk");
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
    net.register_chat_device(did, t.transport_public_key());
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

fn restore_space_client(
    state: &[u8],
    did: &str,
    seed: u8,
    net: &MemoryBackend,
    host: &MemorySpaceHost,
    convo_space: &SpaceRef,
) -> Labyrinth {
    let t = transport(seed);
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
    block_on(Labyrinth::from_state(state, did, Box::new(t), backends)).expect("restore")
}

#[test]
fn fault_line_1_state_sink_persists_pin_and_mek_before_flush_failure() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut bob = init(&net, &clock, B, 2);

    net.register_chat_device(A, tpub(1));
    let failing_backends = Backends {
        mailbox: Box::new(net.mailbox(A)),
        threads: Box::new(FailingThreadStore {
            inner: Box::new(net.threads(A)),
        }),
        directory: Box::new(net.directory()),
        publishers: vec![],
        clock: Box::new(clock.clone()),
    };
    let sink = RecordingSink::default();
    let mut alice = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        failing_backends,
    ))
    .unwrap()
    .with_state_sink(Box::new(sink.clone()));

    assert_eq!(sink.count(), 0);

    // Resolving a peer roster pins `[CB-29]` and immediately checkpoints via StateSink.
    let roster = block_on(alice.resolve_roster(&[A, B])).unwrap();
    let after_pin_count = sink.count();
    assert!(
        after_pin_count >= 1,
        "resolve_roster must checkpoint [CB-29] pins immediately"
    );

    // Queueing an outgoing message mints a MEK and checkpoints BEFORE flush() runs.
    block_on(alice.archive_outgoing(T, &roster, "msg-1", 1_791_000_001_000, b"hello")).unwrap();
    let after_mek_count = sink.count();
    assert!(
        after_mek_count > after_pin_count,
        "archive_outgoing must checkpoint minted MEK before flush"
    );

    // Network flush fails (e.g., offline or app jetsammed before flush completes).
    assert!(block_on(alice.flush()).is_err());

    // Simulate process crash: drop `alice` WITHOUT calling `export_state()` and restore
    // exclusively from the last `StateSink` snapshot with working network backends.
    let crashed_snapshot = sink.latest().expect("snapshot captured before flush");
    drop(alice);

    let mut restored = block_on(Labyrinth::from_state(
        &crashed_snapshot,
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A),
    ))
    .unwrap();

    // Verify `[CB-29]` pin survived!
    assert_eq!(restored.peer_pin(B).map(|p| p.seq), Some(0));

    // Re-queueing under the same roster reuses the persisted MEK (already published to
    // ThreadStore before `flush` failed) and flushes cleanly so Bob can read it!
    let roster2 = block_on(restored.resolve_roster(&[A, B])).unwrap();
    block_on(restored.archive_outgoing(T, &roster2, "msg-1", 1_791_000_001_000, b"hello")).unwrap();
    let reports = block_on(restored.flush()).unwrap();
    assert_eq!(reports.len(), 1);

    let bob_view = block_on(bob.load_thread(T, TimeRange::ALL)).unwrap();
    assert_eq!(bob_view.messages.len(), 1);
    assert_eq!(bob_view.messages[0].frame, b"hello");
}

#[test]
fn fault_line_1_state_sink_persists_revoked_and_rotated_epoch_before_network_errors() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let faulty = Faulty::new(net.mailbox(A));
    net.register_chat_device(A, tpub(1));

    let sink = RecordingSink::default();
    let mut phone = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(faulty.clone()), vec![]),
    ))
    .unwrap()
    .with_state_sink(Box::new(sink.clone()));

    let mut thief = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    let thief_key = thief.device_public().device_key_pub;
    let tablet_key = tablet.device_public().device_key_pub;

    // Case A: `create_epoch` fails mid-revocation -> `revoked` set is already persisted!
    faulty
        .fail_epochs
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(block_on(phone.revoke_device(&thief_key)).is_err());
    faulty
        .fail_epochs
        .store(false, std::sync::atomic::Ordering::Relaxed);

    let snapshot_after_failed_revoke = sink.latest().expect("revoked checkpointed");
    drop(phone);

    // Thief races ahead and opens epoch 3 before phone recovers.
    block_on(thief.revoke_device(&tablet_key)).unwrap();

    // Phone restores from StateSink snapshot and STILL recognizes thief as locally revoked!
    let mut restored_phone = block_on(Labyrinth::from_state(
        &snapshot_after_failed_revoke,
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A),
    ))
    .unwrap();
    assert_eq!(
        block_on(restored_phone.sync_epochs()).unwrap_err(),
        Error::EpochSquatted {
            seq: 3,
            reason: "it was opened by a device this client revoked",
        }
    );

    // Case B: `create_epoch` succeeds in Space, but `KeyPublisher` fails -> rotated `EpochSecret`
    // is ALREADY persisted in `StateSink` before `publish_keys` ran!
    let net2 = MemoryBackend::new();
    let sink2 = RecordingSink::default();
    net2.register_chat_device(A, tpub(1));
    let mut phone2 = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends(&net2, &clock, A),
    ))
    .unwrap();
    let laptop2 = sibling(&net2, &clock, &mut phone2, 2);
    let laptop2_key = laptop2.device_public().device_key_pub;
    let phone2_state = phone2.export_state().unwrap();

    let mut phone2_failing_pub = block_on(Labyrinth::from_state(
        &phone2_state,
        A,
        Box::new(signer(1)),
        backends_with(
            &net2,
            &clock,
            A,
            Box::new(net2.mailbox(A)),
            vec![Box::new(FailingPublisher)],
        ),
    ))
    .unwrap()
    .with_state_sink(Box::new(sink2.clone()));

    // Rotation writes epoch 2 to mailbox, checkpoints EpochSecret 2, then fails in FailingPublisher.
    assert!(block_on(phone2_failing_pub.revoke_device(&laptop2_key)).is_err());
    let crashed_after_rotate = sink2.latest().expect("rotated epoch checkpointed");
    drop(phone2_failing_pub);

    let restored_after_rotate = block_on(Labyrinth::from_state(
        &crashed_after_rotate,
        A,
        Box::new(signer(1)),
        backends(&net2, &clock, A),
    ))
    .unwrap();
    assert_eq!(
        restored_after_rotate.latest_epoch(),
        2,
        "rotated EpochSecret must survive a publish_keys failure"
    );
}

#[test]
fn fault_line_3_clear_squatted_epoch_in_space_mailbox_and_safety_guards() {
    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let convo_space = SpaceRef::parse(&format!(
        "at://{SEQUENCER_DID}/space/blue.catbird.labyrinth.conversation/{CONVO_ID}"
    ))
    .unwrap();
    host.grant_space_member(&convo_space, ALICE_DID);

    let mut phone = make_space_client(ALICE_DID, 1, &net, &host, &convo_space);

    // Enroll a sibling `laptop` via OTC (advances Space mailbox + CompositeDirectory to epoch 1).
    let mut offer = phone.otc_offer().unwrap();
    let code = offer.code().as_str().to_owned();
    let (init_otc, hello) = Labyrinth::otc_start(ALICE_DID, &code).unwrap();
    let reply = block_on(phone.otc_respond(&mut offer, &hello)).unwrap();
    let laptop_t = transport(2);
    net.register_chat_device(ALICE_DID, laptop_t.transport_public_key());
    let mb_space = SpaceRef::parse(&format!(
        "at://{ALICE_DID}/space/blue.catbird.labyrinth.mailbox/self"
    ))
    .unwrap();
    let laptop_backends = Backends {
        mailbox: Box::new(
            SpaceMailboxStore::new(
                host.client(ALICE_DID),
                mb_space.clone(),
                ALICE_DID.to_owned(),
            )
            .with_key_publisher(Box::new(net.pds_publisher(ALICE_DID))),
        ),
        threads: Box::new(SpaceThreadStore::new(
            host.client(ALICE_DID),
            ALICE_DID.to_owned(),
        )),
        directory: Box::new(CompositeDirectory::new(
            Box::new(net.directory()),
            Box::new(net.ds_directory()),
        )),
        publishers: vec![Box::new(net.ds_publisher(ALICE_DID))],
        clock: Box::new(SystemClock),
    };
    let (mut laptop, _) = block_on(Labyrinth::enroll_via_otc(
        ALICE_DID,
        init_otc,
        &reply.message,
        &reply.sealed_payload,
        Box::new(laptop_t),
        laptop_backends,
    ))
    .expect("laptop enroll");

    // Enroll a third device `tablet` (advances Space mailbox + CompositeDirectory to epoch 2).
    let mut offer2 = laptop.otc_offer().unwrap();
    let code2 = offer2.code().as_str().to_owned();
    let (init_otc2, hello2) = Labyrinth::otc_start(ALICE_DID, &code2).unwrap();
    let reply2 = block_on(laptop.otc_respond(&mut offer2, &hello2)).unwrap();
    let tablet_t = transport(3);
    net.register_chat_device(ALICE_DID, tablet_t.transport_public_key());
    let tablet_backends = Backends {
        mailbox: Box::new(
            SpaceMailboxStore::new(
                host.client(ALICE_DID),
                mb_space.clone(),
                ALICE_DID.to_owned(),
            )
            .with_key_publisher(Box::new(net.pds_publisher(ALICE_DID))),
        ),
        threads: Box::new(SpaceThreadStore::new(
            host.client(ALICE_DID),
            ALICE_DID.to_owned(),
        )),
        directory: Box::new(CompositeDirectory::new(
            Box::new(net.directory()),
            Box::new(net.ds_directory()),
        )),
        publishers: vec![Box::new(net.ds_publisher(ALICE_DID))],
        clock: Box::new(SystemClock),
    };
    let (mut tablet, _) = block_on(Labyrinth::enroll_via_otc(
        ALICE_DID,
        init_otc2,
        &reply2.message,
        &reply2.sealed_payload,
        Box::new(tablet_t),
        tablet_backends,
    ))
    .expect("tablet enroll");

    // Guard 1: `phone` is still at local epoch 0 while `laptop` and `tablet` legitimately opened
    // epochs 1 & 2. Calling `clear_squatted_epoch(1)` on `phone` MUST NOT delete epoch 1 —
    // instead it absorbs the valid sibling chain and returns `Ok(false)`!
    assert!(!block_on(phone.clear_squatted_epoch(1)).unwrap());
    assert_eq!(phone.latest_epoch(), 2);

    // Guard 2: `seq <= latest` is refused immediately.
    assert!(matches!(
        block_on(phone.clear_squatted_epoch(2)).unwrap_err(),
        Error::EpochSquatted { seq: 2, .. }
    ));

    // Main squat scenario: an insider chat device writes a bogus unanchored `epoch/3` +
    // `epochMember/3-*` directly into the personal mailbox Space (`com.atproto.space.applyWrites`).
    let alice_mb = SpaceMailboxStore::new(
        host.client(ALICE_DID),
        mb_space.clone(),
        ALICE_DID.to_owned(),
    );
    let e2 = block_on(alice_mb.get_epoch(2)).unwrap().unwrap().value;
    let mut bogus_e3: Epoch = e2.clone();
    bogus_e3.public.epoch_number = 3;
    bogus_e3.public.previous_epoch_head = Some(e2.public.epoch_head.clone());
    bogus_e3.public.prev_sig = Some(e2.public.self_sig.clone());
    bogus_e3.encrypted_previous_epoch_number = Some(Bytes(vec![9; 40]));
    bogus_e3.encrypted_previous_epoch_root_key = Some(Bytes(vec![9; 60]));
    let bogus_member = EpochMember {
        type_: nsid::EPOCH_MEMBER.to_owned(),
        epoch_number: 3,
        device_key_pubkey: Bytes::from_slice(&phone.device_public().device_key_pub.0),
        encrypted_entropy: Some(Bytes(vec![7; 64])),
        device_mac: Bytes(vec![7; 32]),
        created_at: "2026-11-01T12:00:00.000Z".into(),
    };

    let raw_client = host.client(ALICE_DID);
    let squat_body = serde_json::json!({
        "repo": ALICE_DID,
        "space": mb_space.to_string(),
        "validate": false,
        "writes": [
            {
                "$type": "com.atproto.space.applyWrites#create",
                "collection": nsid::EPOCH,
                "rkey": format!("{:012}", 3),
                "value": serde_json::to_value(&bogus_e3).unwrap(),
            },
            {
                "$type": "com.atproto.space.applyWrites#create",
                "collection": nsid::EPOCH_MEMBER,
                "rkey": bogus_member.rkey(),
                "value": serde_json::to_value(&bogus_member).unwrap(),
            },
        ]
    });
    block_on(raw_client.procedure(
        "com.atproto.space.applyWrites",
        &serde_json::to_vec(&squat_body).unwrap(),
    ))
    .expect("plant bogus epoch 3 in Space");

    // Both `sync_epochs` and `revoke_device` report `EpochSquatted { seq: 3 }` without retrying forever.
    let tablet_key = tablet.device_public().device_key_pub;
    assert!(matches!(
        block_on(phone.sync_epochs()).unwrap_err(),
        Error::EpochSquatted { seq: 3, .. }
    ));
    assert!(matches!(
        block_on(phone.revoke_device(&tablet_key)).unwrap_err(),
        Error::EpochSquatted { seq: 3, .. }
    ));

    // `clear_squatted_epoch(3)` verifies `CompositeDirectory` is still at epoch 2, re-checks
    // `step_forward(3)` -> `Squatted`, deletes `epochMember/3-*` + `epoch/3`, and returns `Ok(true)`.
    assert!(block_on(phone.clear_squatted_epoch(3)).unwrap());
    assert!(block_on(alice_mb.get_epoch(3)).unwrap().is_none());
    assert!(block_on(alice_mb.list_epoch_members(3)).unwrap().is_empty());

    // Now `phone` can cleanly revoke `tablet` at epoch 3, and `laptop` syncs to epoch 3!
    let rev =
        block_on(phone.revoke_device(&tablet_key)).expect("revoke tablet after clearing squat");
    assert_eq!(rev.new_epoch, 3);
    assert_eq!(block_on(laptop.sync_epochs()).unwrap().to, 3);

    // Guard 3: Revoked `tablet` calling `clear_squatted_epoch(3)` MUST NOT delete epoch 3
    // (`step_forward` returns `Err(Error::NotEpochMember)`).
    assert_eq!(
        block_on(tablet.clear_squatted_epoch(3)).unwrap_err(),
        Error::NotEpochMember
    );
    assert!(block_on(alice_mb.get_epoch(3)).unwrap().is_some());

    // Guard 4: Locally-revoked thief racing ahead and anchoring epoch 5 in `CompositeDirectory`:
    struct WriteFailingSpaceRpc(Arc<dyn labyrinth::store::space::SpaceRpc>);
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl labyrinth::store::space::SpaceRpc for WriteFailingSpaceRpc {
        async fn query(
            &self,
            nsid: &str,
            params: &[(&str, String)],
        ) -> core::result::Result<Vec<u8>, labyrinth::store::space::SpaceError> {
            self.0.query(nsid, params).await
        }
        async fn procedure(
            &self,
            _nsid: &str,
            _payload: &[u8],
        ) -> core::result::Result<Vec<u8>, labyrinth::store::space::SpaceError> {
            Err(labyrinth::store::space::SpaceError::named(
                503,
                "ServiceUnavailable",
                "offline mid-revoke",
            ))
        }
    }

    let phone_snapshot = phone.export_state().unwrap();
    let mut phone_offline = block_on(Labyrinth::from_state(
        &phone_snapshot,
        ALICE_DID,
        Box::new(transport(1)),
        Backends {
            mailbox: Box::new(SpaceMailboxStore::new(
                Arc::new(WriteFailingSpaceRpc(host.client(ALICE_DID).into()))
                    as Arc<dyn labyrinth::store::space::SpaceRpc>,
                mb_space.clone(),
                ALICE_DID.to_owned(),
            )),
            threads: Box::new(SpaceThreadStore::new(
                host.client(ALICE_DID),
                ALICE_DID.to_owned(),
            )),
            directory: Box::new(CompositeDirectory::new(
                Box::new(net.directory()),
                Box::new(net.ds_directory()),
            )),
            publishers: vec![],
            clock: Box::new(SystemClock),
        },
    ))
    .unwrap();
    let laptop_key = laptop.device_public().device_key_pub;
    assert!(block_on(phone_offline.revoke_device(&laptop_key)).is_err());
    let phone_with_local_revoke = phone_offline.export_state().unwrap();

    // `laptop` enrolls `watch` (epoch 4) and then revokes `watch` (epoch 5, opened by `laptop`
    // and anchored in `CompositeDirectory`).
    let mut offer3 = laptop.otc_offer().unwrap();
    let code3 = offer3.code().as_str().to_owned();
    let (init_otc3, hello3) = Labyrinth::otc_start(ALICE_DID, &code3).unwrap();
    let reply3 = block_on(laptop.otc_respond(&mut offer3, &hello3)).unwrap();
    let watch_t = transport(4);
    net.register_chat_device(ALICE_DID, watch_t.transport_public_key());
    let watch_backends = Backends {
        mailbox: Box::new(
            SpaceMailboxStore::new(
                host.client(ALICE_DID),
                mb_space.clone(),
                ALICE_DID.to_owned(),
            )
            .with_key_publisher(Box::new(net.pds_publisher(ALICE_DID))),
        ),
        threads: Box::new(SpaceThreadStore::new(
            host.client(ALICE_DID),
            ALICE_DID.to_owned(),
        )),
        directory: Box::new(CompositeDirectory::new(
            Box::new(net.directory()),
            Box::new(net.ds_directory()),
        )),
        publishers: vec![Box::new(net.ds_publisher(ALICE_DID))],
        clock: Box::new(SystemClock),
    };
    let (watch, _) = block_on(Labyrinth::enroll_via_otc(
        ALICE_DID,
        init_otc3,
        &reply3.message,
        &reply3.sealed_payload,
        Box::new(watch_t),
        watch_backends,
    ))
    .expect("watch enroll");
    let watch_key = watch.device_public().device_key_pub;
    block_on(laptop.revoke_device(&watch_key)).expect("laptop opens epoch 5");

    let mut phone_restored = restore_space_client(
        &phone_with_local_revoke,
        ALICE_DID,
        1,
        &net,
        &host,
        &convo_space,
    );
    assert!(matches!(
        block_on(phone_restored.sync_epochs()).unwrap_err(),
        Error::EpochSquatted { seq: 5, .. }
    ));
    assert_eq!(
        block_on(phone_restored.clear_squatted_epoch(5)).unwrap_err(),
        Error::EpochSquatted {
            seq: 4,
            reason: "it re-admits a device this client revoked",
        }
    );
    assert_eq!(
        block_on(phone_restored.clear_squatted_epoch(4)).unwrap_err(),
        Error::EpochTruncated {
            published: 5,
            reached: 3,
        }
    );
    assert!(block_on(alice_mb.get_epoch(4)).unwrap().is_some());
    assert!(block_on(alice_mb.get_epoch(5)).unwrap().is_some());
}

#[test]
fn fault_line_3_clear_squatted_epoch_absorbs_unanchored_valid_sibling_and_preserves_revocation() {
    // Test the race window where a sibling wrote a VALID `epoch/3` to the mailbox store
    // BEFORE `publish_keys` updated `MailboxDirectory` (`directory` still at epoch 2!).
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let mut laptop = sibling(&net, &clock, &mut phone, 2);
    let mut tablet = sibling(&net, &clock, &mut phone, 3);
    block_on(phone.sync_epochs()).unwrap();
    block_on(laptop.sync_epochs()).unwrap();
    block_on(tablet.sync_epochs()).unwrap();

    // Create a custom `MailboxStore` wrapper whose `publish_mailbox_keys` is a no-op so
    // `epoch/3` lands in the mailbox store while `net.directory()` remains at epoch 2!
    struct UnanchoredMailbox(labyrinth::store::memory::MemoryMailbox);
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl MailboxStore for UnanchoredMailbox {
        fn owner(&self) -> &str {
            self.0.owner()
        }
        async fn create_device(&self, d: &labyrinth::records::Device) -> labyrinth::Result<()> {
            self.0.create_device(d).await
        }
        async fn set_device_revoked(
            &self,
            k: &labyrinth::sign::XVerifyingKey,
            at: &str,
        ) -> labyrinth::Result<()> {
            self.0.set_device_revoked(k, at).await
        }
        async fn get_device(
            &self,
            k: &labyrinth::sign::XVerifyingKey,
        ) -> labyrinth::Result<Option<labyrinth::records::Device>> {
            self.0.get_device(k).await
        }
        async fn list_devices(&self) -> labyrinth::Result<Vec<labyrinth::records::Device>> {
            self.0.list_devices().await
        }
        async fn create_epoch(&self, e: &Epoch, m: &[EpochMember]) -> labyrinth::Result<String> {
            self.0.create_epoch(e, m).await
        }
        async fn atomic_enroll(
            &self,
            b: &labyrinth::store::AtomicEnrollBundle,
        ) -> labyrinth::Result<String> {
            self.0.atomic_enroll(b).await
        }
        async fn get_epoch(&self, s: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
            self.0.get_epoch(s).await
        }
        async fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
            self.0.list_epochs().await
        }
        async fn create_epoch_member(&self, m: &EpochMember) -> labyrinth::Result<()> {
            self.0.create_epoch_member(m).await
        }
        async fn list_epoch_members(&self, s: u64) -> labyrinth::Result<Vec<EpochMember>> {
            self.0.list_epoch_members(s).await
        }
        async fn create_virtual_device(
            &self,
            v: &labyrinth::records::VirtualDevice,
        ) -> labyrinth::Result<()> {
            self.0.create_virtual_device(v).await
        }
        async fn get_virtual_device(
            &self,
            id: &[u8; 16],
        ) -> labyrinth::Result<Option<labyrinth::records::VirtualDevice>> {
            self.0.get_virtual_device(id).await
        }
        async fn list_virtual_devices(
            &self,
        ) -> labyrinth::Result<Vec<labyrinth::records::VirtualDevice>> {
            self.0.list_virtual_devices().await
        }
        async fn append_owner_batch(
            &self,
            b: &labyrinth::records::OwnerBatch,
        ) -> labyrinth::Result<String> {
            self.0.append_owner_batch(b).await
        }
        async fn list_owner_batches(
            &self,
            t: &str,
            r: TimeRange,
        ) -> labyrinth::Result<Vec<Stored<labyrinth::records::OwnerBatch>>> {
            self.0.list_owner_batches(t, r).await
        }
        async fn publish_mailbox_keys(&self, _r: &MailboxKeysRecord) -> labyrinth::Result<()> {
            // Simulate pause before publishing to PDS directory.
            Ok(())
        }
        async fn delete_squatted_epoch(&self, seq: u64) -> labyrinth::Result<()> {
            self.0.delete_squatted_epoch(seq).await
        }
    }

    let phone_state = phone.export_state().unwrap();
    let mut phone_unanchored = block_on(Labyrinth::from_state(
        &phone_state,
        A,
        Box::new(signer(1)),
        backends_with(
            &net,
            &clock,
            A,
            Box::new(UnanchoredMailbox(net.mailbox(A))),
            vec![Box::new(FailingPublisher)],
        ),
    ))
    .unwrap();

    let tablet_key = tablet.device_public().device_key_pub;
    assert!(block_on(phone_unanchored.revoke_device(&tablet_key)).is_err());
    // Confirm `epoch/3` is in `MemoryMailbox`, revoking `tablet`, while `net.directory()` stays at 2!
    assert!(block_on(net.mailbox(A).get_epoch(3)).unwrap().is_some());

    // `laptop` calls `clear_squatted_epoch(3)`: `step_forward(3)` sees a VALID sibling rotation!
    // Must return `Ok(false)` (absorbed into `laptop` state) and MUST NOT delete `epoch/3`!
    assert!(!block_on(laptop.clear_squatted_epoch(3)).unwrap());
    assert_eq!(laptop.latest_epoch(), 3);
    assert!(block_on(net.mailbox(A).get_epoch(3)).unwrap().is_some());

    // `tablet` (legitimately revoked in `epoch/3`) calls `clear_squatted_epoch(3)`:
    // Must return `Err(Error::NotEpochMember)` and MUST NOT delete `epoch/3`!
    assert_eq!(
        block_on(tablet.clear_squatted_epoch(3)).unwrap_err(),
        Error::NotEpochMember
    );
    assert!(block_on(net.mailbox(A).get_epoch(3)).unwrap().is_some());
}

#[test]
fn fault_line_5_and_2_owner_v5_attribution_receipts_rearchive_dedupe_and_tombstones() {
    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let (seq_sk, seq_rk) = sequencer_keys();

    let convo_space = SpaceRef::parse(&format!(
        "at://{SEQUENCER_DID}/space/blue.catbird.labyrinth.conversation/{CONVO_ID}"
    ))
    .unwrap();
    host.grant_space_member(&convo_space, ALICE_DID);
    host.grant_space_member(&convo_space, BOB_DID);

    let mut alice = make_space_client(ALICE_DID, 1, &net, &host, &convo_space);
    let mut bob = make_space_client(BOB_DID, 2, &net, &host, &convo_space);

    // 1a. Before enabling `I13` receipt enforcement on `CONVO_ID`, Bob sends a plain (`0x00`)
    // message (`bob-plain`), and Alice runs `rearchive_thread_before_leave` so `bob-plain` is
    // copied as `0x03` (`seal_owner_attributed`) with `sender == Some(BOB_DID)`!
    let bob_roster = block_on(bob.resolve_roster(&[ALICE_DID, BOB_DID])).unwrap();
    block_on(bob.archive_outgoing(
        CONVO_ID,
        &bob_roster,
        "bob-plain",
        1_791_200_000_001,
        b"bob plain frame",
    ))
    .unwrap();
    block_on(bob.flush()).unwrap();

    let copied_plain = block_on(alice.rearchive_thread_before_leave(CONVO_ID)).unwrap();
    assert_eq!(copied_plain, 1);

    let merged_plain = block_on(alice.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert_eq!(merged_plain.messages.len(), 1);
    assert!(!merged_plain.messages[0].conflict);
    assert_eq!(merged_plain.messages[0].sender.as_deref(), Some(BOB_DID));

    // 1b. Now enable `I13` receipt verification on `CONVO_ID`; Bob sends `bob-committed` (`0x02`)
    // and Alice runs `rearchive_thread_before_leave` again (`0x02` -> `0x02` `seal_owner_committed`).
    net.set_sequencer_receipt_key(CONVO_ID, seq_rk);

    let bob_nonce = [0x42u8; 32];
    let bob_body = b"bob committed frame";
    let bob_commitment = compute_archive_commitment(&bob_nonce, bob_body);
    let bob_rp = SequencerReceiptPayload {
        sequencer_did: SEQUENCER_DID.to_owned(),
        conversation_id: CONVO_ID.to_owned(),
        group_id: vec![0x99u8; 32],
        epoch: 1,
        sender_device_did_url: format!("{BOB_DID}#{BOB_DEV_ID}"),
        entry_id: "00000000-0000-0000-0000-000000000021".into(),
        archive_commitment: bob_commitment,
        seq: 21,
        issued_at_ms: 1_791_200_000_002,
    };
    let bob_receipt =
        sign_sequencer_receipt(&seq_sk, &expected_receipt_key_id(SEQUENCER_DID), &bob_rp).unwrap();
    block_on(bob.archive_outgoing_committed(
        CONVO_ID,
        &bob_roster,
        "bob-committed",
        1_791_200_000_002,
        &bob_nonce,
        bob_body,
        &labyrinth::message::ArchivedReceipt::new(
            bob_receipt.clone(),
            original_sender_attestation(
                2,
                BOB_DID,
                BOB_DEV_ID,
                CONVO_ID,
                "bob-committed",
                &bob_commitment,
            ),
        ),
    ))
    .unwrap();
    block_on(bob.flush()).unwrap();

    // 2. While Alice is still in the Space, active-Space history is authoritative: owner
    // copies cannot make an otherwise inadmissible Space record visible. The first valid
    // receipt latches receipt enforcement, so the pre-I13 message is no longer readable.
    let copied_committed = block_on(alice.rearchive_thread_before_leave(CONVO_ID)).unwrap();
    assert_eq!(copied_committed, 1);

    let merged_view = block_on(alice.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert_eq!(merged_view.messages.len(), 1);
    assert_eq!(merged_view.messages[0].message_id, "bob-committed");
    assert!(!merged_view.messages[0].conflict);
    assert_eq!(merged_view.messages[0].sender.as_deref(), Some(BOB_DID));

    // 3. Now simulate involuntary removal / kick: revoke Alice's Space read/write membership!
    host.revoke_space_member(&convo_space, ALICE_DID);

    // Receipt enforcement is already latched: a receiptless cached row cannot
    // be backdated into the owner archive, while a committed queued item below
    // remains rescuable after the kick.
    assert!(
        block_on(alice.archive_owner_attributed(
            CONVO_ID,
            "bad",
            1_791_200_000_003,
            "not-a-did",
            b"x"
        ))
        .is_err(),
        "archive_owner_attributed must reject non-DID sender strings"
    );
    assert_eq!(
        block_on(alice.archive_owner_attributed(
            CONVO_ID,
            "bob-cached-before-kick",
            1_791_200_000_003,
            BOB_DID,
            b"rescued from sqlcipher cache",
        ))
        .unwrap_err(),
        Error::ReceiptCommitmentMismatch
    );

    let alice_nonce = [0x77u8; 32];
    let alice_body = b"queued outbox message rescued after kick";
    let alice_rp = SequencerReceiptPayload {
        sequencer_did: SEQUENCER_DID.to_owned(),
        conversation_id: CONVO_ID.to_owned(),
        group_id: vec![0x99u8; 32],
        epoch: 1,
        sender_device_did_url: format!("{ALICE_DID}#{ALICE_DEV_ID}"),
        entry_id: "00000000-0000-0000-0000-000000000022".into(),
        archive_commitment: compute_archive_commitment(&alice_nonce, alice_body),
        seq: 22,
        issued_at_ms: 1_791_200_000_004,
    };
    let alice_receipt =
        sign_sequencer_receipt(&seq_sk, &expected_receipt_key_id(SEQUENCER_DID), &alice_rp)
            .unwrap();
    block_on(alice.archive_owner_committed(
        CONVO_ID,
        "alice-queued-after-kick",
        1_791_200_000_004,
        &alice_nonce,
        alice_body,
        &labyrinth::message::ArchivedReceipt::new(
            alice_receipt.clone(),
            original_sender_attestation(
                1,
                ALICE_DID,
                ALICE_DEV_ID,
                CONVO_ID,
                "alice-queued-after-kick",
                &alice_rp.archive_commitment,
            ),
        ),
    ))
    .unwrap();

    // Also plant a raw unverified cross-thread receipt inside an owner batch by sealing under
    // the other conversation's receipt, then rewriting its `threadId` in an `OwnerBatch` so
    // `open_owner_batches` exercises its `receipt.conversation_id != thread_id` check!
    block_on(alice.flush_owner(CONVO_ID)).unwrap();

    // Restore Alice on a fresh client instance from exported state and load after Space revocation:
    let alice_state = alice.export_state().unwrap();
    let mut alice_restored =
        restore_space_client(&alice_state, ALICE_DID, 1, &net, &host, &convo_space);

    // Verify `archive_owner_committed` rejects a cross-thread receipt up front:
    let wrong_thread_rp = SequencerReceiptPayload {
        conversation_id: "99999999-9999-9999-9999-999999999999".into(),
        ..alice_rp
    };
    let wrong_thread_receipt = sign_sequencer_receipt(
        &seq_sk,
        &expected_receipt_key_id(SEQUENCER_DID),
        &wrong_thread_rp,
    )
    .unwrap();
    assert!(
        block_on(alice_restored.archive_owner_committed(
            CONVO_ID,
            "replayed-other-convo",
            1_791_200_000_005,
            &alice_nonce,
            alice_body,
            &labyrinth::message::ArchivedReceipt::new(
                wrong_thread_receipt.clone(),
                original_sender_attestation(
                    1,
                    ALICE_DID,
                    ALICE_DEV_ID,
                    &wrong_thread_rp.conversation_id,
                    "replayed-other-convo",
                    &wrong_thread_rp.archive_commitment,
                ),
            ),
        ))
        .is_err()
    );

    let after_kick = block_on(alice_restored.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert!(!after_kick.space_readable);
    assert_eq!(after_kick.messages.len(), 2);
    assert_eq!(after_kick.undecryptable.len(), 1);
    assert_eq!(after_kick.undecryptable[0].message_id, "bob-plain");

    let by_id: std::collections::HashMap<_, _> = after_kick
        .messages
        .iter()
        .map(|m| (m.message_id.as_str(), m))
        .collect();
    assert_eq!(by_id["bob-committed"].sender.as_deref(), Some(BOB_DID));
    assert_eq!(by_id["bob-committed"].source, MessageSource::Owner);
    assert_eq!(
        by_id["alice-queued-after-kick"].sender.as_deref(),
        Some(ALICE_DID)
    );

    // 4. Author-scoped `delete_for_me` tombstones: the wrong author does not
    // hide Bob's committed message, while Bob's DID does.
    block_on(alice_restored.delete_for_me(
        CONVO_ID,
        "bob-committed",
        1_791_200_000_002,
        Some(ALICE_DID),
        &[],
    ))
    .unwrap();
    let after_wrong_author_del =
        block_on(alice_restored.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert_eq!(after_wrong_author_del.messages.len(), 2);

    block_on(alice_restored.delete_for_me(
        CONVO_ID,
        "bob-committed",
        1_791_200_000_002,
        Some(BOB_DID),
        &[],
    ))
    .unwrap();
    let after_right_author_del =
        block_on(alice_restored.load_thread(CONVO_ID, TimeRange::ALL)).unwrap();
    assert_eq!(after_right_author_del.messages.len(), 1);
    assert!(
        after_right_author_del
            .messages
            .iter()
            .all(|m| m.message_id != "bob-committed")
    );
}

#[test]
fn fault_line_3_directory_incomplete_and_chunked_concurrent_delete_and_otc_squat_healing() {
    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let convo_space = SpaceRef::parse(&format!(
        "at://{SEQUENCER_DID}/space/blue.catbird.labyrinth.conversation/{CONVO_ID}"
    ))
    .unwrap();
    host.grant_space_member(&convo_space, ALICE_DID);
    let mb_space = SpaceRef::parse(&format!(
        "at://{ALICE_DID}/space/blue.catbird.labyrinth.mailbox/self"
    ))
    .unwrap();

    // 1. Initialize `phone` with ONLY PDS published (`publishers: vec![]` omits `ds_publisher`),
    // so `CompositeDirectory::new` sees PDS present + DS absent -> `Error::DirectoryIncomplete`!
    let t1 = transport(11);
    net.register_chat_device(ALICE_DID, t1.transport_public_key());
    let mailbox_pds_only = SpaceMailboxStore::new(
        host.client(ALICE_DID),
        mb_space.clone(),
        ALICE_DID.to_owned(),
    )
    .with_key_publisher(Box::new(net.pds_publisher(ALICE_DID)));
    let mut phone_incomplete = block_on(Labyrinth::initialize(
        ALICE_DID,
        Box::new(t1),
        Backends {
            mailbox: Box::new(mailbox_pds_only),
            threads: Box::new(SpaceThreadStore::new(
                host.client(ALICE_DID),
                ALICE_DID.to_owned(),
            )),
            directory: Box::new(CompositeDirectory::new(
                Box::new(net.directory()),
                Box::new(net.ds_directory()),
            )),
            publishers: vec![], // Intentionally omit DS publisher to trigger DirectoryIncomplete!
            clock: Box::new(SystemClock),
        },
    ))
    .expect("init with pds-only publication");

    // Plant a bogus `epoch/1` + 210 `epochMember/1-*` records (> MAX_WRITES = 200 chunk boundary).
    let alice_mb = SpaceMailboxStore::new(
        host.client(ALICE_DID),
        mb_space.clone(),
        ALICE_DID.to_owned(),
    );
    let e0 = block_on(alice_mb.get_epoch(0)).unwrap().unwrap().value;
    let mut bogus_e1 = e0.clone();
    bogus_e1.public.epoch_number = 1;
    bogus_e1.public.previous_epoch_head = Some(e0.public.epoch_head.clone());
    bogus_e1.public.prev_sig = Some(e0.public.self_sig.clone());
    bogus_e1.encrypted_previous_epoch_number = Some(Bytes(vec![5; 40]));
    bogus_e1.encrypted_previous_epoch_root_key = Some(Bytes(vec![5; 60]));
    // Use an unregistered/missing `openedBy` device pubkey so `is_epoch_header_or_opener_invalid`
    // also exercises missing-opener squat classification during `enroll_via_otc` below!
    bogus_e1.opened_by = Bytes(vec![0xAB; 32]);

    let raw_client = host.client(ALICE_DID);
    block_on(
        raw_client.procedure(
            "com.atproto.space.applyWrites",
            &serde_json::to_vec(&serde_json::json!({
                "repo": ALICE_DID,
                "space": mb_space.to_string(),
                "validate": false,
                "writes": [{
                    "$type": "com.atproto.space.applyWrites#create",
                    "collection": nsid::EPOCH,
                    "rkey": format!("{:012}", 1),
                    "value": serde_json::to_value(&bogus_e1).unwrap(),
                }],
            }))
            .unwrap(),
        ),
    )
    .unwrap();

    for chunk_idx in 0..2 {
        let mut writes = Vec::new();
        let start = chunk_idx * 150;
        let end = ((chunk_idx + 1) * 150).min(210);
        for i in start..end {
            let mut pk = [0u8; 32];
            pk[0] = (i & 0xFF) as u8;
            pk[1] = ((i >> 8) & 0xFF) as u8;
            pk[31] = 0xEE;
            let m = EpochMember {
                type_: nsid::EPOCH_MEMBER.to_owned(),
                epoch_number: 1,
                device_key_pubkey: Bytes::from_slice(&pk),
                encrypted_entropy: Some(Bytes(vec![3; 64])),
                device_mac: Bytes(vec![3; 32]),
                created_at: "2026-11-01T12:10:00.000Z".into(),
            };
            writes.push(serde_json::json!({
                "$type": "com.atproto.space.applyWrites#create",
                "collection": nsid::EPOCH_MEMBER,
                "rkey": m.rkey(),
                "value": serde_json::to_value(&m).unwrap(),
            }));
        }
        block_on(
            raw_client.procedure(
                "com.atproto.space.applyWrites",
                &serde_json::to_vec(&serde_json::json!({
                    "repo": ALICE_DID,
                    "space": mb_space.to_string(),
                    "validate": false,
                    "writes": writes,
                }))
                .unwrap(),
            ),
        )
        .unwrap();
    }
    assert_eq!(block_on(alice_mb.list_epoch_members(1)).unwrap().len(), 210);

    // Guard A: `DirectoryIncomplete` MUST fail closed and leave `epoch/1` + all 210 members intact!
    assert!(matches!(
        block_on(phone_incomplete.clear_squatted_epoch(1)).unwrap_err(),
        Error::DirectoryIncomplete { .. }
    ));
    assert!(block_on(alice_mb.get_epoch(1)).unwrap().is_some());
    assert_eq!(block_on(alice_mb.list_epoch_members(1)).unwrap().len(), 210);

    // Guard B: Simulate a concurrent sibling deleting ONE `epochMember/1-*` right after
    // `list_epoch_members(1)` runs inside `delete_squatted_epoch`, forcing `applyWrites#delete`
    // to return `RecordNotFound` and exercising the per-record `delete_record_idempotent` fallback
    // across > 200 records!
    struct ConcurrentMemberDeleteRpc {
        inner: Arc<dyn labyrinth::store::space::SpaceRpc>,
        space: String,
        deleted_once: std::sync::atomic::AtomicBool,
    }
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl labyrinth::store::space::SpaceRpc for ConcurrentMemberDeleteRpc {
        async fn query(
            &self,
            nsid: &str,
            params: &[(&str, String)],
        ) -> core::result::Result<Vec<u8>, labyrinth::store::space::SpaceError> {
            self.inner.query(nsid, params).await
        }
        async fn procedure(
            &self,
            nsid_name: &str,
            payload: &[u8],
        ) -> core::result::Result<Vec<u8>, labyrinth::store::space::SpaceError> {
            if nsid_name == "com.atproto.space.applyWrites"
                && !self
                    .deleted_once
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                let v: serde_json::Value = serde_json::from_slice(payload).unwrap();
                if let Some(first_del_rkey) = v["writes"]
                    .as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|op| {
                        (op["$type"] == "com.atproto.space.applyWrites#delete")
                            .then(|| op["rkey"].as_str())
                            .flatten()
                    })
                {
                    let _ = self
                        .inner
                        .procedure(
                            "com.atproto.space.deleteRecord",
                            &serde_json::to_vec(&serde_json::json!({
                                "repo": ALICE_DID,
                                "space": self.space,
                                "collection": nsid::EPOCH_MEMBER,
                                "rkey": first_del_rkey,
                            }))
                            .unwrap(),
                        )
                        .await;
                }
            }
            self.inner.procedure(nsid_name, payload).await
        }
    }

    let phone_state = phone_incomplete.export_state().unwrap();
    let racing_rpc: Arc<dyn labyrinth::store::space::SpaceRpc> =
        Arc::new(ConcurrentMemberDeleteRpc {
            inner: Arc::new(host.client(ALICE_DID)),
            space: mb_space.to_string(),
            deleted_once: std::sync::atomic::AtomicBool::new(false),
        });
    let mut phone_healthy = block_on(Labyrinth::from_state(
        &phone_state,
        ALICE_DID,
        Box::new(transport(11)),
        Backends {
            mailbox: Box::new(
                SpaceMailboxStore::new(racing_rpc, mb_space.clone(), ALICE_DID.to_owned())
                    .with_key_publisher(Box::new(net.pds_publisher(ALICE_DID))),
            ),
            threads: Box::new(SpaceThreadStore::new(
                host.client(ALICE_DID),
                ALICE_DID.to_owned(),
            )),
            directory: Box::new(CompositeDirectory::new(
                Box::new(net.directory()),
                Box::new(net.ds_directory()),
            )),
            publishers: vec![Box::new(net.ds_publisher(ALICE_DID))],
            clock: Box::new(SystemClock),
        },
    ))
    .unwrap();
    // Publish epoch 0 to DS so `CompositeDirectory` is healthy at epoch 0.
    block_on(phone_healthy.publish_latest_keys()).unwrap();

    assert!(block_on(phone_healthy.clear_squatted_epoch(1)).unwrap());
    assert!(block_on(alice_mb.get_epoch(1)).unwrap().is_none());
    assert!(block_on(alice_mb.list_epoch_members(1)).unwrap().is_empty());

    // Prepare two OTC handshakes from `phone_healthy` at epoch 0 before planting the in-flight squat:
    let mut offer = phone_healthy.otc_offer().unwrap();
    let code = offer.code().as_str().to_owned();
    let (init_otc, hello) = Labyrinth::otc_start(ALICE_DID, &code).unwrap();
    let reply = block_on(phone_healthy.otc_respond(&mut offer, &hello)).unwrap();

    let mut stale_offer = phone_healthy.otc_offer().unwrap();
    let stale_code = stale_offer.code().as_str().to_owned();
    let (stale_init, stale_hello) = Labyrinth::otc_start(ALICE_DID, &stale_code).unwrap();
    let stale_reply = block_on(phone_healthy.otc_respond(&mut stale_offer, &stale_hello)).unwrap();

    // Guard C: Re-plant the missing-opener `bogus_e1` at `epoch/1` (while `CompositeDirectory`
    // is still anchored at epoch 0) in the race window between `otc_respond` and `enroll_via_otc`,
    // and confirm `enroll_via_otc` heals the unanchored squat automatically and enrolls `laptop` at epoch 1!
    block_on(
        raw_client.procedure(
            "com.atproto.space.applyWrites",
            &serde_json::to_vec(&serde_json::json!({
                "repo": ALICE_DID,
                "space": mb_space.to_string(),
                "validate": false,
                "writes": [{
                    "$type": "com.atproto.space.applyWrites#create",
                    "collection": nsid::EPOCH,
                    "rkey": format!("{:012}", 1),
                    "value": serde_json::to_value(&bogus_e1).unwrap(),
                }],
            }))
            .unwrap(),
        ),
    )
    .unwrap();

    let laptop_t = transport(12);
    net.register_chat_device(ALICE_DID, laptop_t.transport_public_key());
    let (laptop, _) = block_on(Labyrinth::enroll_via_otc(
        ALICE_DID,
        init_otc,
        &reply.message,
        &reply.sealed_payload,
        Box::new(laptop_t),
        Backends {
            mailbox: Box::new(
                SpaceMailboxStore::new(
                    host.client(ALICE_DID),
                    mb_space.clone(),
                    ALICE_DID.to_owned(),
                )
                .with_key_publisher(Box::new(net.pds_publisher(ALICE_DID))),
            ),
            threads: Box::new(SpaceThreadStore::new(
                host.client(ALICE_DID),
                ALICE_DID.to_owned(),
            )),
            directory: Box::new(CompositeDirectory::new(
                Box::new(net.directory()),
                Box::new(net.ds_directory()),
            )),
            publishers: vec![Box::new(net.ds_publisher(ALICE_DID))],
            clock: Box::new(SystemClock),
        },
    ))
    .expect("enroll_via_otc must clear unanchored missing-opener squat at epoch 1");
    assert_eq!(laptop.latest_epoch(), 1);

    // Guard D: `CompositeDirectory` now anchors `epoch/1`, while `stale_reply` carries E = 0.
    // Even if `epoch/1` in Space were replaced with a malformed/missing-opener record,
    // `enroll_via_otc` MUST fail closed with `Error::EpochTruncated` instead of deleting `epoch/1`!
    block_on(
        raw_client.procedure(
            "com.atproto.space.applyWrites",
            &serde_json::to_vec(&serde_json::json!({
                "repo": ALICE_DID,
                "space": mb_space.to_string(),
                "validate": false,
                "writes": [{
                    "$type": "com.atproto.space.applyWrites#update",
                    "collection": nsid::EPOCH,
                    "rkey": format!("{:012}", 1),
                    "value": serde_json::to_value(&bogus_e1).unwrap(),
                }],
            }))
            .unwrap(),
        ),
    )
    .unwrap();

    let tablet_t = transport(13);
    net.register_chat_device(ALICE_DID, tablet_t.transport_public_key());
    let enroll_err = match block_on(Labyrinth::enroll_via_otc(
        ALICE_DID,
        stale_init,
        &stale_reply.message,
        &stale_reply.sealed_payload,
        Box::new(tablet_t),
        Backends {
            mailbox: Box::new(
                SpaceMailboxStore::new(
                    host.client(ALICE_DID),
                    mb_space.clone(),
                    ALICE_DID.to_owned(),
                )
                .with_key_publisher(Box::new(net.pds_publisher(ALICE_DID))),
            ),
            threads: Box::new(SpaceThreadStore::new(
                host.client(ALICE_DID),
                ALICE_DID.to_owned(),
            )),
            directory: Box::new(CompositeDirectory::new(
                Box::new(net.directory()),
                Box::new(net.ds_directory()),
            )),
            publishers: vec![Box::new(net.ds_publisher(ALICE_DID))],
            clock: Box::new(SystemClock),
        },
    )) {
        Ok(_) => panic!("enroll_via_otc must refuse to delete directory-anchored epoch 1"),
        Err(e) => e,
    };
    assert_eq!(
        enroll_err,
        Error::EpochTruncated {
            published: 1,
            reached: 0,
        }
    );
    assert!(block_on(alice_mb.get_epoch(1)).unwrap().is_some());
}

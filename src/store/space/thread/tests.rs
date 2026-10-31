//! Protocol boundary tests. The sequencer and owner PDS are local models;
//! these do not qualify live credentials, MAC negotiation or MLS admission.
use super::*;
use crate::message::SealedMessage;
use crate::records::datetime_from_ms;
use crate::store::space::host::MemorySpaceHost;
use crate::store::xrpc::XrpcError;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const DID: &str = "did:plc:alice";
const GENERATION: &str = "11111111-1111-4111-8111-111111111111";

struct PageScript {
    replies: Mutex<VecDeque<core::result::Result<Vec<u8>, XrpcError>>>,
}

impl PageScript {
    fn json(replies: impl IntoIterator<Item = Value>) -> Self {
        Self {
            replies: Mutex::new(
                replies
                    .into_iter()
                    .map(|value| Ok(serde_json::to_vec(&value).unwrap()))
                    .collect(),
            ),
        }
    }

    fn raw(replies: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().map(Ok).collect()),
        }
    }
}

impl XrpcTransport for PageScript {
    fn query_with_headers(
        &self,
        _: &str,
        _: &[(&str, String)],
        _: &[(String, String)],
    ) -> core::result::Result<Vec<u8>, XrpcError> {
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(XrpcError::named(599, "ScriptExhausted", "no scripted page")))
    }

    fn procedure(
        &self,
        _: &str,
        _: &[u8],
        _: [u8; 16],
    ) -> core::result::Result<Vec<u8>, XrpcError> {
        Ok(b"{}".to_vec())
    }
}

#[test]
fn owned_space_inventory_rejects_page_and_cursor_width_overflow() {
    let spaces = (0..101)
        .map(|i| {
            json!({"uri": format!(
                "at://did:plc:authority/space/blue.catbird.labyrinth.conversation/11111111-1111-4111-8111-{i:012x}"
            )})
        })
        .collect::<Vec<_>>();
    assert_eq!(
        SequencedSpaceThreadStore::owned_spaces(&PageScript::json([json!({"spaces": spaces})]))
            .unwrap_err(),
        Error::Backend("conversation Space inventory page exceeds 100 items".into())
    );

    assert_eq!(
        SequencedSpaceThreadStore::owned_spaces(&PageScript::json([json!({
            "spaces": [],
            "cursor": "x".repeat(1025),
        })]))
        .unwrap_err(),
        Error::Backend("conversation Space inventory cursor exceeds 1024 bytes".into())
    );
}

#[test]
fn owned_space_inventory_rejects_oversized_response_before_decoding() {
    assert_eq!(
        SequencedSpaceThreadStore::owned_spaces(&PageScript::raw([vec![
            b' ';
            16 * 1024 * 1024 + 1
        ]]))
        .unwrap_err(),
        Error::Backend("space response exceeds 16777216 bytes".into())
    );
}

#[test]
fn owned_space_inventory_rejects_more_than_ten_thousand_items() {
    let replies = (0..101).map(|page| {
        let spaces = (0..100)
            .map(|item| {
                let generation = page * 100 + item;
                json!({"uri": format!(
                    "at://did:plc:authority/space/blue.catbird.labyrinth.conversation/11111111-1111-4111-8111-{generation:012x}"
                )})
            })
            .collect::<Vec<_>>();
        json!({
            "spaces": spaces,
            "cursor": (page < 100).then(|| format!("c{page}")),
        })
    });
    assert_eq!(
        SequencedSpaceThreadStore::owned_spaces(&PageScript::json(replies)).unwrap_err(),
        Error::Backend("conversation Space inventory exceeds 10000 items".into())
    );
}

struct StuckDeletion {
    queries: AtomicUsize,
}

impl XrpcTransport for StuckDeletion {
    fn query_with_headers(
        &self,
        _: &str,
        _: &[(&str, String)],
        _: &[(String, String)],
    ) -> core::result::Result<Vec<u8>, XrpcError> {
        if self.queries.fetch_add(1, Ordering::SeqCst) >= 2 {
            return Err(XrpcError::named(
                599,
                "TooManyReads",
                "delete made no progress",
            ));
        }
        Ok(serde_json::to_vec(&json!({
            "records": [{"rkey": "same-record"}],
        }))
        .unwrap())
    }

    fn procedure(
        &self,
        _: &str,
        _: &[u8],
        _: [u8; 16],
    ) -> core::result::Result<Vec<u8>, XrpcError> {
        Ok(b"{}".to_vec())
    }
}

#[test]
fn conversation_deletion_rejects_a_successful_delete_that_makes_no_progress() {
    let transport = StuckDeletion {
        queries: AtomicUsize::new(0),
    };
    assert_eq!(
        SequencedSpaceThreadStore::purge_owned_records(
            DID,
            &transport,
            &format!(
                "at://did:plc:authority/space/blue.catbird.labyrinth.conversation/{GENERATION}"
            ),
        )
        .unwrap_err(),
        Error::Backend("conversation deletion made no progress".into())
    );
    assert_eq!(transport.queries.load(Ordering::SeqCst), 2);
}

#[test]
fn sender_filtered_listing_rejects_another_authors_view() {
    let (store, ds, _) = setup();
    store.append_batch(&batch()).unwrap();
    assert_eq!(ds.views.lock().unwrap()[0].author, DID);
    assert_eq!(
        store
            .list_batches("thread", Some("did:plc:bob"), TimeRange::ALL)
            .unwrap_err(),
        Error::Malformed("sequencer returned another sender")
    );
}

#[test]
fn batch_cid_matches_independent_canonical_cbor_vector() {
    // Expected value was independently encoded with Python's standard
    // library: length-first UTF-8 map order, native bytes, CIDv1/0x71/0x12.
    // It is a cross-implementation fixture, not a published external KAT.
    let record = Batch::from_messages(
        "00000000-0000-4000-8000-000000000001",
        &[SealedMessage {
            message_id: "msg".into(),
            timestamp: 1,
            mek_id: [6; 12],
            sender_transport_pub: [7; 32],
            signed_enc_message: vec![0x61; 96],
        }],
        "2026-10-04T12:00:00.000Z".into(),
    )
    .unwrap();
    assert_eq!(
        batch_cid(&record).unwrap(),
        "bafyreicrkc72femutpagfsp4yh2ji6otqpgba4fkdxut5srps4honsgyu4"
    );
}
fn placement() -> ThreadPlacement {
    ThreadPlacement {
        placement: "space".into(),
        generation: GENERATION.into(),
        space: Some(format!(
            "at://did:plc:authority/space/blue.catbird.labyrinth.conversation/{GENERATION}"
        )),
    }
}
fn batch() -> Batch {
    Batch::from_messages(
        "thread",
        &[SealedMessage {
            message_id: "message".into(),
            timestamp: 9,
            mek_id: [1; 12],
            sender_transport_pub: [2; 32],
            signed_enc_message: vec![3; 100],
        }],
        datetime_from_ms(1_791_000_000_000),
    )
    .unwrap()
}

#[derive(Default)]
struct Pins(Mutex<Option<ThreadPlacement>>);
impl ThreadPlacementPins for Pins {
    fn check_or_pin(&self, _: &str, p: &ThreadPlacement) -> Result<()> {
        let mut saved = self.0.lock().unwrap();
        match &*saved {
            Some(old) if old != p => Err(Error::Conflict),
            _ => {
                *saved = Some(p.clone());
                Ok(())
            }
        }
    }
}
struct Sequencer {
    placement: Mutex<ThreadPlacement>,
    views: Mutex<Vec<SpaceBatchView>>,
    lose_ack: AtomicUsize,
}
impl Default for Sequencer {
    fn default() -> Self {
        Self {
            placement: Mutex::new(placement()),
            views: Mutex::default(),
            lose_ack: AtomicUsize::new(0),
        }
    }
}
impl XrpcTransport for Sequencer {
    fn query_with_headers(
        &self,
        nsid: &str,
        _: &[(&str, String)],
        _: &[(String, String)],
    ) -> core::result::Result<Vec<u8>, XrpcError> {
        let value = match nsid {
            "blue.catbird.labyrinth.getThreadStorage" => json!(*self.placement.lock().unwrap()),
            "blue.catbird.labyrinth.listSpaceBatches" => {
                json!({"items": *self.views.lock().unwrap()})
            }
            _ => panic!("unexpected query {nsid}"),
        };
        Ok(serde_json::to_vec(&value).unwrap())
    }
    fn procedure(
        &self,
        nsid: &str,
        payload: &[u8],
        _: [u8; 16],
    ) -> core::result::Result<Vec<u8>, XrpcError> {
        assert_eq!(nsid, "blue.catbird.labyrinth.appendSpaceBatch");
        let input: Value = serde_json::from_slice(payload).unwrap();
        let record: Batch = serde_json::from_value(input["record"].clone()).unwrap();
        assert_eq!(input["cid"], batch_cid(&record).unwrap());
        let mut views = self.views.lock().unwrap();
        let rkey = input["rkey"].as_str().unwrap();
        let order = if let Some(old) = views.iter().find(|v| v.rkey == rkey) {
            old.order.clone()
        } else {
            let order = OrderDef {
                seq: views.len() as u64 + 1,
                chat_seq: Some(42),
                received_at: datetime_from_ms(1_791_000_000_100),
            };
            // The model retains only metadata, exactly as the DS contract.
            views.push(SpaceBatchView {
                author: DID.into(),
                rkey: rkey.into(),
                space: input["space"].as_str().unwrap().into(),
                generation: input["generation"].as_str().unwrap().into(),
                cid: input["cid"].as_str().unwrap().into(),
                order: order.clone(),
                item_count: record.items.len(),
                redactions: vec![],
            });
            order
        };
        if self
            .lose_ack
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(XrpcError::named(
                0,
                "LostAcknowledgement",
                "response lost after commit",
            ));
        }
        Ok(serde_json::to_vec(&json!({"rkey": rkey, "order": order})).unwrap())
    }
}
const DS_DID: &str = "did:web:ds.example";

fn ds_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x5e; 32])
}

fn signed_ds_redaction(msg_id: &str) -> RedactionDef {
    let signer = crate::sign::Ed25519Transport(ds_signing_key());
    let r = crate::deletion::ServerRedaction::account_deletion(
        DS_DID,
        DID,
        "thread",
        msg_id,
        &datetime_from_ms(12),
        Some(&signer),
    );
    RedactionDef::from_server(&r)
}

fn signed_author_redaction(msg_id: &str, seed: u8) -> RedactionDef {
    let signer = crate::sign::Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]));
    let mut r = crate::deletion::Redaction::sign(DID, "thread", msg_id, &signer);
    r.redacted_at = Some(datetime_from_ms(12));
    RedactionDef::from_redaction(&r)
}

fn setup() -> (SequencedSpaceThreadStore, Arc<Sequencer>, MemorySpaceHost) {
    let ds = Arc::new(Sequencer::default());
    let host = MemorySpaceHost::new();
    let store = SequencedSpaceThreadStore::new(
        DID,
        ds.clone(),
        Some(Arc::new(host.client(DID))),
        Arc::new(Pins::default()),
    )
    .with_sequencer_key(crate::store::SequencerKey {
        did: DS_DID.into(),
        key: ds_signing_key().verifying_key().to_bytes(),
    });
    (store, ds, host)
}

#[test]
fn lost_sequence_ack_reuses_one_sender_record_and_one_reference() {
    let (store, ds, host) = setup();
    // Fail 2 consecutive `status == 0` responses so the initial `Xrpc::post`
    // (including its single inline retry) fails after committing to both the
    // Space host and sequencer, forcing the caller retry through
    // `SequencedSpaceThreadStore`'s conflict-reconciliation path.
    ds.lose_ack.store(2, Ordering::SeqCst);
    assert!(store.append_batch(&batch()).is_err());
    let key = store.append_batch(&batch()).unwrap();
    assert_eq!(key.len(), 64);
    assert_eq!(ds.views.lock().unwrap().len(), 1);
    assert_eq!(
        host.record_count(&placement().validate().unwrap().unwrap(), DID, None),
        1
    );
    let read = store.list_batches("thread", None, TimeRange::ALL).unwrap();
    assert_eq!(read[0].value, batch());
    assert_eq!(read[0].order.as_ref().unwrap().chat_seq, Some(42));
}

#[test]
fn single_lost_sequence_ack_recovers_via_xrpc_inline_retry() {
    let (store, ds, host) = setup();
    ds.lose_ack.store(1, Ordering::SeqCst);
    let key = store.append_batch(&batch()).unwrap();
    assert_eq!(key.len(), 64);
    assert_eq!(ds.views.lock().unwrap().len(), 1);
    assert_eq!(
        host.record_count(&placement().validate().unwrap().unwrap(), DID, None),
        1
    );
}

#[test]
fn same_uri_recreated_generation_never_replaces_pin() {
    let (store, ds, _) = setup();
    store.append_batch(&batch()).unwrap();
    let mut p = ds.placement.lock().unwrap();
    p.generation = "22222222-2222-4222-8222-222222222222".into();
    p.space = Some(format!(
        "at://did:plc:authority/space/blue.catbird.labyrinth.conversation/{}",
        p.generation
    ));
    drop(p);
    assert!(matches!(
        store.list_batches("thread", None, TimeRange::ALL),
        Err(Error::Conflict)
    ));
}

#[test]
fn authenticated_reference_cannot_be_rebound_to_changed_record() {
    let (store, _, host) = setup();
    let key = store.append_batch(&batch()).unwrap();
    let mut changed = batch();
    changed.items[0].signed_enc_message.0[0] ^= 1;
    host.tamper(
        &placement().validate().unwrap().unwrap(),
        DID,
        nsid::BATCH,
        &key,
        json!(changed),
    );
    assert!(store.list_batches("thread", None, TimeRange::ALL).is_err());
}

#[test]
fn missing_record_or_missing_server_order_is_an_error() {
    let (store, ds, host) = setup();
    let key = store.append_batch(&batch()).unwrap();
    ds.views.lock().unwrap()[0].order.chat_seq = None;
    assert!(store.list_batches("thread", None, TimeRange::ALL).is_err());
    ds.views.lock().unwrap()[0].order.chat_seq = Some(42);
    host.remove(
        &placement().validate().unwrap().unwrap(),
        DID,
        nsid::BATCH,
        &key,
    );
    assert!(store.list_batches("thread", None, TimeRange::ALL).is_err());
}

#[test]
fn tombstones_remove_ciphertext_only_after_original_cid_verification() {
    let (store, ds, _) = setup();
    let mut record = batch();
    let mut second = record.items[0].clone();
    second.message_id = "second".into();
    record.items.push(second);
    store.append_batch(&record).unwrap();
    ds.views.lock().unwrap()[0]
        .redactions
        .push(SpaceBatchRedaction {
            message_id: "message".into(),
            timestamp: 9,
            redaction: signed_ds_redaction("message"),
        });
    let read = store.list_batches("thread", None, TimeRange::ALL).unwrap();
    assert!(read[0].value.items[0].signed_enc_message.0.is_empty());
    assert!(read[0].value.items[0].redaction.is_some());
    assert!(!read[0].value.items[1].signed_enc_message.0.is_empty());
    ds.views.lock().unwrap()[0].redactions[0].timestamp = 10;
    assert!(store.list_batches("thread", None, TimeRange::ALL).is_err());
}

#[test]
fn fully_purged_source_remains_a_tombstone_without_decryptable_content() {
    let (store, ds, host) = setup();
    let key = store.append_batch(&batch()).unwrap();
    ds.views.lock().unwrap()[0]
        .redactions
        .push(SpaceBatchRedaction {
            message_id: "message".into(),
            timestamp: 9,
            redaction: signed_ds_redaction("message"),
        });
    host.remove(
        &placement().validate().unwrap().unwrap(),
        DID,
        nsid::BATCH,
        &key,
    );
    let records = store.list_batches("thread", None, TimeRange::ALL).unwrap();
    assert!(matches!(
        &records[0].value.entries().unwrap()[0],
        crate::records::BatchEntry::Redacted { .. }
    ));
    assert!(records[0].value.items[0].signed_enc_message.0.is_empty());

    // Author-signed redaction after genuine Space record deletion also resolves.
    ds.views.lock().unwrap()[0].redactions[0].redaction = signed_author_redaction("message", 7);
    let records = store.list_batches("thread", None, TimeRange::ALL).unwrap();
    assert!(matches!(
        &records[0].value.entries().unwrap()[0],
        crate::records::BatchEntry::Redacted { .. }
    ));

    // Missing one tombstone is never treated as an empty complete result.
    ds.views.lock().unwrap()[0].item_count = 2;
    assert!(store.list_batches("thread", None, TimeRange::ALL).is_err());
}

#[test]
fn fabricated_sourceless_redaction_with_invalid_signature_is_rejected() {
    let (store, ds, host) = setup();
    let key = store.append_batch(&batch()).unwrap();
    host.remove(
        &placement().validate().unwrap().unwrap(),
        DID,
        nsid::BATCH,
        &key,
    );

    // Unsigned server removal when Space record is 404 -> BadSignature.
    ds.views.lock().unwrap()[0].redactions = vec![SpaceBatchRedaction {
        message_id: "message".into(),
        timestamp: 9,
        redaction: RedactionDef::account_deletion(Some(datetime_from_ms(12))),
    }];
    assert_eq!(
        store
            .list_batches("thread", None, TimeRange::ALL)
            .unwrap_err(),
        Error::BadSignature
    );

    // Forged author signature when Space record is 404 -> BadSignature.
    let mut forged = signed_author_redaction("message", 7);
    forged.sig.as_mut().unwrap().0[0] ^= 1;
    ds.views.lock().unwrap()[0].redactions[0].redaction = forged;
    assert_eq!(
        store
            .list_batches("thread", None, TimeRange::ALL)
            .unwrap_err(),
        Error::BadSignature
    );

    // Valid DS signature when store has no `ds_redaction_pubkey` configured -> BadSignature.
    ds.views.lock().unwrap()[0].redactions[0].redaction = signed_ds_redaction("message");
    let unkeyed = SequencedSpaceThreadStore::new(
        DID,
        ds.clone(),
        Some(Arc::new(host.client(DID))),
        Arc::new(Pins::default()),
    );
    assert_eq!(
        unkeyed
            .list_batches("thread", None, TimeRange::ALL)
            .unwrap_err(),
        Error::BadSignature
    );
}

#[test]
fn fabricated_redaction_with_live_space_record_reads_record_and_rejects_bad_tombstone() {
    struct CountingSpace {
        inner: crate::store::space::host::SpaceClient,
        gets: AtomicUsize,
    }
    impl XrpcTransport for CountingSpace {
        fn query_with_headers(
            &self,
            nsid: &str,
            params: &[(&str, String)],
            headers: &[(String, String)],
        ) -> core::result::Result<Vec<u8>, XrpcError> {
            if nsid == endpoint::GET_RECORD {
                self.gets.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.query_with_headers(nsid, params, headers)
        }
        fn procedure(
            &self,
            nsid: &str,
            payload: &[u8],
            op: [u8; 16],
        ) -> core::result::Result<Vec<u8>, XrpcError> {
            self.inner.procedure(nsid, payload, op)
        }
    }

    let ds = Arc::new(Sequencer::default());
    let host = MemorySpaceHost::new();
    let counting = Arc::new(CountingSpace {
        inner: host.client(DID),
        gets: AtomicUsize::new(0),
    });
    let store = SequencedSpaceThreadStore::new(
        DID,
        ds.clone(),
        Some(counting.clone()),
        Arc::new(Pins::default()),
    )
    .with_sequencer_key(crate::store::SequencerKey {
        did: DS_DID.into(),
        key: ds_signing_key().verifying_key().to_bytes(),
    });
    store.append_batch(&batch()).unwrap();
    counting.gets.store(0, Ordering::SeqCst);

    // Sequencer fabricates `redactions.len() == item_count` while live Space
    // record still exists: `resolve` MUST still call `read_record` AND reject
    // the unverified redaction with `Error::BadSignature`.
    ds.views.lock().unwrap()[0].redactions = vec![SpaceBatchRedaction {
        message_id: "message".into(),
        timestamp: 9,
        redaction: RedactionDef::account_deletion(Some(datetime_from_ms(12))),
    }];
    assert_eq!(
        store
            .list_batches("thread", None, TimeRange::ALL)
            .unwrap_err(),
        Error::BadSignature
    );
    assert_eq!(
        counting.gets.load(Ordering::SeqCst),
        1,
        "live Space record must be read even when redactions.len() == item_count"
    );
}

#[test]
fn purge_owns_only_the_signed_in_accounts_ciphertext_and_is_retryable() {
    let (store, _, host) = setup();
    store.append_batch(&batch()).unwrap();
    let p = placement();
    let space = p.validate().unwrap().unwrap();
    host.tamper(
        &space,
        "did:plc:bob",
        nsid::BATCH,
        "foreign",
        json!(batch()),
    );
    for _ in 0..2 {
        SequencedSpaceThreadStore::purge_owned_records(
            DID,
            &host.client(DID),
            p.space.as_deref().unwrap(),
        )
        .unwrap();
    }
    assert_eq!(host.record_count(&space, DID, None), 0);
    assert_eq!(host.record_count(&space, "did:plc:bob", None), 1);
}

#[test]
fn explicit_space_placement_requires_platform_transport() {
    let store = SequencedSpaceThreadStore::new(
        DID,
        Arc::new(Sequencer::default()),
        None,
        Arc::new(Pins::default()),
    );
    assert!(matches!(
        store.append_batch(&batch()),
        Err(Error::NotSupported(_))
    ));
}

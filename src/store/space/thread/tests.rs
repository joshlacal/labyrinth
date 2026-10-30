//! Protocol boundary tests. The sequencer and owner PDS are local models;
//! these do not qualify live credentials, MAC negotiation or MLS admission.
use super::*;
use crate::message::SealedMessage;
use crate::records::datetime_from_ms;
use crate::store::space::host::MemorySpaceHost;
use crate::store::xrpc::XrpcError;
use serde_json::{Value, json};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

const DID: &str = "did:plc:alice";
const GENERATION: &str = "11111111-1111-4111-8111-111111111111";

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
    lose_ack: AtomicBool,
}
impl Default for Sequencer {
    fn default() -> Self {
        Self {
            placement: Mutex::new(placement()),
            views: Mutex::default(),
            lose_ack: AtomicBool::new(false),
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
        if self.lose_ack.swap(false, Ordering::SeqCst) {
            return Err(XrpcError::named(
                0,
                "LostAcknowledgement",
                "response lost after commit",
            ));
        }
        Ok(serde_json::to_vec(&json!({"rkey": rkey, "order": order})).unwrap())
    }
}
fn setup() -> (SequencedSpaceThreadStore, Arc<Sequencer>, MemorySpaceHost) {
    let ds = Arc::new(Sequencer::default());
    let host = MemorySpaceHost::new();
    let store = SequencedSpaceThreadStore::new(
        DID,
        ds.clone(),
        Some(Arc::new(host.client(DID))),
        Arc::new(Pins::default()),
    );
    (store, ds, host)
}

#[test]
fn lost_sequence_ack_reuses_one_sender_record_and_one_reference() {
    let (store, ds, host) = setup();
    ds.lose_ack.store(true, Ordering::SeqCst);
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
            redaction: RedactionDef::account_deletion(Some(datetime_from_ms(12))),
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
            redaction: RedactionDef::account_deletion(Some(datetime_from_ms(12))),
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
    // Missing one tombstone is never treated as an empty complete result.
    ds.views.lock().unwrap()[0].item_count = 2;
    assert!(store.list_batches("thread", None, TimeRange::ALL).is_err());
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

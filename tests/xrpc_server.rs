//! What the XRPC stores and the reference server reject, and how errors
//! map (design `docs/MLSDS_BACKEND.md` §2–§3; `--features xrpc`).

#![cfg(feature = "xrpc")]

#[path = "support/lexicon.rs"]
mod lexicon;

use std::path::Path;

use labyrinth::Error;
use labyrinth::device::{ChatBinding, DeviceSecrets};
use labyrinth::mek::{Mek, distribute_transport};
use labyrinth::message::seal_sender;
use labyrinth::records::{
    Batch, Device, Epoch, EpochMember, MailboxKeysRecord, MekDistribution, datetime_from_ms,
};
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::xrpc::server::MemoryXrpcServer;
use labyrinth::store::xrpc::{
    NSID_PREFIX, XrpcDirectory, XrpcError, XrpcMailboxStore, XrpcThreadStore, map_error,
};
use labyrinth::store::{KeyPublisher, MailboxDirectory, MailboxStore, ThreadStore, TimeRange};
use serde_json::json;

const A: &str = "did:plc:alice";
const T: &str = "conv-1";

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}
fn tpub(seed: u8) -> [u8; 32] {
    signer(seed).0.verifying_key().to_bytes()
}

/// A physical device record bound to chat key `seed` ([CB-36]).
fn bound(d: &DeviceSecrets, seed: u8, at: &str) -> Device {
    let b = ChatBinding::sign(A, &d.public().device_key_pub, &signer(seed));
    Device::bound(d.public(), &b, at.to_owned())
}

fn server() -> MemoryXrpcServer {
    let s = MemoryXrpcServer::new(MemoryBackend::new());
    s.backend().register_chat_device(A, tpub(1));
    s
}

/// A transport MEK minted by device `seed`, its record, and a sealed message.
fn mek_and_message(seed: u8, id: &str) -> (MekDistribution, labyrinth::message::SealedMessage) {
    let d = DeviceSecrets::generate().unwrap();
    let e = labyrinth::epoch::open_genesis(A, &d, &signer(seed))
        .unwrap()
        .1
        .record
        .public;
    let mut m = Mek::generate(&[e.head]).unwrap();
    let rec = distribute_transport(T, &mut m, &signer(seed), &[(A.to_owned(), e)]).unwrap();
    let wire = MekDistribution::from_record(&rec, None, datetime_from_ms(1)).unwrap();
    (
        wire,
        seal_sender(&m, T, id, 1, b"x", &signer(seed)).unwrap(),
    )
}

#[test]
fn errors_map_to_store_errors() {
    let e = |name: &str| map_error(XrpcError::named(400, name, ""));
    assert_eq!(e("RecordAlreadyExists"), Error::Conflict);
    assert_eq!(e("EpochHeadConflict"), Error::Conflict);
    for f in [
        "NotAuthorized",
        "NotRecipient",
        "NotParticipant",
        "DeviceRevoked",
        "SpaceDeleted",
    ] {
        assert_eq!(e(f), Error::Forbidden);
    }
    assert_eq!(e("DeviceNotFound"), Error::NotFound("device"));
    assert_eq!(e("MemberDeviceNotRegistered"), Error::NotFound("device"));
    assert_eq!(e("NotFound"), Error::NotFound("attachment"));
    for f in ["LabyrinthDeviceNotBound", "AttachmentNotEntitled"] {
        assert_eq!(e(f), Error::Forbidden);
    }
    assert_eq!(e("AttachmentAlreadyReferenced"), Error::Conflict);
    for f in ["InvalidChatBinding", "InvalidRedaction"] {
        assert_eq!(e(f), Error::BadSignature);
    }
    for f in [
        "RelayUnavailable",
        "ConversationMoved",
        "AttachmentsUnavailable",
    ] {
        assert!(matches!(e(f), Error::Backend(_)));
    }
    assert_eq!(e("AttestationNotCurrent"), Error::Unattested);
    assert!(matches!(e("MixedMekBatch"), Error::Backend(m) if m.contains("MixedMekBatch")));
    let no_response = XrpcError {
        status: 0,
        error: None,
        message: Some("timeout".into()),
    };
    assert!(matches!(map_error(no_response), Error::Backend(_)));
}

#[test]
fn mailbox_create_get_and_replay() {
    let s = server();
    let t = s.transport(A, tpub(1));
    let mb = XrpcMailboxStore::new(A, t.clone());
    let d = DeviceSecrets::generate().unwrap();
    let key = d.public().device_key_pub;
    assert_eq!(mb.get_device(&key).unwrap(), None);
    assert_eq!(mb.get_epoch(0).unwrap(), None);
    // mls-ds refuses an unbound physical device, and one bound to another
    // chat key than the caller's (InvalidChatBinding).
    let unbound = Device::from_public(d.public(), datetime_from_ms(1));
    assert_eq!(mb.create_device(&unbound), Err(Error::BadSignature));
    assert_eq!(
        mb.create_device(&bound(&d, 2, &datetime_from_ms(1))),
        Err(Error::BadSignature)
    );
    let rec = bound(&d, 1, &datetime_from_ms(1));
    mb.create_device(&rec).unwrap();
    assert_eq!(mb.create_device(&rec), Err(Error::Conflict));
    assert_eq!(mb.get_device(&key).unwrap(), Some(rec.clone()));
    assert_eq!(
        mb.set_device_revoked(
            &DeviceSecrets::generate().unwrap().public().device_key_pub,
            "x"
        ),
        Err(Error::NotFound("device"))
    );

    // A retried procedure with the same operationId replays its response
    // instead of failing as a second create.
    let other = bound(&DeviceSecrets::generate().unwrap(), 1, "t");
    let payload = serde_json::to_vec(&json!({ "record": other })).unwrap();
    let nsid = format!("{NSID_PREFIX}createDevice");
    let first = t.procedure(&nsid, &payload, [7; 16]).unwrap();
    assert_eq!(t.procedure(&nsid, &payload, [7; 16]).unwrap(), first);
    assert_eq!(
        t.procedure(&nsid, &payload, [8; 16])
            .unwrap_err()
            .error
            .as_deref(),
        Some("RecordAlreadyExists")
    );

    // A revoked chat device is refused everywhere.
    s.backend().remove_chat_device(A, tpub(1), 5);
    assert_eq!(mb.list_devices(), Err(Error::Forbidden));
}

/// An account whose mailbox is in its PDS Space keeps none on mls-ds: any
/// of its chat devices publishes its own heads and may purge, with no
/// bound device. Once it keeps a mailbox here, the binding rules apply.
#[test]
fn a_space_account_publishes_heads_without_a_mailbox_here() {
    let s = server();
    s.backend().register_chat_device(A, tpub(2));
    let dir = |seed: u8| XrpcDirectory::new(s.transport(A, tpub(seed)));
    let head = |seed: u8, d: &DeviceSecrets| {
        let g = labyrinth::epoch::open_genesis(A, d, &signer(seed)).unwrap();
        g.1.record.public
    };
    let keys = |e: &labyrinth::mailbox::EpochPublic| {
        MailboxKeysRecord::from_public(e, None, datetime_from_ms(1))
    };
    let d = DeviceSecrets::generate().unwrap();
    let genesis = head(1, &d);

    dir(1).publish(&keys(&genesis)).unwrap();
    assert_eq!(dir(2).latest(A).unwrap(), Some(genesis.clone()));
    // Only the calling device's own key attests; a second genesis is a fork.
    assert!(matches!(
        dir(2).publish(&keys(&genesis)),
        Err(Error::Backend(m)) if m.contains("AttestationNotCaller")
    ));
    let fork = head(1, &DeviceSecrets::generate().unwrap());
    assert_eq!(dir(1).publish(&keys(&fork)), Err(Error::Conflict));
    // Account deletion needs no bound device either.
    dir(2).retract().unwrap();
    assert_eq!(dir(1).latest(A).unwrap(), None);

    // With a mailbox here, a head must be one of its epochs, re-published
    // by a bound device.
    let mb = XrpcMailboxStore::new(A, s.transport(A, tpub(1)));
    mb.create_device(&bound(&d, 1, &datetime_from_ms(1)))
        .unwrap();
    assert_eq!(
        dir(1).publish(&keys(&genesis)),
        Err(Error::NotFound("epoch"))
    );
    assert_eq!(dir(2).publish(&keys(&genesis)), Err(Error::Forbidden));
    assert_eq!(dir(2).retract(), Err(Error::Forbidden));
}

/// mls-ds `record_head` lets only the calling chat device's own key attest
/// a head, on createEpoch as on publishEpochHead: another current chat
/// device of the same DID cannot open the epoch for it.
#[test]
fn create_epoch_needs_the_callers_own_attestation() {
    let s = server();
    s.backend().register_chat_device(A, tpub(2));
    let d = DeviceSecrets::generate().unwrap();
    let mb = XrpcMailboxStore::new(A, s.transport(A, tpub(1)));
    mb.create_device(&bound(&d, 1, &datetime_from_ms(1)))
        .unwrap();
    let opened = |seed: u8| {
        let new = labyrinth::epoch::open_genesis(A, &d, &signer(seed))
            .unwrap()
            .1;
        let at = datetime_from_ms(1);
        let members: Vec<EpochMember> = new
            .members
            .iter()
            .map(|m| EpochMember::from_record(m, at.clone()))
            .collect();
        (Epoch::from_record(&new.record, at), members)
    };
    let (foreign, members) = opened(2);
    assert!(matches!(
        mb.create_epoch(&foreign, &members),
        Err(Error::Backend(m)) if m.contains("AttestationNotCaller")
    ));
    assert_eq!(mb.get_epoch(0).unwrap(), None);
    let (own, members) = opened(1);
    mb.create_epoch(&own, &members).unwrap();
}

#[test]
fn thread_writes_are_checked_and_stamped() {
    let s = server();
    s.backend().set_server_time(900);
    let th = XrpcThreadStore::new(A, s.transport(A, tpub(1)));
    let (mek, m1) = mek_and_message(1, "m1");
    let (_, other) = mek_and_message(1, "m2");
    let batch = |items: &[labyrinth::message::SealedMessage]| {
        Batch::from_messages(T, items, datetime_from_ms(1)).unwrap()
    };
    let backend_err = |r: labyrinth::Result<String>, name: &str| match r {
        Err(Error::Backend(m)) => assert!(m.contains(name), "{m}"),
        r => panic!("{r:?}"),
    };
    // No MEK yet, then a MEK from another device's key.
    backend_err(
        th.append_batch(&batch(std::slice::from_ref(&m1))),
        "UnknownMek",
    );
    let (foreign, _) = mek_and_message(2, "x");
    assert!(
        matches!(th.create_mek(&foreign), Err(Error::Backend(m)) if m.contains("SenderMismatch"))
    );
    th.create_mek(&mek).unwrap();
    assert_eq!(th.create_mek(&mek), Err(Error::Conflict));
    // One MEK per batch, and only the caller's own key.
    backend_err(
        th.append_batch(&batch(&[m1.clone(), other])),
        "MixedMekBatch",
    );
    let (_, wrong_key) = mek_and_message(2, "m3");
    backend_err(th.append_batch(&batch(&[wrong_key])), "SenderKeyMismatch");
    th.append_batch(&batch(&[m1])).unwrap();
    let got = th.list_batches(T, None, TimeRange::ALL).unwrap();
    let order = got[0].order.unwrap();
    assert_eq!((order.labyrinth_seq, order.received_at_ms), (2, 900));
    let id: [u8; 12] = mek.mek_id.array("mekId").unwrap();
    assert!(th.find_meks(T, &id).unwrap()[0].order.is_some());
    // The leaf view is absent until the conversation has one.
    let dir = XrpcDirectory::new(s.transport(A, tpub(1)));
    assert_eq!(dir.member_device_keys(T, A).unwrap(), None);
    s.backend().add_leaf(T, A, tpub(1));
    assert_eq!(dir.member_device_keys(T, A).unwrap().unwrap().len(), 1);
    assert_eq!(dir.latest(A).unwrap(), None);
}

/// Positive controls: the lexicon checks in `e2e_xrpc` catch bad calls.
#[test]
fn validator_rejects_bad_calls() {
    let lex = lexicon::Lexicons::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("lexicons/blue/catbird/labyrinth"),
    );
    let n = |name: &str| format!("{NSID_PREFIX}{name}");
    let ok = [("threadId", "t".to_owned()), ("fromMs", "5".to_owned())];
    lex.validate_params(&n("listBatches"), &ok).unwrap();
    assert!(
        lex.validate_params(&n("listBatches"), &[("fromMs", "5".into())])
            .is_err()
    );
    assert!(
        lex.validate_params(
            &n("listBatches"),
            &[("threadId", "t".into()), ("x", "1".into())]
        )
        .is_err()
    );
    assert!(
        lex.validate_params(
            &n("listBatches"),
            &[("threadId", "t".into()), ("fromMs", "-1".into())]
        )
        .is_err()
    );
    assert!(
        lex.validate_params(&n("getDevice"), &[("deviceKeyPubkey", "ab".into())])
            .is_err()
    );
    let d = Device::from_public(
        DeviceSecrets::generate().unwrap().public(),
        datetime_from_ms(0),
    );
    lex.validate_input(&n("createDevice"), &json!({ "record": d }))
        .unwrap();
    assert!(
        lex.validate_input(&n("createDevice"), &json!({ "record": d, "x": 1 }))
            .is_err()
    );
    let mut bad = serde_json::to_value(&d).unwrap();
    bad["virtual"] = json!("no");
    assert!(
        lex.validate_input(&n("createDevice"), &json!({ "record": bad }))
            .is_err()
    );
    assert!(
        lex.validate_output(&n("appendBatch"), &json!({ "rkey": "x" }))
            .is_err()
    );
    lex.validate_output(
        &n("appendBatch"),
        &json!({ "rkey": "x", "order": { "seq": 1, "receivedAt": "2026-10-04T00:00:00.000Z" } }),
    )
    .unwrap();
    assert!(lex.declares_error(&n("appendBatch"), "MixedMekBatch"));
    assert!(lex.declares_error(&n("appendBatch"), "RateLimited"));
    assert!(!lex.declares_error(&n("getDevice"), "MixedMekBatch"));
}

#[test]
fn unknown_conversation_state_is_conversation_not_found() {
    let net = MemoryBackend::new();
    let s = MemoryXrpcServer::new(net.clone());
    net.register_chat_device(A, tpub(1));
    let t = s.transport(A, tpub(1));
    let q = |c: &str| {
        t.query(
            "blue.catbird.chat.getConversationState",
            &[("conversationId", c.to_owned())],
        )
    };
    let e = q("gone").unwrap_err();
    assert_eq!(
        (e.status, e.error.as_deref()),
        (404, Some("ConversationNotFound"))
    );
    assert_eq!(
        labyrinth::store::xrpc::map_error(e),
        Error::NotFound("conversation")
    );
    net.add_leaf(T, A, tpub(1));
    assert!(q(T).is_ok());
}

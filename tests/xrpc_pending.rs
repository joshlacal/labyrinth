//! The reference server's handlers for the gap-closing endpoints
//! (`src/store/xrpc/server/pending.rs`): the agreed request shapes and
//! errors, exercised over a raw transport because the XRPC stores do not
//! call them until the mls-ds lexicons land.

#![cfg(feature = "xrpc")]

use base64::Engine as _;
use labyrinth::attachment::blind;
use labyrinth::deletion::Redaction;
use labyrinth::mek::Mek;
use labyrinth::message::seal_sender;
use labyrinth::orf::orf_client_init;
use labyrinth::records::{Batch, datetime_from_ms};
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::ThreadStore;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::xrpc::server::MemoryXrpcServer;
use labyrinth::store::xrpc::{XrpcError, XrpcTransport};
use serde_json::{Value, json};

const A: &str = "did:plc:alice";
const T: &str = "conv-1";

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}
fn b(x: &[u8]) -> Value {
    json!({"$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(x)})
}

fn call(t: &dyn XrpcTransport, name: &str, body: Value) -> Result<Vec<u8>, XrpcError> {
    let mut op = [0u8; 16];
    getrandom::fill(&mut op).unwrap();
    t.procedure(
        &format!("blue.catbird.labyrinth.{name}"),
        &serde_json::to_vec(&body).unwrap(),
        op,
    )
}

fn err_name(r: Result<Vec<u8>, XrpcError>) -> String {
    r.unwrap_err().error.unwrap()
}

#[test]
fn pending_endpoints_follow_the_agreed_shapes() {
    let net = MemoryBackend::new();
    let s = MemoryXrpcServer::new(net.clone());
    let me = signer(1).0.verifying_key().to_bytes();
    net.register_chat_device(A, me);
    let t = s.transport(A, me);

    // One archived message by Alice.
    let mek = Mek::generate(&[[1u8; 32]]).unwrap();
    let sealed = seal_sender(&mek, T, "m1", 5, b"hi", &signer(1)).unwrap();
    net.threads(A)
        .append_batch(&Batch::from_messages(T, &[sealed], datetime_from_ms(1)).unwrap())
        .unwrap();

    // Attachments: an ORF state for a Labyrinth device key, then a ref.
    let device = [7u8; 32];
    call(
        &*t,
        "registerOrfState",
        json!({"deviceKeyPubkey": b(&device)}),
    )
    .unwrap();
    net.put_blob("blob-1", b"ciphertext");
    let c = orf_client_init().unwrap();
    let (bi, bt) = blind(&c, T, "blob-1");
    let put = |message: &str| {
        call(
            &*t,
            "putAttachmentRef",
            json!({"deviceKeyPubkey": b(&device), "blindedIndex": b(&bi.0),
                   "blindedTokenSalt": b(&bt.0), "blobId": "blob-1",
                   "threadId": T, "messageId": message}),
        )
    };
    let get = |message: &str| {
        call(
            &*t,
            "getAttachmentBlob",
            json!({"deviceKeyPubkey": b(&device), "blindedIndex": b(&bi.0),
                   "blindedTokenSalt": b(&bt.0), "threadId": T, "messageId": message}),
        )
    };
    put("m1").unwrap();
    assert_eq!(get("m1").unwrap(), b"ciphertext");
    assert_eq!(err_name(get("m2")), "NotAuthorized");

    // Unsend: only with the calling chat device's own key.
    let r = Redaction::sign(A, T, "m1", &signer(1));
    let other = Redaction::sign(A, T, "m1", &signer(2));
    let redact = |r: &Redaction| {
        call(
            &*t,
            "redactMessage",
            json!({"threadId": T, "messageId": "m1",
                   "redaction": {"transportPubkey": b(&r.transport_public_key), "sig": b(&r.sig)}}),
        )
    };
    assert_eq!(err_name(redact(&other)), "InvalidRequest");
    let out: Value = serde_json::from_slice(&redact(&r).unwrap()).unwrap();
    assert_eq!(out, json!({"redacted": 1}));
    // The message is gone, so the attachment is too.
    assert_eq!(err_name(get("m1")), "NotAuthorized");
    call(
        &*t,
        "deleteAttachmentRef",
        json!({"deviceKeyPubkey": b(&device), "blindedIndex": b(&bi.0)}),
    )
    .unwrap();
    assert_eq!(err_name(get("m1")), "NotFound");

    // Recovery bundles and the mailbox.
    assert_eq!(
        err_name(call(
            &*t,
            "touchVirtualDevice",
            json!({"vdeviceId": b(&[1; 16])})
        )),
        "VirtualDeviceNotFound"
    );
    let threads: Value = serde_json::from_slice(
        &t.query("blue.catbird.labyrinth.listOwnerThreads", &[])
            .unwrap(),
    )
    .unwrap();
    assert_eq!(threads, json!({"threads": []}));
    call(&*t, "purgeMailbox", json!({})).unwrap();
    assert_eq!(net.attachment_ref_count(A), 0);
}

#[test]
fn a_second_message_for_one_blob_is_refused() {
    let net = MemoryBackend::new();
    let s = MemoryXrpcServer::new(net.clone());
    let me = signer(1).0.verifying_key().to_bytes();
    net.register_chat_device(A, me);
    let t = s.transport(A, me);
    let mek = Mek::generate(&[[1u8; 32]]).unwrap();
    let items = [
        seal_sender(&mek, T, "m1", 5, b"a", &signer(1)).unwrap(),
        seal_sender(&mek, T, "m2", 6, b"b", &signer(1)).unwrap(),
    ];
    net.threads(A)
        .append_batch(&Batch::from_messages(T, &items, datetime_from_ms(1)).unwrap())
        .unwrap();
    let device = [7u8; 32];
    call(
        &*t,
        "registerOrfState",
        json!({"deviceKeyPubkey": b(&device)}),
    )
    .unwrap();
    net.put_blob("blob-1", b"x");
    let c = orf_client_init().unwrap();
    let (bi, bt) = blind(&c, T, "blob-1");
    let put = |message: &str| {
        call(
            &*t,
            "putAttachmentRef",
            json!({"deviceKeyPubkey": b(&device), "blindedIndex": b(&bi.0),
                   "blindedTokenSalt": b(&bt.0), "blobId": "blob-1",
                   "threadId": T, "messageId": message}),
        )
    };
    put("m1").unwrap();
    assert_eq!(err_name(put("m2")), "AttachmentAlreadyReferenced");
}

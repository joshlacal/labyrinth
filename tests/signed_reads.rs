//! Device-signed reads (`store::xrpc::read_auth`): the golden vector the
//! mls-ds lane verifies against (`tests/vectors/labyrinth_read_header.json`)
//! and the reference server's refusals.

#![cfg(feature = "xrpc")]

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use labyrinth::sign::{Ed25519Transport, TransportSigner};
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::xrpc::read_auth::{
    READ_HEADER, READ_SIGNATURE_HEADER, ReadClaim, canonical_query, verify_read,
};
use labyrinth::store::xrpc::server::MemoryXrpcServer;
use labyrinth::store::xrpc::XrpcError;
use serde_json::Value;

fn vector() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/labyrinth_read_header.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn golden_vector() {
    let v = vector();
    let input = &v["input"];
    let params: Vec<(String, String)> = input["params"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (s(&p[0]).to_owned(), s(&p[1]).to_owned()))
        .collect();
    let params: Vec<(&str, String)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    let seed: [u8; 32] = hex::decode(s(&input["ed25519SeedHex"]))
        .unwrap()
        .try_into()
        .unwrap();
    let signer = Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&seed));
    let out = &v["output"];
    assert_eq!(
        hex::encode(signer.transport_public_key()),
        s(&out["publicKeyHex"])
    );

    assert_eq!(canonical_query(&params), s(&out["canonicalQuery"]));
    let claim = ReadClaim::new(
        s(&input["nsid"]),
        &params,
        s(&input["did"]),
        s(&input["deviceId"]),
        input["issuedAt"].as_u64().unwrap(),
    );
    let json = claim.to_json();
    assert_eq!(std::str::from_utf8(&json).unwrap(), s(&out["claimJson"]));
    assert_eq!(hex::encode(&json), s(&out["claimHex"]));
    assert_eq!(
        hex::encode(ReadClaim::signing_input(&json)),
        s(&out["signingInputHex"])
    );
    let headers = claim.sign(&signer);
    assert_eq!(
        headers[0],
        (READ_HEADER.to_owned(), s(&out["readHeader"]).to_owned())
    );
    assert_eq!(
        headers[1],
        (
            READ_SIGNATURE_HEADER.to_owned(),
            s(&out["readSignatureHeader"]).to_owned()
        )
    );
    assert_eq!(URL_SAFE_NO_PAD.decode(s(&out["readHeader"])).unwrap(), json);
    let got = verify_read(
        s(&out["readHeader"]),
        s(&out["readSignatureHeader"]),
        &signer.transport_public_key(),
    )
    .unwrap();
    assert_eq!(got, claim);
}

const DID: &str = "did:plc:alice";
const NSID: &str = "blue.catbird.labyrinth.listThreads";

fn signer(seed: u8) -> Arc<Ed25519Transport> {
    Arc::new(Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(
        &[seed; 32],
    )))
}

fn server() -> MemoryXrpcServer {
    let s = MemoryXrpcServer::new(MemoryBackend::new()).require_signed_reads();
    s.backend()
        .register_chat_device(DID, signer(1).transport_public_key());
    s.backend().set_server_time(10_000_000);
    s
}

fn refused(r: Result<Vec<u8>, XrpcError>) {
    let e = r.expect_err("must be refused");
    assert_eq!(
        (e.status, e.error.as_deref()),
        (401, Some("InvalidSignature"))
    );
}

#[test]
fn server_accepts_signed_and_refuses_unsigned_reads() {
    let s = server();
    s.signed_transport(DID, signer(1)).query(NSID, &[]).unwrap();
    refused(
        s.transport(DID, signer(1).transport_public_key())
            .query(NSID, &[]),
    );
}

#[test]
fn server_refuses_mismatched_claims() {
    let s = server();
    let key = signer(1).transport_public_key();
    let t = s.transport(DID, key);
    let dev = hex::encode(key);
    let now = 10_000_000;
    let p = [("limit", "5".to_owned())];
    let send = |c: ReadClaim, by: &Ed25519Transport| t.query_with_headers(NSID, &p, &c.sign(by));
    // Valid.
    send(ReadClaim::new(NSID, &p, DID, &dev, now), &signer(1)).unwrap();
    // Parameters the claim does not cover.
    refused(send(ReadClaim::new(NSID, &[], DID, &dev, now), &signer(1)));
    // Another endpoint, DID, device, or a stale claim.
    let other = "blue.catbird.labyrinth.listOwnerThreads";
    refused(send(ReadClaim::new(other, &p, DID, &dev, now), &signer(1)));
    refused(send(
        ReadClaim::new(NSID, &p, "did:plc:bob", &dev, now),
        &signer(1),
    ));
    refused(send(ReadClaim::new(NSID, &p, DID, "dev2", now), &signer(1)));
    refused(send(
        ReadClaim::new(NSID, &p, DID, &dev, now - 300_001),
        &signer(1),
    ));
    // Signed by a key that is not the caller's chat device.
    refused(send(ReadClaim::new(NSID, &p, DID, &dev, now), &signer(2)));
    // One header without the other.
    let mut h = ReadClaim::new(NSID, &p, DID, &dev, now).sign(&*signer(1));
    h.pop();
    refused(t.query_with_headers(NSID, &p, &h));
    // Procedures and non-Labyrinth queries are not read-signed.
    assert_ne!(
        t.query("blue.catbird.chat.getConversationState", &[])
            .map_err(|e| e.error),
        Err(Some("InvalidSignature".to_owned()))
    );
}

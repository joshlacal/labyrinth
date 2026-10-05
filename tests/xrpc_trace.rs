//! Records the crate client's XRPC call sequence against the reference
//! server, in the format mls-ds `tests/labyrinth_crate_trace.rs` replays
//! through its real handlers (`tests/fixtures/labyrinth_crate_xrpc_trace.json`):
//!
//! `{generator, thread, members: [[did, chatSeed, joinedSeq]], nextEntrySeq,
//! calls: [{did, seed, kind, nsid, params | operationId + payload, status,
//! response | error}]}`. A caller's chat key is `Ed25519::from_bytes([seed; 32])`.
//!
//! The scenario covers the binding-era genesis order (`createDevice` with a
//! `chatBinding` before `createEpoch`), sends, reads, recovery bundles
//! (create, restore, touch, remove), unsend, the attachment refusals that
//! need no seeded blob, server-side account deletion and `purgeMailbox`.
//! Every call is validated against the lexicons.
//!
//! The test always runs the scenario and checks it. To (re)write the
//! fixture set `LABYRINTH_TRACE_OUT` to a path, e.g.
//! `LABYRINTH_TRACE_OUT=tests/fixtures/labyrinth_crate_xrpc_trace.json
//! cargo test --features xrpc --test xrpc_trace`.

#![cfg(feature = "xrpc")]

#[path = "support/lexicon.rs"]
mod lexicon;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, Labyrinth};
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::MailboxStore;
use labyrinth::store::TimeRange;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::xrpc::server::MemoryXrpcServer;
use labyrinth::store::xrpc::{
    NSID_PREFIX, XrpcDirectory, XrpcError, XrpcMailboxStore, XrpcOrf, XrpcThreadStore,
    XrpcTransport,
};
use labyrinth::virtual_device::Mechanism;
use lexicon::Lexicons;
use serde_json::{Value, json};

const ALICE: &str = "did:plc:labyrinthtracealiceaaaaa";
const BOB: &str = "did:plc:labyrinthtracebobbbbbbbb";
const CAROL: &str = "did:plc:labyrinthtracecarolccccc";
const THREAD: &str = "5f0c6b2e-8d3a-4c1f-9e7b-2a4d6c8e0f12";

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        1_791_000_000_000 + self.0.fetch_add(1, Ordering::Relaxed)
    }
}

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}
fn tpub(seed: u8) -> [u8; 32] {
    signer(seed).0.verifying_key().to_bytes()
}
fn msg_id(n: u8) -> String {
    format!("00000000-0000-4000-8000-0000000000{n:02x}")
}

type Log = Arc<Mutex<Vec<Value>>>;

/// Records and lexicon-validates every Labyrinth call of one chat device.
struct Recorder {
    inner: Arc<dyn XrpcTransport>,
    did: String,
    seed: u8,
    lex: Arc<Lexicons>,
    log: Log,
}

impl Recorder {
    fn finish(&self, mut call: Value, nsid: &str, out: &Result<Vec<u8>, XrpcError>) {
        match out {
            Ok(body) => {
                let v: Value = serde_json::from_slice(body).expect("JSON output");
                self.lex
                    .validate_output(nsid, &v)
                    .unwrap_or_else(|e| panic!("{nsid}: {e}\n{v:#}"));
                call["status"] = json!(200);
                call["response"] = v;
            }
            Err(e) => {
                let name = e.error.clone().unwrap_or_default();
                assert!(
                    self.lex.declares_error(nsid, &name),
                    "{nsid} undeclared {name}"
                );
                call["status"] = json!(e.status);
                call["error"] = json!(name);
            }
        }
        self.log.lock().unwrap().push(call);
    }
}

impl XrpcTransport for Recorder {
    fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, XrpcError> {
        let out = self.inner.query(nsid, params);
        if nsid.starts_with(NSID_PREFIX) {
            self.lex
                .validate_params(nsid, params)
                .unwrap_or_else(|e| panic!("{nsid}: {e}"));
            let call = json!({
                "did": self.did, "seed": self.seed, "kind": "query", "nsid": nsid,
                "params": params.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
            });
            self.finish(call, nsid, &out);
        }
        out
    }

    fn procedure(&self, nsid: &str, payload: &[u8], op: [u8; 16]) -> Result<Vec<u8>, XrpcError> {
        let v: Value = serde_json::from_slice(payload).unwrap();
        self.lex
            .validate_input(nsid, &v)
            .unwrap_or_else(|e| panic!("{nsid}: {e}\n{v:#}"));
        let out = self.inner.procedure(nsid, payload, op);
        let call = json!({
            "did": self.did, "seed": self.seed, "kind": "procedure", "nsid": nsid,
            "operationId": hex::encode(op), "payload": v,
        });
        self.finish(call, nsid, &out);
        out
    }
}

struct World {
    server: MemoryXrpcServer,
    lex: Arc<Lexicons>,
    log: Log,
    members: Vec<Value>,
    ts: u64,
}

impl World {
    fn transport(&self, did: &str, seed: u8) -> Arc<dyn XrpcTransport> {
        Arc::new(Recorder {
            inner: self.server.transport(did, tpub(seed)),
            did: did.to_owned(),
            seed,
            lex: self.lex.clone(),
            log: self.log.clone(),
        })
    }

    fn backends(&self, did: &str, seed: u8) -> Backends {
        let t = self.transport(did, seed);
        Backends {
            mailbox: Box::new(XrpcMailboxStore::new(did, t.clone())),
            threads: Box::new(XrpcThreadStore::new(did, t.clone())),
            directory: Box::new(XrpcDirectory::new(t.clone())),
            orf: Box::new(XrpcOrf::new(t)),
            publishers: vec![],
            clock: Box::new(TestClock::default()),
        }
    }

    /// A chat device with a leaf in THREAD (a `members` row).
    fn chat_device(&mut self, did: &str, seed: u8) -> Box<Ed25519Transport> {
        let net = self.server.backend();
        net.register_chat_device(did, tpub(seed));
        let joined = net.add_leaf(THREAD, did, tpub(seed));
        self.members.push(json!([did, seed, joined]));
        Box::new(signer(seed))
    }

    fn init(&mut self, did: &str, seed: u8) -> Labyrinth {
        let t = self.chat_device(did, seed);
        Labyrinth::initialize(did, t, self.backends(did, seed)).unwrap()
    }

    fn send(&mut self, lab: &mut Labyrinth, n: u8) {
        self.ts += 10;
        self.server.backend().set_server_time(self.ts);
        let roster = lab.resolve_roster(&[ALICE, BOB, CAROL]).unwrap();
        lab.archive_outgoing(THREAD, &roster, &msg_id(n), self.ts, &[n; 8])
            .unwrap();
    }
}

fn names(log: &Log) -> Vec<String> {
    log.lock()
        .unwrap()
        .iter()
        .map(|c| c["nsid"].as_str().unwrap()[NSID_PREFIX.len()..].to_owned())
        .collect()
}

#[test]
fn record_crate_xrpc_trace() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("lexicons/blue/catbird/labyrinth");
    let mut w = World {
        server: MemoryXrpcServer::new(MemoryBackend::new()),
        lex: Arc::new(Lexicons::load(&dir)),
        log: Log::default(),
        members: Vec::new(),
        ts: 1_000,
    };
    w.server.backend().set_server_time(w.ts);
    let mut alice = w.init(ALICE, 1);
    // Binding-era genesis: the bound device record precedes epoch 0.
    let first = names(&w.log);
    assert_eq!(&first[..2], ["createDevice", "createEpoch"], "{first:?}");
    let mut bob = w.init(BOB, 3);
    let mut carol = w.init(CAROL, 4);
    // Every leaf exists before the first send, as mls-ds seeds them.
    let tablet_chat = w.chat_device(ALICE, 2);

    w.send(&mut alice, 1);
    w.send(&mut alice, 2);
    w.send(&mut bob, 3);
    w.send(&mut carol, 4);
    for lab in [&mut alice, &mut bob, &mut carol] {
        lab.flush().unwrap();
    }
    assert_eq!(
        bob.load_thread(THREAD, TimeRange::ALL)
            .unwrap()
            .messages
            .len(),
        4
    );

    // Recovery bundles: create two, restore a tablet, touch, remove one.
    let keychain = alice.create_recovery_code(Mechanism::Keychain).unwrap();
    let code = alice.create_recovery_code(Mechanism::Code).unwrap();
    let (mut tablet, _) = Labyrinth::restore_with_recovery_code(
        ALICE,
        keychain.code.as_str(),
        tablet_chat,
        w.backends(ALICE, 2),
    )
    .unwrap();
    assert_eq!(
        tablet
            .load_thread(THREAD, TimeRange::ALL)
            .unwrap()
            .messages
            .len(),
        4
    );
    alice.touch_recovery_method(&code.vdevice_id).unwrap();
    assert_eq!(
        alice.touch_recovery_method(&[9; 16]).unwrap_err(),
        Error::NotFound("virtual device")
    );

    // Unsend, idempotent.
    assert_eq!(alice.unsend(THREAD, &msg_id(1)).unwrap(), 1);
    assert_eq!(alice.unsend(THREAD, &msg_id(1)).unwrap(), 0);
    assert_eq!(
        bob.load_thread(THREAD, TimeRange::ALL)
            .unwrap()
            .redacted
            .len(),
        1
    );

    // Attachment refusals that need no seeded chat blob.
    let blob = "7a1e0c4d-2b3f-4a5e-8d6c-9f0a1b2c3d4e";
    assert_eq!(
        alice
            .attach_reference(THREAD, &msg_id(2), blob)
            .unwrap_err(),
        Error::Forbidden
    );
    assert_eq!(
        tablet
            .fetch_attachment(THREAD, &msg_id(2), blob)
            .unwrap_err(),
        Error::NotFound("attachment")
    );
    alice.delete_attachment_reference(THREAD, blob).unwrap();

    // Removing a recovery method rotates its device out and deletes it.
    alice.remove_recovery_method(&keychain.vdevice_id).unwrap();

    // Carol deletes her account server-side; Bob sees "account removed".
    assert!(carol.purge_account().unwrap().server_side);
    let h = bob.load_thread(THREAD, TimeRange::ALL).unwrap();
    assert!(h.redacted.iter().any(|r| r.account_deleted));
    XrpcMailboxStore::new(BOB, w.transport(BOB, 3))
        .purge_mailbox()
        .unwrap();

    let seen = names(&w.log);
    for name in [
        "createDevice",
        "createEpoch",
        "registerOrfState",
        "publishEpochHead",
        "createMek",
        "appendBatch",
        "listBatches",
        "createVirtualDevice",
        "getVirtualDevice",
        "touchVirtualDevice",
        "markDeviceRevoked",
        "deleteVirtualDevice",
        "redactMessage",
        "putAttachmentRef",
        "getAttachmentBlob",
        "deleteAttachmentRef",
        "deleteAccountData",
        "purgeMailbox",
    ] {
        assert!(seen.iter().any(|s| s == name), "{name} not in the trace");
    }

    if let Ok(out) = std::env::var("LABYRINTH_TRACE_OUT") {
        let next = w
            .members
            .iter()
            .map(|m| m[2].as_u64().unwrap())
            .max()
            .unwrap()
            + 1;
        let trace = json!({
            "generator": "labyrinth crate (local/labyrinth-wire-20261005) client against \
                          MemoryXrpcServer, via tests/xrpc_trace.rs",
            "thread": THREAD,
            "members": w.members,
            "nextEntrySeq": next,
            "calls": *w.log.lock().unwrap(),
        });
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(out);
        std::fs::write(&path, serde_json::to_vec_pretty(&trace).unwrap()).unwrap();
    }
}

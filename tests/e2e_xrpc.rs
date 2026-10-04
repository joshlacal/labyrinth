//! The `tests/e2e_memory.rs` lifecycle over the XRPC stores
//! (`--features xrpc`), against the memory-backed reference server, with
//! every request and response validated against the lexicons. Where mls-ds
//! semantics differ from a Space they are asserted here: server order,
//! per-MEK read authorization ([CB-16], [CB-22]) and revoked transports.

#![cfg(feature = "xrpc")]

#[path = "support/lexicon.rs"]
mod lexicon;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth, MessageSource};
use labyrinth::recovery_code::ALPHABET;
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::xrpc::server::MemoryXrpcServer;
use labyrinth::store::xrpc::{
    NSID_PREFIX, XrpcDirectory, XrpcError, XrpcMailboxStore, XrpcOrf, XrpcThreadStore,
    XrpcTransport,
};
use labyrinth::store::{MailboxDirectory, TimeRange};
use labyrinth::virtual_device::Mechanism;
use lexicon::Lexicons;
use serde_json::Value;

const ALICE: &str = "did:plc:alice";
const BOB: &str = "did:plc:bob";
const CAROL: &str = "did:plc:carol";
const DAVE: &str = "did:plc:dave";
const THREAD: &str = "conv-e2e";

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

/// Validates every Labyrinth call against the lexicons; records NSIDs.
struct Validating {
    inner: Arc<dyn XrpcTransport>,
    lex: Arc<Lexicons>,
    seen: Arc<Mutex<BTreeSet<String>>>,
}

impl Validating {
    fn check(&self, nsid: &str, out: &Result<Vec<u8>, XrpcError>) {
        if !nsid.starts_with(NSID_PREFIX) {
            return;
        }
        self.seen.lock().unwrap().insert(nsid.to_owned());
        match out {
            Ok(body) => {
                let v: Value = serde_json::from_slice(body).unwrap();
                self.lex
                    .validate_output(nsid, &v)
                    .unwrap_or_else(|e| panic!("{nsid}: {e}\n{v:#}"));
            }
            Err(e) => {
                let name = e.error.as_deref().unwrap_or("");
                assert!(
                    self.lex.declares_error(nsid, name),
                    "{nsid} undeclared {name}"
                );
            }
        }
    }
}

impl XrpcTransport for Validating {
    fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, XrpcError> {
        if nsid.starts_with(NSID_PREFIX) {
            self.lex
                .validate_params(nsid, params)
                .unwrap_or_else(|e| panic!("{nsid}: {e}"));
        }
        let out = self.inner.query(nsid, params);
        self.check(nsid, &out);
        out
    }

    fn procedure(&self, nsid: &str, payload: &[u8], op: [u8; 16]) -> Result<Vec<u8>, XrpcError> {
        let v: Value = serde_json::from_slice(payload).unwrap();
        self.lex
            .validate_input(nsid, &v)
            .unwrap_or_else(|e| panic!("{nsid}: {e}\n{v:#}"));
        let out = self.inner.procedure(nsid, payload, op);
        self.check(nsid, &out);
        out
    }
}

struct World {
    server: MemoryXrpcServer,
    lex: Arc<Lexicons>,
    seen: Arc<Mutex<BTreeSet<String>>>,
    sent: Vec<(String, String, Vec<u8>)>,
    ts: u64,
}

impl World {
    fn new() -> Self {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("lexicons/blue/catbird/labyrinth");
        Self {
            // Two items per page exercises every store's paging.
            server: MemoryXrpcServer::new(MemoryBackend::new()).with_page_size(2),
            lex: Arc::new(Lexicons::load(&dir)),
            seen: Arc::default(),
            sent: Vec::new(),
            ts: 1_000,
        }
    }

    fn net(&self) -> &MemoryBackend {
        self.server.backend()
    }

    fn transport(&self, did: &str, seed: u8) -> Arc<dyn XrpcTransport> {
        Arc::new(Validating {
            inner: self.server.transport(did, tpub(seed)),
            lex: self.lex.clone(),
            seen: self.seen.clone(),
        })
    }

    /// An mls-ds mailbox; the PDS `mailboxKeys` copy goes through a
    /// publisher, and the directory cross-checks PDS and mls-ds.
    fn backends(&self, did: &str, seed: u8) -> Backends {
        let t = self.transport(did, seed);
        Backends {
            mailbox: Box::new(XrpcMailboxStore::new(did, t.clone())),
            threads: Box::new(XrpcThreadStore::new(did, t.clone())),
            directory: Box::new(CompositeDirectory::new(
                Box::new(self.net().directory()),
                Box::new(XrpcDirectory::new(t.clone())),
            )),
            orf: Box::new(XrpcOrf::new(t)),
            publishers: vec![Box::new(self.net().pds_publisher(did))],
            clock: Box::new(TestClock::default()),
        }
    }

    /// Chat device `seed` of `did` joins MLS and gets a leaf in THREAD.
    fn chat_device(&self, did: &str, seed: u8) -> Box<Ed25519Transport> {
        self.net().register_chat_device(did, tpub(seed));
        self.net().add_leaf(THREAD, did, tpub(seed));
        Box::new(signer(seed))
    }

    fn init(&self, did: &str, seed: u8) -> Labyrinth {
        let t = self.chat_device(did, seed);
        Labyrinth::initialize(did, t, self.backends(did, seed)).unwrap()
    }

    fn send(&mut self, lab: &mut Labyrinth, members: &[&str], id: &str) -> bool {
        self.ts += 10;
        self.net().set_server_time(self.ts);
        let frame = format!("frame {id} from {}", lab.did()).into_bytes();
        let roster = lab.resolve_roster(members).unwrap();
        let out = lab
            .archive_outgoing(THREAD, &roster, id, self.ts, &frame)
            .unwrap();
        self.sent.push((id.to_owned(), lab.did().to_owned(), frame));
        out.mek_written.is_some()
    }

    fn expected(&self, ids: &[&str]) -> Vec<(String, Option<String>, Vec<u8>)> {
        ids.iter()
            .map(|id| {
                let (i, s, f) = self.sent.iter().find(|(i, ..)| i == id).unwrap();
                (i.clone(), Some(s.clone()), f.clone())
            })
            .collect()
    }
}

fn read(lab: &mut Labyrinth) -> labyrinth::client::ThreadHistory {
    lab.load_thread(THREAD, TimeRange::ALL).unwrap()
}

fn got(h: &labyrinth::client::ThreadHistory) -> Vec<(String, Option<String>, Vec<u8>)> {
    h.messages
        .iter()
        .map(|m| (m.message_id.clone(), m.sender.clone(), m.frame.clone()))
        .collect()
}

fn one_typo(code: &str) -> String {
    let mut s = code.as_bytes().to_vec();
    let i = ALPHABET.iter().position(|&c| c == s[11]).unwrap();
    s[11] = ALPHABET[(i + 7) % 32];
    String::from_utf8(s).unwrap()
}

#[test]
fn full_lifecycle_over_xrpc() {
    let mut w = World::new();
    let mut phone = w.init(ALICE, 1);
    let mut responder = phone.otc_offer().unwrap();
    let typed = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(ALICE, &typed).unwrap();
    let reply = phone.otc_respond(&mut responder, &hello).unwrap();
    let (mut laptop, _) = Labyrinth::enroll_via_otc(
        ALICE,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        w.chat_device(ALICE, 2),
        w.backends(ALICE, 2),
    )
    .unwrap();
    let code = phone
        .create_recovery_code(Mechanism::Code)
        .unwrap()
        .code
        .as_str()
        .to_owned();
    let mut bob = w.init(BOB, 3);
    let mut carol = w.init(CAROL, 4);
    let group = [ALICE, BOB, CAROL];

    assert!(w.send(&mut phone, &group, "a1"));
    assert!(w.send(&mut bob, &group, "b1"));
    assert!(w.send(&mut carol, &group, "c1"));
    assert!(w.send(&mut laptop, &group, "a2"));
    assert!(!w.send(&mut bob, &group, "b2"));
    for lab in [&mut phone, &mut laptop, &mut bob, &mut carol] {
        lab.flush().unwrap();
    }
    let before = ["a1", "b1", "c1", "a2", "b2"];
    let h = read(&mut carol);
    assert_eq!(got(&h), w.expected(&before));

    // The phone is lost: removed from MLS, revoked; mls-ds refuses it.
    w.net().remove_chat_device(ALICE, tpub(1), w.ts + 1);
    w.net().remove_leaf(THREAD, ALICE, tpub(1));
    let rot = laptop
        .revoke_device(&phone.device_public().device_key_pub)
        .unwrap();
    assert_eq!(rot.new_epoch, 1);
    assert_eq!(phone.sync_epochs().unwrap_err(), Error::Forbidden);
    assert_eq!(w.net().directory().latest(ALICE).unwrap().unwrap().seq, 1);
    let ds = XrpcDirectory::new(w.transport(BOB, 3));
    assert_eq!(ds.latest(ALICE).unwrap().unwrap().seq, 1);
    let heads = ds.conversation_heads(THREAD).unwrap();
    let alice_head = heads.iter().find(|h| h.did == ALICE).unwrap();
    assert_eq!(alice_head.epoch_number, 1);
    assert_eq!(alice_head.epoch_head, laptop.latest_public().unwrap().head);

    assert!(w.send(&mut laptop, &group, "a3"));
    assert!(w.send(&mut bob, &group, "b3"));
    assert!(w.send(&mut carol, &group, "c2"));
    for lab in [&mut laptop, &mut bob, &mut carol] {
        lab.flush().unwrap();
    }

    // Restores: from an epoch-1 bundle, and from the epoch-0 code with a typo.
    let keychain = laptop.create_recovery_code(Mechanism::Keychain).unwrap();
    let (mut tablet, _) = Labyrinth::restore_with_recovery_code(
        ALICE,
        keychain.code.as_str(),
        w.chat_device(ALICE, 8),
        w.backends(ALICE, 8),
    )
    .unwrap();
    let (mut alice, _) = Labyrinth::restore_with_recovery_code(
        ALICE,
        &one_typo(&code),
        w.chat_device(ALICE, 5),
        w.backends(ALICE, 5),
    )
    .unwrap();
    assert_eq!(alice.latest_epoch(), 1);
    let all = ["a1", "b1", "c1", "a2", "b2", "a3", "b3", "c2"];
    let h = read(&mut alice);
    assert_eq!(got(&h), w.expected(&all));
    assert!(h.undecryptable.is_empty());
    assert!(h.messages.iter().all(|m| m.source == MessageSource::Sender));
    assert_eq!(got(&read(&mut tablet)), w.expected(&all));

    // Carol leaves. mls-ds keeps serving what she was addressed in, and
    // never shows her b4 ([CB-22] without re-archiving).
    w.net().remove_leaf(THREAD, CAROL, tpub(4));
    let group = [ALICE, BOB];
    assert!(w.send(&mut bob, &group, "b4"));
    bob.flush().unwrap();
    let h = read(&mut carol);
    assert_eq!(got(&h), w.expected(&all));
    assert!(h.undecryptable.is_empty());

    // Dave joins and sees only what was sent after, with nothing hidden
    // behind NotRecipient: earlier batches are never served to him.
    let mut dave = w.init(DAVE, 6);
    let group = [ALICE, BOB, DAVE];
    assert!(w.send(&mut bob, &group, "b5"));
    assert!(w.send(&mut dave, &group, "d1"));
    bob.flush().unwrap();
    dave.flush().unwrap();
    let h = read(&mut dave);
    assert_eq!(got(&h), w.expected(&["b5", "d1"]));
    assert!(h.undecryptable.is_empty());

    let everything = [&all[..], &["b4", "b5", "d1"]].concat();
    assert_eq!(got(&read(&mut alice)), w.expected(&everything));
    let h = alice
        .load_thread(
            THREAD,
            TimeRange {
                from_ms: Some(w.ts),
                until_ms: None,
            },
        )
        .unwrap();
    assert_eq!(got(&h), w.expected(&["d1"]));

    // Owner archive and ORF state over XRPC.
    alice.archive_owner(THREAD, "own-1", 5, b"note").unwrap();
    alice.flush().unwrap();
    assert!(
        read(&mut alice)
            .messages
            .iter()
            .any(|m| m.source == MessageSource::Owner && m.frame == b"note")
    );
    assert!(matches!(
        alice.orf_evaluate(b"c", b"s", b"x"),
        Err(Error::Backend(_))
    ));

    // Every Labyrinth endpoint the stores use was exercised and validated.
    let seen = w.seen.lock().unwrap();
    for name in [
        "createDevice",
        "markDeviceRevoked",
        "getDevice",
        "createEpoch",
        "getEpoch",
        "listEpochs",
        "createEpochMember",
        "listEpochMembers",
        "createVirtualDevice",
        "getVirtualDevice",
        "appendOwnerBatch",
        "listOwnerBatches",
        "createMek",
        "findMeks",
        "appendBatch",
        "listBatches",
        "publishEpochHead",
        "getEpochHead",
        "getChatDeviceKeys",
        "getMemberDevices",
        "registerOrfState",
        "deleteOrfState",
    ] {
        assert!(
            seen.contains(&format!("{NSID_PREFIX}{name}")),
            "{name} not called"
        );
    }
}

#[test]
fn passkey_restore_and_paging_over_xrpc() {
    let mut w = World::new();
    let mut phone = w.init(ALICE, 1);
    phone
        .create_passkey_recovery(&[42u8; 32], b"credential-1")
        .unwrap();
    let (mut tablet, _) = Labyrinth::restore_with_passkey(
        ALICE,
        &[42u8; 32],
        b"credential-1",
        w.chat_device(ALICE, 3),
        w.backends(ALICE, 3),
    )
    .unwrap();
    let mut bob = w.init(BOB, 4);
    for i in 0..300 {
        w.send(&mut bob, &[ALICE, BOB], &format!("m{i:03}"));
    }
    assert_eq!(bob.flush().unwrap()[0].count, 44);
    assert_eq!(read(&mut tablet).messages.len(), 300);
}

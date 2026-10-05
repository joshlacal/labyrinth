//! The `tests/e2e_memory.rs` lifecycle over the XRPC stores
//! (`--features xrpc`), against the memory-backed reference server, with
//! every request and response validated against the lexicons. Where mls-ds
//! semantics differ from a Space they are asserted here: server order,
//! per-MEK read authorization ([CB-16], [CB-22]), revoked transports, the
//! chat binding ([CB-36]), unsend and account deletion ([CB-38]),
//! attachment references ([CB-33]) and the recovery lifecycle ([CB-39]).

#![cfg(feature = "xrpc")]

#[path = "support/lexicon.rs"]
mod lexicon;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use labyrinth::Error;
use labyrinth::attachment::blind;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth, MessageSource};
use labyrinth::orf::orf_client_init;
use labyrinth::recovery_code::ALPHABET;
use labyrinth::sign::Ed25519Transport;
use labyrinth::sign::XVerifyingKey;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::xrpc::server::MemoryXrpcServer;
use labyrinth::store::xrpc::{
    NSID_PREFIX, XrpcDirectory, XrpcError, XrpcMailboxStore, XrpcOrf, XrpcThreadStore,
    XrpcTransport,
};
use labyrinth::store::{AttachmentPut, MailboxDirectory, MailboxStore, OrfServer, TimeRange};
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
            // Raw-bytes output (`*/*`): nothing to validate but the encoding.
            Ok(_) if self.lex.output_encoding(nsid) == Some("*/*") => {}
            Ok(body) => {
                assert_eq!(self.lex.output_encoding(nsid), Some("application/json"));
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

fn assert_seen(w: &World, names: &[&str]) {
    let seen = w.seen.lock().unwrap();
    for name in names {
        assert!(
            seen.contains(&format!("{NSID_PREFIX}{name}")),
            "{name} not called"
        );
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

#[test]
fn unsend_attachments_and_recovery_lifecycle_over_xrpc() {
    let mut w = World::new();
    let mut alice = w.init(ALICE, 1);
    let mut bob = w.init(BOB, 3);
    let group = [ALICE, BOB];
    w.net().put_blob("blob-1", b"gcm ciphertext");
    assert!(w.send(&mut alice, &group, "a1"));
    w.send(&mut alice, &group, "a2");
    w.send(&mut bob, &group, "b1");
    let b1_ts = w.ts;
    alice.flush().unwrap();
    bob.flush().unwrap();

    // Attachments: entitlement, one message per blob, then a restored
    // device fetches through its evolved ORF state.
    assert_eq!(
        alice.attach_reference(THREAD, "zz", "blob-1").unwrap_err(),
        Error::Forbidden
    );
    alice.attach_reference(THREAD, "a1", "blob-1").unwrap();
    assert_eq!(
        alice.attach_reference(THREAD, "a2", "blob-1").unwrap_err(),
        Error::Conflict
    );
    let keychain = alice.create_recovery_code(Mechanism::Keychain).unwrap();
    let code = alice.create_recovery_code(Mechanism::Code).unwrap();
    let (tablet, _) = Labyrinth::restore_with_recovery_code(
        ALICE,
        keychain.code.as_str(),
        w.chat_device(ALICE, 8),
        w.backends(ALICE, 8),
    )
    .unwrap();
    assert_eq!(
        tablet.fetch_attachment(THREAD, "a1", "blob-1").unwrap(),
        b"gcm ciphertext"
    );
    assert_eq!(
        tablet.fetch_attachment(THREAD, "a2", "blob-1").unwrap_err(),
        Error::NotFound("attachment")
    );

    // Recovery lifecycle: the restore touched the keychain bundle; touch
    // and remove go through touchVirtualDevice / deleteVirtualDevice.
    let kc = |lab: &Labyrinth| {
        lab.list_recovery_methods()
            .unwrap()
            .into_iter()
            .find(|m| m.vdevice_id == keychain.vdevice_id)
    };
    assert!(kc(&alice).unwrap().last_used_at_ms.is_some());
    alice.touch_recovery_method(&code.vdevice_id).unwrap();
    assert_eq!(
        alice.touch_recovery_method(&[9; 16]).unwrap_err(),
        Error::NotFound("virtual device")
    );
    let rot = alice.remove_recovery_method(&keychain.vdevice_id).unwrap();
    assert_eq!(rot.new_epoch, 1);
    assert!(kc(&alice).is_none());
    assert_eq!(alice.list_recovery_methods().unwrap().len(), 1);

    // A chat device holding no bound Labyrinth device cannot write epochs.
    w.net().register_chat_device(ALICE, tpub(9));
    let stray = XrpcMailboxStore::new(ALICE, w.transport(ALICE, 9));
    assert_eq!(
        stray.set_device_revoked(
            &tablet.device_public().device_key_pub,
            "2026-10-05T00:00:00Z"
        ),
        Err(Error::Forbidden)
    );

    // Unsend: author-only, idempotent, and it takes the attachment along.
    assert_eq!(alice.unsend(THREAD, "a1").unwrap(), 1);
    assert_eq!(alice.unsend(THREAD, "a1").unwrap(), 0);
    let h = read(&mut bob);
    assert_eq!(got(&h), w.expected(&["a2", "b1"]));
    let r = h.redacted.iter().find(|r| r.message_id == "a1").unwrap();
    assert!(r.by_author && !r.account_deleted && r.sender == ALICE);
    assert_eq!(
        tablet.fetch_attachment(THREAD, "a1", "blob-1").unwrap_err(),
        Error::NotFound("attachment")
    );

    // Delete for me hides b1 from Bob only.
    bob.delete_for_me(THREAD, "b1", b1_ts, Some(BOB), &[])
        .unwrap();
    assert_eq!(read(&mut bob).deleted_for_me, ["b1"]);
    assert!(
        read(&mut alice)
            .messages
            .iter()
            .any(|m| m.message_id == "b1")
    );

    // The raw ORF wrappers: put, getAttachmentRef, delete.
    let orf = XrpcOrf::new(w.transport(ALICE, 1));
    let dev = XVerifyingKey([7; 32]);
    orf.register(&dev, None).unwrap();
    w.net().put_blob("blob-2", b"two");
    let state = orf_client_init().unwrap();
    let (bi, bt) = blind(&state, THREAD, "blob-2");
    assert_eq!(orf.attachment_ref_created_at(&dev, &bi).unwrap(), None);
    orf.put_attachment_ref(
        &dev,
        &AttachmentPut {
            blinded_index: bi,
            blinded_token_salt: bt,
            blob_id: "blob-2".into(),
            thread_id: THREAD.into(),
            message_id: "a2".into(),
        },
    )
    .unwrap();
    assert_eq!(
        orf.attachment_ref_created_at(&dev, &bi).unwrap(),
        Some(w.ts)
    );
    orf.delete_attachment_ref(&dev, &bi).unwrap();
    orf.delete_attachment_ref(&dev, &bi).unwrap(); // idempotent
    assert_eq!(orf.attachment_ref_created_at(&dev, &bi).unwrap(), None);

    assert_seen(
        &w,
        &[
            "redactMessage",
            "touchVirtualDevice",
            "deleteVirtualDevice",
            "markDeviceRevoked",
            "putAttachmentRef",
            "getAttachmentRef",
            "getAttachmentBlob",
            "deleteAttachmentRef",
        ],
    );
}

#[test]
fn account_purge_over_xrpc_is_server_side() {
    let mut w = World::new();
    let mut alice = w.init(ALICE, 1);
    let mut bob = w.init(BOB, 3);
    let group = [ALICE, BOB];
    w.send(&mut alice, &group, "a1");
    w.send(&mut alice, &group, "a2");
    w.send(&mut bob, &group, "b1");
    alice.flush().unwrap();
    bob.flush().unwrap();
    alice.create_recovery_code(Mechanism::Code).unwrap();

    // mls-ds has no listThreads, so the client hands the redaction and
    // purge to deleteAccountData after retracting the PDS copy.
    let report = alice.purge_account().unwrap();
    assert!(report.server_side);
    assert_eq!(report.publishers_not_retracted, 0);
    let h = read(&mut bob);
    assert_eq!(got(&h), w.expected(&["b1"]));
    assert_eq!(h.redacted.len(), 2);
    assert!(
        h.redacted
            .iter()
            .all(|r| r.sender == ALICE && r.account_deleted && !r.by_author)
    );
    // Both directories forgot Alice, and her mailbox is empty.
    assert!(w.net().directory().latest(ALICE).unwrap().is_none());
    let ds = XrpcDirectory::new(w.transport(BOB, 3));
    assert!(ds.latest(ALICE).unwrap().is_none());
    let mb = XrpcMailboxStore::new(ALICE, w.transport(ALICE, 1));
    assert!(mb.list_devices().unwrap().is_empty());
    assert!(mb.list_virtual_devices().unwrap().is_empty());

    // purgeMailbox alone keeps thread records; Bob purges and re-enrolls.
    mb.purge_mailbox().unwrap();
    XrpcMailboxStore::new(BOB, w.transport(BOB, 3))
        .purge_mailbox()
        .unwrap();
    assert_eq!(got(&read(&mut alice)).len(), 0);
    let mut bob2 = Labyrinth::initialize(BOB, Box::new(signer(3)), w.backends(BOB, 3)).unwrap();
    assert_eq!(bob2.latest_epoch(), 0);
    let h = read(&mut bob2);
    assert!(h.messages.is_empty());

    assert_seen(&w, &["deleteAccountData", "purgeMailbox"]);
}

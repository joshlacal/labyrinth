//! The client lifecycle with every account's mailbox in a personal atproto
//! Space (`--features space`), against the reference Space host, with
//! every `com.atproto.space.*` request and response validated against the
//! vendored lexicons (`tests/vectors/atproto-space/`, upstream
//! `permissioned-data` at `5b95b2f2`) and every record value against ours.
//! Threads, the ORF and the mls-ds head directory stay on the memory
//! backend, as they stay on mls-ds in production; the directory is the
//! production composition: PDS `mailboxKeys` × mls-ds heads ([CB-28]).

#![cfg(feature = "space")]

#[path = "support/lexicon.rs"]
mod lexicon;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth, MessageSource};
use labyrinth::records::{Device, Epoch, EpochMember, nsid};
use labyrinth::recovery_code::ALPHABET;
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef};
use labyrinth::store::xrpc::{XrpcError, XrpcTransport};
use labyrinth::store::{MailboxDirectory, MailboxStore, TimeRange};
use labyrinth::virtual_device::Mechanism;
use lexicon::Lexicons;
use serde_json::Value;

const ALICE: &str = "did:plc:alice";
const BOB: &str = "did:plc:bob";
const CAROL: &str = "did:plc:carol";
const DAVE: &str = "did:plc:dave";
const THREAD: &str = "conv-space";
const SPACE_PREFIX: &str = "com.atproto.space.";
/// Small pages, so every listing follows `cursor`.
const PAGE: usize = 2;

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

/// Validates every Space call against the lexicons; records NSIDs.
struct Validating {
    inner: Arc<dyn XrpcTransport>,
    lex: Arc<Lexicons>,
    seen: Arc<Mutex<BTreeSet<String>>>,
}

impl Validating {
    fn check(&self, nsid: &str, out: &Result<Vec<u8>, XrpcError>) {
        assert!(nsid.starts_with(SPACE_PREFIX), "{nsid}");
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
                    self.lex.declares_error(nsid, name) || name == "Forbidden",
                    "{nsid} undeclared {name}"
                );
            }
        }
    }
}

impl XrpcTransport for Validating {
    fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<Vec<u8>, XrpcError> {
        self.lex
            .validate_params(nsid, params)
            .unwrap_or_else(|e| panic!("{nsid}: {e}"));
        let out = self.inner.query_with_headers(nsid, params, headers);
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
    net: MemoryBackend,
    host: MemorySpaceHost,
    lex: Arc<Lexicons>,
    seen: Arc<Mutex<BTreeSet<String>>>,
    clock: TestClock,
    sent: Vec<(String, String, Vec<u8>)>,
    ts: u64,
}

impl World {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let lex = Lexicons::load(&root.join("lexicons/blue/catbird/labyrinth"))
            .with(&root.join("tests/vectors/atproto-space"));
        let host = MemorySpaceHost::new();
        for did in [ALICE, BOB, CAROL, DAVE] {
            host.create_space(&SpaceRef::mailbox(did));
        }
        Self {
            net: MemoryBackend::new(),
            host,
            lex: Arc::new(lex),
            seen: Arc::default(),
            clock: TestClock::default(),
            sent: Vec::new(),
            ts: 1_000,
        }
    }

    /// `as_did`'s OAuth session on the host, validated.
    fn transport(&self, as_did: &str) -> Arc<dyn XrpcTransport> {
        Arc::new(Validating {
            inner: Arc::new(self.host.client(as_did)),
            lex: self.lex.clone(),
            seen: self.seen.clone(),
        })
    }

    fn mailbox(&self, did: &str) -> SpaceMailboxStore {
        let clock = self.clock.clone();
        SpaceMailboxStore::new(
            did,
            self.transport(did),
            Box::new(self.net.pds_publisher(did)),
        )
        .with_page_size(PAGE)
        .with_clock(Arc::new(move || clock.now_ms()))
    }

    fn directory(&self) -> CompositeDirectory {
        CompositeDirectory::new(
            Box::new(self.net.directory()),
            Box::new(self.net.ds_directory()),
        )
    }

    fn backends(&self, did: &str) -> Backends {
        Backends {
            mailbox: Box::new(self.mailbox(did)),
            threads: Box::new(self.net.threads(did)),
            directory: Box::new(self.directory()),
            orf: Box::new(self.net.orf(did)),
            publishers: vec![Box::new(self.net.ds_publisher(did))],
            clock: Box::new(self.clock.clone()),
        }
    }

    fn chat_device(&self, did: &str, seed: u8) -> Box<Ed25519Transport> {
        self.net.register_chat_device(did, tpub(seed));
        Box::new(signer(seed))
    }

    fn init(&self, did: &str, seed: u8) -> Labyrinth {
        Labyrinth::initialize(did, self.chat_device(did, seed), self.backends(did)).unwrap()
    }

    fn send(&mut self, lab: &mut Labyrinth, members: &[&str], id: &str) -> bool {
        self.ts += 10;
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

    fn count(&self, did: &str, collection: Option<&str>) -> usize {
        self.host
            .record_count(&SpaceRef::mailbox(did), did, collection)
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

fn ids(h: &labyrinth::client::ThreadHistory) -> Vec<&str> {
    h.messages.iter().map(|m| m.message_id.as_str()).collect()
}

fn one_typo(code: &str) -> String {
    let mut s = code.as_bytes().to_vec();
    let i = ALPHABET.iter().position(|&c| c == s[11]).unwrap();
    s[11] = ALPHABET[(i + 7) % 32];
    String::from_utf8(s).unwrap()
}

#[test]
fn full_lifecycle_in_spaces() {
    let mut w = World::new();
    let space = SpaceRef::mailbox(ALICE);

    // Alice: phone (genesis), laptop via one-time code, recovery code.
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
        w.backends(ALICE),
    )
    .unwrap();
    let recovery = phone.create_recovery_code(Mechanism::Code).unwrap();
    let code = recovery.code.as_str().to_owned();
    // The mailbox lives in Alice's Space; its head in both directories.
    assert_eq!(w.count(ALICE, Some(nsid::DEVICE)), 3);
    assert_eq!(w.count(ALICE, Some(nsid::EPOCH)), 1);
    assert_eq!(w.count(ALICE, Some(nsid::VIRTUAL_DEVICE)), 1);
    assert_eq!(w.net.directory().latest(ALICE).unwrap().unwrap().seq, 0);
    assert_eq!(w.net.ds_directory().latest(ALICE).unwrap().unwrap().seq, 0);

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
    assert_eq!(got(&read(&mut carol)), w.expected(&before));

    // The phone is lost: the laptop revokes it (an `#update` of its device
    // record) and opens epoch 1.
    w.net.remove_chat_device(ALICE, tpub(1), w.ts + 1);
    let phone_key = phone.device_public().device_key_pub;
    let rot = laptop.revoke_device(&phone_key).unwrap();
    assert_eq!(rot.new_epoch, 1);
    assert_eq!(phone.sync_epochs().unwrap_err(), Error::NotEpochMember);
    let rec = w
        .host
        .record(&space, ALICE, nsid::DEVICE, &hex::encode(phone_key.0))
        .unwrap();
    assert!(rec["revokedAt"].is_string());
    assert_eq!(w.net.directory().latest(ALICE).unwrap().unwrap().seq, 1);
    assert_eq!(w.net.ds_directory().latest(ALICE).unwrap().unwrap().seq, 1);

    assert!(w.send(&mut laptop, &group, "a3"));
    assert!(w.send(&mut bob, &group, "b3"));
    assert!(w.send(&mut carol, &group, "c2"));
    for lab in [&mut laptop, &mut bob, &mut carol] {
        lab.flush().unwrap();
    }

    // A new device restores from the code (with a typo) and reads it all;
    // restoring stamps the bundle's `lastUsedAt` in the Space.
    let (mut alice, _) = Labyrinth::restore_with_recovery_code(
        ALICE,
        &one_typo(&code),
        w.chat_device(ALICE, 5),
        w.backends(ALICE),
    )
    .unwrap();
    assert_eq!(alice.latest_epoch(), 1);
    let all = ["a1", "b1", "c1", "a2", "b2", "a3", "b3", "c2"];
    let h = read(&mut alice);
    assert_eq!(got(&h), w.expected(&all));
    assert!(h.undecryptable.is_empty());
    let vrec = w
        .host
        .record(
            &space,
            ALICE,
            nsid::VIRTUAL_DEVICE,
            &hex::encode(recovery.vdevice_id),
        )
        .unwrap();
    assert!(vrec["lastUsedAt"].is_string());
    let methods = alice.list_recovery_methods().unwrap();
    assert!(methods[0].last_used_at_ms.is_some());

    // Carol re-archives into her own Space (PDS-assigned TIDs), leaves,
    // and still reads the thread from there.
    assert_eq!(
        carol.rearchive_thread_before_leave(THREAD).unwrap(),
        all.len()
    );
    assert!(w.count(CAROL, Some(nsid::OWNER_BATCH)) >= 1);
    assert_eq!(
        w.mailbox(CAROL).list_owner_threads().unwrap(),
        vec![THREAD.to_owned()]
    );
    w.net.revoke_thread_access(THREAD, CAROL);
    let h = read(&mut carol);
    assert!(!h.space_readable);
    assert_eq!(ids(&h), all);
    assert!(h.messages.iter().all(|m| m.source == MessageSource::Owner));

    // A PDS that hides epoch 1 is caught against the mls-ds heads.
    let hidden = w
        .host
        .remove(&space, ALICE, nsid::EPOCH, "000000000001")
        .unwrap();
    let err = Labyrinth::restore_with_recovery_code(
        ALICE,
        &code,
        w.chat_device(ALICE, 7),
        w.backends(ALICE),
    )
    .unwrap_err();
    assert_eq!(
        err,
        Error::EpochTruncated {
            published: 1,
            reached: 0
        }
    );
    w.host
        .tamper(&space, ALICE, nsid::EPOCH, "000000000001", hidden);

    // Removing the recovery method rotates and deletes its bundle.
    let rot = alice.remove_recovery_method(&recovery.vdevice_id).unwrap();
    assert_eq!(rot.new_epoch, 2);
    assert_eq!(w.count(ALICE, Some(nsid::VIRTUAL_DEVICE)), 0);
    assert_eq!(got(&read(&mut alice)), w.expected(&all));

    // Account deletion empties the Space and retracts both directories.
    let report = alice.purge_account().unwrap();
    assert!(report.remote_pending.is_none(), "{report:?}");
    assert_eq!(w.count(ALICE, None), 0);
    assert!(w.net.directory().latest(ALICE).unwrap().is_none());
    assert!(w.net.ds_directory().latest(ALICE).unwrap().is_none());

    let seen = w.seen.lock().unwrap();
    for name in ["applyWrites", "getRecord", "listRecords", "deleteRecord"] {
        assert!(
            seen.contains(&format!("{SPACE_PREFIX}{name}")),
            "{name} not called"
        );
    }
}

#[test]
fn space_store_semantics() {
    let w = World::new();
    let _alice = w.init(ALICE, 1);
    let space = SpaceRef::mailbox(ALICE);
    let mb = w.mailbox(ALICE);
    let device: Device = mb.list_devices().unwrap().remove(0);
    let epoch: Epoch = mb.get_epoch(0).unwrap().unwrap().value;
    let member: EpochMember = mb.list_epoch_members(0).unwrap().remove(0);
    let key = labyrinth::sign::XVerifyingKey(device.device_key_pubkey.array("key").unwrap());

    // Create-if-absent.
    assert_eq!(mb.create_device(&device).unwrap_err(), Error::Conflict);
    assert_eq!(
        mb.create_epoch_member(&member).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        mb.get_epoch_member(0, &key).unwrap().as_ref(),
        Some(&member)
    );

    // An epoch is all-or-nothing: a clashing member leaves no epoch behind.
    let mut e1 = epoch.clone();
    e1.public.epoch_number = 1;
    let mut m1 = member.clone();
    m1.epoch_number = 1;
    w.host.tamper(
        &space,
        ALICE,
        nsid::EPOCH_MEMBER,
        &m1.rkey(),
        serde_json::to_value(&m1).unwrap(),
    );
    let before = w.count(ALICE, None);
    assert_eq!(
        mb.create_epoch(&e1, std::slice::from_ref(&m1)).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(w.count(ALICE, None), before);
    assert!(mb.get_epoch(1).unwrap().is_none());
    // Members of another epoch are refused before any write.
    assert_eq!(
        mb.create_epoch(&e1, std::slice::from_ref(&member))
            .unwrap_err(),
        Error::Conflict
    );
    // More than one applyWrites can carry is refused, not split.
    let many = vec![m1.clone(); 200];
    assert!(matches!(
        mb.create_epoch(&e1, &many).unwrap_err(),
        Error::Backend(_)
    ));
    // A member for an epoch that does not exist.
    let mut m9 = member.clone();
    m9.epoch_number = 9;
    assert_eq!(
        mb.create_epoch_member(&m9).unwrap_err(),
        Error::NotFound("epoch")
    );

    // Revocation is set once.
    mb.set_device_revoked(&key, "2026-10-11T00:00:00.000Z")
        .unwrap();
    mb.set_device_revoked(&key, "2026-10-12T00:00:00.000Z")
        .unwrap();
    assert_eq!(
        mb.get_device(&key).unwrap().unwrap().revoked_at.as_deref(),
        Some("2026-10-11T00:00:00.000Z")
    );

    // read_self only: Bob's session sees no repo in Alice's Space and
    // cannot write there.
    let as_bob = SpaceMailboxStore::in_space(
        space.clone(),
        w.transport(BOB),
        Box::new(w.net.pds_publisher(BOB)),
    );
    assert!(as_bob.list_devices().unwrap().is_empty());
    assert!(as_bob.get_epoch(0).unwrap().is_none());
    assert_eq!(as_bob.create_device(&device).unwrap_err(), Error::Forbidden);

    // An account whose Space was never created.
    let host = MemorySpaceHost::new();
    let nowhere = SpaceMailboxStore::new(
        DAVE,
        Arc::new(host.client(DAVE)),
        Box::new(w.net.pds_publisher(DAVE)),
    );
    assert_eq!(
        nowhere.list_devices().unwrap_err(),
        Error::NotFound("space")
    );
    // A Space with no writes yet reads as empty.
    host.create_space(&SpaceRef::mailbox(DAVE));
    assert!(nowhere.list_devices().unwrap().is_empty());
    assert!(nowhere.get_virtual_device(&[0; 16]).unwrap().is_none());
    assert_eq!(nowhere.list_owner_threads().unwrap(), Vec::<String>::new());
}

#[test]
fn space_ref_round_trips() {
    let r = SpaceRef::mailbox(ALICE);
    let s = r.to_string();
    assert_eq!(
        s,
        "at://did:plc:alice/space/blue.catbird.labyrinth.mailbox/self"
    );
    assert_eq!(SpaceRef::parse(&s).unwrap(), r);
    for bad in [
        "did:plc:alice/space/x/y",
        "at://did:plc:alice/space/x",
        "at://did:plc:alice/space/x/y/did:plc:bob/c/k",
        "at://alice.test/space/x/y",
    ] {
        assert!(SpaceRef::parse(bad).is_err(), "{bad}");
    }
}

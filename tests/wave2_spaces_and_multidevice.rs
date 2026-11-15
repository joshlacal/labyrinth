//! Wave 2 integration tests: Nov-12 `com.atproto.space.*` / `com.atproto.memberspace.*`
//! wire contract, RFC 9421 + HPKE `0xFFFF` Export MACs, STAR v0.2 `getRepo`,
//! multi-device `{seq:016x}-{dev8}-{tid}` batch keys, `409 ConcurrentWrite`
//! jitter retries, persisted per-writer `repoRev` rollback floors, and encrypted
//! `readState` / `circleOwnerState` OwnerMailbox CRDT & CAS semantics.

#[path = "support/lexicon.rs"]
mod lexicon;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{
    ACL_REMOVE_PENDING_ROTATED, Backends, CircleOwnerState, Clock, CompositeDirectory, Labyrinth,
    StateSink,
};
use labyrinth::records::{Batch, ReadStateRecord, nsid};
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::thread::SpaceThreadStore;
use labyrinth::store::space::{
    MemberAccess, SpaceError, SpaceMailboxStore, SpaceRef, SpaceRpc, WriterUpdate, map_space_error,
};
use labyrinth::store::{MailboxStore, ThreadStore, TimeRange};
use lexicon::Lexicons;
use serde_json::Value;

const ALICE: &str = "did:plc:alice";
const BOB: &str = "did:plc:bob";
const CAROL: &str = "did:plc:carol";
const THREAD: &str = "conv-wave2";

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        1_795_000_000_000 + self.0.fetch_add(1, Ordering::Relaxed)
    }
}

#[derive(Clone)]
struct FrozenClock(u64);
impl Clock for FrozenClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Default)]
struct MemorySink(Arc<Mutex<Vec<u8>>>);
impl StateSink for MemorySink {
    fn save_state(&self, exported_state: &[u8]) -> labyrinth::Result<()> {
        *self.0.lock().unwrap() = exported_state.to_vec();
        Ok(())
    }
}

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

fn tpub(seed: u8) -> [u8; 32] {
    signer(seed).0.verifying_key().to_bytes()
}

struct Validating {
    inner: Arc<dyn SpaceRpc>,
    lex: Arc<Lexicons>,
    seen: Arc<Mutex<BTreeSet<String>>>,
}

impl Validating {
    fn check(&self, nsid: &str, out: &Result<Vec<u8>, SpaceError>) {
        assert!(
            nsid.starts_with("com.atproto.space.") || nsid.starts_with("com.atproto.memberspace."),
            "unexpected nsid {nsid}"
        );
        self.seen.lock().unwrap().insert(nsid.to_owned());
        match out {
            Ok(body) => match self.lex.output_encoding(nsid) {
                Some("application/json") => {
                    let v: Value = serde_json::from_slice(body).unwrap();
                    self.lex
                        .validate_output(nsid, &v)
                        .unwrap_or_else(|e| panic!("{nsid}: {e}\n{v:#}"));
                }
                Some("application/vnd.dasl.star") => {
                    assert!(!body.is_empty(), "{nsid}: empty STAR archive");
                }
                None => {
                    assert!(body.is_empty(), "{nsid}: expected empty output");
                }
                Some(enc) => panic!("{nsid}: unexpected output encoding {enc}"),
            },
            Err(e) => {
                let name = e.error.as_deref().unwrap_or("");
                assert!(
                    self.lex.declares_error(nsid, name)
                        || name == "Forbidden"
                        || name == "ConcurrentWrite",
                    "{nsid} undeclared error {name}"
                );
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SpaceRpc for Validating {
    async fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, SpaceError> {
        self.lex
            .validate_params(nsid, params)
            .unwrap_or_else(|e| panic!("{nsid}: {e}"));
        let out = self.inner.query(nsid, params).await;
        self.check(nsid, &out);
        out
    }

    async fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<(Vec<(String, String)>, Vec<u8>), SpaceError> {
        self.lex
            .validate_params(nsid, params)
            .unwrap_or_else(|e| panic!("{nsid}: {e}"));
        let out = self.inner.query_with_headers(nsid, params, headers).await;
        let body_res = out.as_ref().map(|(_, b)| b.clone()).map_err(Clone::clone);
        self.check(nsid, &body_res);
        out
    }

    async fn procedure(&self, nsid: &str, payload: &[u8]) -> Result<Vec<u8>, SpaceError> {
        let v: Value = serde_json::from_slice(payload).unwrap();
        self.lex
            .validate_input(nsid, &v)
            .unwrap_or_else(|e| panic!("{nsid}: {e}\n{v:#}"));
        let out = self.inner.procedure(nsid, payload).await;
        self.check(nsid, &out);
        out
    }

    async fn upload_blob(&self, bytes: &[u8], mime_type: &str) -> Result<String, SpaceError> {
        self.inner.upload_blob(bytes, mime_type).await
    }

    async fn get_blob(&self, space: &str, did: &str, cid: &str) -> Result<Vec<u8>, SpaceError> {
        self.inner.get_blob(space, did, cid).await
    }

    async fn host_kem_did_key(&self, space: &str) -> Result<Option<String>, SpaceError> {
        self.inner.host_kem_did_key(space).await
    }
}

struct SpaceHarness {
    net: MemoryBackend,
    host: MemorySpaceHost,
    lex: Arc<Lexicons>,
    seen: Arc<Mutex<BTreeSet<String>>>,
    clock: TestClock,
    conv_space: SpaceRef,
}

impl SpaceHarness {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let lex = Lexicons::load(&root.join("lexicons/blue/catbird/labyrinth"))
            .with(&root.join("tests/vectors/atproto-space"));
        let host = MemorySpaceHost::new();
        let conv_space = SpaceRef::conversation(ALICE, THREAD);
        host.grant_space_member(&conv_space, ALICE);
        host.grant_space_member(&conv_space, BOB);
        host.grant_space_member(&conv_space, CAROL);
        Self {
            net: MemoryBackend::new(),
            host,
            lex: Arc::new(lex),
            seen: Arc::default(),
            clock: TestClock::default(),
            conv_space,
        }
    }

    fn transport(&self, did: &str) -> Arc<dyn SpaceRpc> {
        Arc::new(Validating {
            inner: self.host.client(did).into(),
            lex: self.lex.clone(),
            seen: self.seen.clone(),
        })
    }

    fn mailbox(&self, did: &str) -> SpaceMailboxStore {
        let clock = self.clock.clone();
        SpaceMailboxStore::for_owner(
            did,
            self.transport(did),
            Box::new(self.net.pds_publisher(did)),
        )
        .with_page_size(2)
        .with_clock(Arc::new(move || clock.now_ms()))
    }

    fn threads(&self, did: &str, device_seed: u8) -> SpaceThreadStore {
        let clock = self.clock.clone();
        let store = SpaceThreadStore::new(self.transport(did), did)
            .with_page_size(2)
            .with_device_pubkey(&tpub(device_seed))
            .with_clock(Arc::new(move || clock.now_ms()));
        store.set_thread_space(THREAD, self.conv_space.clone());
        store
    }

    fn directory(&self) -> CompositeDirectory {
        CompositeDirectory::new(
            Box::new(self.net.directory()),
            Box::new(self.net.ds_directory()),
        )
    }

    fn backends(&self, did: &str, device_seed: u8) -> Backends {
        Backends {
            mailbox: Box::new(self.mailbox(did)),
            threads: Box::new(self.threads(did, device_seed)),
            directory: Box::new(self.directory()),
            publishers: vec![Box::new(self.net.ds_publisher(did))],
            clock: Box::new(self.clock.clone()),
        }
    }

    fn init(&self, did: &str, seed: u8) -> Labyrinth {
        self.net.register_chat_device(did, tpub(seed));
        block_on(Labyrinth::initialize(
            did,
            Box::new(signer(seed)),
            self.backends(did, seed),
        ))
        .unwrap()
    }

    fn enroll_sibling(
        &self,
        primary: &mut Labyrinth,
        did: &str,
        seed: u8,
        b: Backends,
    ) -> Labyrinth {
        self.net.register_chat_device(did, tpub(seed));
        let mut responder = primary.otc_offer().unwrap();
        let typed = responder.code().as_str().to_owned();
        let (initiator, hello) = Labyrinth::otc_start(did, &typed).unwrap();
        let reply = block_on(primary.otc_respond(&mut responder, &hello)).unwrap();
        let (sibling, _) = block_on(Labyrinth::enroll_via_otc(
            did,
            initiator,
            &reply.message,
            &reply.sealed_payload,
            Box::new(signer(seed)),
            b,
        ))
        .unwrap();
        block_on(primary.sync_epochs()).unwrap();
        sibling
    }
}

#[test]
fn nov12_list_writers_memberspace_authorize_mac_and_star_end_to_end() {
    let h = SpaceHarness::new();
    let mut alice = h.init(ALICE, 1);
    let mut bob = h.init(BOB, 2);
    let _carol = h.init(CAROL, 3);

    let alice_threads = h.threads(ALICE, 1);
    let circle_space =
        SpaceRef::parse_hedged("at:space/did:plc:alice/blue.catbird.circles.circle/close-friends")
            .unwrap();
    assert_eq!(
        circle_space.to_string(),
        "at://did:plc:alice/space/blue.catbird.circles.circle/close-friends"
    );

    // Batched memberspace ACL management + authorizeSpaceSync.
    block_on(alice_threads.put_members(
        THREAD,
        &[
            MemberAccess {
                did: ALICE.to_owned(),
                read: true,
                write: true,
            },
            MemberAccess {
                did: BOB.to_owned(),
                read: true,
                write: true,
            },
            MemberAccess {
                did: CAROL.to_owned(),
                read: true,
                write: true,
            },
        ],
    ))
    .unwrap();
    let members = block_on(alice_threads.list_members(THREAD)).unwrap();
    assert_eq!(members.len(), 3);

    let host_kem = h.host.kem_did_key();
    let sync_auth = block_on(alice_threads.authorize_space_sync(THREAD, &host_kem, None)).unwrap();
    assert!(!sync_auth.credential.is_empty());

    // Alice and Bob write batches to the conversation Space.
    let roster = block_on(alice.resolve_roster(&[ALICE, BOB, CAROL])).unwrap();
    block_on(alice.archive_outgoing(THREAD, &roster, "m-alice-1", 1_010, b"hello from alice"))
        .unwrap();
    let flushed_alice = block_on(alice.flush()).unwrap();
    assert_eq!(flushed_alice.len(), 1);
    let alice_batch_rkey = flushed_alice[0].rkey.clone();

    let bob_roster = block_on(bob.resolve_roster(&[ALICE, BOB, CAROL])).unwrap();
    block_on(bob.archive_outgoing(THREAD, &bob_roster, "m-bob-1", 1_020, b"hello from bob"))
        .unwrap();
    block_on(bob.flush()).unwrap();

    // Remove Bob via memberspace.removeMembers -> listWriters surfaces #repoWrite for Alice and #repoRemoved for Bob.
    block_on(alice_threads.remove_members(THREAD, &[BOB.to_owned()])).unwrap();
    let writers = block_on(alice_threads.list_writers(&h.conv_space)).unwrap();
    assert!(
        writers
            .iter()
            .any(|w| matches!(w, WriterUpdate::RepoWrite { repo, .. } if repo == ALICE))
    );
    assert!(
        writers
            .iter()
            .any(|w| matches!(w, WriterUpdate::RepoRemoved { repo, .. } if repo == BOB))
    );

    // Authenticated getRecord (RFC 9421 + HPKE 0xFFFF Export MAC: Atproto-Space-Record).
    let (cid, fetched_batch): (String, Batch) = block_on(alice_threads.get_record_authenticated(
        THREAD,
        ALICE,
        nsid::BATCH,
        &alice_batch_rkey,
        &host_kem,
    ))
    .unwrap()
    .expect("authenticated record present");
    assert!(!cid.is_empty());
    assert_eq!(fetched_batch.thread_id, THREAD);

    // Authenticated STAR v0.2 getRepo (RFC 9421 + HPKE 0xFFFF Export MAC: Atproto-Space-Commit + LtHash).
    let star_repo =
        block_on(alice_threads.get_repo_star_authenticated(THREAD, ALICE, &host_kem)).unwrap();
    assert_eq!(star_repo.repo, ALICE);
    assert!(
        star_repo
            .records
            .iter()
            .any(|r| r.collection == nsid::BATCH && r.rkey == alice_batch_rkey)
    );

    // Negative check: tampering with MAC headers or STAR archive bytes fails closed.
    struct TamperedMacTransport {
        inner: Arc<dyn SpaceRpc>,
    }
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl SpaceRpc for TamperedMacTransport {
        async fn query(
            &self,
            nsid: &str,
            params: &[(&str, String)],
        ) -> Result<Vec<u8>, SpaceError> {
            self.inner.query(nsid, params).await
        }
        async fn query_with_headers(
            &self,
            nsid: &str,
            params: &[(&str, String)],
            headers: &[(String, String)],
        ) -> Result<(Vec<(String, String)>, Vec<u8>), SpaceError> {
            let (mut resp_headers, mut body) =
                self.inner.query_with_headers(nsid, params, headers).await?;
            if nsid == "com.atproto.space.getRecord" {
                for (k, v) in &mut resp_headers {
                    if k.eq_ignore_ascii_case("signature") && v.len() > 8 {
                        let mut bytes = v.clone().into_bytes();
                        bytes[6] ^= 0x01;
                        *v = String::from_utf8(bytes).unwrap();
                    }
                }
            } else if nsid == "com.atproto.space.getRepo"
                && let Some(last) = body.last_mut()
            {
                *last ^= 0xff;
            }
            Ok((resp_headers, body))
        }
        async fn procedure(&self, nsid: &str, payload: &[u8]) -> Result<Vec<u8>, SpaceError> {
            self.inner.procedure(nsid, payload).await
        }
        async fn upload_blob(&self, bytes: &[u8], mime_type: &str) -> Result<String, SpaceError> {
            self.inner.upload_blob(bytes, mime_type).await
        }
        async fn get_blob(&self, space: &str, did: &str, cid: &str) -> Result<Vec<u8>, SpaceError> {
            self.inner.get_blob(space, did, cid).await
        }
    }

    let tampered_store = SpaceThreadStore::new(
        Arc::new(TamperedMacTransport {
            inner: h.transport(ALICE),
        }) as Arc<dyn SpaceRpc>,
        ALICE,
    );
    tampered_store.set_thread_space(THREAD, h.conv_space.clone());
    let bad_rec = block_on(tampered_store.get_record_authenticated::<Batch>(
        THREAD,
        ALICE,
        nsid::BATCH,
        &alice_batch_rkey,
        &host_kem,
    ));
    assert_eq!(bad_rec, Err(Error::BadSignature));

    let bad_star = block_on(tampered_store.get_repo_star_authenticated(THREAD, ALICE, &host_kem));
    assert!(bad_star.is_err());

    let seen = h.seen.lock().unwrap().clone();
    for expected_nsid in [
        "com.atproto.memberspace.putMembers",
        "com.atproto.memberspace.listMembers",
        "com.atproto.memberspace.removeMembers",
        "com.atproto.space.authorizeSpaceSync",
        "com.atproto.space.listWriters",
        "com.atproto.space.getRecord",
        "com.atproto.space.getRepo",
    ] {
        assert!(
            seen.contains(expected_nsid),
            "missing validated call {expected_nsid}"
        );
    }
}

#[test]
fn multidevice_batch_rkey_includes_device_tag_and_never_collides_at_same_seq_and_ms() {
    let h = SpaceHarness::new();
    let mut phone = h.init(ALICE, 11);
    let _bob = h.init(BOB, 22);

    let frozen_ms = 1_795_555_000_000u64;
    let make_frozen_backends = |dev_tag: [u8; 4]| -> Backends {
        let mailbox = SpaceMailboxStore::for_owner(
            ALICE,
            h.transport(ALICE),
            Box::new(h.net.pds_publisher(ALICE)),
        )
        .with_clock(Arc::new(move || frozen_ms));
        let threads = SpaceThreadStore::new(h.transport(ALICE), ALICE)
            .with_device_tag(dev_tag)
            .with_clock(Arc::new(move || frozen_ms));
        threads.set_thread_space(THREAD, h.conv_space.clone());
        Backends {
            mailbox: Box::new(mailbox),
            threads: Box::new(threads),
            directory: Box::new(h.directory()),
            publishers: vec![Box::new(h.net.ds_publisher(ALICE))],
            clock: Box::new(FrozenClock(frozen_ms)),
        }
    };

    let mut tablet = h.enroll_sibling(
        &mut phone,
        ALICE,
        12,
        make_frozen_backends([0xaa, 0xbb, 0xcc, 0xdd]),
    );

    let phone_state = phone.export_state().unwrap();
    let mut phone_frozen = block_on(Labyrinth::from_state(
        &phone_state,
        ALICE,
        Box::new(signer(11)),
        make_frozen_backends([0x11, 0x22, 0x33, 0x44]),
    ))
    .unwrap();

    let roster_a = block_on(phone_frozen.resolve_roster(&[ALICE, BOB])).unwrap();
    let roster_b = block_on(tablet.resolve_roster(&[ALICE, BOB])).unwrap();
    block_on(phone_frozen.archive_outgoing(
        THREAD,
        &roster_a,
        "msg-phone",
        frozen_ms,
        b"from phone",
    ))
    .unwrap();
    block_on(tablet.archive_outgoing(
        THREAD,
        &roster_b,
        "msg-tablet",
        frozen_ms + 1,
        b"from tablet",
    ))
    .unwrap();

    let f_phone = block_on(phone_frozen.flush()).unwrap();
    let f_tablet = block_on(tablet.flush()).unwrap();
    assert_eq!(f_phone.len(), 1);
    assert_eq!(f_tablet.len(), 1);

    let rkey_a = &f_phone[0].rkey;
    let rkey_b = &f_tablet[0].rkey;
    assert_ne!(
        rkey_a, rkey_b,
        "sibling devices must not collide on batch rkey"
    );
    let parts_a: Vec<&str> = rkey_a.split('-').collect();
    let parts_b: Vec<&str> = rkey_b.split('-').collect();
    assert_eq!(
        parts_a.len(),
        3,
        "expected <seq16>-<dev8>-<tid>, got {rkey_a}"
    );
    assert_eq!(
        parts_b.len(),
        3,
        "expected <seq16>-<dev8>-<tid>, got {rkey_b}"
    );
    assert_eq!(parts_a[0], "0000000000000000");
    assert_eq!(parts_b[0], "0000000000000000");
    assert_eq!(parts_a[1], "11223344");
    assert_eq!(parts_b[1], "aabbccdd");
    assert_eq!(
        parts_a[2], parts_b[2],
        "TIDs were identical at frozen ms, proving dev8 prevented collision"
    );

    let loaded = block_on(phone_frozen.load_thread(THREAD, TimeRange::ALL)).unwrap();
    let frames: Vec<&[u8]> = loaded.messages.iter().map(|m| m.frame.as_slice()).collect();
    assert_eq!(
        frames,
        vec![b"from phone".as_slice(), b"from tablet".as_slice()]
    );

    // Also verify explicit seq (`Some(42)`) at the exact same frozen millisecond across sibling stores.
    let mut seq_batch: Batch = h
        .host
        .record(&h.conv_space, ALICE, nsid::BATCH, rkey_a)
        .and_then(|v| serde_json::from_value(v).ok())
        .expect("stored batch");
    seq_batch.items[0].seq = Some(42);

    let store_a = SpaceThreadStore::new(h.transport(ALICE), ALICE)
        .with_device_tag([0x11, 0x22, 0x33, 0x44])
        .with_clock(Arc::new(move || frozen_ms));
    store_a.set_thread_space(THREAD, h.conv_space.clone());
    let store_b = SpaceThreadStore::new(h.transport(ALICE), ALICE)
        .with_device_tag([0xaa, 0xbb, 0xcc, 0xdd])
        .with_clock(Arc::new(move || frozen_ms));
    store_b.set_thread_space(THREAD, h.conv_space.clone());

    let seq_rkey_a = block_on(store_a.append_batch(&seq_batch)).unwrap();
    let seq_rkey_b = block_on(store_b.append_batch(&seq_batch)).unwrap();
    assert_ne!(seq_rkey_a, seq_rkey_b);
    assert!(seq_rkey_a.starts_with("000000000000002a-11223344-"));
    assert!(seq_rkey_b.starts_with("000000000000002a-aabbccdd-"));
}

#[test]
fn map_space_error_and_flush_jitter_retry_handle_concurrent_write_conflicts() {
    for err in [
        SpaceError {
            status: 409,
            error: None,
            message: Some("HTTP 409".into()),
        },
        SpaceError::named(400, "ConcurrentWrite", "repo lock busy"),
        SpaceError::named(400, "InvalidSwap", "swap mismatch"),
        SpaceError::named(400, "RecordAlreadyExists", "exists"),
    ] {
        assert_eq!(map_space_error(err), Error::Conflict);
    }

    let h = SpaceHarness::new();
    let mut alice = h.init(ALICE, 1);
    let mut bob = h.init(BOB, 2);
    let roster = block_on(alice.resolve_roster(&[ALICE, BOB])).unwrap();

    // 1) Inject 3 transient 409 ConcurrentWrite faults: flush() retries with jitter and succeeds on attempt 4.
    block_on(alice.archive_outgoing(
        THREAD,
        &roster,
        "m-retry-ok",
        2_000,
        b"survives 3 conflicts",
    ))
    .unwrap();
    h.host
        .inject_concurrent_write_conflicts(&h.conv_space, ALICE, 3);
    let flushed =
        block_on(alice.flush()).expect("bounded retry should absorb 3 transient conflicts");
    assert_eq!(flushed.len(), 1);

    // 2) Inject 10 persistent 409 ConcurrentWrite faults: flush() fails with Error::Conflict and preserves outbox.
    block_on(alice.archive_outgoing(
        THREAD,
        &roster,
        "m-retry-preserved",
        2_010,
        b"outbox preserved across contention",
    ))
    .unwrap();
    h.host
        .inject_concurrent_write_conflicts(&h.conv_space, ALICE, 10);
    assert_eq!(block_on(alice.flush()), Err(Error::Conflict));

    // Clear remaining faults and flush again: queued message is delivered intact.
    h.host
        .inject_concurrent_write_conflicts(&h.conv_space, ALICE, 0);
    let flushed_after =
        block_on(alice.flush()).expect("second flush succeeds after contention clears");
    assert_eq!(flushed_after.len(), 1);

    let history = block_on(bob.load_thread(THREAD, TimeRange::ALL)).unwrap();
    let ids: Vec<&str> = history
        .messages
        .iter()
        .map(|m| m.message_id.as_str())
        .collect();
    assert_eq!(ids, vec!["m-retry-ok", "m-retry-preserved"]);
}

#[test]
fn persisted_writer_revision_floor_rejects_rollback_across_restart() {
    let h = SpaceHarness::new();
    let sink = MemorySink::default();
    let mut alice = h.init(ALICE, 1).with_state_sink(Box::new(sink.clone()));
    let mut bob = h.init(BOB, 2);

    let roster_b = block_on(bob.resolve_roster(&[ALICE, BOB])).unwrap();
    block_on(bob.archive_outgoing(THREAD, &roster_b, "b1", 3_000, b"first")).unwrap();
    block_on(bob.flush()).unwrap();
    block_on(bob.archive_outgoing(THREAD, &roster_b, "b2", 3_010, b"second")).unwrap();
    block_on(bob.flush()).unwrap();

    // Alice loads the thread, observing and checkpointing Bob's repoRev floor into LBYS v4.
    let hist = block_on(alice.load_thread(THREAD, TimeRange::ALL)).unwrap();
    assert_eq!(hist.messages.len(), 2);
    let conv_uri = h.conv_space.to_string();
    let pinned_bob_rev = alice
        .writer_rev_floor(&conv_uri, BOB)
        .expect("Bob's repoRev floor must be pinned")
        .to_owned();

    // Restart Alice from checkpointed state bytes.
    let saved_bytes = sink.0.lock().unwrap().clone();
    assert!(
        !saved_bytes.is_empty(),
        "StateSink must checkpoint writer_floors"
    );
    let mut alice_restarted = block_on(Labyrinth::from_state(
        &saved_bytes,
        ALICE,
        Box::new(signer(1)),
        h.backends(ALICE, 1),
    ))
    .unwrap();
    assert_eq!(
        alice_restarted.writer_rev_floor(&conv_uri, BOB),
        Some(pinned_bob_rev.as_str())
    );

    // Space host rolls back Bob's writer revision below Alice's persisted floor.
    let rolled_back_rev = "2222222222223";
    assert!(rolled_back_rev < pinned_bob_rev.as_str());
    h.host
        .rollback_writer_rev(&h.conv_space, BOB, rolled_back_rev);

    let err = block_on(alice_restarted.load_thread(THREAD, TimeRange::ALL)).unwrap_err();
    assert_eq!(
        err,
        Error::WriterRollback {
            space: conv_uri.clone(),
            author: BOB.to_owned(),
            pinned_rev: pinned_bob_rev,
            offered_rev: rolled_back_rev.to_owned(),
        }
    );

    // Direct STAR getRepo with seeded floors also rejects the rolled-back commit before accepting frames.
    let seeded_threads = h.threads(ALICE, 1);
    seeded_threads.seed_writer_rev_floors(alice_restarted.writer_rev_floors());
    let host_kem = h.host.kem_did_key();
    let star_err =
        block_on(seeded_threads.get_repo_star_authenticated(THREAD, BOB, &host_kem)).unwrap_err();
    assert!(matches!(star_err, Error::WriterRollback { .. }));

    // Rolling back Alice's own repo in listSpaces is also caught by list_owned_spaces.
    let roster_a = block_on(alice_restarted.resolve_roster(&[ALICE, BOB])).unwrap();
    block_on(alice_restarted.archive_outgoing(THREAD, &roster_a, "a1", 3_020, b"alice msg"))
        .unwrap();
    block_on(alice_restarted.flush()).unwrap();
    let alice_threads = h.threads(ALICE, 1);
    let spaces = block_on(alice_threads.list_owned_spaces()).unwrap();
    assert!(spaces.contains(&conv_uri));
    h.host
        .rollback_writer_rev(&h.conv_space, ALICE, "2222222222222");
    let list_err = block_on(alice_threads.list_owned_spaces()).unwrap_err();
    assert!(matches!(list_err, Error::WriterRollback { .. }));
}

#[test]
fn encrypted_read_state_monotonic_crdt_and_historical_epoch_aad_binding() {
    let h = SpaceHarness::new();
    let mut phone = h.init(ALICE, 1);
    let mut tablet = h.enroll_sibling(&mut phone, ALICE, 2, h.backends(ALICE, 2));

    // Advance on phone to 42, then tablet tries to write stale 19 (with transient write conflict injected):
    // monotonic MAX(42, 19) = 42 is preserved!
    let s1 = block_on(phone.advance_read_state("conv-alpha", 42)).unwrap();
    assert_eq!(s1.read_through_seq, 42);

    let mailbox_space = SpaceRef::mailbox(ALICE);
    h.host
        .inject_concurrent_write_conflicts(&mailbox_space, ALICE, 2);
    let s2 = block_on(tablet.advance_read_state("conv-alpha", 19)).unwrap();
    assert_eq!(s2.read_through_seq, 42);

    let s3 = block_on(tablet.advance_read_state("conv-alpha", 105)).unwrap();
    assert_eq!(s3.read_through_seq, 105);
    assert_eq!(
        block_on(phone.get_read_state("conv-alpha"))
            .unwrap()
            .unwrap()
            .read_through_seq,
        105
    );

    // Rotate epoch on phone, write a second conversation's readState in the new epoch,
    // and verify both historical-epoch and new-epoch records decrypt on both devices!
    block_on(phone.rotate_epoch()).unwrap();
    block_on(phone.advance_read_state("conv-beta", 7)).unwrap();

    let listed = block_on(tablet.list_read_states()).unwrap();
    let map: BTreeMap<String, u64> = listed
        .into_iter()
        .map(|s| (s.conversation_id, s.read_through_seq))
        .collect();
    assert_eq!(map.get("conv-alpha"), Some(&105));
    assert_eq!(map.get("conv-beta"), Some(&7));

    // Negative check: copying a valid readState record's ciphertext to another rkey fails AAD check.
    let mb = h.mailbox(ALICE);
    let (raw_alpha, _) = block_on(mb.get_read_state("conv-alpha"))
        .unwrap()
        .expect("conv-alpha record");
    let swapped = ReadStateRecord::new(
        raw_alpha.ciphertext.0,
        raw_alpha.epoch,
        raw_alpha.updated_at,
    )
    .unwrap();
    block_on(mb.put_read_state("conv-swapped", &swapped, None)).unwrap();
    let swap_err = block_on(phone.get_read_state("conv-swapped")).unwrap_err();
    assert_eq!(swap_err, Error::Decrypt);
}

#[test]
fn encrypted_circle_owner_state_cas_monotonic_join_version_and_acl_tombstone_dominance() {
    let h = SpaceHarness::new();
    let mut phone = h.init(ALICE, 1);
    let mut tablet = h.enroll_sibling(&mut phone, ALICE, 2, h.backends(ALICE, 2));

    let circle_id = "circle-close-friends";
    let space_uri = "at://did:plc:alice/space/blue.catbird.circles.circle/circle-close-friends";
    let initial = CircleOwnerState {
        circle_id: circle_id.to_owned(),
        space_uri: space_uri.to_owned(),
        current_key_version: 1,
        joined_at_version_by_did: BTreeMap::from([(BOB.to_owned(), 1), (CAROL.to_owned(), 1)]),
        pending_ops: BTreeMap::new(),
        updated_at: "2026-11-13T12:00:00.000Z".to_owned(),
    };

    // #create succeeds once; a second #create with expected_cid = None fails with Error::Conflict.
    let cid1 = block_on(phone.put_circle_owner_state(&initial, None)).unwrap();
    assert_eq!(
        block_on(tablet.put_circle_owner_state(&initial, None)),
        Err(Error::Conflict)
    );

    // Phone removes Bob (marking __acl__:did:plc:bob with rotated=true) and re-adds Carol at key version 4.
    let mut phone_update = initial.clone();
    phone_update.current_key_version = 4;
    phone_update
        .joined_at_version_by_did
        .insert(CAROL.to_owned(), 4);
    phone_update.mark_acl_remove_pending(BOB, true);
    phone_update.updated_at = "2026-11-13T12:05:00.000Z".to_owned();
    let cid2 = block_on(phone.put_circle_owner_state(&phone_update, Some(&cid1))).unwrap();
    assert_ne!(cid1, cid2);

    // Stale CAS update using cid1 fails with Error::Conflict.
    assert_eq!(
        block_on(tablet.put_circle_owner_state(&initial, Some(&cid1))),
        Err(Error::Conflict)
    );

    // Tablet holds stale snapshot (Bob at v1, Carol at v1, plus a new member Dave at v2) and calls merge_circle_owner_state:
    // - __acl__:did:plc:bob tombstone MUST win (Bob stays excluded, tombstone retained as aclRemovePending:rotated)
    // - Carol's joinedAtVersion MUST be MAX(4, 1) = 4 (no downgrade to hidden history v1..v3)
    // - Dave is preserved at v2, and currentKeyVersion = MAX(4, 2) = 4.
    let mut tablet_stale = initial.clone();
    tablet_stale.current_key_version = 2;
    tablet_stale
        .joined_at_version_by_did
        .insert("did:plc:dave".to_owned(), 2);
    tablet_stale
        .pending_ops
        .insert(BOB.to_owned(), "staleAddOp".to_owned());
    tablet_stale.updated_at = "2026-11-13T12:02:00.000Z".to_owned();

    let (merged, _cid3) = block_on(tablet.merge_circle_owner_state(&tablet_stale)).unwrap();
    assert_eq!(merged.current_key_version, 4);
    assert!(!merged.joined_at_version_by_did.contains_key(BOB));
    assert_eq!(merged.joined_at_version_by_did.get(CAROL), Some(&4));
    assert_eq!(
        merged.joined_at_version_by_did.get("did:plc:dave"),
        Some(&2)
    );
    assert!(!merged.pending_ops.contains_key(BOB));
    assert_eq!(
        merged
            .pending_ops
            .get(&CircleOwnerState::acl_tombstone_key(BOB))
            .map(String::as_str),
        Some(ACL_REMOVE_PENDING_ROTATED)
    );

    // Once Space ACL removeMembers completes, clear_circle_acl_tombstone removes the tombstone cleanly.
    let (cleared, _) = block_on(phone.clear_circle_acl_tombstone(circle_id, BOB))
        .unwrap()
        .expect("circle state exists");
    assert!(!cleared.has_acl_tombstone(BOB));
    assert!(!cleared.joined_at_version_by_did.contains_key(BOB));

    let all_circles = block_on(tablet.list_circle_owner_states()).unwrap();
    assert_eq!(all_circles.len(), 1);
    assert_eq!(all_circles[0].circle_id, circle_id);
}

#[test]
fn space_thread_store_new_uses_deterministic_random_hook_for_device_tag() {
    let frozen_ms = 1_795_777_000_000u64;
    let run_with_seed = |start: u8| -> String {
        let counter = Arc::new(Mutex::new(start));
        let hook: labyrinth::encoding::RandomFillHook = Arc::new(move |out: &mut [u8]| {
            let mut cur = counter.lock().unwrap();
            for b in out.iter_mut() {
                *b = *cur;
                *cur = cur.wrapping_add(1);
            }
            Ok(())
        });
        labyrinth::encoding::with_random_hook(hook, || {
            let host = MemorySpaceHost::new();
            let space = SpaceRef::conversation(ALICE, THREAD);
            host.grant_space_member(&space, ALICE);
            // Construct WITHOUT with_device_tag or with_device_pubkey so SpaceThreadStore::new draws from random().
            let store = SpaceThreadStore::new(host.client(ALICE), ALICE)
                .with_clock(Arc::new(move || frozen_ms));
            store.set_thread_space(THREAD, space);
            let batch = Batch {
                type_: nsid::BATCH.to_owned(),
                thread_id: THREAD.to_owned(),
                items: Vec::new(),
                created_at: "2026-11-13T12:00:00.000Z".to_owned(),
            };
            block_on(store.append_batch(&batch)).unwrap()
        })
    };

    let rkey_1 = run_with_seed(0x41);
    let rkey_2 = run_with_seed(0x41);
    let rkey_other = run_with_seed(0x90);
    assert_eq!(
        rkey_1, rkey_2,
        "SpaceThreadStore::new must replay deterministically under with_random_hook"
    );
    assert!(
        rkey_1.starts_with("0000000000000000-41424344-"),
        "expected deterministic 41424344 dev8 tag, got {rkey_1}"
    );
    assert!(
        rkey_other.starts_with("0000000000000000-90919293-"),
        "expected deterministic 90919293 dev8 tag, got {rkey_other}"
    );
}

struct AdvWritersRpc {
    inner: Arc<dyn SpaceRpc>,
    target_space: String,
    override_writers: Arc<Mutex<Option<Value>>>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SpaceRpc for AdvWritersRpc {
    async fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, SpaceError> {
        if nsid == "com.atproto.space.listWriters"
            && params
                .iter()
                .any(|(k, v)| *k == "space" && v == &self.target_space)
            && let Some(payload) = self.override_writers.lock().unwrap().clone()
        {
            return Ok(serde_json::to_vec(&payload).unwrap());
        }
        self.inner.query(nsid, params).await
    }

    async fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<(Vec<(String, String)>, Vec<u8>), SpaceError> {
        self.inner.query_with_headers(nsid, params, headers).await
    }

    async fn procedure(&self, nsid: &str, payload: &[u8]) -> Result<Vec<u8>, SpaceError> {
        self.inner.procedure(nsid, payload).await
    }

    async fn upload_blob(&self, bytes: &[u8], mime_type: &str) -> Result<String, SpaceError> {
        self.inner.upload_blob(bytes, mime_type).await
    }

    async fn get_blob(&self, space: &str, did: &str, cid: &str) -> Result<Vec<u8>, SpaceError> {
        self.inner.get_blob(space, did, cid).await
    }

    async fn host_kem_did_key(&self, space: &str) -> Result<Option<String>, SpaceError> {
        self.inner.host_kem_did_key(space).await
    }
}

#[derive(Clone)]
struct FailOnceSink {
    fail_next: Arc<Mutex<bool>>,
    saved: Arc<Mutex<Vec<u8>>>,
}

impl StateSink for FailOnceSink {
    fn save_state(&self, exported_state: &[u8]) -> labyrinth::Result<()> {
        let mut fail = self.fail_next.lock().unwrap();
        if *fail {
            *fail = false;
            return Err(Error::Backend("injected sink write failure".into()));
        }
        *self.saved.lock().unwrap() = exported_state.to_vec();
        Ok(())
    }
}

#[test]
fn oversized_and_malformed_writer_revs_rejected_without_poisoning_client_state_or_other_threads() {
    let h = SpaceHarness::new();
    let healthy_thread = "conv-healthy";
    let healthy_space = SpaceRef::conversation(ALICE, healthy_thread);
    h.host.grant_space_member(&healthy_space, ALICE);
    h.host.grant_space_member(&healthy_space, BOB);

    let override_writers: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let adv_rpc: Arc<dyn SpaceRpc> = Arc::new(AdvWritersRpc {
        inner: Arc::new(h.host.client(ALICE)),
        target_space: h.conv_space.to_string(),
        override_writers: override_writers.clone(),
    });

    h.net.register_chat_device(ALICE, tpub(11));
    let mut bob = h.init(BOB, 22);
    let bob_healthy_threads = SpaceThreadStore::new(h.host.client(BOB), BOB)
        .with_device_pubkey(&tpub(22))
        .with_clock({
            let clock = h.clock.clone();
            Arc::new(move || clock.now_ms())
        });
    bob_healthy_threads.set_thread_space(THREAD, h.conv_space.clone());
    bob_healthy_threads.set_thread_space(healthy_thread, healthy_space.clone());
    let bob_state = bob.export_state().unwrap();
    bob = block_on(Labyrinth::from_state(
        &bob_state,
        BOB,
        Box::new(signer(22)),
        Backends {
            mailbox: Box::new(h.mailbox(BOB)),
            threads: Box::new(bob_healthy_threads),
            directory: Box::new(h.directory()),
            publishers: vec![Box::new(h.net.ds_publisher(BOB))],
            clock: Box::new(h.clock.clone()),
        },
    ))
    .unwrap();

    let alice_threads = SpaceThreadStore::new(adv_rpc, ALICE)
        .with_device_pubkey(&tpub(11))
        .with_clock({
            let clock = h.clock.clone();
            Arc::new(move || clock.now_ms())
        });
    alice_threads.set_thread_space(THREAD, h.conv_space.clone());
    alice_threads.set_thread_space(healthy_thread, healthy_space.clone());
    let alice_floors_handle = alice_threads.writer_rev_floors().clone();

    let fail_next = Arc::new(Mutex::new(false));
    let sink = FailOnceSink {
        fail_next: fail_next.clone(),
        saved: Arc::default(),
    };
    h.net.register_chat_device(ALICE, tpub(1));
    let mut alice = block_on(Labyrinth::initialize(
        ALICE,
        Box::new(signer(11)),
        Backends {
            mailbox: Box::new(h.mailbox(ALICE)),
            threads: Box::new(alice_threads),
            directory: Box::new(h.directory()),
            publishers: vec![Box::new(h.net.ds_publisher(ALICE))],
            clock: Box::new(h.clock.clone()),
        },
    ))
    .unwrap();
    alice.set_state_sink(Box::new(sink));

    // Bob posts a valid message to the sibling healthy conversation.
    let roster = block_on(bob.resolve_roster(&[ALICE, BOB])).unwrap();
    block_on(bob.archive_outgoing(
        healthy_thread,
        &roster,
        "msg-healthy-1",
        h.clock.now_ms(),
        b"healthy conversation payload",
    ))
    .unwrap();
    block_on(bob.flush()).unwrap();

    // Attack 1: Byzantine Space host returns > 65,535-byte repoRev, > 256-byte repo DID, and control chars.
    for bad_entry in [
        serde_json::json!({
            "$type": "com.atproto.space.defs#repoWrite",
            "repo": BOB,
            "repoRev": "z".repeat(70_000),
            "data": { "$bytes": "AAEC" },
            "spaceRev": "3k22222222222",
        }),
        serde_json::json!({
            "$type": "com.atproto.space.defs#repoWrite",
            "repo": format!("did:plc:{}", "b".repeat(300)),
            "repoRev": "3k22222222222",
            "data": { "$bytes": "AAEC" },
            "spaceRev": "3k22222222222",
        }),
        serde_json::json!({
            "$type": "com.atproto.space.defs#repoWrite",
            "repo": BOB,
            "repoRev": "rev\ncontrol",
            "data": { "$bytes": "AAEC" },
            "spaceRev": "3k22222222222",
        }),
    ] {
        *override_writers.lock().unwrap() = Some(serde_json::json!({
            "repos": [bad_entry]
        }));
        let err = block_on(alice.load_thread(THREAD, TimeRange::ALL))
            .expect_err("oversized or non-printable writer floor must fail closed");
        assert!(
            matches!(err, Error::Malformed(_)),
            "unexpected error: {err:?}"
        );
        assert!(
            alice_floors_handle
                .get(&h.conv_space.to_string(), BOB)
                .is_none(),
            "rejected floor must never enter SpaceThreadStore::floors"
        );
    }

    // Client state export, roster resolution, epoch rotation, and sibling conversations remain completely healthy.
    let state_bytes = alice
        .export_state()
        .expect("export_state must not be poisoned by rejected writer floors");
    assert!(!state_bytes.is_empty());
    let _ =
        block_on(alice.resolve_roster(&[ALICE, BOB])).expect("resolve_roster must remain healthy");
    let _ = block_on(alice.rotate_epoch()).expect("rotate_epoch must remain healthy");

    // Attack 2: If checkpoint_state fails during sync_store_writer_floors, store floors are replaced (not additively seeded).
    *fail_next.lock().unwrap() = true;
    let checkpoint_err = block_on(alice.load_thread(healthy_thread, TimeRange::ALL))
        .expect_err("injected StateSink failure must surface");
    assert!(matches!(checkpoint_err, Error::Backend(_)));
    assert!(
        alice
            .writer_rev_floor(&healthy_space.to_string(), BOB)
            .is_none(),
        "uncheckpointed writer floor must roll back on Labyrinth"
    );
    assert!(
        alice_floors_handle
            .get(&healthy_space.to_string(), BOB)
            .is_none(),
        "uncheckpointed writer floor must be purged from SpaceThreadStore::floors on rollback"
    );

    // Subsequent load succeeds cleanly once sink recovers.
    let loaded = block_on(alice.load_thread(healthy_thread, TimeRange::ALL)).unwrap();
    assert_eq!(loaded.messages.len(), 1);
    assert_eq!(loaded.messages[0].frame, b"healthy conversation payload");
}

#[test]
fn intra_list_writers_stream_rollback_and_pre_removal_floor_pinning_rejected() {
    let h = SpaceHarness::new();
    let override_writers: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let adv_rpc: Arc<dyn SpaceRpc> = Arc::new(AdvWritersRpc {
        inner: Arc::new(h.host.client(ALICE)),
        target_space: h.conv_space.to_string(),
        override_writers: override_writers.clone(),
    });

    h.net.register_chat_device(ALICE, tpub(11));
    let _bob = h.init(BOB, 22);
    let alice_threads = SpaceThreadStore::new(adv_rpc, ALICE)
        .with_device_pubkey(&tpub(11))
        .with_clock({
            let clock = h.clock.clone();
            Arc::new(move || clock.now_ms())
        });
    alice_threads.set_thread_space(THREAD, h.conv_space.clone());
    h.net.register_chat_device(ALICE, tpub(1));
    let mut alice = block_on(Labyrinth::initialize(
        ALICE,
        Box::new(signer(11)),
        Backends {
            mailbox: Box::new(h.mailbox(ALICE)),
            threads: Box::new(alice_threads),
            directory: Box::new(h.directory()),
            publishers: vec![Box::new(h.net.ds_publisher(ALICE))],
            clock: Box::new(h.clock.clone()),
        },
    ))
    .unwrap();

    // Case A: [RepoWrite(bob, 3k22222222225), RepoWrite(bob, 3k22222222223)] in one listWriters stream must reject R5 -> R3.
    *override_writers.lock().unwrap() = Some(serde_json::json!({
        "repos": [
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": BOB,
                "repoRev": "3k22222222225",
                "data": { "$bytes": "AAEC" },
                "spaceRev": "3k22222222225",
            },
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": BOB,
                "repoRev": "3k22222222223",
                "data": { "$bytes": "AAEC" },
                "spaceRev": "3k22222222226",
            }
        ]
    }));
    let err_a = block_on(alice.load_thread(THREAD, TimeRange::ALL))
        .expect_err("intra-listing R5 -> R3 regression must fail closed");
    assert_eq!(
        err_a,
        Error::WriterRollback {
            space: h.conv_space.to_string(),
            author: BOB.to_owned(),
            pinned_rev: "3k22222222225".to_owned(),
            offered_rev: "3k22222222223".to_owned(),
        }
    );

    // Phase 1: Unauthenticated listWriters advertising non-TID strings fails closed with Malformed,
    // and advertising a valid high TID ("bzzzzzzzzzzzz") without an authenticated STAR commit NEVER poisons floors.
    *override_writers.lock().unwrap() = Some(serde_json::json!({
        "repos": [
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": CAROL,
                "repoRev": "~~~~~~~~~~~~~",
                "data": { "$bytes": "AAEC" },
                "spaceRev": "3k22222222227",
            }
        ]
    }));
    assert!(matches!(
        block_on(alice.load_thread(THREAD, TimeRange::ALL)).unwrap_err(),
        Error::Malformed("invalid writer revision")
    ));
    assert_eq!(
        alice.writer_rev_floor(&h.conv_space.to_string(), CAROL),
        None
    );

    *override_writers.lock().unwrap() = Some(serde_json::json!({
        "repos": [
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": CAROL,
                "repoRev": "bzzzzzzzzzzzz",
                "data": { "$bytes": "AAEC" },
                "spaceRev": "3k22222222232",
            },
            {
                "$type": "com.atproto.space.defs#repoRemoved",
                "repo": CAROL,
                "spaceRev": "3k22222222233",
            }
        ]
    }));
    let _ = block_on(alice.load_thread(THREAD, TimeRange::ALL))
        .expect("unauthenticated listWriters write+remove must not poison floor");
    assert_eq!(
        alice.writer_rev_floor(&h.conv_space.to_string(), CAROL),
        None,
        "unauthenticated listWriters JSON must never pin writer_rev_floor"
    );

    // Phase 2: Once CAROL publishes an authentic STAR repo (verified via HPKE Commit MAC),
    // CAROL's real TID is pinned, so removing CAROL and later offering a lower rev fails closed.
    *override_writers.lock().unwrap() = None;
    let mut carol = h.init(CAROL, 33);
    let roster_c = block_on(carol.resolve_roster(&[ALICE, BOB, CAROL])).unwrap();
    block_on(carol.archive_outgoing(THREAD, &roster_c, "c1", 4_000, b"carol authentic")).unwrap();
    block_on(carol.flush()).unwrap();

    let loaded_carol = block_on(alice.load_thread(THREAD, TimeRange::ALL)).unwrap();
    assert_eq!(loaded_carol.messages.len(), 1);
    let pinned_carol = alice
        .writer_rev_floor(&h.conv_space.to_string(), CAROL)
        .expect("authenticated STAR sync must pin CAROL's writer_rev_floor")
        .to_owned();

    *override_writers.lock().unwrap() = Some(serde_json::json!({
        "repos": [
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": CAROL,
                "repoRev": "2222222222222",
                "data": { "$bytes": "AAEC" },
                "spaceRev": "3k22222222234",
            }
        ]
    }));
    let err_b = block_on(alice.load_thread(THREAD, TimeRange::ALL))
        .expect_err("post-sync rollback below authenticated floor must fail closed");
    assert_eq!(
        err_b,
        Error::WriterRollback {
            space: h.conv_space.to_string(),
            author: CAROL.to_owned(),
            pinned_rev: pinned_carol,
            offered_rev: "2222222222222".to_owned(),
        }
    );
}

#[derive(Default)]
struct RpcAuditLog {
    writes: Vec<(String, String, String)>,
    mek_get_repos: Vec<String>,
    mek_list_writers: usize,
}

type PreCreateHook = Arc<dyn Fn(&str, &str) + Send + Sync>;

struct SpySpaceRpc {
    inner: Arc<dyn SpaceRpc>,
    log: Arc<Mutex<RpcAuditLog>>,
    pre_create_hook: Option<PreCreateHook>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SpaceRpc for SpySpaceRpc {
    async fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, SpaceError> {
        if nsid == "com.atproto.space.getRecord" {
            let collection = params
                .iter()
                .find(|(k, _)| *k == "collection")
                .map(|(_, v)| v.as_str());
            if collection == Some(nsid::MEK)
                && let Some((_, repo)) = params.iter().find(|(k, _)| *k == "repo")
            {
                self.log.lock().unwrap().mek_get_repos.push(repo.clone());
            }
        } else if nsid == "com.atproto.space.listWriters" {
            self.log.lock().unwrap().mek_list_writers += 1;
        }
        self.inner.query(nsid, params).await
    }

    async fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<(Vec<(String, String)>, Vec<u8>), SpaceError> {
        if nsid == "com.atproto.space.getRecord" {
            let collection = params
                .iter()
                .find(|(k, _)| *k == "collection")
                .map(|(_, v)| v.as_str());
            if collection == Some(nsid::MEK)
                && let Some((_, repo)) = params.iter().find(|(k, _)| *k == "repo")
            {
                self.log.lock().unwrap().mek_get_repos.push(repo.clone());
            }
        }
        self.inner.query_with_headers(nsid, params, headers).await
    }

    async fn procedure(&self, nsid: &str, payload: &[u8]) -> Result<Vec<u8>, SpaceError> {
        if nsid == "com.atproto.space.applyWrites"
            && let Ok(v) = serde_json::from_slice::<Value>(payload)
            && let Some(writes) = v["writes"].as_array()
        {
            for w in writes {
                let kind = w["$type"].as_str().unwrap_or("").to_owned();
                let collection = w["collection"].as_str().unwrap_or("").to_owned();
                let rkey = w["rkey"].as_str().unwrap_or("").to_owned();
                if kind == "com.atproto.space.applyWrites#create"
                    && let Some(hook) = &self.pre_create_hook
                {
                    hook(&collection, &rkey);
                }
                self.log
                    .lock()
                    .unwrap()
                    .writes
                    .push((kind, collection, rkey));
            }
        }
        self.inner.procedure(nsid, payload).await
    }

    async fn upload_blob(&self, bytes: &[u8], mime_type: &str) -> Result<String, SpaceError> {
        self.inner.upload_blob(bytes, mime_type).await
    }

    async fn get_blob(&self, space: &str, did: &str, cid: &str) -> Result<Vec<u8>, SpaceError> {
        self.inner.get_blob(space, did, cid).await
    }

    async fn host_kem_did_key(&self, space: &str) -> Result<Option<String>, SpaceError> {
        self.inner.host_kem_did_key(space).await
    }
}

#[test]
fn versioned_circle_owner_state_create_cas_eliminates_toctou_and_preserves_acl_tombstones() {
    let h = SpaceHarness::new();
    let mut phone = h.init(ALICE, 1);

    let tablet_log = Arc::new(Mutex::new(RpcAuditLog::default()));
    let hook_armed = Arc::new(Mutex::new(false));
    let host_for_hook = h.host.clone();
    let transport_for_hook = h.transport(ALICE);
    let net_for_hook = h.net.clone();
    let clock_for_hook = h.clock.clone();
    let hook_armed_cl = hook_armed.clone();

    let circle_id = "550e8400-e29b-41d4-a716-446655440000";
    let space_uri = format!("at://{ALICE}/space/blue.catbird.circles.circle/{circle_id}");

    // Seed initial state v1 on phone.
    let initial = CircleOwnerState {
        circle_id: circle_id.to_owned(),
        space_uri: space_uri.clone(),
        current_key_version: 1,
        joined_at_version_by_did: BTreeMap::from([(BOB.to_owned(), 1), (CAROL.to_owned(), 1)]),
        pending_ops: BTreeMap::new(),
        updated_at: "2026-11-14T10:00:00.000Z".to_owned(),
    };
    let cid_v1 = block_on(phone.put_circle_owner_state(&initial, None)).unwrap();

    // Enroll tablet with an intercepting transport that injects a concurrent phone write
    // AFTER tablet has listed circleOwnerState v1 and right BEFORE tablet sends #create v2!
    let pre_create_target = format!("{circle_id}-000000000002");
    let cid_v1_for_hook = cid_v1.clone();
    let initial_for_hook = initial.clone();
    let spy_rpc: Arc<dyn SpaceRpc> = Arc::new(SpySpaceRpc {
        inner: h.transport(ALICE),
        log: tablet_log.clone(),
        pre_create_hook: Some(Arc::new(move |collection, rkey| {
            let mut armed = hook_armed_cl.lock().unwrap();
            if *armed && collection == nsid::CIRCLE_OWNER_STATE && rkey == pre_create_target {
                *armed = false;
                // Concurrent writer (phone) commits v2 with __acl__ removal tombstone for BOB
                // in the exact window between tablet's pre-read and tablet's applyWrites!
                let mb = SpaceMailboxStore::for_owner(
                    ALICE,
                    transport_for_hook.clone(),
                    Box::new(net_for_hook.pds_publisher(ALICE)),
                )
                .with_clock(Arc::new({
                    let c = clock_for_hook.clone();
                    move || c.now_ms()
                }));
                let (_, existing_rec) = (
                    &host_for_hook,
                    block_on(mb.get_circle_owner_state(circle_id))
                        .unwrap()
                        .expect("v1 exists"),
                );
                assert_eq!(existing_rec.1.as_deref(), Some(cid_v1_for_hook.as_str()));
            }
        })),
    });

    let tablet_backends = Backends {
        mailbox: Box::new(
            SpaceMailboxStore::for_owner(ALICE, spy_rpc, Box::new(h.net.pds_publisher(ALICE)))
                .with_page_size(2)
                .with_clock(Arc::new({
                    let c = h.clock.clone();
                    move || c.now_ms()
                })),
        ),
        threads: Box::new(h.threads(ALICE, 2)),
        directory: Box::new(h.directory()),
        publishers: vec![Box::new(h.net.ds_publisher(ALICE))],
        clock: Box::new(h.clock.clone()),
    };
    let mut tablet = h.enroll_sibling(&mut phone, ALICE, 2, tablet_backends);

    // Both devices read v1 (`cid_v1`) concurrently.
    let (phone_snap, phone_cid) = block_on(phone.get_circle_owner_state(circle_id))
        .unwrap()
        .unwrap();
    let (_tablet_snap, tablet_cid) = block_on(tablet.get_circle_owner_state(circle_id))
        .unwrap()
        .unwrap();
    assert_eq!(phone_cid.as_deref(), Some(cid_v1.as_str()));
    assert_eq!(tablet_cid.as_deref(), Some(cid_v1.as_str()));

    // Phone writes v2 removing BOB with an __acl__ tombstone.
    let mut phone_v2 = phone_snap;
    phone_v2.current_key_version = 2;
    phone_v2.mark_acl_remove_pending(BOB, true);
    phone_v2.updated_at = "2026-11-14T10:01:00.000Z".to_owned();
    let cid_v2 = block_on(phone.put_circle_owner_state(&phone_v2, phone_cid.as_deref())).unwrap();
    assert_ne!(cid_v1, cid_v2);

    // Tablet races a direct CAS put using stale `tablet_cid` (`cid_v1`): must fail closed with Conflict.
    let mut tablet_candidate = initial_for_hook;
    tablet_candidate.current_key_version = 3;
    tablet_candidate
        .joined_at_version_by_did
        .insert("did:plc:dave".to_owned(), 3);
    tablet_candidate.updated_at = "2026-11-14T10:02:00.000Z".to_owned();
    assert_eq!(
        block_on(tablet.put_circle_owner_state(&tablet_candidate, tablet_cid.as_deref())),
        Err(Error::Conflict)
    );

    // Now simulate the exact TOCTOU race inside `put_versioned_cas` itself:
    // a concurrent sibling wins `#create` for `circle_id-000000000003` right before tablet's `#create` for v3 lands!
    let pre_v3_rkey = format!("{circle_id}-000000000003");
    let winning_sibling = Arc::new(Mutex::new(h.enroll_sibling(
        &mut phone,
        ALICE,
        5,
        h.backends(ALICE, 5),
    )));
    let winning_sibling_cl = winning_sibling.clone();
    let race_log = Arc::new(Mutex::new(RpcAuditLog::default()));
    let raced_once = Arc::new(Mutex::new(true));
    let raced_once_cl = raced_once.clone();
    let pre_v3_rkey_cl = pre_v3_rkey.clone();
    let circle_id_cl = circle_id.to_owned();
    let racing_rpc: Arc<dyn SpaceRpc> = Arc::new(SpySpaceRpc {
        inner: h.transport(ALICE),
        log: race_log.clone(),
        pre_create_hook: Some(Arc::new(move |collection, rkey| {
            let mut should_race = raced_once_cl.lock().unwrap();
            if *should_race && collection == nsid::CIRCLE_OWNER_STATE && rkey == pre_v3_rkey_cl {
                *should_race = false;
                std::thread::scope(|s| {
                    s.spawn(|| {
                        let mut winner = winning_sibling_cl.lock().unwrap();
                        let (cur, cur_cid) = block_on(winner.get_circle_owner_state(&circle_id_cl))
                            .unwrap()
                            .expect("v2 present before race");
                        block_on(winner.put_circle_owner_state(&cur, cur_cid.as_deref()))
                            .expect("winning concurrent #create on v3 succeeds");
                    })
                    .join()
                    .unwrap();
                });
            }
        })),
    });
    let mut racing_tablet = h.enroll_sibling(
        &mut phone,
        ALICE,
        3,
        Backends {
            mailbox: Box::new(
                SpaceMailboxStore::for_owner(
                    ALICE,
                    racing_rpc,
                    Box::new(h.net.pds_publisher(ALICE)),
                )
                .with_page_size(2),
            ),
            threads: Box::new(h.threads(ALICE, 3)),
            directory: Box::new(h.directory()),
            publishers: vec![Box::new(h.net.ds_publisher(ALICE))],
            clock: Box::new(h.clock.clone()),
        },
    );

    // `merge_circle_owner_state` hits atomic RecordAlreadyExists on v3, re-reads v3, merges CRDT,
    // and commits append-only v4 without deleting older versions!
    let (merged, _cid_v4) = block_on(racing_tablet.merge_circle_owner_state(&tablet_candidate))
        .expect("merge retries onto v4 after atomic #create conflict on v3");
    assert_eq!(merged.current_key_version, 3);
    assert!(!merged.joined_at_version_by_did.contains_key(BOB));
    assert_eq!(
        merged.joined_at_version_by_did.get("did:plc:dave"),
        Some(&3)
    );
    assert_eq!(
        merged
            .pending_ops
            .get(&CircleOwnerState::acl_tombstone_key(BOB))
            .map(String::as_str),
        Some(ACL_REMOVE_PENDING_ROTATED)
    );

    // Verify ZERO `#update` or `#delete` ops were emitted on circleOwnerState, and all append-only rkeys v1..=v4 remain!
    let audit = race_log.lock().unwrap();
    assert!(
        !audit
            .writes
            .iter()
            .any(|(kind, col, _)| col == nsid::CIRCLE_OWNER_STATE && kind.ends_with("#update")),
        "circleOwnerState must never use client-side #update CAS: {:?}",
        audit.writes
    );
    assert!(
        audit.writes.iter().any(|(kind, col, rkey)| {
            kind.ends_with("#create")
                && col == nsid::CIRCLE_OWNER_STATE
                && rkey == &format!("{circle_id}-000000000004")
        }),
        "expected atomic #create on v4, got {:?}",
        audit.writes
    );
    drop(audit);

    let list_params = [
        ("space", SpaceRef::mailbox(ALICE).to_string()),
        ("repo", ALICE.to_owned()),
        ("collection", nsid::CIRCLE_OWNER_STATE.to_owned()),
    ];
    let raw_list: Value = serde_json::from_slice(
        &block_on(
            h.host
                .client(ALICE)
                .query("com.atproto.space.listRecords", &list_params),
        )
        .unwrap(),
    )
    .unwrap();
    let mut remaining_rkeys: Vec<&str> = raw_list["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["rkey"].as_str())
        .collect();
    remaining_rkeys.sort_unstable();
    assert_eq!(
        remaining_rkeys,
        vec![
            format!("{circle_id}-000000000001").as_str(),
            format!("{circle_id}-000000000002").as_str(),
            format!("{circle_id}-000000000003").as_str(),
            format!("{circle_id}-000000000004").as_str(),
        ]
    );

    // Replaying v1 ciphertext into v5 fails AEAD (`cas_version` bound in AAD),
    // and deleting v4 after racing_tablet observed v4 fails closed with version rollback (even across restart)!
    let v1_rkey = format!("{circle_id}-000000000001");
    let v1_value = raw_list["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["rkey"].as_str() == Some(v1_rkey.as_str()))
        .unwrap()["value"]
        .clone();
    let plant_v5_replay = serde_json::to_vec(&serde_json::json!({
        "space": SpaceRef::mailbox(ALICE).to_string(),
        "repo": ALICE,
        "validate": false,
        "writes": [{
            "$type": "com.atproto.space.applyWrites#create",
            "collection": nsid::CIRCLE_OWNER_STATE,
            "rkey": format!("{circle_id}-000000000005"),
            "value": v1_value,
        }]
    }))
    .unwrap();
    block_on(
        h.host
            .client(ALICE)
            .procedure("com.atproto.space.applyWrites", &plant_v5_replay),
    )
    .unwrap();
    assert!(matches!(
        block_on(racing_tablet.get_circle_owner_state(circle_id)).unwrap_err(),
        Error::Decrypt
    ));

    // Delete tampered v5 and v4 so head regresses to v3; persisted monotonic floor rejects rollback!
    for suffix in ["000000000005", "000000000004"] {
        let del = serde_json::to_vec(&serde_json::json!({
            "space": SpaceRef::mailbox(ALICE).to_string(),
            "repo": ALICE,
            "collection": nsid::CIRCLE_OWNER_STATE,
            "rkey": format!("{circle_id}-{suffix}"),
        }))
        .unwrap();
        block_on(
            h.host
                .client(ALICE)
                .procedure("com.atproto.space.deleteRecord", &del),
        )
        .unwrap();
    }
    let exported_tablet = racing_tablet.export_state().unwrap();
    let mut restarted_tablet = block_on(Labyrinth::from_state(
        &exported_tablet,
        ALICE,
        Box::new(signer(3)),
        h.backends(ALICE, 3),
    ))
    .unwrap();
    assert!(matches!(
        block_on(restarted_tablet.get_circle_owner_state(circle_id)).unwrap_err(),
        Error::Malformed("owner state version rollback")
    ));

    // 36-char UUID ending in 12 decimal digits parses as unversioned `ver = 0`,
    // and planting a `v1` ciphertext under `ver = 0` is rejected by `cas_version` AAD binding!
    let legacy_id = "123e4567-e89b-12d3-a456-123456789012";
    let mut legacy_state = initial;
    legacy_state.circle_id = legacy_id.to_owned();
    legacy_state.space_uri = format!("at://{ALICE}/com.atproto.space.space/3k00000000099");
    let _ = block_on(phone.put_circle_owner_state(&legacy_state, None)).unwrap();
    let (v1_rec, _, parsed_v1) =
        block_on(h.mailbox(ALICE).get_circle_owner_state_versioned(legacy_id))
            .unwrap()
            .unwrap();
    assert_eq!(parsed_v1, 1);
    let del_v1 = serde_json::to_vec(&serde_json::json!({
        "space": SpaceRef::mailbox(ALICE).to_string(),
        "repo": ALICE,
        "collection": nsid::CIRCLE_OWNER_STATE,
        "rkey": format!("{legacy_id}-000000000001"),
    }))
    .unwrap();
    block_on(
        h.host
            .client(ALICE)
            .procedure("com.atproto.space.deleteRecord", &del_v1),
    )
    .unwrap();
    let plant_unversioned = serde_json::to_vec(&serde_json::json!({
        "space": SpaceRef::mailbox(ALICE).to_string(),
        "repo": ALICE,
        "validate": false,
        "writes": [{
            "$type": "com.atproto.space.applyWrites#create",
            "collection": nsid::CIRCLE_OWNER_STATE,
            "rkey": legacy_id,
            "value": serde_json::to_value(&v1_rec).unwrap(),
        }]
    }))
    .unwrap();
    block_on(
        h.host
            .client(ALICE)
            .procedure("com.atproto.space.applyWrites", &plant_unversioned),
    )
    .unwrap();
    let (_, _, parsed_v0) = block_on(h.mailbox(ALICE).get_circle_owner_state_versioned(legacy_id))
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed_v0, 0,
        "36-char hyphenated UUID must parse as unversioned ver = 0"
    );
    let mut fresh_sibling = h.enroll_sibling(&mut phone, ALICE, 6, h.backends(ALICE, 6));
    assert!(
        matches!(
            block_on(fresh_sibling.get_circle_owner_state(legacy_id)).unwrap_err(),
            Error::Decrypt
        ),
        "downgrading v1 ciphertext to unversioned ver = 0 must fail AEAD"
    );
}

#[test]
fn read_state_write_conflict_merges_monotonic_max_watermark() {
    let h = SpaceHarness::new();
    let mut phone = h.init(ALICE, 1);

    let conv = "conv-monotonic-race";
    assert_eq!(
        block_on(phone.advance_read_state(conv, 10))
            .unwrap()
            .read_through_seq,
        10
    );

    // Pre-encrypt a higher watermark (95) on phone so our pre-create hook can commit `conv-000000000002`
    // right before tablet's attempt to advance to `40` commits `conv-000000000002`.
    let other_conv = "conv-template";
    block_on(phone.advance_read_state(other_conv, 95)).unwrap();
    // Instead of swapping conversation AAD, have a second phone handle advance `conv` to 95 inside the hook!
    let raced = Arc::new(Mutex::new(true));
    let raced_cl = raced.clone();
    let target_rkey = format!("{conv}-000000000002");
    let phone_for_race = Arc::new(Mutex::new(h.enroll_sibling(
        &mut phone,
        ALICE,
        4,
        h.backends(ALICE, 4),
    )));
    let phone_for_race_cl = phone_for_race.clone();

    let spy_rpc: Arc<dyn SpaceRpc> = Arc::new(SpySpaceRpc {
        inner: h.transport(ALICE),
        log: Arc::default(),
        pre_create_hook: Some(Arc::new(move |collection, rkey| {
            let mut fire = raced_cl.lock().unwrap();
            if *fire && collection == nsid::READ_STATE && rkey == target_rkey {
                *fire = false;
                std::thread::scope(|s| {
                    s.spawn(|| {
                        let mut winner = phone_for_race_cl.lock().unwrap();
                        let res = block_on(winner.advance_read_state(conv, 95)).unwrap();
                        assert_eq!(res.read_through_seq, 95);
                    })
                    .join()
                    .unwrap();
                });
            }
        })),
    });

    let mut tablet = h.enroll_sibling(
        &mut phone,
        ALICE,
        2,
        Backends {
            mailbox: Box::new(
                SpaceMailboxStore::for_owner(ALICE, spy_rpc, Box::new(h.net.pds_publisher(ALICE)))
                    .with_page_size(2),
            ),
            threads: Box::new(h.threads(ALICE, 2)),
            directory: Box::new(h.directory()),
            publishers: vec![Box::new(h.net.ds_publisher(ALICE))],
            clock: Box::new(h.clock.clone()),
        },
    );

    // Tablet tries to advance to 40, collides on v2 against phone's 95, re-reads and returns MAX(40, 95) = 95!
    let resolved = block_on(tablet.advance_read_state(conv, 40)).unwrap();
    assert_eq!(resolved.read_through_seq, 95);
    assert_eq!(
        block_on(phone.get_read_state(conv))
            .unwrap()
            .unwrap()
            .read_through_seq,
        95
    );
}

#[test]
fn find_meks_probes_batch_author_first_o1_and_falls_back_across_writers() {
    let h = SpaceHarness::new();
    let log = Arc::new(Mutex::new(RpcAuditLog::default()));
    let spy_rpc: Arc<dyn SpaceRpc> = Arc::new(SpySpaceRpc {
        inner: h.transport(ALICE),
        log: log.clone(),
        pre_create_hook: None,
    });
    let alice_threads = SpaceThreadStore::new(spy_rpc, ALICE)
        .with_page_size(2)
        .with_device_pubkey(&tpub(1))
        .with_clock(Arc::new({
            let c = h.clock.clone();
            move || c.now_ms()
        }));
    alice_threads.set_thread_space(THREAD, h.conv_space.clone());
    h.net.register_chat_device(ALICE, tpub(1));
    let mut alice = block_on(Labyrinth::initialize(
        ALICE,
        Box::new(signer(1)),
        Backends {
            mailbox: Box::new(h.mailbox(ALICE)),
            threads: Box::new(alice_threads),
            directory: Box::new(h.directory()),
            publishers: vec![Box::new(h.net.ds_publisher(ALICE))],
            clock: Box::new(h.clock.clone()),
        },
    ))
    .unwrap();

    // Populate 10 additional active writers in the Space so `listWriters` has 12 repos.
    let mut all_dids = vec![ALICE.to_owned(), BOB.to_owned(), CAROL.to_owned()];
    let mut senders = Vec::new();
    for i in 0..9u8 {
        let did = format!("did:plc:writer{i:02}");
        h.host.grant_space_member(&h.conv_space, &did);
        let peer = h.init(&did, 20 + i);
        all_dids.push(did.clone());
        senders.push((did, peer));
    }
    let mut bob = h.init(BOB, 2);
    let _carol = h.init(CAROL, 3);
    let roster_refs: Vec<&str> = all_dids.iter().map(String::as_str).collect();

    // Have each extra writer publish a batch so all repos appear in `listWriters`.
    for (idx, (_did, peer)) in senders.iter_mut().enumerate() {
        let r = block_on(peer.resolve_roster(&roster_refs)).unwrap();
        block_on(peer.archive_outgoing(
            THREAD,
            &r,
            &format!("noise-{idx}"),
            4_000 + idx as u64,
            b"noise",
        ))
        .unwrap();
        block_on(peer.flush()).unwrap();
    }

    // Bob publishes message "bob-target" under Bob's MEK.
    let bob_roster = block_on(bob.resolve_roster(&roster_refs)).unwrap();
    block_on(bob.archive_outgoing(THREAD, &bob_roster, "bob-target", 5_000, b"hello o1")).unwrap();
    block_on(bob.flush()).unwrap();

    // Clear spy log and fetch ONLY Bob's batch on Alice (`sender = Some(BOB)` -> no listWriters for batches either!).
    // Actually `load_thread` lists batches across writers, then decrypts Bob's batch.
    // Clear right before `load_thread` and inspect `mek_get_repos`!
    *log.lock().unwrap() = RpcAuditLog::default();
    let loaded = block_on(alice.load_thread(
        THREAD,
        TimeRange {
            from_ms: Some(4_999),
            until_ms: None,
        },
    ))
    .unwrap();
    assert_eq!(loaded.messages.len(), 1);
    assert_eq!(loaded.messages[0].frame, b"hello o1");

    let mek_gets = log.lock().unwrap().mek_get_repos.clone();
    assert_eq!(
        mek_gets,
        vec![BOB.to_owned()],
        "MEK lookup must probe batch author BOB first in O(1) without touching the other 11 writers"
    );

    // Bounded fallback check across all 12 writers when preferred author (`CAROL`) misses:
    // `CAROL` is probed first, NOT re-probed during the 8-way concurrent fallback sweep,
    // and `BOB`'s `MekDistribution` is recovered cleanly!
    let bob_meks: Value = serde_json::from_slice(
        &block_on(h.host.client(BOB).query(
            "com.atproto.space.listRecords",
            &[
                ("space", h.conv_space.to_string()),
                ("repo", BOB.to_owned()),
                ("collection", nsid::MEK.to_owned()),
            ],
        ))
        .unwrap(),
    )
    .unwrap();
    let mek_rec = &bob_meks["records"].as_array().unwrap()[0];
    let mek_rkey = mek_rec["rkey"].as_str().unwrap().to_owned();
    let mek_id_bytes: [u8; 12] = hex::decode(&mek_rkey).unwrap().try_into().unwrap();

    let fb_log = Arc::new(Mutex::new(RpcAuditLog::default()));
    let fb_spy: Arc<dyn SpaceRpc> = Arc::new(SpySpaceRpc {
        inner: h.transport(ALICE),
        log: fb_log.clone(),
        pre_create_hook: None,
    });
    let fb_store = SpaceThreadStore::new(fb_spy, ALICE)
        .with_page_size(2)
        .with_device_pubkey(&tpub(1));
    fb_store.set_thread_space(THREAD, h.conv_space.clone());

    let found = block_on(fb_store.find_meks_with_hint(THREAD, &mek_id_bytes, Some(CAROL)))
        .expect("bounded fallback across 12 writers must locate BOB's MEK");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].author, BOB);
    let fb_gets = fb_log.lock().unwrap().mek_get_repos.clone();
    assert_eq!(
        fb_gets.first().map(String::as_str),
        Some(CAROL),
        "preferred_author CAROL must be probed first"
    );
    assert_eq!(
        fb_gets.iter().filter(|d| d.as_str() == CAROL).count(),
        1,
        "preferred_author CAROL must not be probed twice during fallback"
    );
    assert_eq!(
        fb_gets.len(),
        1 + senders.len() + 1,
        "preferred probe (CAROL) + 10 active writers in listWriters (9 peers + BOB) = 11 total getRecord probes"
    );

    // Also verify `find_mek_from_author` issues 0 `listWriters` and 1 `getRecord`.
    *fb_log.lock().unwrap() = RpcAuditLog::default();
    let direct = block_on(fb_store.find_mek_from_author(THREAD, BOB, &mek_id_bytes))
        .unwrap()
        .expect("direct author probe must find BOB's MEK");
    assert_eq!(direct.author, BOB);
    let direct_audit = fb_log.lock().unwrap();
    assert_eq!(direct_audit.mek_list_writers, 0);
    assert_eq!(direct_audit.mek_get_repos, vec![BOB.to_owned()]);
}

#[test]
fn passkey_recovery_registration_rotates_owner_mailbox_epoch_and_anchors_virtual_device() {
    use labyrinth::store::MailboxDirectory as _;

    let h = SpaceHarness::new();
    let mut phone = h.init(ALICE, 1);
    assert_eq!(phone.latest_epoch(), 0);

    let prf = [0x5A; 32];
    let cred_id = b"cred-passkey-rotate";
    let setup = block_on(phone.create_passkey_recovery(&prf, cred_id)).unwrap();
    assert_eq!(
        phone.latest_epoch(),
        1,
        "create_passkey_recovery must rotate OwnerMailbox epoch so EpochPublic.membersHash anchors the virtual device"
    );

    // Virtual device bundle is carried forward as an initial member of epoch 1 (`encrypted_entropy` present),
    // and both PDS `mailboxKeys` and DS `epoch_head_floors` commit `membersHash` over `{phone, virtual_device}`!
    let mb = h.mailbox(ALICE);
    let vdev = block_on(mb.get_virtual_device(&setup.vdevice_id))
        .unwrap()
        .expect("virtual device bundle");
    let (vrec, _) = vdev.to_bundle_for_did(ALICE).unwrap();
    let expected_members_hash = labyrinth::mailbox::members_hash_for_devices(&[
        phone.device_public().clone(),
        vrec.public.clone(),
    ])
    .unwrap();

    let dir = h.directory();
    let latest_pub = block_on(dir.latest_two_source(ALICE)).unwrap().unwrap();
    assert_eq!(latest_pub.seq, 1);
    assert_eq!(latest_pub.members_hash, expected_members_hash);

    let member_e1 = block_on(mb.get_epoch_member(1, &vrec.public.device_key_pub))
        .unwrap()
        .expect("virtual device must be an initial member of rotated epoch 1");
    assert!(
        member_e1.encrypted_entropy.is_some(),
        "carried-over virtual device in epoch 1 must hold encrypted_entropy"
    );

    h.net.register_chat_device(ALICE, tpub(9));
    let (restored, _) = block_on(Labyrinth::restore_with_passkey(
        ALICE,
        &prf,
        cred_id,
        Box::new(signer(9)),
        h.backends(ALICE, 9),
    ))
    .expect("passkey restore after registration epoch rotation must succeed");
    assert_eq!(restored.latest_epoch(), 2);
}

struct TamperingSpaceRpc {
    inner: Arc<dyn SpaceRpc>,
    tamper_nsid: &'static str,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SpaceRpc for TamperingSpaceRpc {
    async fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, SpaceError> {
        self.inner.query(nsid, params).await
    }

    async fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<(Vec<(String, String)>, Vec<u8>), SpaceError> {
        let (mut resp_headers, body) = self.inner.query_with_headers(nsid, params, headers).await?;
        if nsid == self.tamper_nsid {
            for (k, v) in &mut resp_headers {
                if k.eq_ignore_ascii_case("signature") {
                    *v = "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".to_owned();
                }
            }
        }
        Ok((resp_headers, body))
    }

    async fn procedure(&self, nsid: &str, payload: &[u8]) -> Result<Vec<u8>, SpaceError> {
        self.inner.procedure(nsid, payload).await
    }

    async fn upload_blob(&self, bytes: &[u8], mime_type: &str) -> Result<String, SpaceError> {
        self.inner.upload_blob(bytes, mime_type).await
    }

    async fn get_blob(&self, space: &str, did: &str, cid: &str) -> Result<Vec<u8>, SpaceError> {
        self.inner.get_blob(space, did, cid).await
    }

    async fn host_kem_did_key(&self, space: &str) -> Result<Option<String>, SpaceError> {
        self.inner.host_kem_did_key(space).await
    }
}

#[test]
fn space_thread_store_authenticates_star_commit_and_record_macs_and_settled_tombstones_resist_resurrection()
 {
    let h = SpaceHarness::new();
    let mut alice = h.init(ALICE, 1);
    let mut tablet = h.enroll_sibling(&mut alice, ALICE, 2, h.backends(ALICE, 2));
    let mut bob = h.init(BOB, 3);

    let roster_b = block_on(bob.resolve_roster(&[ALICE, BOB])).unwrap();
    block_on(bob.archive_outgoing(THREAD, &roster_b, "m-auth-1", 5_000, b"mac verified")).unwrap();
    block_on(bob.flush()).unwrap();

    // 1. Tampering `Atproto-Space-Commit` MAC on `getRepo` during `load_thread` fails closed with BadSignature.
    let tamper_commit: Arc<dyn SpaceRpc> = Arc::new(TamperingSpaceRpc {
        inner: h.transport(ALICE),
        tamper_nsid: "com.atproto.space.getRepo",
    });
    let commit_threads = SpaceThreadStore::new(tamper_commit, ALICE).with_device_pubkey(&tpub(7));
    commit_threads.set_thread_space(THREAD, h.conv_space.clone());
    let mut alice_bad_commit = h.enroll_sibling(
        &mut alice,
        ALICE,
        7,
        Backends {
            mailbox: Box::new(h.mailbox(ALICE)),
            threads: Box::new(commit_threads),
            directory: Box::new(h.directory()),
            publishers: vec![Box::new(h.net.ds_publisher(ALICE))],
            clock: Box::new(h.clock.clone()),
        },
    );
    assert_eq!(
        block_on(alice_bad_commit.load_thread(THREAD, TimeRange::ALL)).unwrap_err(),
        Error::BadSignature
    );

    // 2. Tampering `Atproto-Space-Record` MAC on `getRecord` during `find_meks` fails closed with BadSignature.
    let bob_meks: Value = serde_json::from_slice(
        &block_on(h.host.client(BOB).query(
            "com.atproto.space.listRecords",
            &[
                ("space", h.conv_space.to_string()),
                ("repo", BOB.to_owned()),
                ("collection", nsid::MEK.to_owned()),
            ],
        ))
        .unwrap(),
    )
    .unwrap();
    let bob_mek_rkey = bob_meks["records"].as_array().unwrap()[0]["rkey"]
        .as_str()
        .unwrap();
    let bob_mek_id: [u8; 12] = hex::decode(bob_mek_rkey).unwrap().try_into().unwrap();
    let tamper_record: Arc<dyn SpaceRpc> = Arc::new(TamperingSpaceRpc {
        inner: h.transport(ALICE),
        tamper_nsid: "com.atproto.space.getRecord",
    });
    let rec_threads = SpaceThreadStore::new(tamper_record, ALICE).with_device_pubkey(&tpub(1));
    rec_threads.set_thread_space(THREAD, h.conv_space.clone());
    assert_eq!(
        block_on(rec_threads.find_mek_from_author(THREAD, BOB, &bob_mek_id)).unwrap_err(),
        Error::BadSignature
    );

    // 3. Multi-device settled ACL tombstone prevents resurrection when tablet merges stale pre-removal state.
    let circle_id = "circle-monotone-tombstone";
    let s1 = CircleOwnerState {
        circle_id: circle_id.to_owned(),
        space_uri: format!("at://{ALICE}/com.atproto.space.space/3k00000000077"),
        current_key_version: 1,
        joined_at_version_by_did: BTreeMap::from([(ALICE.to_owned(), 1), (BOB.to_owned(), 1)]),
        pending_ops: BTreeMap::new(),
        updated_at: "2026-11-15T12:00:00.000Z".to_owned(),
    };
    let (_, _) = block_on(alice.merge_circle_owner_state(&s1)).unwrap();

    // Tablet snapshots v1 before BOB is removed and cleared on Alice's phone.
    let (tablet_stale, _) = block_on(tablet.get_circle_owner_state(circle_id))
        .unwrap()
        .unwrap();

    // Phone removes BOB at key version 2 and then clears the pending ACL tombstone.
    let mut s2_remove = s1.clone();
    s2_remove.current_key_version = 2;
    s2_remove.updated_at = "2026-11-15T12:01:00.000Z".to_owned();
    s2_remove.mark_acl_remove_pending(BOB, true);
    block_on(alice.merge_circle_owner_state(&s2_remove)).unwrap();
    let (cleared, _) = block_on(alice.clear_circle_acl_tombstone(circle_id, BOB))
        .unwrap()
        .expect("circle state present");
    assert!(!cleared.has_acl_tombstone(BOB));
    assert!(!cleared.joined_at_version_by_did.contains_key(BOB));

    // Tablet adds CAROL onto its stale v1 snapshot (which still contained BOB at v1) and merges:
    // BOB MUST stay evicted and `__acl__:bob` MUST stay cleared!
    let mut tablet_update = tablet_stale;
    tablet_update
        .joined_at_version_by_did
        .insert(CAROL.to_owned(), 2);
    tablet_update.updated_at = "2026-11-15T12:02:00.000Z".to_owned();
    let (merged, _) = block_on(tablet.merge_circle_owner_state(&tablet_update)).unwrap();
    assert!(!merged.joined_at_version_by_did.contains_key(BOB));
    assert!(!merged.has_acl_tombstone(BOB));
    assert_eq!(merged.joined_at_version_by_did.get(CAROL), Some(&2));
}

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
    let rolled_back_rev = "000000000001";
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
        .rollback_writer_rev(&h.conv_space, ALICE, "000000000000");
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

    // Case A: [RepoWrite(bob, rev-0005), RepoWrite(bob, rev-0003)] in one listWriters stream must reject R5 -> R3.
    *override_writers.lock().unwrap() = Some(serde_json::json!({
        "repos": [
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": BOB,
                "repoRev": "rev-0005",
                "data": { "$bytes": "AAEC" },
                "spaceRev": "3k00000000005",
            },
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": BOB,
                "repoRev": "rev-0003",
                "data": { "$bytes": "AAEC" },
                "spaceRev": "3k00000000006",
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
            pinned_rev: "rev-0005".to_owned(),
            offered_rev: "rev-0003".to_owned(),
        }
    );

    // Case B: [RepoWrite(carol, rev-0008), RepoRemoved(carol)] pins rev-0008 before removal,
    // so a subsequent [RepoWrite(carol, rev-0007)] re-admission at an older rev fails closed.
    *override_writers.lock().unwrap() = Some(serde_json::json!({
        "repos": [
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": CAROL,
                "repoRev": "rev-0008",
                "data": { "$bytes": "AAEC" },
                "spaceRev": "3k00000000008",
            },
            {
                "$type": "com.atproto.space.defs#repoRemoved",
                "repo": CAROL,
                "spaceRev": "3k00000000009",
            }
        ]
    }));
    let _ = block_on(alice.load_thread(THREAD, TimeRange::ALL))
        .expect("clean write + removal succeeds and pins rev-0008");
    assert_eq!(
        alice.writer_rev_floor(&h.conv_space.to_string(), CAROL),
        Some("rev-0008")
    );

    *override_writers.lock().unwrap() = Some(serde_json::json!({
        "repos": [
            {
                "$type": "com.atproto.space.defs#repoWrite",
                "repo": CAROL,
                "repoRev": "rev-0007",
                "data": { "$bytes": "AAEC" },
                "spaceRev": "3k00000000010",
            }
        ]
    }));
    let err_b = block_on(alice.load_thread(THREAD, TimeRange::ALL))
        .expect_err("post-removal re-add below rev-0008 floor must fail closed");
    assert_eq!(
        err_b,
        Error::WriterRollback {
            space: h.conv_space.to_string(),
            author: CAROL.to_owned(),
            pinned_rev: "rev-0008".to_owned(),
            offered_rev: "rev-0007".to_owned(),
        }
    );
}

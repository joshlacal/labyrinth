//! Space reads authenticate before they are trusted: readers fail closed when
//! no response authentication is available, revision and CAS floors move only
//! after the record authenticates, and the `listWriters` listing cannot hide a
//! writer this client has already authenticated.

use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use labyrinth::records::{Batch, Bytes, SealedMessageDef, nsid};
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::thread::SpaceThreadStore;
use labyrinth::store::space::{SpaceError, SpaceMailboxStore, SpaceRef, SpaceRpc, endpoint};
use labyrinth::store::{MailboxStore, ThreadStore, TimeRange};
use serde_json::{Value, json};

const ALICE: &str = "did:plc:alice";
const BOB: &str = "did:plc:bob";
const CAROL: &str = "did:plc:carol";
const THREAD: &str = "conv-read-auth";

/// Forwards to the in-memory host. `kem` controls whether the host KEM key is
/// served; `listing` replaces `listWriters`; `hide_repo` answers `getRepo` for
/// that DID with `RepoNotFound`.
struct Relay {
    inner: Arc<dyn SpaceRpc>,
    kem: bool,
    listing: Arc<Mutex<Option<Value>>>,
    hide_repo: Arc<Mutex<Option<String>>>,
    trusted: bool,
}

impl Relay {
    fn new(inner: impl SpaceRpc + 'static, kem: bool) -> Self {
        Self {
            inner: Arc::new(inner),
            kem,
            listing: Arc::new(Mutex::new(None)),
            hide_repo: Arc::new(Mutex::new(None)),
            trusted: false,
        }
    }

    fn intercept(
        &self,
        nsid: &str,
        params: &[(&str, String)],
    ) -> Option<Result<Vec<u8>, SpaceError>> {
        if nsid == endpoint::LIST_WRITERS
            && let Some(v) = self.listing.lock().unwrap().clone()
        {
            return Some(Ok(serde_json::to_vec(&v).unwrap()));
        }
        if nsid == endpoint::GET_REPO
            && let Some(hidden) = self.hide_repo.lock().unwrap().clone()
            && params.iter().any(|(k, v)| *k == "repo" && *v == hidden)
        {
            return Some(Err(SpaceError::named(404, "RepoNotFound", "hidden")));
        }
        None
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SpaceRpc for Relay {
    async fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, SpaceError> {
        if let Some(out) = self.intercept(nsid, params) {
            return out;
        }
        self.inner.query(nsid, params).await
    }

    async fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<(Vec<(String, String)>, Vec<u8>), SpaceError> {
        if let Some(out) = self.intercept(nsid, params) {
            return out.map(|b| (Vec::new(), b));
        }
        self.inner.query_with_headers(nsid, params, headers).await
    }

    async fn procedure(&self, nsid: &str, payload: &[u8]) -> Result<Vec<u8>, SpaceError> {
        self.inner.procedure(nsid, payload).await
    }

    async fn get_blob(&self, space: &str, did: &str, cid: &str) -> Result<Vec<u8>, SpaceError> {
        self.inner.get_blob(space, did, cid).await
    }

    fn authenticates_responses(&self) -> bool {
        self.trusted
    }

    async fn host_kem_did_key(&self, space: &str) -> Result<Option<String>, SpaceError> {
        if self.kem {
            self.inner.host_kem_did_key(space).await
        } else {
            Ok(None)
        }
    }
}

fn batch() -> Batch {
    Batch {
        type_: nsid::BATCH.to_owned(),
        thread_id: THREAD.to_owned(),
        items: vec![SealedMessageDef {
            message_id: "m1".into(),
            seq: None,
            timestamp: 1_795_000_000_000,
            mek_id: Bytes(vec![0xAA; 12]),
            sender_transport_pubkey: Bytes(vec![1; 32]),
            signed_enc_message: Bytes(vec![1, 2, 3]),
            sequencer_receipt: None,
            redaction: None,
        }],
        created_at: "2026-11-16T12:00:00.000Z".to_owned(),
    }
}

fn conversation(host: &MemorySpaceHost) -> SpaceRef {
    let space = SpaceRef::conversation(ALICE, THREAD);
    for did in [ALICE, BOB, CAROL] {
        host.grant_space_member(&space, did);
    }
    space
}

fn writer(host: &MemorySpaceHost, did: &str, space: &SpaceRef) -> SpaceThreadStore {
    let s = SpaceThreadStore::new(host.client(did), did);
    s.set_thread_space(THREAD, space.clone());
    s
}

fn auth_failure(e: &labyrinth::Error) -> bool {
    e.to_string().contains("authentication")
}

#[test]
fn thread_readers_fail_closed_without_a_host_kem_key() {
    let host = MemorySpaceHost::new();
    let space = conversation(&host);
    block_on(writer(&host, ALICE, &space).append_batch(&batch())).unwrap();

    let bob = SpaceThreadStore::new(
        Arc::new(Relay::new(host.client(BOB), false)) as Arc<dyn SpaceRpc>,
        BOB,
    );
    bob.set_thread_space(THREAD, space.clone());
    block_on(bob.append_batch(&batch())).unwrap();

    let e = block_on(bob.list_batches(THREAD, None, TimeRange::ALL)).unwrap_err();
    assert!(auth_failure(&e), "list_batches: {e}");
    let e = block_on(bob.list_batches_quarantined(THREAD, None, TimeRange::ALL)).unwrap_err();
    assert!(auth_failure(&e), "list_batches_quarantined: {e}");
    let e = block_on(bob.find_mek_from_author(THREAD, ALICE, &[7; 12])).unwrap_err();
    assert!(auth_failure(&e), "find_mek_from_author: {e}");
    let e = block_on(bob.get_attachment_manifest(THREAD, ALICE, "3kabcdefghij2")).unwrap_err();
    assert!(auth_failure(&e), "get_attachment_manifest: {e}");
    let e = block_on(bob.get_attachment_verified(THREAD, ALICE, "3kabcdefghij2")).unwrap_err();
    assert!(auth_failure(&e), "get_attachment_verified: {e}");
    let e = block_on(bob.list_owned_spaces()).unwrap_err();
    assert!(auth_failure(&e), "list_owned_spaces: {e}");
}

#[test]
fn mailbox_space_revision_listing_never_raises_the_floor() {
    let host = MemorySpaceHost::new();
    let mb_space = SpaceRef::mailbox(ALICE);
    host.grant_space_member(&mb_space, ALICE);
    host.tamper(
        &mb_space,
        ALICE,
        nsid::READ_STATE,
        "seed",
        json!({ "$type": nsid::READ_STATE }),
    );
    let mb = SpaceMailboxStore::new(host.client(ALICE), mb_space.clone(), ALICE.to_owned());
    let observed = block_on(mb.observe_space_revision()).unwrap();
    assert!(observed.is_some(), "listSpaces carries a repoRev");
    assert_eq!(
        mb.writer_rev_floors().get(&mb_space.to_string(), ALICE),
        None,
        "an unauthenticated listSpaces repoRev must not pin the writer floor"
    );
}

#[test]
fn owner_state_version_floor_is_not_raised_by_an_unauthenticated_listing() {
    let host = MemorySpaceHost::new();
    let mb_space = SpaceRef::mailbox(ALICE);
    host.grant_space_member(&mb_space, ALICE);
    host.tamper(
        &mb_space,
        ALICE,
        nsid::READ_STATE,
        "conv-1-999999999999",
        json!({
            "$type": nsid::READ_STATE,
            "ciphertext": { "$bytes": "AAAA" },
            "epoch": 1,
            "updatedAt": "2026-11-16T12:00:00.000Z",
        }),
    );
    let mb = SpaceMailboxStore::new(host.client(ALICE), mb_space, ALICE.to_owned());
    let fetched = block_on(mb.get_read_state_versioned("conv-1")).unwrap();
    assert_eq!(fetched.map(|(_, _, ver)| ver), Some(999_999_999_999));
    assert!(
        mb.export_owner_state_version_floors().is_empty(),
        "the store must not pin a CAS version before the record decrypts: {:?}",
        mb.export_owner_state_version_floors()
    );
    let listed = block_on(mb.list_read_states_versioned()).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(mb.export_owner_state_version_floors().is_empty());
}

#[test]
fn listing_cannot_hide_an_already_authenticated_writer() {
    let host = MemorySpaceHost::new();
    let space = conversation(&host);
    block_on(writer(&host, CAROL, &space).append_batch(&batch())).unwrap();

    let relay = Relay::new(host.client(BOB), true);
    let listing = relay.listing.clone();
    let bob = SpaceThreadStore::new(Arc::new(relay) as Arc<dyn SpaceRpc>, BOB);
    bob.set_thread_space(THREAD, space.clone());

    let first = block_on(bob.list_batches(THREAD, None, TimeRange::ALL)).unwrap();
    assert_eq!(first.len(), 1);
    assert!(
        bob.writer_rev_floors()
            .get(&space.to_string(), CAROL)
            .is_some()
    );

    // The host now omits Carol, then claims Carol was removed.
    for forged in [
        json!({ "repos": [] }),
        json!({ "repos": [{
            "$type": "com.atproto.space.defs#repoRemoved",
            "repo": CAROL,
            "spaceRev": "3kzzzzzzzzzz2",
        }]}),
    ] {
        *listing.lock().unwrap() = Some(forged);
        let again = block_on(bob.list_batches(THREAD, None, TimeRange::ALL)).unwrap();
        assert_eq!(
            again.len(),
            1,
            "carol's authenticated history must stay visible"
        );
        assert_eq!(again[0].author, CAROL);
        let (q, quarantined) =
            block_on(bob.list_batches_quarantined(THREAD, None, TimeRange::ALL)).unwrap();
        assert_eq!(q.len(), 1);
        assert!(quarantined.is_empty(), "{quarantined:?}");
    }
}

#[test]
fn withheld_authenticated_writer_is_reported_not_dropped() {
    let host = MemorySpaceHost::new();
    let space = conversation(&host);
    block_on(writer(&host, CAROL, &space).append_batch(&batch())).unwrap();

    let relay = Relay::new(host.client(BOB), true);
    let (listing, hide) = (relay.listing.clone(), relay.hide_repo.clone());
    let bob = SpaceThreadStore::new(Arc::new(relay) as Arc<dyn SpaceRpc>, BOB);
    bob.set_thread_space(THREAD, space.clone());
    assert_eq!(
        block_on(bob.list_batches(THREAD, None, TimeRange::ALL))
            .unwrap()
            .len(),
        1
    );

    *listing.lock().unwrap() = Some(json!({ "repos": [] }));
    *hide.lock().unwrap() = Some(CAROL.to_owned());
    assert_eq!(
        block_on(bob.list_batches(THREAD, None, TimeRange::ALL)).unwrap_err(),
        labyrinth::Error::WriterWithheld {
            space: space.to_string(),
            author: CAROL.to_owned(),
        }
    );
    let (batches, quarantined) =
        block_on(bob.list_batches_quarantined(THREAD, None, TimeRange::ALL)).unwrap();
    assert!(batches.is_empty());
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].author, CAROL);
    assert_eq!(
        quarantined[0].reason,
        labyrinth::store::QuarantineReason::WithheldRepository
    );
}

#[test]
fn an_authenticating_transport_may_read_without_a_host_kem_key() {
    let host = MemorySpaceHost::new();
    let space = conversation(&host);
    block_on(writer(&host, ALICE, &space).append_batch(&batch())).unwrap();
    let mut relay = Relay::new(host.client(BOB), false);
    relay.trusted = true;
    let bob = SpaceThreadStore::new(Arc::new(relay) as Arc<dyn SpaceRpc>, BOB);
    bob.set_thread_space(THREAD, space);
    assert_eq!(
        block_on(bob.list_batches(THREAD, None, TimeRange::ALL))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        block_on(bob.get_attachment_manifest(THREAD, ALICE, "3kabcdefghij2")).unwrap(),
        None
    );
}

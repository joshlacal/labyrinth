//! ATProto Spaces storage (`com.atproto.space.*`) for personal mailboxes and
//! conversation history (`SPEC §9`, Gates 1, 3, and 5).

pub mod host;
pub mod thread;

pub use petrel_spaces;
pub use thread::{SequencedSpaceThreadStore, SpaceThreadStore, batch_cid};

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    AtomicEnrollBundle, EnrollCleanup, KeyPublisher, MailboxStore, MaybeSend, MaybeSync, Stored,
    TimeRange,
};
use crate::attachment::{AttachmentCiphertextMeta, verify_attachment_ciphertext};
use crate::epoch::space_epoch_id;
use crate::records::{
    AttachmentManifest, Bytes, CircleOwnerStateRecord, Device, Epoch, EpochMember,
    MailboxKeysRecord, OtcSession, OwnerBatch, ReadStateRecord, VirtualDevice, datetime_from_ms,
    nsid,
};
use crate::sign::XVerifyingKey;
use crate::{Error, Result};

/// `spaceType` of the personal mailbox Space.
pub const MAILBOX_SPACE_TYPE: &str = "blue.catbird.labyrinth.mailbox";

/// `spaceType` of a conversation Space.
pub const CONVERSATION_SPACE_TYPE: &str = "blue.catbird.labyrinth.conversation";

/// `skey` of the personal mailbox Space (one per account).
pub const MAILBOX_SKEY: &str = "self";

/// Most writes in one `applyWrites` (reference PDS `MAX_WRITES`).
pub const MAX_WRITES: usize = 200;

/// Records per `listRecords` page (`Swan` `atproto#5187` permits `1..=100`).
pub const LIST_LIMIT: usize = 50;

pub(super) const MAX_SPACE_PAGES: usize = 1_024;
pub(super) const MAX_SPACE_LIST_ITEMS: usize = 10_000;
pub(super) const MAX_SPACE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_SPACE_LIST_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_SPACE_CURSOR_BYTES: usize = 1_024;

/// The Space NSIDs the stores call.
pub mod endpoint {
    pub const APPLY_WRITES: &str = "com.atproto.space.applyWrites";
    pub const CREATE_SPACE: &str = "com.atproto.space.createSpace";
    pub const GET_RECORD: &str = "com.atproto.space.getRecord";
    pub const LIST_RECORDS: &str = "com.atproto.space.listRecords";
    pub const LIST_WRITERS: &str = "com.atproto.space.listWriters";
    pub const LIST_REPOS: &str = LIST_WRITERS;
    pub const LIST_SPACES: &str = "com.atproto.space.listSpaces";
    pub const DELETE_RECORD: &str = "com.atproto.space.deleteRecord";
    pub const AUTHORIZE_SPACE_SYNC: &str = "com.atproto.space.authorizeSpaceSync";
    pub const GET_REPO: &str = "com.atproto.space.getRepo";
    pub const GET_BLOB: &str = "com.atproto.space.getBlob";
    pub const UPLOAD_BLOB: &str = "com.atproto.repo.uploadBlob";
    pub const PUT_MEMBERS: &str = "com.atproto.memberspace.putMembers";
    pub const REMOVE_MEMBERS: &str = "com.atproto.memberspace.removeMembers";
    pub const LIST_MEMBERS: &str = "com.atproto.memberspace.listMembers";
}

/// Every collection the personal mailbox Space holds, for purge.
pub const MAILBOX_COLLECTIONS: [&str; 9] = [
    nsid::DEVICE,
    nsid::EPOCH,
    nsid::EPOCH_MEMBER,
    nsid::VIRTUAL_DEVICE,
    nsid::OTC_SESSION,
    nsid::READ_STATE,
    nsid::CIRCLE_OWNER_STATE,
    nsid::OWNER_BATCH,
    nsid::ATTACHMENT_MANIFEST,
];

/// Monotonic per-`(space_uri, author_did)` repository commit revision floors.
///
/// Tracks the highest observed commit revision (`repoRev` / `Atproto-Space-Commit`
/// `rev`) per `(space_uri, author_did)` and refuses any rollback (`offered < pinned`)
/// with [`Error::WriterRollback`].
#[derive(Clone, Default, Debug)]
pub struct WriterRevFloors {
    inner: Arc<Mutex<BTreeMap<(String, String), String>>>,
}

impl WriterRevFloors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_map(floors: BTreeMap<(String, String), String>) -> Self {
        let out = Self::new();
        out.replace(&floors);
        out
    }

    /// Read-only check verifying `(space, author, offered_rev)` is well-formed and not
    /// older than any previously authenticated revision floor, without mutating floors.
    pub fn check_not_rolled_back(
        &self,
        space: &str,
        author: &str,
        offered_rev: &str,
    ) -> Result<()> {
        crate::store::validate_writer_rev_floor(space, author, offered_rev)?;
        let key = (
            crate::store::canonical_writer_floor_space(space),
            author.to_owned(),
        );
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pinned) = guard.get(&key)
            && offered_rev < pinned.as_str()
        {
            return Err(Error::WriterRollback {
                space: space.to_owned(),
                author: author.to_owned(),
                pinned_rev: pinned.clone(),
                offered_rev: offered_rev.to_owned(),
            });
        }
        Ok(())
    }

    pub fn observe(&self, space: &str, author: &str, offered_rev: &str) -> Result<()> {
        crate::store::validate_writer_rev_floor(space, author, offered_rev)?;
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (
            crate::store::canonical_writer_floor_space(space),
            author.to_owned(),
        );
        if let Some(pinned) = guard.get(&key) {
            if offered_rev < pinned.as_str() {
                return Err(Error::WriterRollback {
                    space: space.to_owned(),
                    author: author.to_owned(),
                    pinned_rev: pinned.clone(),
                    offered_rev: offered_rev.to_owned(),
                });
            }
            if offered_rev == pinned.as_str() {
                return Ok(());
            }
            guard.insert(key, offered_rev.to_owned());
            return Ok(());
        }
        if guard.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
            return Err(Error::Malformed("writer revision floor table full"));
        }
        guard.insert(key, offered_rev.to_owned());
        Ok(())
    }

    /// Raises floors from `floors`, keyed by the canonical `at:space/` form; a legacy
    /// `at://{did}/space/...` key and its canonical spelling merge to the maximum revision.
    pub fn seed(&self, floors: &BTreeMap<(String, String), String>) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for ((space, author), rev) in floors {
            if crate::store::validate_writer_rev_floor(space, author, rev).is_err() {
                continue;
            }
            crate::store::merge_writer_floor_max(&mut guard, space, author, rev);
        }
    }

    /// Replaces the table with `floors`, keyed by the canonical `at:space/` form; a legacy
    /// `at://{did}/space/...` key and its canonical spelling merge to the maximum revision.
    pub fn replace(&self, floors: &BTreeMap<(String, String), String>) {
        let mut next = BTreeMap::new();
        for ((space, author), rev) in floors {
            if crate::store::validate_writer_rev_floor(space, author, rev).is_err() {
                continue;
            }
            crate::store::merge_writer_floor_max(&mut next, space, author, rev);
        }
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        *guard = next;
    }

    pub fn snapshot(&self) -> BTreeMap<(String, String), String> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Every author with an authenticated revision floor in `space`.
    pub fn authors_in(&self, space: &str) -> Vec<String> {
        let space = crate::store::canonical_writer_floor_space(space);
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .filter(|(s, _)| *s == space)
            .map(|(_, author)| author.clone())
            .collect()
    }

    pub fn get(&self, space: &str, author: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(
                crate::store::canonical_writer_floor_space(space),
                author.to_owned(),
            ))
            .cloned()
    }
}

/// Monotonic per-`(collection, logical_id)` CAS version floors for account-private
/// owner-state records (`readState` and `circleOwnerState`).
#[derive(Clone, Default, Debug)]
pub struct OwnerStateVersionFloors {
    inner: Arc<Mutex<BTreeMap<(String, String), u64>>>,
}

impl OwnerStateVersionFloors {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pinned(&self, collection: &str, logical_id: &str) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(collection.to_owned(), logical_id.to_owned()))
            .copied()
    }

    /// Read-only check that `ver` is well formed and not below the pinned
    /// floor for `(collection, logical_id)`; never raises the floor.
    pub fn check(&self, collection: &str, logical_id: &str, ver: u64) -> Result<()> {
        crate::store::validate_owner_state_version_floor(collection, logical_id, ver)?;
        if self
            .pinned(collection, logical_id)
            .is_some_and(|pinned| ver < pinned)
        {
            return Err(Error::Malformed("owner state version rollback"));
        }
        Ok(())
    }

    pub fn observe(&self, collection: &str, logical_id: &str, ver: u64) -> Result<()> {
        crate::store::validate_owner_state_version_floor(collection, logical_id, ver)?;
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (collection.to_owned(), logical_id.to_owned());
        if let Some(&pinned) = guard.get(&key) {
            if ver < pinned {
                return Err(Error::Malformed("owner state version rollback"));
            }
            if ver > pinned {
                guard.insert(key, ver);
            }
            return Ok(());
        }
        if guard.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
            return Err(Error::Malformed("owner state version floor table full"));
        }
        guard.insert(key, ver);
        Ok(())
    }

    pub fn seed(&self, floors: &BTreeMap<(String, String), u64>) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for ((collection, logical_id), &ver) in floors {
            if crate::store::validate_owner_state_version_floor(collection, logical_id, ver)
                .is_err()
            {
                continue;
            }
            let key = (collection.clone(), logical_id.clone());
            match guard.get(&key) {
                Some(&cur) if cur >= ver => {}
                Some(_) => {
                    guard.insert(key, ver);
                }
                None if guard.len() < crate::store::MAX_WRITER_FLOOR_ENTRIES => {
                    guard.insert(key, ver);
                }
                None => {}
            }
        }
    }

    pub fn replace(&self, floors: &BTreeMap<(String, String), u64>) {
        let mut next = BTreeMap::new();
        for ((collection, logical_id), &ver) in floors {
            if crate::store::validate_owner_state_version_floor(collection, logical_id, ver)
                .is_err()
            {
                continue;
            }
            let key = (collection.clone(), logical_id.clone());
            if next.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES && !next.contains_key(&key) {
                continue;
            }
            next.insert(key, ver);
        }
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = next;
    }

    pub fn snapshot(&self) -> BTreeMap<(String, String), u64> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// Member access entry in `com.atproto.memberspace.{putMembers,listMembers}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberAccess {
    pub did: String,
    pub read: bool,
    pub write: bool,
}

/// Output of `com.atproto.space.authorizeSpaceSync`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizeSpaceSyncOut {
    pub credential: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_rev: Option<String>,
}

/// Union item of `com.atproto.space.listWriters` (`#repoWrite` / `#repoRemoved`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum WriterUpdate {
    #[serde(rename = "com.atproto.space.defs#repoWrite", rename_all = "camelCase")]
    RepoWrite {
        repo: String,
        repo_rev: String,
        data: Bytes,
        space_rev: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prev_space_rev: Option<String>,
    },
    #[serde(
        rename = "com.atproto.space.defs#repoRemoved",
        rename_all = "camelCase"
    )]
    RepoRemoved {
        repo: String,
        space_rev: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prev_space_rev: Option<String>,
    },
}

/// Transport-level error from a `com.atproto.space.*` or blob endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceError {
    pub status: u16,
    pub error: Option<String>,
    pub message: Option<String>,
}

impl SpaceError {
    pub fn named(status: u16, name: &str, msg: impl Into<String>) -> Self {
        Self {
            status,
            error: Some(name.to_owned()),
            message: Some(msg.into()),
        }
    }
}

/// Async transport for `com.atproto.space.*` and Space-scoped blobs (`?Send` on `wasm32`).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait SpaceRpc: MaybeSend + MaybeSync {
    async fn query(
        &self,
        nsid: &str,
        params: &[(&str, String)],
    ) -> core::result::Result<Vec<u8>, SpaceError>;

    /// Query carrying request headers (such as `Accept-Signature` for RFC 9421 + HPKE
    /// `0xFFFF` Export MAC negotiation) and returning `(response_headers, body)`.
    async fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        _headers: &[(String, String)],
    ) -> core::result::Result<(Vec<(String, String)>, Vec<u8>), SpaceError> {
        let body = self.query(nsid, params).await?;
        Ok((Vec::new(), body))
    }

    async fn procedure(
        &self,
        nsid: &str,
        payload: &[u8],
    ) -> core::result::Result<Vec<u8>, SpaceError>;

    async fn upload_blob(
        &self,
        _bytes: &[u8],
        _mime_type: &str,
    ) -> core::result::Result<String, SpaceError> {
        Err(SpaceError::named(
            501,
            "MethodNotImplemented",
            "uploadBlob not configured",
        ))
    }

    async fn get_blob(
        &self,
        _space: &str,
        _did: &str,
        _cid: &str,
    ) -> core::result::Result<Vec<u8>, SpaceError> {
        Err(SpaceError::named(
            501,
            "MethodNotImplemented",
            "space.getBlob not configured",
        ))
    }

    /// Optional host `#atproto_kem` P-256 `did:key:zDn...` for RFC 9421 + HPKE `0xFFFF`
    /// Export MAC negotiation on `com.atproto.space.{getRecord,getRepo}`.
    async fn host_kem_did_key(
        &self,
        _space: &str,
    ) -> core::result::Result<Option<String>, SpaceError> {
        Ok(None)
    }

    /// `true` only when this transport itself verifies every Space read
    /// response (RFC 9421 + HPKE `0xFFFF` Export MAC on `getRecord`/`getRepo`,
    /// writer-inventory commitment on `listWriters`) and fails closed. When
    /// no host KEM key is known, readers accept plain responses only from a
    /// transport that returns `true`; otherwise they refuse with
    /// [`Error::Unauthenticated`].
    fn authenticates_responses(&self) -> bool {
        false
    }
}

/// A Space reference, `at:space/{spaceDid}/{spaceType}/{skey}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SpaceRef {
    pub space_did: String,
    pub space_type: String,
    pub skey: String,
}

impl SpaceRef {
    /// The personal mailbox Space of `did`.
    pub fn mailbox(did: &str) -> Self {
        Self {
            space_did: did.to_owned(),
            space_type: MAILBOX_SPACE_TYPE.to_owned(),
            skey: MAILBOX_SKEY.to_owned(),
        }
    }

    /// Conversation Space `at:space/{authority_did}/blue.catbird.labyrinth.conversation/{skey}`.
    pub fn conversation(authority_did: &str, skey: &str) -> Self {
        Self {
            space_did: authority_did.to_owned(),
            space_type: CONVERSATION_SPACE_TYPE.to_owned(),
            skey: skey.to_owned(),
        }
    }

    /// Parses the canonical `at:space/{did}/{type}/{skey}` form via
    /// [`petrel_spaces::SpaceRef::parse`]; a record URI inside a Space is refused.
    pub fn parse(s: &str) -> Result<Self> {
        petrel_spaces::SpaceRef::parse(s)
            .map(Self::from)
            .map_err(|_| Error::Malformed("space ref"))
    }

    /// Parses canonical `at:space/{did}/{type}/{skey}` or, leniently for values read back from
    /// storage, the alpha `at://{did}/space/{type}/{skey}` form via
    /// [`petrel_spaces::AtUri::from_legacy_space_uri`] (TODO: remove before beta).
    pub fn parse_hedged(s: &str) -> Result<Self> {
        let canonical = petrel_spaces::AtUri::from_legacy_space_uri(s);
        Self::parse(canonical.as_deref().unwrap_or(s))
    }

    /// Converts to a validated [`petrel_spaces::SpaceRef`].
    pub fn to_space_uri(&self) -> Result<petrel_spaces::SpaceRef> {
        petrel_spaces::SpaceRef::parse(self.to_string()).map_err(|_| Error::Malformed("space ref"))
    }
}

impl From<petrel_spaces::SpaceRef> for SpaceRef {
    fn from(uri: petrel_spaces::SpaceRef) -> Self {
        Self {
            space_did: uri.space_did().to_string(),
            space_type: uri.space_type().to_string(),
            skey: uri.skey().to_string(),
        }
    }
}

impl core::fmt::Display for SpaceRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "at:space/{}/{}/{}",
            self.space_did, self.space_type, self.skey
        )
    }
}

#[cfg(feature = "sim")]
thread_local! {
    static FORBID_MEMBER_REPO_SPACE_NOT_FOUND: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Set the simulation-only P16 regression and return its previous scoped value.
#[doc(hidden)]
#[inline]
pub fn set_sim_member_repo_space_not_found_as_forbidden(enabled: bool) -> bool {
    #[cfg(feature = "sim")]
    {
        FORBID_MEMBER_REPO_SPACE_NOT_FOUND.with(|active| active.replace(enabled))
    }
    #[cfg(not(feature = "sim"))]
    {
        let _ = enabled;
        false
    }
}

#[inline(always)]
fn forbid_member_repo_space_not_found() -> bool {
    #[cfg(feature = "sim")]
    {
        FORBID_MEMBER_REPO_SPACE_NOT_FOUND.with(std::cell::Cell::get)
    }
    #[cfg(not(feature = "sim"))]
    {
        false
    }
}

/// Map a member-repository response without treating an unsigned missing Space as removal proof.
///
/// Only an authenticated denial reaches this boundary as `401`/`403`. A relay's unsigned
/// `400`/`404 SpaceNotFound` remains `NotFound`, so read callers cannot enter owner-history
/// fallback and write callers cannot mistake it for permission to dequeue shared-archive work.
pub fn map_member_repo_space_error(e: SpaceError) -> Error {
    let missing_space =
        matches!(e.status, 400 | 404) && e.error.as_deref() == Some("SpaceNotFound");
    if missing_space && forbid_member_repo_space_not_found() {
        Error::Forbidden
    } else {
        map_space_error(e)
    }
}

/// Maps a `com.atproto.space.*` error to the store error.
pub fn map_space_error(e: SpaceError) -> Error {
    let is_not_found_status = e.status == 404 || e.status == 400;
    match e.error.as_deref() {
        Some("MethodNotImplemented") if e.status == 501 => Error::NotSupported("Space endpoint"),
        Some("RecordAlreadyExists" | "InvalidSwap" | "ConcurrentWrite") => Error::Conflict,
        _ if e.status == 409 => Error::Conflict,
        Some("RecordNotFound" | "BlobNotFound") if is_not_found_status => Error::NotFound("record"),
        Some("SpaceNotFound") if is_not_found_status => Error::NotFound("space"),
        Some("SpaceDeleted" | "AccountNotAuthorized" | "NotAuthorized" | "CredentialRevoked") => {
            Error::Forbidden
        }
        Some("RepoNotFound") if is_not_found_status => Error::NotFound("repo"),
        _ if e.status == 403 || e.status == 401 => Error::Forbidden,
        name => Error::Backend(format!(
            "space {}: {}: {}",
            e.status,
            name.unwrap_or("no error name"),
            e.message.as_deref().unwrap_or("")
        )),
    }
}

// ---- wire shapes (com.atproto.space lexicons) ----

#[derive(Serialize)]
#[serde(tag = "$type")]
pub(super) enum WriteOp {
    #[serde(rename = "com.atproto.space.applyWrites#create")]
    Create {
        collection: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        rkey: Option<String>,
        value: Value,
    },
    #[serde(rename = "com.atproto.space.applyWrites#update")]
    Update {
        collection: &'static str,
        rkey: String,
        value: Value,
    },
    #[serde(rename = "com.atproto.space.applyWrites#delete")]
    Delete {
        collection: &'static str,
        rkey: String,
    },
}

#[derive(Serialize)]
pub(super) struct ApplyWritesIn<'a> {
    pub space: String,
    pub repo: &'a str,
    pub validate: bool,
    pub writes: &'a [WriteOp],
}

#[derive(Deserialize)]
pub(super) struct ApplyWritesOut {
    #[serde(default)]
    pub results: Vec<WriteResult>,
}

#[derive(Deserialize)]
pub(super) struct WriteResult {
    pub uri: Option<String>,
    #[serde(default)]
    pub cid: Option<String>,
}

#[derive(Serialize)]
struct DeleteRecordIn<'a> {
    space: String,
    repo: &'a str,
    collection: &'static str,
    rkey: String,
}

#[derive(Deserialize)]
pub(super) struct GetRecordOut {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub cid: Option<String>,
    pub value: Value,
}

#[derive(Deserialize)]
pub(super) struct ListRecordsOut {
    pub cursor: Option<String>,
    pub records: Vec<ListedRecord>,
}

#[derive(Deserialize)]
pub(super) struct ListedRecord {
    pub rkey: String,
    #[serde(default)]
    pub cid: Option<String>,
    pub value: Option<Value>,
}

pub(super) fn encode<T: Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| Error::Backend(format!("encode: {e}")))
}

pub(super) fn decode<T: DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| Error::Malformed("space record"))
}

pub(super) fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|e| Error::Backend(format!("bad space response: {e}")))
}

pub(super) fn uri_rkey(uri: &str) -> Result<String> {
    uri.rsplit('/')
        .next()
        .filter(|r| !r.is_empty())
        .map(str::to_owned)
        .ok_or(Error::Backend("space write result without rkey".into()))
}

fn system_now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Default)]
struct NoopKeyPublisher;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyPublisher for NoopKeyPublisher {
    async fn publish(&self, _record: &MailboxKeysRecord) -> Result<()> {
        Ok(())
    }

    async fn retract(&self) -> Result<()> {
        Ok(())
    }
}

/// A personal mailbox in the owner's own Space on its PDS.
pub struct SpaceMailboxStore {
    did: String,
    space: SpaceRef,
    t: Arc<dyn SpaceRpc>,
    keys: Box<dyn KeyPublisher>,
    now_ms: crate::store::ClockFn,
    page: usize,
    floors: WriterRevFloors,
    version_floors: OwnerStateVersionFloors,
}

impl SpaceMailboxStore {
    /// Constructs a [`SpaceMailboxStore`] bound to `space` and `did`.
    /// Attach a public `mailboxKeys` publisher via [`Self::with_key_publisher`].
    pub fn new(
        transport: impl Into<Arc<dyn SpaceRpc>>,
        space: SpaceRef,
        did: impl Into<String>,
    ) -> Self {
        Self {
            did: did.into(),
            space,
            t: transport.into(),
            keys: Box::new(NoopKeyPublisher),
            now_ms: Arc::new(system_now_ms),
            page: LIST_LIMIT,
            floors: WriterRevFloors::new(),
            version_floors: OwnerStateVersionFloors::new(),
        }
    }

    /// Convenience constructor for `did`'s canonical [`SpaceRef::mailbox`] with an explicit publisher.
    pub fn for_owner(
        did: &str,
        transport: impl Into<Arc<dyn SpaceRpc>>,
        mailbox_keys: Box<dyn KeyPublisher>,
    ) -> Self {
        Self::new(transport, SpaceRef::mailbox(did), did.to_owned())
            .with_key_publisher(mailbox_keys)
    }

    /// Validated constructor checking `space` is `blue.catbird.labyrinth.mailbox` owned by `owner_did`.
    pub fn in_space(
        owner_did: &str,
        space: SpaceRef,
        transport: impl Into<Arc<dyn SpaceRpc>>,
        mailbox_keys: Box<dyn KeyPublisher>,
    ) -> Result<Self> {
        if space.space_type != MAILBOX_SPACE_TYPE {
            return Err(Error::Malformed("mailbox Space type"));
        }
        if space.space_did != owner_did || !owner_did.starts_with("did:") || owner_did.contains('/')
        {
            return Err(Error::Malformed("mailbox Space owner"));
        }
        Ok(Self::new(transport, space, owner_did.to_owned()).with_key_publisher(mailbox_keys))
    }

    #[doc(hidden)]
    pub fn in_space_unchecked_for_test(
        space: SpaceRef,
        transport: impl Into<Arc<dyn SpaceRpc>>,
        mailbox_keys: Box<dyn KeyPublisher>,
    ) -> Self {
        let did = space.space_did.clone();
        Self::new(transport, space, did).with_key_publisher(mailbox_keys)
    }

    pub fn with_key_publisher(mut self, keys: Box<dyn KeyPublisher>) -> Self {
        self.keys = keys;
        self
    }

    /// Records per `listRecords` page (`1..=1000`; default [`LIST_LIMIT`]).
    pub fn with_page_size(mut self, n: usize) -> Self {
        self.page = n.clamp(1, 1_000);
        self
    }

    /// Replaces the clock that stamps `lastUsedAt`.
    pub fn with_clock(mut self, now_ms: crate::store::ClockFn) -> Self {
        self.now_ms = now_ms;
        self
    }

    /// Attaches a shared [`WriterRevFloors`] tracker.
    pub fn with_writer_rev_floors(mut self, floors: WriterRevFloors) -> Self {
        self.floors = floors;
        self
    }

    /// Returns the attached [`WriterRevFloors`] tracker.
    pub fn writer_rev_floors(&self) -> &WriterRevFloors {
        &self.floors
    }

    /// Queries `listSpaces` for this mailbox's authority and checks the
    /// owner's `(space_uri, owner_did)` commit revision against the pinned
    /// floor. The listing is not authenticated, so it never raises the floor;
    /// only an authenticated commit does.
    pub async fn observe_space_revision(&self) -> Result<Option<String>> {
        let p = [
            ("spaceDid", self.space.space_did.clone()),
            ("spaceType", self.space.space_type.clone()),
            ("limit", "100".to_owned()),
        ];
        let body = self
            .t
            .query(endpoint::LIST_SPACES, &p)
            .await
            .map_err(map_space_error)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SpaceView {
            space: String,
            #[serde(default)]
            repo_rev: Option<String>,
        }
        #[derive(Deserialize)]
        struct Out {
            #[serde(default)]
            spaces: Vec<SpaceView>,
        }
        let out: Out = decode_body(&body)?;
        let target = self.space.to_string();
        for s in out.spaces {
            if s.space == target
                && let Some(rev) = s.repo_rev
            {
                self.floors
                    .check_not_rolled_back(&target, &self.did, &rev)?;
                return Ok(Some(rev));
            }
        }
        Ok(None)
    }

    pub fn space(&self) -> &SpaceRef {
        &self.space
    }

    async fn apply_results(&self, writes: &[WriteOp]) -> Result<Vec<WriteResult>> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        if writes.len() > MAX_WRITES {
            return Err(Error::Backend(format!(
                "space applyWrites: {} writes, max {MAX_WRITES}",
                writes.len()
            )));
        }
        let input = ApplyWritesIn {
            space: self.space.to_string(),
            repo: &self.did,
            validate: false,
            writes,
        };
        let payload =
            serde_json::to_vec(&input).map_err(|e| Error::Backend(format!("encode: {e}")))?;
        let body = self
            .t
            .procedure(endpoint::APPLY_WRITES, &payload)
            .await
            .map_err(map_space_error)?;
        let out: ApplyWritesOut = decode_body(&body)?;
        Ok(out.results)
    }

    async fn apply(&self, writes: &[WriteOp]) -> Result<Vec<Option<String>>> {
        Ok(self
            .apply_results(writes)
            .await?
            .into_iter()
            .map(|r| r.uri)
            .collect())
    }

    async fn get_with_cid<T: DeserializeOwned>(
        &self,
        collection: &str,
        rkey: &str,
    ) -> Result<Option<(T, Option<String>)>> {
        let p = [
            ("space", self.space.to_string()),
            ("repo", self.did.clone()),
            ("collection", collection.to_owned()),
            ("rkey", rkey.to_owned()),
        ];
        match self
            .t
            .query(endpoint::GET_RECORD, &p)
            .await
            .map_err(map_space_error)
        {
            Ok(body) => {
                let out: GetRecordOut = decode_body(&body)?;
                Ok(Some((decode(out.value)?, out.cid)))
            }
            Err(Error::NotFound("record" | "repo")) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn get<T: DeserializeOwned>(&self, collection: &str, rkey: &str) -> Result<Option<T>> {
        Ok(self
            .get_with_cid(collection, rkey)
            .await?
            .map(|(value, _)| value))
    }

    async fn delete_record_idempotent(&self, collection: &'static str, rkey: &str) -> Result<()> {
        let input = DeleteRecordIn {
            space: self.space.to_string(),
            repo: &self.did,
            collection,
            rkey: rkey.to_owned(),
        };
        let payload =
            serde_json::to_vec(&input).map_err(|e| Error::Backend(format!("encode: {e}")))?;
        match self
            .t
            .procedure(endpoint::DELETE_RECORD, &payload)
            .await
            .map_err(map_space_error)
        {
            Ok(_) | Err(Error::NotFound("record" | "repo")) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Every `(rkey, cid, value)` of `collection`, ascending by `rkey`.
    async fn list_raw_with_cid(
        &self,
        collection: &str,
        values: bool,
    ) -> Result<Vec<(String, Option<String>, Value)>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        let mut response_bytes = 0usize;
        for _ in 0..MAX_SPACE_PAGES {
            let mut p = vec![
                ("space", self.space.to_string()),
                ("repo", self.did.clone()),
                ("collection", collection.to_owned()),
                ("limit", self.page.to_string()),
            ];
            if !values {
                p.push(("excludeValues", "true".to_owned()));
            }
            if let Some(c) = &cursor {
                p.push(("cursor", c.clone()));
            }
            let body = match self
                .t
                .query(endpoint::LIST_RECORDS, &p)
                .await
                .map_err(map_space_error)
            {
                Ok(body) => body,
                Err(Error::NotFound("repo")) => return Ok(out),
                Err(e) => return Err(e),
            };
            if body.len() > MAX_SPACE_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "space response exceeds {MAX_SPACE_RESPONSE_BYTES} bytes"
                )));
            }
            response_bytes = response_bytes.checked_add(body.len()).ok_or_else(|| {
                Error::Backend("space listing response byte count overflow".into())
            })?;
            if response_bytes > MAX_SPACE_LIST_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "space listing responses exceed {MAX_SPACE_LIST_RESPONSE_BYTES} bytes"
                )));
            }
            let page: ListRecordsOut = decode_body(&body)?;
            if page.records.len() > self.page {
                return Err(Error::Backend(format!(
                    "space page exceeds {} records",
                    self.page
                )));
            }
            let total = out
                .len()
                .checked_add(page.records.len())
                .ok_or_else(|| Error::Backend("space listing item count overflow".into()))?;
            if total > MAX_SPACE_LIST_ITEMS {
                return Err(Error::Backend(format!(
                    "space listing exceeds {MAX_SPACE_LIST_ITEMS} records"
                )));
            }
            out.extend(
                page.records
                    .into_iter()
                    .map(|r| (r.rkey, r.cid, r.value.unwrap_or(Value::Null))),
            );
            match page.cursor {
                Some(c) if c.len() > MAX_SPACE_CURSOR_BYTES => {
                    return Err(Error::Backend(format!(
                        "space cursor exceeds {MAX_SPACE_CURSOR_BYTES} bytes"
                    )));
                }
                Some(c) if seen_cursors.insert(c.clone()) => cursor = Some(c),
                Some(_) => return Err(Error::Backend("space cursor cycle".into())),
                None => {
                    out.sort_by(|a, b| a.0.cmp(&b.0));
                    return Ok(out);
                }
            }
        }
        Err(Error::Backend("space listing too long".into()))
    }

    /// Every `(rkey, value)` of `collection`, ascending by `rkey`.
    async fn list_raw(&self, collection: &str, values: bool) -> Result<Vec<(String, Value)>> {
        Ok(self
            .list_raw_with_cid(collection, values)
            .await?
            .into_iter()
            .map(|(k, _, v)| (k, v))
            .collect())
    }

    async fn list_with_cid<T: DeserializeOwned>(
        &self,
        collection: &str,
    ) -> Result<Vec<(String, T, Option<String>)>> {
        self.list_raw_with_cid(collection, true)
            .await?
            .into_iter()
            .map(|(k, cid, v)| Ok((k, decode(v)?, cid)))
            .collect()
    }

    async fn list<T: DeserializeOwned>(&self, collection: &str) -> Result<Vec<(String, T)>> {
        self.list_raw(collection, true)
            .await?
            .into_iter()
            .map(|(k, v)| Ok((k, decode(v)?)))
            .collect()
    }

    async fn create(
        &self,
        collection: &'static str,
        rkey: String,
        value: &impl Serialize,
    ) -> Result<()> {
        self.apply(&[WriteOp::Create {
            collection,
            rkey: Some(rkey),
            value: encode(value)?,
        }])
        .await?;
        Ok(())
    }

    async fn update(
        &self,
        collection: &'static str,
        rkey: String,
        value: &impl Serialize,
    ) -> Result<()> {
        self.apply(&[WriteOp::Update {
            collection,
            rkey,
            value: encode(value)?,
        }])
        .await?;
        Ok(())
    }

    fn is_hyphenated_uuid_36(s: &str) -> bool {
        let b = s.as_bytes();
        if b.len() != 36 {
            return false;
        }
        for (i, &ch) in b.iter().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if ch != b'-' {
                    return false;
                }
            } else if !ch.is_ascii_hexdigit() {
                return false;
            }
        }
        true
    }

    fn versioned_cas_rkey(logical_id: &str, version: u64) -> String {
        format!("{logical_id}-{version:012}")
    }

    fn match_versioned_rkey(logical_id: &str, rkey: &str) -> Option<u64> {
        if rkey == logical_id {
            return Some(0);
        }
        let suffix = rkey.strip_prefix(logical_id)?.strip_prefix('-')?;
        if suffix.len() != 12 || !suffix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        suffix.parse::<u64>().ok().filter(|&v| v >= 1)
    }

    fn split_versioned_rkey(rkey: &str) -> (&str, u64) {
        if !Self::is_hyphenated_uuid_36(rkey)
            && let Some((prefix, suffix)) = rkey.rsplit_once('-')
            && !prefix.is_empty()
            && suffix.len() == 12
            && suffix.bytes().all(|b| b.is_ascii_digit())
            && let Ok(ver) = suffix.parse::<u64>()
            && ver >= 1
        {
            return (prefix, ver);
        }
        (rkey, 0)
    }

    async fn get_versioned_cas<T: DeserializeOwned>(
        &self,
        collection: &'static str,
        logical_id: &str,
    ) -> Result<Option<(T, Option<String>, u64)>> {
        let best = self
            .list_raw_with_cid(collection, true)
            .await?
            .into_iter()
            .filter_map(|(rkey, cid, value)| {
                Self::match_versioned_rkey(logical_id, &rkey).map(|ver| (ver, cid, value))
            })
            .max_by_key(|(ver, _, _)| *ver);
        let Some((ver, cid, value)) = best else {
            if self
                .version_floors
                .pinned(collection, logical_id)
                .is_some_and(|pinned| pinned > 0)
            {
                return Err(Error::Malformed("owner state version rollback"));
            }
            return Ok(None);
        };
        // Check only: the record is not authenticated until the client opens
        // it, so the floor is raised by the client after decryption.
        self.version_floors.check(collection, logical_id, ver)?;
        Ok(Some((decode(value)?, cid, ver)))
    }

    async fn list_versioned_cas<T: DeserializeOwned>(
        &self,
        collection: &'static str,
    ) -> Result<Vec<(String, T, Option<String>, u64)>> {
        let mut by_logical: BTreeMap<String, (u64, T, Option<String>)> = BTreeMap::new();
        for (rkey, rec, cid) in self.list_with_cid::<T>(collection).await? {
            let (logical_id, ver) = Self::split_versioned_rkey(&rkey);
            match by_logical.get(logical_id) {
                Some((cur_ver, _, _)) if *cur_ver > ver => {}
                _ => {
                    by_logical.insert(logical_id.to_owned(), (ver, rec, cid));
                }
            }
        }
        for ((pinned_col, pinned_id), pinned_ver) in self.version_floors.snapshot() {
            if pinned_col == collection
                && pinned_ver > 0
                && by_logical
                    .get(&pinned_id)
                    .is_none_or(|(ver, _, _)| *ver < pinned_ver)
            {
                return Err(Error::Malformed("owner state version rollback"));
            }
        }
        for (logical_id, (ver, _, _)) in &by_logical {
            self.version_floors.check(collection, logical_id, *ver)?;
        }
        Ok(by_logical
            .into_iter()
            .map(|(logical_id, (ver, rec, cid))| (logical_id, rec, cid, ver))
            .collect())
    }

    async fn put_versioned_cas(
        &self,
        collection: &'static str,
        logical_id: &str,
        value: &impl Serialize,
        expected_cid: Option<&str>,
    ) -> Result<String> {
        let encoded = encode(value)?;
        let existing: Vec<(u64, String, Option<String>)> = self
            .list_raw_with_cid(collection, false)
            .await?
            .into_iter()
            .filter_map(|(rkey, cid, _)| {
                Self::match_versioned_rkey(logical_id, &rkey).map(|ver| (ver, rkey, cid))
            })
            .collect();
        let pinned = self
            .version_floors
            .pinned(collection, logical_id)
            .unwrap_or(0);

        let next_ver = match expected_cid {
            None => {
                if !existing.is_empty() {
                    return Err(Error::Conflict);
                }
                if pinned > 0 {
                    return Err(Error::Malformed("owner state version rollback"));
                }
                1
            }
            Some(expected) => {
                let Some((max_ver, _, max_cid)) = existing.iter().max_by_key(|(ver, _, _)| *ver)
                else {
                    if pinned > 0 {
                        return Err(Error::Malformed("owner state version rollback"));
                    }
                    return Err(Error::Conflict);
                };
                if *max_ver < pinned {
                    return Err(Error::Malformed("owner state version rollback"));
                }
                if max_cid.as_deref() != Some(expected) {
                    return Err(Error::Conflict);
                }
                max_ver
                    .checked_add(1)
                    .ok_or_else(|| Error::Backend("cas version overflow".into()))?
            }
        };

        let target_rkey = Self::versioned_cas_rkey(logical_id, next_ver);
        let results = self
            .apply_results(&[WriteOp::Create {
                collection,
                rkey: Some(target_rkey),
                value: encoded,
            }])
            .await?;
        let written_cid = results
            .into_iter()
            .next()
            .and_then(|r| r.cid)
            .ok_or_else(|| Error::Backend("space create result missing cid".into()))?;
        self.version_floors
            .observe(collection, logical_id, next_ver)?;
        Ok(written_cid)
    }

    fn stored<T>(&self, rkey: String, value: T) -> Stored<T> {
        Stored {
            author: self.did.clone(),
            rkey,
            value,
            order: None,
        }
    }

    async fn owner_batches(&self, thread_id: Option<&str>) -> Result<Vec<Stored<OwnerBatch>>> {
        Ok(self
            .list::<OwnerBatch>(nsid::OWNER_BATCH)
            .await?
            .into_iter()
            .filter(|(_, b)| thread_id.is_none_or(|t| b.thread_id == t))
            .map(|(k, b)| self.stored(k, b))
            .collect())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxStore for SpaceMailboxStore {
    fn owner(&self) -> &str {
        &self.did
    }

    async fn create_device(&self, device: &Device) -> Result<()> {
        self.create(
            nsid::DEVICE,
            hex::encode(&device.device_key_pubkey.0),
            device,
        )
        .await
    }

    async fn set_device_revoked(&self, device_key: &XVerifyingKey, revoked_at: &str) -> Result<()> {
        let rkey = hex::encode(device_key.0);
        let mut d: Device = self
            .get(nsid::DEVICE, &rkey)
            .await?
            .ok_or(Error::NotFound("device"))?;
        if d.revoked_at.is_some() {
            return Ok(());
        }
        d.revoked_at = Some(revoked_at.to_owned());
        self.update(nsid::DEVICE, rkey, &d).await
    }

    async fn set_device_revocation(
        &self,
        device_key: &XVerifyingKey,
        revoked_at: &str,
        revocation: &crate::records::DeviceRevocationDef,
    ) -> Result<()> {
        let rkey = hex::encode(device_key.0);
        let mut d: Device = self
            .get(nsid::DEVICE, &rkey)
            .await?
            .ok_or(Error::NotFound("device"))?;
        let all_devices = self.list_devices().await?;
        if !crate::records::should_replace_device_revocation(
            self.owner(),
            device_key,
            &d,
            &all_devices,
            revoked_at,
            revocation,
        ) {
            return Ok(());
        }
        d.revoked_at = Some(revoked_at.to_owned());
        d.revocation = Some(revocation.clone());
        self.update(nsid::DEVICE, rkey, &d).await
    }

    async fn get_device(&self, device_key: &XVerifyingKey) -> Result<Option<Device>> {
        self.get(nsid::DEVICE, &hex::encode(device_key.0)).await
    }

    async fn list_devices(&self) -> Result<Vec<Device>> {
        Ok(self
            .list(nsid::DEVICE)
            .await?
            .into_iter()
            .map(|(_, d)| d)
            .collect())
    }

    async fn create_epoch(&self, epoch: &Epoch, members: &[EpochMember]) -> Result<String> {
        let id = space_epoch_id(epoch.seq());
        if members.iter().any(|m| m.epoch_number != epoch.seq()) {
            return Err(Error::Conflict);
        }
        let mut writes = vec![WriteOp::Create {
            collection: nsid::EPOCH,
            rkey: Some(id.clone()),
            value: encode(epoch)?,
        }];
        for m in members {
            writes.push(WriteOp::Create {
                collection: nsid::EPOCH_MEMBER,
                rkey: Some(m.rkey()),
                value: encode(m)?,
            });
        }
        self.apply(&writes).await?;
        Ok(id)
    }

    async fn atomic_enroll(&self, bundle: &AtomicEnrollBundle) -> Result<String> {
        let seq = bundle.epoch.seq();
        let id = space_epoch_id(seq);
        if bundle.members.iter().any(|m| m.epoch_number != seq) {
            return Err(Error::Conflict);
        }
        let mut writes = Vec::with_capacity(3 + bundle.members.len());
        if let Some(cleanup) = &bundle.cleanup {
            match cleanup {
                EnrollCleanup::ConsumeOtcSession { rkey } => {
                    if self
                        .get::<OtcSession>(nsid::OTC_SESSION, rkey)
                        .await?
                        .is_none()
                    {
                        return Err(Error::Conflict);
                    }
                    writes.push(WriteOp::Delete {
                        collection: nsid::OTC_SESSION,
                        rkey: rkey.clone(),
                    });
                }
                EnrollCleanup::TouchVirtualDevice { updated } => {
                    let vkey = updated.rkey();
                    if self
                        .get::<VirtualDevice>(nsid::VIRTUAL_DEVICE, &vkey)
                        .await?
                        .is_none()
                    {
                        return Err(Error::NotFound("virtual device"));
                    }
                    writes.push(WriteOp::Update {
                        collection: nsid::VIRTUAL_DEVICE,
                        rkey: vkey,
                        value: encode(updated)?,
                    });
                }
            }
        }
        writes.push(WriteOp::Create {
            collection: nsid::DEVICE,
            rkey: Some(hex::encode(&bundle.device.device_key_pubkey.0)),
            value: encode(&bundle.device)?,
        });
        writes.push(WriteOp::Create {
            collection: nsid::EPOCH,
            rkey: Some(id.clone()),
            value: encode(&bundle.epoch)?,
        });
        for m in &bundle.members {
            writes.push(WriteOp::Create {
                collection: nsid::EPOCH_MEMBER,
                rkey: Some(m.rkey()),
                value: encode(m)?,
            });
        }
        match self.apply(&writes).await {
            Ok(_) => Ok(id),
            Err(Error::NotFound("record")) => Err(Error::Conflict),
            Err(e) => Err(e),
        }
    }

    async fn get_epoch(&self, seq: u64) -> Result<Option<Stored<Epoch>>> {
        let id = space_epoch_id(seq);
        Ok(self
            .get::<Epoch>(nsid::EPOCH, &id)
            .await?
            .map(|e| self.stored(id, e)))
    }

    async fn list_epochs(&self) -> Result<Vec<Stored<Epoch>>> {
        Ok(self
            .list::<Epoch>(nsid::EPOCH)
            .await?
            .into_iter()
            .map(|(k, e)| self.stored(k, e))
            .collect())
    }

    async fn create_epoch_member(&self, member: &EpochMember) -> Result<()> {
        if self.get_epoch(member.epoch_number).await?.is_none() {
            return Err(Error::NotFound("epoch"));
        }
        self.create(nsid::EPOCH_MEMBER, member.rkey(), member).await
    }

    async fn list_epoch_members(&self, seq: u64) -> Result<Vec<EpochMember>> {
        let prefix = format!("{}-", space_epoch_id(seq));
        Ok(self
            .list::<EpochMember>(nsid::EPOCH_MEMBER)
            .await?
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, m)| m)
            .collect())
    }

    async fn get_epoch_member(
        &self,
        seq: u64,
        device_key: &XVerifyingKey,
    ) -> Result<Option<EpochMember>> {
        let rkey = format!("{}-{}", space_epoch_id(seq), hex::encode(device_key.0));
        self.get(nsid::EPOCH_MEMBER, &rkey).await
    }

    async fn create_virtual_device(&self, vdevice: &VirtualDevice) -> Result<()> {
        self.create(nsid::VIRTUAL_DEVICE, vdevice.rkey(), vdevice)
            .await
    }

    async fn get_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<Option<VirtualDevice>> {
        self.get(nsid::VIRTUAL_DEVICE, &hex::encode(vdevice_id))
            .await
    }

    async fn list_virtual_devices(&self) -> Result<Vec<VirtualDevice>> {
        Ok(self
            .list(nsid::VIRTUAL_DEVICE)
            .await?
            .into_iter()
            .map(|(_, v)| v)
            .collect())
    }

    async fn list_virtual_device_records(&self) -> Result<Vec<Result<VirtualDevice>>> {
        Ok(self
            .list_raw(nsid::VIRTUAL_DEVICE, true)
            .await?
            .into_iter()
            .map(|(rkey, v)| {
                let vd = decode::<VirtualDevice>(v)?;
                if vd.rkey() != rkey {
                    return Err(Error::Malformed("virtualDevice filed under wrong rkey"));
                }
                Ok(vd)
            })
            .collect())
    }

    async fn put_otc_session(&self, session: &OtcSession) -> Result<()> {
        session.check()?;
        let rkey = session.rkey().to_owned();
        if self
            .get::<OtcSession>(nsid::OTC_SESSION, &rkey)
            .await?
            .is_some()
        {
            self.update(nsid::OTC_SESSION, rkey, session).await
        } else {
            self.create(nsid::OTC_SESSION, rkey, session).await
        }
    }

    async fn get_otc_session(&self, session_id: &str) -> Result<Option<OtcSession>> {
        self.get(nsid::OTC_SESSION, session_id).await
    }

    async fn append_owner_batch(&self, batch: &OwnerBatch) -> Result<String> {
        let uris = self
            .apply(&[WriteOp::Create {
                collection: nsid::OWNER_BATCH,
                rkey: None,
                value: encode(batch)?,
            }])
            .await?;
        match uris.as_slice() {
            [Some(uri)] => uri_rkey(uri),
            _ => Err(Error::Backend(
                "space applyWrites returned no create result".into(),
            )),
        }
    }

    async fn list_owner_batches(
        &self,
        thread_id: &str,
        range: TimeRange,
    ) -> Result<Vec<Stored<OwnerBatch>>> {
        let mut v = self.owner_batches(Some(thread_id)).await?;
        v.retain(|b| b.value.items.iter().any(|i| range.contains(i.timestamp)));
        Ok(v)
    }

    async fn upload_and_commit_owner_attachment(
        &self,
        rkey: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> Result<String> {
        verify_attachment_ciphertext(ciphertext, meta)?;
        let mime = meta
            .mime_type_hint
            .as_deref()
            .unwrap_or("application/octet-stream");
        let cid = self
            .t
            .upload_blob(ciphertext, mime)
            .await
            .map_err(map_space_error)?;
        let manifest = AttachmentManifest::from_meta(&cid, meta, created_at.to_owned());
        self.create(nsid::ATTACHMENT_MANIFEST, rkey.to_owned(), &manifest)
            .await?;
        Ok(cid)
    }

    async fn get_owner_attachment_verified(&self, rkey: &str) -> Result<Vec<u8>> {
        let manifest: AttachmentManifest = self
            .get(nsid::ATTACHMENT_MANIFEST, rkey)
            .await?
            .ok_or(Error::NotFound("attachmentManifest"))?;
        let (cid, meta) = manifest.to_meta()?;
        let bytes = self
            .t
            .get_blob(&self.space.to_string(), &self.did, &cid)
            .await
            .map_err(map_space_error)?;
        verify_attachment_ciphertext(&bytes, &meta)?;
        Ok(bytes)
    }

    async fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> Result<()> {
        self.keys.publish(record).await
    }

    async fn list_owner_threads(&self) -> Result<Vec<String>> {
        let mut v: Vec<String> = self
            .owner_batches(None)
            .await?
            .into_iter()
            .map(|b| b.value.thread_id)
            .collect();
        v.sort();
        v.dedup();
        Ok(v)
    }

    async fn touch_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        let rkey = hex::encode(vdevice_id);
        let mut v: VirtualDevice = self
            .get(nsid::VIRTUAL_DEVICE, &rkey)
            .await?
            .ok_or(Error::NotFound("virtual device"))?;
        v.last_used_at = Some(datetime_from_ms((self.now_ms)()));
        self.update(nsid::VIRTUAL_DEVICE, rkey, &v).await
    }

    async fn delete_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        self.delete_record_idempotent(nsid::VIRTUAL_DEVICE, &hex::encode(vdevice_id))
            .await
    }

    async fn delete_squatted_epoch(&self, seq: u64) -> Result<()> {
        let epoch_rkey = space_epoch_id(seq);
        let member_prefix = format!("{seq:012}-");
        let mut writes: Vec<WriteOp> = self
            .list_raw(nsid::EPOCH_MEMBER, false)
            .await?
            .into_iter()
            .filter(|(rkey, _)| rkey.starts_with(&member_prefix))
            .map(|(rkey, _)| WriteOp::Delete {
                collection: nsid::EPOCH_MEMBER,
                rkey,
            })
            .collect();
        if self.get::<Value>(nsid::EPOCH, &epoch_rkey).await?.is_some() {
            writes.push(WriteOp::Delete {
                collection: nsid::EPOCH,
                rkey: epoch_rkey,
            });
        }
        for chunk in writes.chunks(MAX_WRITES) {
            match self.apply(chunk).await {
                Ok(_) => {}
                Err(Error::NotFound("record")) => {
                    for op in chunk {
                        if let WriteOp::Delete { collection, rkey } = op {
                            self.delete_record_idempotent(collection, rkey).await?;
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn purge_mailbox(&self) -> Result<()> {
        for collection in MAILBOX_COLLECTIONS {
            let rkeys: Vec<String> = self
                .list_raw(collection, false)
                .await?
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            for chunk in rkeys.chunks(MAX_WRITES) {
                let writes: Vec<WriteOp> = chunk
                    .iter()
                    .map(|rkey| WriteOp::Delete {
                        collection,
                        rkey: rkey.clone(),
                    })
                    .collect();
                self.apply(&writes).await?;
            }
        }
        self.version_floors.clear();
        self.keys.retract().await
    }

    async fn get_read_state_versioned(
        &self,
        conversation_id: &str,
    ) -> Result<Option<(ReadStateRecord, Option<String>, u64)>> {
        let Some((rec, cid, ver)) = self
            .get_versioned_cas::<ReadStateRecord>(nsid::READ_STATE, conversation_id)
            .await?
        else {
            return Ok(None);
        };
        rec.check()?;
        Ok(Some((rec, cid, ver)))
    }

    async fn get_read_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<(ReadStateRecord, Option<String>)>> {
        Ok(self
            .get_read_state_versioned(conversation_id)
            .await?
            .map(|(rec, cid, _)| (rec, cid)))
    }

    async fn put_read_state(
        &self,
        conversation_id: &str,
        record: &ReadStateRecord,
        expected_cid: Option<&str>,
    ) -> Result<String> {
        record.check()?;
        self.put_versioned_cas(nsid::READ_STATE, conversation_id, record, expected_cid)
            .await
    }

    async fn list_read_states_versioned(
        &self,
    ) -> Result<Vec<(String, ReadStateRecord, Option<String>, u64)>> {
        let rows = self
            .list_versioned_cas::<ReadStateRecord>(nsid::READ_STATE)
            .await?;
        for (_, rec, _, _) in &rows {
            rec.check()?;
        }
        Ok(rows)
    }

    async fn list_read_states(&self) -> Result<Vec<(String, ReadStateRecord, Option<String>)>> {
        Ok(self
            .list_read_states_versioned()
            .await?
            .into_iter()
            .map(|(id, rec, cid, _)| (id, rec, cid))
            .collect())
    }

    async fn get_circle_owner_state_versioned(
        &self,
        circle_id: &str,
    ) -> Result<Option<(CircleOwnerStateRecord, Option<String>, u64)>> {
        let Some((rec, cid, ver)) = self
            .get_versioned_cas::<CircleOwnerStateRecord>(nsid::CIRCLE_OWNER_STATE, circle_id)
            .await?
        else {
            return Ok(None);
        };
        rec.check()?;
        Ok(Some((rec, cid, ver)))
    }

    async fn get_circle_owner_state(
        &self,
        circle_id: &str,
    ) -> Result<Option<(CircleOwnerStateRecord, Option<String>)>> {
        Ok(self
            .get_circle_owner_state_versioned(circle_id)
            .await?
            .map(|(rec, cid, _)| (rec, cid)))
    }

    async fn put_circle_owner_state(
        &self,
        circle_id: &str,
        record: &CircleOwnerStateRecord,
        expected_cid: Option<&str>,
    ) -> Result<String> {
        record.check()?;
        self.put_versioned_cas(nsid::CIRCLE_OWNER_STATE, circle_id, record, expected_cid)
            .await
    }

    async fn list_circle_owner_states_versioned(
        &self,
    ) -> Result<Vec<(String, CircleOwnerStateRecord, Option<String>, u64)>> {
        let rows = self
            .list_versioned_cas::<CircleOwnerStateRecord>(nsid::CIRCLE_OWNER_STATE)
            .await?;
        for (_, rec, _, _) in &rows {
            rec.check()?;
        }
        Ok(rows)
    }

    async fn list_circle_owner_states(
        &self,
    ) -> Result<Vec<(String, CircleOwnerStateRecord, Option<String>)>> {
        Ok(self
            .list_circle_owner_states_versioned()
            .await?
            .into_iter()
            .map(|(id, rec, cid, _)| (id, rec, cid))
            .collect())
    }

    fn seed_writer_rev_floors(&self, floors: &BTreeMap<(String, String), String>) {
        self.floors.seed(floors);
    }

    fn replace_writer_rev_floors(&self, floors: &BTreeMap<(String, String), String>) {
        self.floors.replace(floors);
    }

    fn export_writer_rev_floors(&self) -> BTreeMap<(String, String), String> {
        self.floors.snapshot()
    }

    fn seed_owner_state_version_floors(&self, floors: &BTreeMap<(String, String), u64>) {
        self.version_floors.seed(floors);
    }

    fn replace_owner_state_version_floors(&self, floors: &BTreeMap<(String, String), u64>) {
        self.version_floors.replace(floors);
    }

    fn export_owner_state_version_floors(&self) -> BTreeMap<(String, String), u64> {
        self.version_floors.snapshot()
    }
}

#[cfg(test)]
mod bounded_tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use futures::executor::block_on;
    use serde_json::json;

    use super::*;

    #[test]
    fn unsigned_member_repo_space_not_found_remains_not_found() {
        for status in [400, 404] {
            let missing = || SpaceError::named(status, "SpaceNotFound", "gone");
            assert_eq!(
                map_member_repo_space_error(missing()),
                Error::NotFound("space")
            );
            assert_eq!(map_space_error(missing()), Error::NotFound("space"));
        }
    }

    #[cfg(feature = "sim")]
    #[test]
    fn p16_restores_the_unsigned_member_repo_denial_bug() {
        let previous = set_sim_member_repo_space_not_found_as_forbidden(true);
        assert_eq!(
            map_member_repo_space_error(SpaceError::named(404, "SpaceNotFound", "gone")),
            Error::Forbidden
        );
        set_sim_member_repo_space_not_found_as_forbidden(previous);
    }

    struct Scripted {
        replies: Mutex<VecDeque<Vec<u8>>>,
    }

    impl Scripted {
        fn new(replies: impl IntoIterator<Item = Value>) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(
                    replies
                        .into_iter()
                        .map(|value| serde_json::to_vec(&value).unwrap())
                        .collect(),
                ),
            })
        }

        fn raw(replies: impl IntoIterator<Item = Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies.into_iter().collect()),
            })
        }
    }

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl SpaceRpc for Scripted {
        async fn query(
            &self,
            _: &str,
            _: &[(&str, String)],
        ) -> core::result::Result<Vec<u8>, SpaceError> {
            self.replies.lock().unwrap().pop_front().ok_or(SpaceError {
                status: 599,
                error: Some("ScriptExhausted".into()),
                message: None,
            })
        }

        async fn procedure(&self, _: &str, _: &[u8]) -> core::result::Result<Vec<u8>, SpaceError> {
            unreachable!("listing tests never write")
        }
    }

    fn store(transport: Arc<dyn SpaceRpc>) -> SpaceMailboxStore {
        SpaceMailboxStore::new(
            transport,
            SpaceRef::mailbox("did:plc:alice"),
            "did:plc:alice",
        )
        .with_page_size(100)
    }

    #[test]
    fn personal_listing_rejects_a_non_adjacent_cursor_cycle() {
        let transport = Scripted::new([
            json!({"records": [], "cursor": "a"}),
            json!({"records": [], "cursor": "b"}),
            json!({"records": [], "cursor": "a"}),
        ]);
        assert_eq!(
            block_on(store(transport).list_raw(nsid::DEVICE, false)).unwrap_err(),
            Error::Backend("space cursor cycle".into())
        );
    }

    #[test]
    fn personal_listing_rejects_more_than_ten_thousand_records() {
        let replies = (0..101).map(|page| {
            let records = (0..100)
                .map(|item| json!({"rkey": format!("r{page:03}-{item:03}")}))
                .collect::<Vec<_>>();
            json!({
                "records": records,
                "cursor": (page < 100).then(|| format!("c{page}")),
            })
        });
        assert_eq!(
            block_on(store(Scripted::new(replies)).list_raw(nsid::DEVICE, false)).unwrap_err(),
            Error::Backend("space listing exceeds 10000 records".into())
        );
    }

    #[test]
    fn personal_listing_rejects_an_oversized_response_before_decoding() {
        assert_eq!(
            block_on(
                store(Scripted::raw([vec![b' '; 16 * 1024 * 1024 + 1]]))
                    .list_raw(nsid::DEVICE, false)
            )
            .unwrap_err(),
            Error::Backend("space response exceeds 16777216 bytes".into())
        );
    }

    #[test]
    fn personal_listing_rejects_more_than_sixty_four_mebibytes_across_pages() {
        let replies = (0..5).map(|page| {
            json!({
                "records": [],
                "cursor": (page < 4).then(|| format!("c{page}")),
                "padding": "x".repeat(if page < 4 { 15 * 1024 * 1024 } else { 5 * 1024 * 1024 }),
            })
        });
        assert_eq!(
            block_on(store(Scripted::new(replies)).list_raw(nsid::DEVICE, false)).unwrap_err(),
            Error::Backend("space listing responses exceed 67108864 bytes".into())
        );
    }

    #[test]
    fn personal_listing_rejects_page_and_cursor_width_overflow() {
        let records = (0..101)
            .map(|item| json!({"rkey": format!("r{item}")}))
            .collect::<Vec<_>>();
        assert_eq!(
            block_on(
                store(Scripted::new([json!({"records": records})])).list_raw(nsid::DEVICE, false)
            )
            .unwrap_err(),
            Error::Backend("space page exceeds 100 records".into())
        );

        assert_eq!(
            block_on(
                store(Scripted::new([json!({
                    "records": [],
                    "cursor": "x".repeat(1025),
                })]))
                .list_raw(nsid::DEVICE, false)
            )
            .unwrap_err(),
            Error::Backend("space cursor exceeds 1024 bytes".into())
        );
    }

    #[test]
    fn checked_mailbox_space_constructor_binds_type_and_owner() {
        let transport: Arc<dyn SpaceRpc> = Scripted::raw(std::iter::empty());
        let wrong_type = SpaceRef {
            space_did: "did:plc:alice".into(),
            space_type: "blue.catbird.labyrinth.conversation".into(),
            skey: "self".into(),
        };
        assert_eq!(
            SpaceMailboxStore::in_space(
                "did:plc:alice",
                wrong_type,
                transport.clone(),
                Box::new(NoopKeyPublisher),
            )
            .err(),
            Some(Error::Malformed("mailbox Space type"))
        );

        assert_eq!(
            SpaceMailboxStore::in_space(
                "did:plc:bob",
                SpaceRef::mailbox("did:plc:alice"),
                transport,
                Box::new(NoopKeyPublisher),
            )
            .err(),
            Some(Error::Malformed("mailbox Space owner"))
        );
    }
}

#[cfg(test)]
mod writer_floor_migration_tests {
    use super::*;

    const AUTHOR: &str = "did:plc:abcdefghijklmnopqrstuvwx";
    const OLD_REV: &str = "3kaaaaaaaaaaa";
    const MID_REV: &str = "3kbbbbbbbbbbb";
    const NEW_REV: &str = "3kccccccccccc";

    fn spellings() -> (String, String) {
        let space = SpaceRef::conversation("did:plc:zyxwvutsrqponmlkjihgfedc", "3kzzzzzzzzzzz");
        let canonical = space.to_string();
        assert!(canonical.starts_with("at:space/"));
        let legacy = format!(
            "at://{}/space/{}/{}",
            space.space_did, space.space_type, space.skey
        );
        (canonical, legacy)
    }

    fn floors(entries: &[(&str, &str)]) -> BTreeMap<(String, String), String> {
        entries
            .iter()
            .map(|(space, rev)| (((*space).to_owned(), AUTHOR.to_owned()), (*rev).to_owned()))
            .collect()
    }

    #[test]
    fn legacy_persisted_floor_blocks_rollback_under_canonical_key() {
        let (canonical, legacy) = spellings();
        let persisted = floors(&[(legacy.as_str(), MID_REV)]);
        for restored in [WriterRevFloors::from_map(persisted.clone()), {
            let f = WriterRevFloors::new();
            f.seed(&persisted);
            f
        }] {
            let err = restored
                .check_not_rolled_back(&canonical, AUTHOR, OLD_REV)
                .unwrap_err();
            assert!(matches!(err, Error::WriterRollback { .. }), "{err:?}");
            assert!(matches!(
                restored.observe(&canonical, AUTHOR, OLD_REV),
                Err(Error::WriterRollback { .. })
            ));
            restored
                .check_not_rolled_back(&canonical, AUTHOR, MID_REV)
                .unwrap();
            assert_eq!(restored.get(&canonical, AUTHOR).as_deref(), Some(MID_REV));
            assert_eq!(restored.authors_in(&canonical), vec![AUTHOR.to_owned()]);
            let snapshot = restored.snapshot();
            assert_eq!(snapshot.len(), 1);
            assert!(snapshot.contains_key(&(canonical.clone(), AUTHOR.to_owned())));
        }
    }

    #[test]
    fn both_spellings_merge_to_the_maximum_revision() {
        let (canonical, legacy) = spellings();
        for (legacy_rev, canonical_rev) in [(NEW_REV, MID_REV), (MID_REV, NEW_REV)] {
            let persisted = floors(&[
                (legacy.as_str(), legacy_rev),
                (canonical.as_str(), canonical_rev),
            ]);
            assert_eq!(persisted.len(), 2);

            let normalized = crate::store::normalize_writer_floors(&persisted);
            assert_eq!(normalized.len(), 1);
            assert_eq!(
                normalized.get(&(canonical.clone(), AUTHOR.to_owned())),
                Some(&NEW_REV.to_owned())
            );

            let replaced = WriterRevFloors::from_map(persisted.clone());
            let seeded = WriterRevFloors::new();
            seeded.seed(&persisted);
            for restored in [replaced, seeded] {
                assert_eq!(restored.snapshot(), normalized);
                for lookup in [&canonical, &legacy] {
                    assert!(matches!(
                        restored.check_not_rolled_back(lookup, AUTHOR, MID_REV),
                        Err(Error::WriterRollback { .. })
                    ));
                    restored
                        .check_not_rolled_back(lookup, AUTHOR, NEW_REV)
                        .unwrap();
                }
            }
        }
    }
}

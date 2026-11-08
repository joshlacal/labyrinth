//! ATProto Spaces storage (`com.atproto.space.*`) for personal mailboxes and
//! conversation history (`SPEC §9`, Gates 1, 3, and 5).

pub mod host;
pub mod thread;

pub use thread::{SpaceThreadStore, batch_cid};

use std::sync::Arc;

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
    AttachmentManifest, Device, Epoch, EpochMember, MailboxKeysRecord, OtcSession, OwnerBatch,
    VirtualDevice, datetime_from_ms, nsid,
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
    pub const GET_RECORD: &str = "com.atproto.space.getRecord";
    pub const LIST_RECORDS: &str = "com.atproto.space.listRecords";
    pub const LIST_REPOS: &str = "com.atproto.space.listRepos";
    pub const LIST_SPACES: &str = "com.atproto.space.listSpaces";
    pub const DELETE_RECORD: &str = "com.atproto.space.deleteRecord";
    pub const GET_BLOB: &str = "com.atproto.space.getBlob";
    pub const UPLOAD_BLOB: &str = "com.atproto.repo.uploadBlob";
}

/// Every collection the personal mailbox Space holds, for purge.
pub const MAILBOX_COLLECTIONS: [&str; 7] = [
    nsid::DEVICE,
    nsid::EPOCH,
    nsid::EPOCH_MEMBER,
    nsid::VIRTUAL_DEVICE,
    nsid::OTC_SESSION,
    nsid::OWNER_BATCH,
    nsid::ATTACHMENT_MANIFEST,
];

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
}

/// A Space reference, `at://{spaceDid}/space/{spaceType}/{skey}`.
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

    /// Conversation Space `at://{authority_did}/space/blue.catbird.labyrinth.conversation/{skey}`.
    pub fn conversation(authority_did: &str, skey: &str) -> Self {
        Self {
            space_did: authority_did.to_owned(),
            space_type: CONVERSATION_SPACE_TYPE.to_owned(),
            skey: skey.to_owned(),
        }
    }

    /// Parses the three-part form; a record URI inside a Space is refused.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("at://")
            .ok_or(Error::Malformed("space ref"))?;
        let parts: Vec<&str> = rest.split('/').collect();
        match parts[..] {
            [did, "space", ty, skey]
                if did.starts_with("did:") && !ty.is_empty() && !skey.is_empty() =>
            {
                Ok(Self {
                    space_did: did.to_owned(),
                    space_type: ty.to_owned(),
                    skey: skey.to_owned(),
                })
            }
            _ => Err(Error::Malformed("space ref")),
        }
    }
}

impl core::fmt::Display for SpaceRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "at://{}/space/{}/{}",
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
        Some("RecordAlreadyExists") => Error::Conflict,
        Some("RecordNotFound" | "BlobNotFound") if is_not_found_status => Error::NotFound("record"),
        Some("SpaceNotFound") if is_not_found_status => Error::NotFound("space"),
        Some("SpaceDeleted") => Error::Forbidden,
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

    /// Records per `listRecords` page (`1..=100`; default [`LIST_LIMIT`]).
    pub fn with_page_size(mut self, n: usize) -> Self {
        self.page = n.clamp(1, 100);
        self
    }

    /// Replaces the clock that stamps `lastUsedAt`.
    pub fn with_clock(mut self, now_ms: crate::store::ClockFn) -> Self {
        self.now_ms = now_ms;
        self
    }

    pub fn space(&self) -> &SpaceRef {
        &self.space
    }

    async fn apply(&self, writes: &[WriteOp]) -> Result<Vec<Option<String>>> {
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
        Ok(out.results.into_iter().map(|r| r.uri).collect())
    }

    async fn get<T: DeserializeOwned>(&self, collection: &str, rkey: &str) -> Result<Option<T>> {
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
            Ok(body) => decode(decode_body::<GetRecordOut>(&body)?.value).map(Some),
            Err(Error::NotFound("record" | "repo")) => Ok(None),
            Err(e) => Err(e),
        }
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

    /// Every `(rkey, value)` of `collection`, ascending by `rkey`.
    async fn list_raw(&self, collection: &str, values: bool) -> Result<Vec<(String, Value)>> {
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
                ("reverse", "true".to_owned()),
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
                    .map(|r| (r.rkey, r.value.unwrap_or(Value::Null))),
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
                    writes.push(WriteOp::Delete {
                        collection: nsid::OTC_SESSION,
                        rkey: rkey.clone(),
                    });
                }
                EnrollCleanup::TouchVirtualDevice { updated } => {
                    writes.push(WriteOp::Update {
                        collection: nsid::VIRTUAL_DEVICE,
                        rkey: updated.rkey(),
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
        self.apply(&writes).await?;
        Ok(id)
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
        self.keys.retract().await
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

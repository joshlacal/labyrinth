//! The personal mailbox in an atproto Space (SPEC §9, backend A of the
//! plan; feature `space`).
//!
//! [`SpaceMailboxStore`] implements [`MailboxStore`] over the PDS's
//! `com.atproto.space.{applyWrites,getRecord,listRecords,deleteRecord}`
//! endpoints, in one personal Space per account
//! ([`SpaceRef::mailbox`]: authority = the owner's DID, `spaceType` =
//! `blue.catbird.labyrinth.mailbox`, `skey` = `self`). Only the owner
//! writes (OAuth, `repo == auth.did`) and only the owner reads
//! (`read_self`), so the Space needs no notifyWrite, syncer or member list.
//!
//! The store reuses [`XrpcTransport`]: the embedding app supplies one
//! bound to the user's PDS with the account's OAuth session (no service
//! auth, no `labyrinthWriteBody`; `operation_id` is ignored). The store
//! never calls `createSpace`: the owner's PDS accepts writes to a Space no
//! authority governs and serves them back with `read_self`, which is all an
//! owner-only mailbox needs (checked live, `tests/live_space_pds.rs`). An
//! app may still create it with `com.atproto.space.createSpace`.
//!
//! What the PDS gives and how the store uses it:
//!
//! - **Create-if-absent.** `#create` on an existing rkey fails with
//!   `RecordAlreadyExists` → [`Error::Conflict`]. There is no `swapRecord`
//!   in Space writes; the zero-padded epoch rkey is the race guard
//!   between devices ([CB-9]).
//! - **Atomic epochs.** `create_epoch` writes the epoch and its members in
//!   one `applyWrites` (at most [`MAX_WRITES`] ops; all ops share a rev).
//! - **Owner batches** are `#create` without an rkey: the PDS assigns a
//!   TID, read back from the result URI.
//! - **No server order.** Records carry no stamp ([`Stored::order`] is
//!   `None`), so the removed-key bound falls back to sender timestamps
//!   ([CB-27]).
//! - **Reads scan.** `listRecords` has no filter beyond the collection, so
//!   per-epoch members and per-thread owner batches are filtered client
//!   side. Owner batches are few (re-archive on leave and delete-for-me
//!   only, [CB-22]), so this is cheap in practice.
//! - **`mailboxKeys` is public.** It goes to the owner's public repo, not
//!   the Space, through the [`KeyPublisher`] given at construction
//!   ([`crate::store::pds::PdsPublisher`] in production).
//! - **Purge** deletes every mailbox record in [`MAX_WRITES`]-op batches
//!   and retracts `mailboxKeys`. ORF states and attachment references live
//!   on mls-ds ([CB-17]) and go with its own `purgeMailbox`, reached
//!   through the mls-ds publisher's `retract`.
//!
//! [`host::MemorySpaceHost`] is a memory-backed reference PDS for these
//! endpoints, matching the reference implementation's limits and errors.

pub mod host;
pub mod thread;

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::xrpc::{XrpcError, XrpcTransport};
use super::{KeyPublisher, MailboxStore, Stored, TimeRange};
use crate::epoch::space_epoch_id;
use crate::records::{
    Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice, datetime_from_ms,
    nsid,
};
use crate::sign::XVerifyingKey;
use crate::{Error, Result};

/// `spaceType` of the personal mailbox Space.
pub const MAILBOX_SPACE_TYPE: &str = "blue.catbird.labyrinth.mailbox";

/// `skey` of the personal mailbox Space (one per account).
pub const MAILBOX_SKEY: &str = "self";

/// Most writes in one `applyWrites` (reference PDS `MAX_WRITES`).
pub const MAX_WRITES: usize = 200;

/// Records per `listRecords` page the store asks for (the lexicon allows
/// up to 1000; owner batches can be near 1 MB each, so pages stay small).
pub const LIST_LIMIT: usize = 50;

/// Cross-page bounds for direct `com.atproto.space.*` reads. These calls do
/// not pass through the generic Labyrinth XRPC pager, so they enforce their
/// own budgets.
pub(super) const MAX_SPACE_PAGES: usize = 1_024;
pub(super) const MAX_SPACE_LIST_ITEMS: usize = 10_000;
pub(super) const MAX_SPACE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_SPACE_LIST_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_SPACE_CURSOR_BYTES: usize = 1_024;

/// The Space NSIDs the store calls.
pub mod endpoint {
    pub const APPLY_WRITES: &str = "com.atproto.space.applyWrites";
    pub const GET_RECORD: &str = "com.atproto.space.getRecord";
    pub const LIST_RECORDS: &str = "com.atproto.space.listRecords";
    pub const LIST_SPACES: &str = "com.atproto.space.listSpaces";
    pub const DELETE_RECORD: &str = "com.atproto.space.deleteRecord";
}

/// Every collection the mailbox Space holds, for purge.
pub const MAILBOX_COLLECTIONS: [&str; 5] = [
    nsid::DEVICE,
    nsid::EPOCH,
    nsid::EPOCH_MEMBER,
    nsid::VIRTUAL_DEVICE,
    nsid::OWNER_BATCH,
];

/// A Space reference, `at://{spaceDid}/space/{spaceType}/{skey}`.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Maps a `com.atproto.space.*` error to the store error.
pub fn map_space_error(e: XrpcError) -> Error {
    let is_not_found_status = e.status == 404 || e.status == 400;
    match e.error.as_deref() {
        Some("MethodNotImplemented") if e.status == 501 => {
            Error::NotSupported("personal Space mailbox")
        }
        Some("RecordAlreadyExists") => Error::Conflict,
        Some("RecordNotFound") if is_not_found_status => Error::NotFound("record"),
        Some("SpaceNotFound") if is_not_found_status => Error::NotFound("space"),
        // Deletion is terminal for this generation. It must never become
        // an absent mailbox that initialization silently recreates.
        Some("SpaceDeleted") => Error::Forbidden,
        Some("RepoNotFound") if is_not_found_status => Error::NotFound("repo"),
        _ if e.status == 403 => Error::Forbidden,
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
enum WriteOp {
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
struct ApplyWritesIn<'a> {
    space: String,
    repo: &'a str,
    validate: bool,
    writes: &'a [WriteOp],
}

#[derive(Deserialize)]
struct ApplyWritesOut {
    #[serde(default)]
    results: Vec<WriteResult>,
}

#[derive(Deserialize)]
struct WriteResult {
    uri: Option<String>,
}

#[derive(Serialize)]
struct DeleteRecordIn<'a> {
    space: String,
    repo: &'a str,
    collection: &'static str,
    rkey: String,
}

#[derive(Deserialize)]
struct GetRecordOut {
    value: Value,
}

#[derive(Deserialize)]
struct ListRecordsOut {
    cursor: Option<String>,
    records: Vec<ListedRecord>,
}

#[derive(Deserialize)]
struct ListedRecord {
    rkey: String,
    value: Option<Value>,
}

fn encode<T: Serialize>(v: &T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| Error::Backend(format!("encode: {e}")))
}

fn decode<T: DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| Error::Malformed("space record"))
}

fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|e| Error::Backend(format!("bad space response: {e}")))
}

/// The rkey of a record URI (`…/{collection}/{rkey}`).
fn uri_rkey(uri: &str) -> Result<String> {
    uri.rsplit('/')
        .next()
        .filter(|r| !r.is_empty())
        .map(str::to_owned)
        .ok_or(Error::Backend("space write result without rkey".into()))
}

fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A personal mailbox in the owner's own Space on its PDS.
pub struct SpaceMailboxStore {
    did: String,
    space: SpaceRef,
    t: Arc<dyn XrpcTransport>,
    keys: Box<dyn KeyPublisher + Send>,
    now_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
    page: usize,
}

impl SpaceMailboxStore {
    /// `did`'s mailbox in [`SpaceRef::mailbox`]`(did)`. `transport` reaches
    /// the account's PDS with its OAuth session; `mailbox_keys` writes the
    /// public `mailboxKeys` records ([`crate::store::pds::PdsPublisher`]).
    pub fn new(
        did: &str,
        transport: Arc<dyn XrpcTransport>,
        mailbox_keys: Box<dyn KeyPublisher + Send>,
    ) -> Self {
        Self::from_space(SpaceRef::mailbox(did), transport, mailbox_keys)
    }

    /// A mailbox in another Space owned by the same account (the Space's
    /// authority is the mailbox owner). The signed-in account is explicit
    /// so a caller cannot accidentally bind mailbox operations to a foreign
    /// authority or to a conversation Space.
    pub fn in_space(
        owner_did: &str,
        space: SpaceRef,
        transport: Arc<dyn XrpcTransport>,
        mailbox_keys: Box<dyn KeyPublisher + Send>,
    ) -> Result<Self> {
        if space.space_type != MAILBOX_SPACE_TYPE {
            return Err(Error::Malformed("mailbox Space type"));
        }
        if space.space_did != owner_did || !owner_did.starts_with("did:") || owner_did.contains('/')
        {
            return Err(Error::Malformed("mailbox Space owner"));
        }
        Ok(Self::from_space(space, transport, mailbox_keys))
    }

    /// Test-only escape hatch for exercising a PDS with credentials that do
    /// not own `space`. Production callers must use [`Self::in_space`].
    #[doc(hidden)]
    pub fn in_space_unchecked_for_test(
        space: SpaceRef,
        transport: Arc<dyn XrpcTransport>,
        mailbox_keys: Box<dyn KeyPublisher + Send>,
    ) -> Self {
        Self::from_space(space, transport, mailbox_keys)
    }

    fn from_space(
        space: SpaceRef,
        transport: Arc<dyn XrpcTransport>,
        mailbox_keys: Box<dyn KeyPublisher + Send>,
    ) -> Self {
        Self {
            did: space.space_did.clone(),
            space,
            t: transport,
            keys: mailbox_keys,
            now_ms: Arc::new(system_now_ms),
            page: LIST_LIMIT,
        }
    }

    /// Records per `listRecords` page (1..=1000; default [`LIST_LIMIT`]).
    pub fn with_page_size(mut self, n: usize) -> Self {
        self.page = n.clamp(1, 1000);
        self
    }

    /// Replaces the clock that stamps `lastUsedAt` ([`MailboxStore::touch_virtual_device`]).
    pub fn with_clock(mut self, now_ms: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.now_ms = now_ms;
        self
    }

    pub fn space(&self) -> &SpaceRef {
        &self.space
    }

    fn apply(&self, writes: &[WriteOp]) -> Result<Vec<Option<String>>> {
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
            .procedure(endpoint::APPLY_WRITES, &payload, [0; 16])
            .map_err(map_space_error)?;
        let out: ApplyWritesOut = decode_body(&body)?;
        Ok(out.results.into_iter().map(|r| r.uri).collect())
    }

    fn get<T: DeserializeOwned>(&self, collection: &str, rkey: &str) -> Result<Option<T>> {
        let p = [
            ("space", self.space.to_string()),
            ("repo", self.did.clone()),
            ("collection", collection.to_owned()),
            ("rkey", rkey.to_owned()),
        ];
        match self
            .t
            .query(endpoint::GET_RECORD, &p)
            .map_err(map_space_error)
        {
            Ok(body) => decode(decode_body::<GetRecordOut>(&body)?.value).map(Some),
            Err(Error::NotFound("record" | "repo")) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Every `(rkey, value)` of `collection`, ascending by rkey. With
    /// `values = false` the values are `Null` (`excludeValues`).
    fn list_raw(&self, collection: &str, values: bool) -> Result<Vec<(String, Value)>> {
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
                .map_err(map_space_error)
            {
                Ok(body) => body,
                // No repo in the Space yet: nothing written.
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
                None => return Ok(out),
            }
        }
        Err(Error::Backend("space listing too long".into()))
    }

    fn list<T: DeserializeOwned>(&self, collection: &str) -> Result<Vec<(String, T)>> {
        self.list_raw(collection, true)?
            .into_iter()
            .map(|(k, v)| Ok((k, decode(v)?)))
            .collect()
    }

    fn create(&self, collection: &'static str, rkey: String, value: &impl Serialize) -> Result<()> {
        self.apply(&[WriteOp::Create {
            collection,
            rkey: Some(rkey),
            value: encode(value)?,
        }])?;
        Ok(())
    }

    fn update(&self, collection: &'static str, rkey: String, value: &impl Serialize) -> Result<()> {
        self.apply(&[WriteOp::Update {
            collection,
            rkey,
            value: encode(value)?,
        }])?;
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

    fn owner_batches(&self, thread_id: Option<&str>) -> Result<Vec<Stored<OwnerBatch>>> {
        Ok(self
            .list::<OwnerBatch>(nsid::OWNER_BATCH)?
            .into_iter()
            .filter(|(_, b)| thread_id.is_none_or(|t| b.thread_id == t))
            .map(|(k, b)| self.stored(k, b))
            .collect())
    }
}

impl MailboxStore for SpaceMailboxStore {
    fn owner(&self) -> &str {
        &self.did
    }

    fn create_device(&self, device: &Device) -> Result<()> {
        self.create(
            nsid::DEVICE,
            hex::encode(&device.device_key_pubkey.0),
            device,
        )
    }

    /// Read, set `revokedAt`, `#update`. Spaces have no `swapRecord`; the
    /// field is only ever set, so a lost race leaves one of two revocation
    /// times, either of which revokes.
    fn set_device_revoked(&self, device_key: &XVerifyingKey, revoked_at: &str) -> Result<()> {
        let rkey = hex::encode(device_key.0);
        let mut d: Device = self
            .get(nsid::DEVICE, &rkey)?
            .ok_or(Error::NotFound("device"))?;
        if d.revoked_at.is_some() {
            return Ok(());
        }
        d.revoked_at = Some(revoked_at.to_owned());
        self.update(nsid::DEVICE, rkey, &d)
    }

    fn get_device(&self, device_key: &XVerifyingKey) -> Result<Option<Device>> {
        self.get(nsid::DEVICE, &hex::encode(device_key.0))
    }

    fn list_devices(&self) -> Result<Vec<Device>> {
        Ok(self
            .list(nsid::DEVICE)?
            .into_iter()
            .map(|(_, d)| d)
            .collect())
    }

    fn create_epoch(&self, epoch: &Epoch, members: &[EpochMember]) -> Result<String> {
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
        self.apply(&writes)?;
        Ok(id)
    }

    fn get_epoch(&self, seq: u64) -> Result<Option<Stored<Epoch>>> {
        let id = space_epoch_id(seq);
        Ok(self
            .get::<Epoch>(nsid::EPOCH, &id)?
            .map(|e| self.stored(id, e)))
    }

    fn list_epochs(&self) -> Result<Vec<Stored<Epoch>>> {
        // Ascending rkey is ascending seq: rkeys are zero-padded.
        Ok(self
            .list::<Epoch>(nsid::EPOCH)?
            .into_iter()
            .map(|(k, e)| self.stored(k, e))
            .collect())
    }

    fn create_epoch_member(&self, member: &EpochMember) -> Result<()> {
        if self.get_epoch(member.epoch_number)?.is_none() {
            return Err(Error::NotFound("epoch"));
        }
        self.create(nsid::EPOCH_MEMBER, member.rkey(), member)
    }

    fn list_epoch_members(&self, seq: u64) -> Result<Vec<EpochMember>> {
        let prefix = format!("{}-", space_epoch_id(seq));
        Ok(self
            .list::<EpochMember>(nsid::EPOCH_MEMBER)?
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, m)| m)
            .collect())
    }

    fn get_epoch_member(
        &self,
        seq: u64,
        device_key: &XVerifyingKey,
    ) -> Result<Option<EpochMember>> {
        let rkey = format!("{}-{}", space_epoch_id(seq), hex::encode(device_key.0));
        self.get(nsid::EPOCH_MEMBER, &rkey)
    }

    fn create_virtual_device(&self, vdevice: &VirtualDevice) -> Result<()> {
        self.create(nsid::VIRTUAL_DEVICE, vdevice.rkey(), vdevice)
    }

    fn get_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<Option<VirtualDevice>> {
        self.get(nsid::VIRTUAL_DEVICE, &hex::encode(vdevice_id))
    }

    fn list_virtual_devices(&self) -> Result<Vec<VirtualDevice>> {
        Ok(self
            .list(nsid::VIRTUAL_DEVICE)?
            .into_iter()
            .map(|(_, v)| v)
            .collect())
    }

    /// `#create` without an rkey; the PDS assigns the TID.
    fn append_owner_batch(&self, batch: &OwnerBatch) -> Result<String> {
        let uris = self.apply(&[WriteOp::Create {
            collection: nsid::OWNER_BATCH,
            rkey: None,
            value: encode(batch)?,
        }])?;
        match uris.as_slice() {
            [Some(uri)] => uri_rkey(uri),
            _ => Err(Error::Backend(
                "space applyWrites returned no create result".into(),
            )),
        }
    }

    fn list_owner_batches(
        &self,
        thread_id: &str,
        range: TimeRange,
    ) -> Result<Vec<Stored<OwnerBatch>>> {
        let mut v = self.owner_batches(Some(thread_id))?;
        v.retain(|b| b.value.items.iter().any(|i| range.contains(i.timestamp)));
        Ok(v)
    }

    /// Writes the public `mailboxKeys` records through the publisher given
    /// at construction; the Space holds no copy.
    fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> Result<()> {
        self.keys.publish(record)
    }

    fn list_owner_threads(&self) -> Result<Vec<String>> {
        let mut v: Vec<String> = self
            .owner_batches(None)?
            .into_iter()
            .map(|b| b.value.thread_id)
            .collect();
        v.sort();
        v.dedup();
        Ok(v)
    }

    /// Stamps `lastUsedAt` with this client's clock: a Space has no server
    /// to do it, so on this backend expiry trusts the owner's devices.
    fn touch_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        let rkey = hex::encode(vdevice_id);
        let mut v: VirtualDevice = self
            .get(nsid::VIRTUAL_DEVICE, &rkey)?
            .ok_or(Error::NotFound("virtual device"))?;
        v.last_used_at = Some(datetime_from_ms((self.now_ms)()));
        self.update(nsid::VIRTUAL_DEVICE, rkey, &v)
    }

    /// `deleteRecord`, which succeeds whether or not the bundle exists.
    /// The ORF state went with the revocation that preceded it.
    fn delete_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        let input = DeleteRecordIn {
            space: self.space.to_string(),
            repo: &self.did,
            collection: nsid::VIRTUAL_DEVICE,
            rkey: hex::encode(vdevice_id),
        };
        let payload =
            serde_json::to_vec(&input).map_err(|e| Error::Backend(format!("encode: {e}")))?;
        self.t
            .procedure(endpoint::DELETE_RECORD, &payload, [0; 16])
            .map_err(map_space_error)?;
        Ok(())
    }

    /// Deletes every mailbox record ([`MAX_WRITES`] per `applyWrites`),
    /// then retracts `mailboxKeys`. Rerunnable: each pass lists what is
    /// left.
    fn purge_mailbox(&self) -> Result<()> {
        for collection in MAILBOX_COLLECTIONS {
            let rkeys: Vec<String> = self
                .list_raw(collection, false)?
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
                self.apply(&writes)?;
            }
        }
        self.keys.retract()
    }
}

#[cfg(test)]
mod bounded_tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;

    #[derive(Default)]
    struct NoopPublisher;
    impl KeyPublisher for NoopPublisher {
        fn publish(&self, _: &MailboxKeysRecord) -> Result<()> {
            Ok(())
        }
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

    impl XrpcTransport for Scripted {
        fn query_with_headers(
            &self,
            _: &str,
            _: &[(&str, String)],
            _: &[(String, String)],
        ) -> core::result::Result<Vec<u8>, XrpcError> {
            self.replies.lock().unwrap().pop_front().ok_or(XrpcError {
                status: 599,
                error: Some("ScriptExhausted".into()),
                message: None,
            })
        }

        fn procedure(
            &self,
            _: &str,
            _: &[u8],
            _: [u8; 16],
        ) -> core::result::Result<Vec<u8>, XrpcError> {
            unreachable!("listing tests never write")
        }
    }

    fn store(transport: Arc<dyn XrpcTransport>) -> SpaceMailboxStore {
        SpaceMailboxStore::new("did:plc:alice", transport, Box::new(NoopPublisher))
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
            store(transport).list_raw(nsid::DEVICE, false).unwrap_err(),
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
            store(Scripted::new(replies))
                .list_raw(nsid::DEVICE, false)
                .unwrap_err(),
            Error::Backend("space listing exceeds 10000 records".into())
        );
    }

    #[test]
    fn personal_listing_rejects_an_oversized_response_before_decoding() {
        assert_eq!(
            store(Scripted::raw([vec![b' '; 16 * 1024 * 1024 + 1]]))
                .list_raw(nsid::DEVICE, false)
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
            store(Scripted::new(replies))
                .list_raw(nsid::DEVICE, false)
                .unwrap_err(),
            Error::Backend("space listing responses exceed 67108864 bytes".into())
        );
    }

    #[test]
    fn personal_listing_rejects_page_and_cursor_width_overflow() {
        let records = (0..101)
            .map(|item| json!({"rkey": format!("r{item}")}))
            .collect::<Vec<_>>();
        assert_eq!(
            store(Scripted::new([json!({"records": records})]))
                .list_raw(nsid::DEVICE, false)
                .unwrap_err(),
            Error::Backend("space page exceeds 100 records".into())
        );

        assert_eq!(
            store(Scripted::new([json!({
                "records": [],
                "cursor": "x".repeat(1025),
            })]))
            .list_raw(nsid::DEVICE, false)
            .unwrap_err(),
            Error::Backend("space cursor exceeds 1024 bytes".into())
        );
    }

    #[test]
    fn checked_mailbox_space_constructor_binds_type_and_owner() {
        let transport: Arc<dyn XrpcTransport> = Scripted::raw(std::iter::empty());
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
                Box::new(NoopPublisher),
            )
            .err(),
            Some(Error::Malformed("mailbox Space type"))
        );

        assert_eq!(
            SpaceMailboxStore::in_space(
                "did:plc:bob",
                SpaceRef::mailbox("did:plc:alice"),
                transport,
                Box::new(NoopPublisher),
            )
            .err(),
            Some(Error::Malformed("mailbox Space owner"))
        );
    }
}

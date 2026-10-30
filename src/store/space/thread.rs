//! Sender-owned conversation ciphertext, indexed and ordered by mls-ds.
//!
//! The Space transport must verify credential-authenticated `getRecord`
//! responses using the October 22 MAC protocol before returning success.
//! Owner OAuth writes and reads need no MAC. This store additionally binds
//! each returned record to the sequencer's immutable generation, repo and CID;
//! only then can its authenticated server order be used for removed-key checks.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{SpaceRef, endpoint, map_space_error};
use crate::deletion::Redaction;
use crate::encoding::sha256;
use crate::records::{Batch, Bytes, MekDistribution, RedactionDef, SealedMessageDef, nsid};
use crate::store::xrpc::wire::{OrderDef, RkeyOrderOut};
use crate::store::xrpc::{Xrpc, XrpcError, XrpcThreadStore, XrpcTransport};
use crate::store::{Stored, ThreadListing, ThreadStore, TimeRange};
use crate::{Error, Result};

#[cfg(test)]
mod tests;

/// The delivery service's durable choice for one conversation generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThreadPlacement {
    pub placement: String,
    pub generation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
}

impl ThreadPlacement {
    pub fn validate(&self) -> Result<Option<SpaceRef>> {
        if !canonical_uuid(&self.generation) {
            return Err(Error::Malformed("conversation storage generation"));
        }
        match (self.placement.as_str(), self.space.as_deref()) {
            ("mlsds", None) => Ok(None),
            ("space", Some(uri)) => {
                let space = SpaceRef::parse(uri)?;
                if space.space_type != "blue.catbird.labyrinth.conversation"
                    || space.skey != self.generation
                    || space.to_string() != uri
                {
                    return Err(Error::Malformed("conversation Space placement"));
                }
                Ok(Some(space))
            }
            _ => Err(Error::Malformed("conversation storage placement")),
        }
    }
}

/// Maps an error from reading a member's repo in a conversation Space.
///
/// The repo host answers `SpaceNotFound` both when the Space (or that
/// member's repo in it) is gone and when the caller may not read it; the
/// lexicon does not tell them apart. To a reader either is a refusal, not a
/// missing mailbox, so it becomes `Forbidden` and the read degrades to the
/// owner archive instead of failing the whole thread. `SpaceDeleted` stays
/// terminal (`Forbidden`) through [`map_space_error`].
fn map_space_read_error(e: XrpcError) -> Error {
    match e.error.as_deref() {
        Some("SpaceNotFound") => Error::Forbidden,
        _ => map_space_error(e),
    }
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

/// Pins are encrypted, per-account durable state in a production adapter.
/// Accepting a new generation requires an explicit new conversation flow;
/// reads never replace a pin after deletion/recreation or a host outage.
pub trait ThreadPlacementPins: Send + Sync {
    fn check_or_pin(&self, thread_id: &str, placement: &ThreadPlacement) -> Result<()>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpaceBatchRedaction {
    pub message_id: String,
    pub timestamp: u64,
    pub redaction: RedactionDef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpaceBatchView {
    pub author: String,
    pub rkey: String,
    pub space: String,
    pub generation: String,
    pub cid: String,
    pub order: OrderDef,
    pub item_count: usize,
    pub redactions: Vec<SpaceBatchRedaction>,
}

/// Canonical DRISL bytes and CID v1 (DAG-CBOR, SHA-256) of a sender record.
/// `Bytes` uses CBOR byte strings, not the JSON `$bytes` wrapper.
pub fn batch_cid(batch: &Batch) -> Result<String> {
    batch.to_messages()?;
    let encoded = serde_ipld_dagcbor::to_vec(batch)
        .map_err(|_| Error::Malformed("conversation batch DRISL"))?;
    if encoded.len() > 1_048_576 {
        return Err(Error::Malformed("conversation batch exceeds 1 MiB"));
    }
    let digest = cid::multihash::Multihash::<64>::wrap(0x12, &sha256(&encoded))
        .map_err(|_| Error::Malformed("conversation batch CID"))?;
    Ok(cid::Cid::new_v1(0x71, digest).to_string())
}

#[derive(Deserialize)]
struct GetRecord {
    uri: String,
    cid: String,
    value: Batch,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppendSpaceBatch<'a> {
    record: &'a Batch,
    generation: &'a str,
    space: &'a str,
    rkey: &'a str,
    cid: &'a str,
}

/// Mixed-account deployment: legacy conversations continue on mls-ds;
/// an explicitly configured Space placement never falls back to DS storage.
pub struct SequencedSpaceThreadStore {
    did: String,
    ds: Xrpc,
    legacy: XrpcThreadStore,
    space: Option<Arc<dyn XrpcTransport>>,
    pins: Arc<dyn ThreadPlacementPins>,
}

impl SequencedSpaceThreadStore {
    /// Owner-authenticated inventory includes data written on other devices
    /// and remains available after the account leaves a conversation.
    pub fn owned_spaces(transport: &dyn XrpcTransport) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct View {
            uri: String,
        }
        #[derive(Deserialize)]
        struct Page {
            spaces: Vec<View>,
            cursor: Option<String>,
        }
        let mut cursor: Option<String> = None;
        let mut seen = std::collections::BTreeSet::new();
        let mut spaces = std::collections::BTreeSet::new();
        for _ in 0..100_000 {
            let mut params = vec![
                ("spaceType", "blue.catbird.labyrinth.conversation".into()),
                ("limit", "100".into()),
            ];
            if let Some(cursor) = &cursor {
                params.push(("cursor", cursor.clone()));
            }
            let body = transport
                .query(endpoint::LIST_SPACES, &params)
                .map_err(map_space_error)?;
            let page: Page = serde_json::from_slice(&body)
                .map_err(|_| Error::Malformed("owned conversation Space inventory"))?;
            for view in page.spaces {
                let space = SpaceRef::parse(&view.uri)?;
                ThreadPlacement {
                    placement: "space".into(),
                    generation: space.skey.clone(),
                    space: Some(view.uri.clone()),
                }
                .validate()?;
                spaces.insert(view.uri);
            }
            let Some(next) = page.cursor else {
                return Ok(spaces.into_iter().collect());
            };
            if !seen.insert(next.clone()) {
                return Err(Error::Malformed("Space inventory cursor repeated"));
            }
            cursor = Some(next);
        }
        Err(Error::Backend(
            "conversation Space inventory page limit reached".into(),
        ))
    }

    pub fn new(
        did: &str,
        sequencer: Arc<dyn XrpcTransport>,
        space: Option<Arc<dyn XrpcTransport>>,
        pins: Arc<dyn ThreadPlacementPins>,
    ) -> Self {
        Self {
            did: did.into(),
            ds: Xrpc::new(sequencer.clone()),
            legacy: XrpcThreadStore::new(did, sequencer),
            space,
            pins,
        }
    }

    fn placement(&self, thread: &str) -> Result<ThreadPlacement> {
        let placement: ThreadPlacement = self
            .ds
            .get("getThreadStorage", &[("threadId", thread.into())])?;
        placement.validate()?;
        self.pins.check_or_pin(thread, &placement)?;
        Ok(placement)
    }

    fn space_transport(&self) -> Result<&dyn XrpcTransport> {
        self.space
            .as_deref()
            .ok_or(Error::NotSupported("verified conversation Space transport"))
    }

    fn read_record(&self, space: &str, author: &str, rkey: &str) -> Result<GetRecord> {
        let params = [
            ("space", space.into()),
            ("repo", author.into()),
            ("collection", nsid::BATCH.into()),
            ("rkey", rkey.into()),
        ];
        let body = self
            .space_transport()?
            .query(endpoint::GET_RECORD, &params)
            .map_err(map_space_read_error)?;
        let record: GetRecord = serde_json::from_slice(&body)
            .map_err(|_| Error::Malformed("conversation Space record response"))?;
        let expected_uri = format!("{space}/{author}/{}/{rkey}", nsid::BATCH);
        if record.uri != expected_uri || record.cid != batch_cid(&record.value)? {
            return Err(Error::Malformed("conversation Space URI or CID mismatch"));
        }
        Ok(record)
    }

    fn resolve(
        &self,
        thread: &str,
        placement: &ThreadPlacement,
        view: SpaceBatchView,
    ) -> Result<Stored<Batch>> {
        if view.generation != placement.generation
            || Some(&view.space) != placement.space.as_ref()
            || view.order.chat_seq.is_none()
            || view.order.seq == 0
            || view.item_count == 0
            || view.item_count > crate::records::MAX_BATCH_ITEMS
            || view.redactions.len() > view.item_count
            || !view.author.starts_with("did:")
            || view.author.contains('/')
            || view.rkey.is_empty()
            || !view
                .rkey
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        {
            return Err(Error::Malformed("sequenced conversation Space reference"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for tombstone in &view.redactions {
            if !seen.insert(&tombstone.message_id) {
                return Err(Error::Malformed("duplicate conversation tombstone"));
            }
            tombstone.redaction.to_stored()?;
        }
        // After account deletion the owner PDS is physically purged. A
        // complete DS tombstone set remains displayable without the source
        // record. This envelope can only remove content: no ciphertext or
        // sender key is invented, and no source CID is claimed verified.
        if view.redactions.len() == view.item_count {
            let items = view
                .redactions
                .into_iter()
                .map(|r| SealedMessageDef {
                    message_id: r.message_id,
                    timestamp: r.timestamp,
                    mek_id: Bytes(vec![]),
                    sender_transport_pubkey: Bytes(vec![]),
                    signed_enc_message: Bytes(vec![]),
                    redaction: Some(r.redaction),
                })
                .collect();
            return Ok(Stored {
                author: view.author,
                rkey: view.rkey,
                value: Batch {
                    type_: nsid::BATCH.into(),
                    thread_id: thread.into(),
                    items,
                    created_at: view.order.received_at.clone(),
                },
                order: Some(view.order.to_order()?),
            });
        }
        let mut record = self.read_record(&view.space, &view.author, &view.rkey)?;
        if record.cid != view.cid
            || record.value.thread_id != thread
            || record.value.items.len() != view.item_count
        {
            return Err(Error::Malformed("sequenced conversation record identity"));
        }
        // Apply DS-authenticated tombstones after authenticating the immutable
        // original record. A retained PDS copy cannot resurrect an unsent item.
        for tombstone in view.redactions {
            let item = record
                .value
                .items
                .iter_mut()
                .find(|i| {
                    i.message_id == tombstone.message_id && i.timestamp == tombstone.timestamp
                })
                .ok_or(Error::Malformed(
                    "conversation tombstone does not match batch",
                ))?;
            item.signed_enc_message.0.clear();
            item.redaction = Some(tombstone.redaction);
        }
        Ok(Stored {
            author: view.author,
            rkey: view.rkey,
            value: record.value,
            order: Some(view.order.to_order()?),
        })
    }

    /// Remove every batch this account owns in a previously pinned Space.
    /// Called by the durable account-deletion journal. Only owner OAuth is
    /// used; neither foreign records nor the authority's Space are deleted.
    pub fn purge_owned_records(did: &str, transport: &dyn XrpcTransport, uri: &str) -> Result<()> {
        let space = SpaceRef::parse(uri)?;
        ThreadPlacement {
            placement: "space".into(),
            generation: space.skey.clone(),
            space: Some(uri.into()),
        }
        .validate()?;
        // Re-read the first page after each removal, avoiding pagination
        // cursors whose source record has just been deleted.
        for _ in 0..100_000 {
            let raw = transport
                .query(
                    endpoint::LIST_RECORDS,
                    &[
                        ("space", uri.into()),
                        ("repo", did.into()),
                        ("collection", nsid::BATCH.into()),
                        ("limit", "100".into()),
                        ("excludeValues", "true".into()),
                    ],
                )
                .map_err(map_space_error)?;
            let page: super::ListRecordsOut = serde_json::from_slice(&raw)
                .map_err(|_| Error::Malformed("conversation deletion listing"))?;
            if page.records.is_empty() {
                return Ok(());
            }
            for record in page.records {
                if record.rkey.is_empty()
                    || record.rkey.len() > 512
                    || !record
                        .rkey
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
                {
                    return Err(Error::Malformed("conversation deletion record key"));
                }
                let body = serde_json::to_vec(&serde_json::json!({"space": uri, "repo": did,
                    "collection": nsid::BATCH, "rkey": record.rkey}))
                .map_err(|_| Error::Malformed("conversation record deletion"))?;
                transport
                    .procedure(endpoint::DELETE_RECORD, &body, [0; 16])
                    .map_err(map_space_error)?;
            }
        }
        Err(Error::Backend(
            "conversation deletion page limit reached".into(),
        ))
    }
}

impl ThreadStore for SequencedSpaceThreadStore {
    fn author(&self) -> &str {
        &self.did
    }
    fn create_mek(&self, mek: &MekDistribution) -> Result<()> {
        self.legacy.create_mek(mek)
    }
    fn find_meks(&self, thread: &str, mek: &[u8; 12]) -> Result<Vec<Stored<MekDistribution>>> {
        self.legacy.find_meks(thread, mek)
    }
    fn append_batch(&self, batch: &Batch) -> Result<String> {
        let placement = self.placement(&batch.thread_id)?;
        let Some(space) = &placement.space else {
            return self.legacy.append_batch(batch);
        };
        let cid = batch_cid(batch)?;
        // Content-addressed rkeys make PDS commit / DS acknowledgement loss
        // safely retryable without a second ciphertext record.
        let rkey = hex::encode(sha256(cid.as_bytes()));
        let payload = serde_json::to_vec(&serde_json::json!({"space": space, "repo": self.did,
            "validate": false, "writes": [{"$type": "com.atproto.space.applyWrites#create",
                "collection": nsid::BATCH, "rkey": rkey, "value": batch}]}))
        .map_err(|_| Error::Malformed("conversation batch write"))?;
        match self
            .space_transport()?
            .procedure(endpoint::APPLY_WRITES, &payload, [0; 16])
            .map_err(map_space_error)
        {
            Ok(_) => {}
            Err(Error::Conflict) => {
                if self.read_record(space, &self.did, &rkey)?.cid != cid {
                    return Err(Error::Conflict);
                }
            }
            Err(e) => return Err(e),
        }
        let accepted: RkeyOrderOut = self.ds.post(
            "appendSpaceBatch",
            &AppendSpaceBatch {
                record: batch,
                generation: &placement.generation,
                space,
                rkey: &rkey,
                cid: &cid,
            },
        )?;
        if accepted.rkey != rkey || accepted.order.chat_seq.is_none() || accepted.order.seq == 0 {
            return Err(Error::Malformed("conversation admission receipt"));
        }
        Ok(rkey)
    }
    fn list_batches(
        &self,
        thread: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<Stored<Batch>>> {
        let placement = self.placement(thread)?;
        if placement.space.is_none() {
            return self.legacy.list_batches(thread, sender, range);
        }
        let mut params = vec![
            ("threadId", thread.into()),
            ("generation", placement.generation.clone()),
        ];
        if let Some(sender) = sender {
            params.push(("sender", sender.into()));
        }
        if let Some(from) = range.from_ms {
            params.push(("fromMs", from.to_string()));
        }
        if let Some(until) = range.until_ms {
            params.push(("untilMs", until.to_string()));
        }
        let views: Vec<SpaceBatchView> = self.ds.list_all("listSpaceBatches", &params)?;
        views
            .into_iter()
            .map(|v| self.resolve(thread, &placement, v))
            .collect()
    }
    fn list_threads(&self) -> Result<Vec<String>> {
        self.legacy.list_threads()
    }
    fn list_threads_report(&self) -> Result<ThreadListing> {
        self.legacy.list_threads_report()
    }
    fn redact_item(&self, thread: &str, message: &str, redaction: &Redaction) -> Result<usize> {
        self.legacy.redact_item(thread, message, redaction)
    }
}

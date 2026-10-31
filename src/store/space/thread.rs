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
use crate::store::xrpc::{Xrpc, XrpcThreadStore, XrpcTransport};
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
    ds_redaction_pubkey: Option<crate::store::SequencerKey>,
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
        let mut response_bytes = 0usize;
        let mut item_count = 0usize;
        for _ in 0..super::MAX_SPACE_PAGES {
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
            if body.len() > super::MAX_SPACE_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "space response exceeds {} bytes",
                    super::MAX_SPACE_RESPONSE_BYTES
                )));
            }
            response_bytes = response_bytes
                .checked_add(body.len())
                .ok_or_else(|| Error::Backend("space inventory response size overflow".into()))?;
            if response_bytes > super::MAX_SPACE_LIST_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "conversation Space inventory responses exceed {} bytes",
                    super::MAX_SPACE_LIST_RESPONSE_BYTES
                )));
            }
            let page: Page = serde_json::from_slice(&body)
                .map_err(|_| Error::Malformed("owned conversation Space inventory"))?;
            if page.spaces.len() > 100 {
                return Err(Error::Backend(
                    "conversation Space inventory page exceeds 100 items".into(),
                ));
            }
            item_count = item_count
                .checked_add(page.spaces.len())
                .ok_or_else(|| Error::Backend("space inventory item count overflow".into()))?;
            if item_count > super::MAX_SPACE_LIST_ITEMS {
                return Err(Error::Backend(format!(
                    "conversation Space inventory exceeds {} items",
                    super::MAX_SPACE_LIST_ITEMS
                )));
            }
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
            if next.len() > super::MAX_SPACE_CURSOR_BYTES {
                return Err(Error::Backend(format!(
                    "conversation Space inventory cursor exceeds {} bytes",
                    super::MAX_SPACE_CURSOR_BYTES
                )));
            }
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
            ds_redaction_pubkey: None,
        }
    }

    /// Configures the sequencer DS signing key (`[CB-38]`) trusted for
    /// `ACCOUNT_DELETED` server redactions on Space conversation batches.
    pub fn with_sequencer_key(mut self, key: crate::store::SequencerKey) -> Self {
        self.ds_redaction_pubkey = Some(key);
        self
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
            .map_err(map_space_error)?;
        let record: GetRecord = serde_json::from_slice(&body)
            .map_err(|_| Error::Malformed("conversation Space record response"))?;
        let expected_uri = format!("{space}/{author}/{}/{rkey}", nsid::BATCH);
        if record.uri != expected_uri || record.cid != batch_cid(&record.value)? {
            return Err(Error::Malformed("conversation Space URI or CID mismatch"));
        }
        Ok(record)
    }

    fn verify_tombstone(
        &self,
        thread: &str,
        author: &str,
        tombstone: &SpaceBatchRedaction,
    ) -> Result<()> {
        match tombstone.redaction.to_stored()? {
            crate::deletion::StoredRedaction::Author(r) => {
                r.verify(author, thread, &tombstone.message_id)
            }
            crate::deletion::StoredRedaction::Server(r) => {
                if r.reason != crate::deletion::ACCOUNT_DELETED {
                    return Err(Error::BadSignature);
                }
                let Some(k) = &self.ds_redaction_pubkey else {
                    return Err(Error::BadSignature);
                };
                if r.by != k.did {
                    return Err(Error::BadSignature);
                }
                r.verify_account_deletion(author, thread, &tombstone.message_id, &k.key)
            }
            crate::deletion::StoredRedaction::Unsigned { .. } => Err(Error::BadSignature),
        }
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
        match self.read_record(&view.space, &view.author, &view.rkey) {
            Ok(mut record) => {
                if record.cid != view.cid
                    || record.value.thread_id != thread
                    || record.value.items.len() != view.item_count
                {
                    return Err(Error::Malformed("sequenced conversation record identity"));
                }
                // Apply DS-authenticated tombstones after authenticating the
                // immutable original record and verifying each redaction signature.
                for tombstone in view.redactions {
                    self.verify_tombstone(thread, &view.author, &tombstone)?;
                    let item = record
                        .value
                        .items
                        .iter_mut()
                        .find(|i| {
                            i.message_id == tombstone.message_id
                                && i.timestamp == tombstone.timestamp
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
            Err(Error::NotFound("record")) => {
                // Only synthesize sourceless redacted items when the Space
                // record is genuinely 404 AND every item in the batch is
                // covered by a cryptographically verified author or DS
                // ACCOUNT_DELETED tombstone.
                if view.redactions.is_empty() || view.redactions.len() != view.item_count {
                    return Err(Error::NotFound("record"));
                }
                for tombstone in &view.redactions {
                    self.verify_tombstone(thread, &view.author, tombstone)?;
                }
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
                Ok(Stored {
                    author: view.author,
                    rkey: view.rkey,
                    value: Batch {
                        type_: nsid::BATCH.into(),
                        thread_id: thread.into(),
                        items,
                        created_at: view.order.received_at.clone(),
                    },
                    order: Some(view.order.to_order()?),
                })
            }
            Err(err) => Err(err),
        }
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
        // cursors whose source record has just been deleted, while still
        // advancing if a page returns empty records alongside a cursor.
        let mut response_bytes = 0usize;
        let mut record_count = 0usize;
        let mut seen_rkeys = std::collections::BTreeSet::new();
        let mut seen_cursors = std::collections::BTreeSet::new();
        let mut cursor: Option<String> = None;
        for _ in 0..super::MAX_SPACE_PAGES {
            let mut params = vec![
                ("space", uri.into()),
                ("repo", did.into()),
                ("collection", nsid::BATCH.into()),
                ("limit", "100".into()),
                ("excludeValues", "true".into()),
            ];
            if let Some(c) = &cursor {
                params.push(("cursor", c.clone()));
            }
            let raw = transport
                .query(endpoint::LIST_RECORDS, &params)
                .map_err(map_space_error)?;
            if raw.len() > super::MAX_SPACE_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "space response exceeds {} bytes",
                    super::MAX_SPACE_RESPONSE_BYTES
                )));
            }
            response_bytes = response_bytes.checked_add(raw.len()).ok_or_else(|| {
                Error::Backend("conversation deletion response size overflow".into())
            })?;
            if response_bytes > super::MAX_SPACE_LIST_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "conversation deletion responses exceed {} bytes",
                    super::MAX_SPACE_LIST_RESPONSE_BYTES
                )));
            }
            let page: super::ListRecordsOut = serde_json::from_slice(&raw)
                .map_err(|_| Error::Malformed("conversation deletion listing"))?;
            if page.records.is_empty() {
                let Some(next) = page.cursor else {
                    return Ok(());
                };
                if next.len() > super::MAX_SPACE_CURSOR_BYTES {
                    return Err(Error::Backend(format!(
                        "space cursor exceeds {} bytes",
                        super::MAX_SPACE_CURSOR_BYTES
                    )));
                }
                if !seen_cursors.insert(next.clone()) {
                    return Err(Error::Backend("space cursor cycle".into()));
                }
                cursor = Some(next);
                continue;
            }
            cursor = None;
            seen_cursors.clear();
            if page.records.len() > 100 {
                return Err(Error::Backend(
                    "conversation deletion page exceeds 100 records".into(),
                ));
            }
            record_count = record_count
                .checked_add(page.records.len())
                .ok_or_else(|| {
                    Error::Backend("conversation deletion record count overflow".into())
                })?;
            if record_count > super::MAX_SPACE_LIST_ITEMS {
                return Err(Error::Backend(format!(
                    "conversation deletion exceeds {} records",
                    super::MAX_SPACE_LIST_ITEMS
                )));
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
                if !seen_rkeys.insert(record.rkey.clone()) {
                    return Err(Error::Backend(
                        "conversation deletion made no progress".into(),
                    ));
                }
                let body = serde_json::to_vec(&serde_json::json!({"space": uri, "repo": did,
                    "collection": nsid::BATCH, "rkey": record.rkey}))
                .map_err(|_| Error::Malformed("conversation record deletion"))?;
                let acknowledgement = transport
                    .procedure(endpoint::DELETE_RECORD, &body, [0; 16])
                    .map_err(map_space_error)?;
                if acknowledgement.len() > super::MAX_SPACE_RESPONSE_BYTES {
                    return Err(Error::Backend(format!(
                        "space response exceeds {} bytes",
                        super::MAX_SPACE_RESPONSE_BYTES
                    )));
                }
                response_bytes = response_bytes
                    .checked_add(acknowledgement.len())
                    .ok_or_else(|| {
                        Error::Backend("conversation deletion response size overflow".into())
                    })?;
                if response_bytes > super::MAX_SPACE_LIST_RESPONSE_BYTES {
                    return Err(Error::Backend(format!(
                        "conversation deletion responses exceed {} bytes",
                        super::MAX_SPACE_LIST_RESPONSE_BYTES
                    )));
                }
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
        if let Some(sender) = sender
            && views.iter().any(|view| view.author != sender)
        {
            return Err(Error::Malformed("sequencer returned another sender"));
        }
        views
            .into_iter()
            .map(|v| self.resolve(thread, &placement, v))
            .collect()
    }
    fn list_batches_before(
        &self,
        thread: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Stored<Batch>>> {
        let placement = self.placement(thread)?;
        if placement.space.is_none() {
            return self.legacy.list_batches_before(thread, before_ms, limit);
        }
        let target = limit.max(1).saturating_add(1);
        let mut params = vec![
            ("threadId", thread.into()),
            ("generation", placement.generation.clone()),
            ("reverse", "true".into()),
        ];
        if let Some(until) = before_ms {
            params.push(("untilMs", until.to_string()));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut eligible = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        let mut floor_ts = None;
        self.ds.list_pages(
            "listSpaceBatches",
            &params,
            |views: Vec<SpaceBatchView>, has_more| {
                for view in views {
                    if !seen.insert((view.author.clone(), view.rkey.clone())) {
                        continue;
                    }
                    let b = self.resolve(thread, &placement, view)?;
                    for i in &b.value.items {
                        if before_ms.is_none_or(|u| i.timestamp < u.saturating_sub(1)) {
                            eligible.insert((i.timestamp, i.message_id.clone()));
                        }
                    }
                    out.push(b);
                }
                if has_more && eligible.len() >= target {
                    floor_ts = eligible.iter().rev().nth(target - 1).map(|(ts, _)| *ts);
                    return Ok(false);
                }
                Ok(true)
            },
        )?;
        if let Some(floor) = floor_ts {
            let mut sweep = params;
            sweep.push(("fromMs", floor.to_string()));
            let extra: Vec<SpaceBatchView> = self.ds.list_all("listSpaceBatches", &sweep)?;
            for view in extra {
                if seen.insert((view.author.clone(), view.rkey.clone())) {
                    if out.len() >= crate::store::xrpc::MAX_LIST_ITEMS {
                        return Err(Error::Backend(format!(
                            "xrpc listing exceeds {} items",
                            crate::store::xrpc::MAX_LIST_ITEMS
                        )));
                    }
                    out.push(self.resolve(thread, &placement, view)?);
                }
            }
        }
        out.sort_by_key(|b| core::cmp::Reverse(b.value.items.iter().map(|i| i.timestamp).max()));
        Ok(out)
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

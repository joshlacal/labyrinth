//! Spaces-only conversation thread store (`com.atproto.space.*`, Gates 1 & 5).
//!
//! Each conversation maps to a single ATProto Space
//! (`at://{authorityDid}/space/blue.catbird.labyrinth.conversation/{skey}`).
//! Members write MEK distributions, sender batches (`<16-hex-first-seq>-<tid>`),
//! and encrypted attachment manifests directly into their own Space repo.
//! `mls-ds` holds zero long-term history or ciphertext index (`G6`, `I14`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{
    ApplyWritesIn, ApplyWritesOut, GetRecordOut, LIST_LIMIT, ListRecordsOut,
    MAX_SPACE_CURSOR_BYTES, MAX_SPACE_LIST_ITEMS, MAX_SPACE_LIST_RESPONSE_BYTES, MAX_SPACE_PAGES,
    MAX_SPACE_RESPONSE_BYTES, MAX_WRITES, SpaceRef, SpaceRpc, WriteOp, decode, decode_body, encode,
    endpoint, map_member_repo_space_error, map_space_error, uri_rkey,
};
use crate::attachment::{AttachmentCiphertextMeta, verify_attachment_ciphertext};
use crate::deletion::Redaction;
use crate::encoding::sha256;
use crate::records::{
    AttachmentManifest, AuthorRedaction, Batch, Bytes, MekDistribution, SealedMessageDef,
    datetime_from_ms, ms_from_datetime, nsid,
};
use crate::store::{Stored, ThreadStore, TimeRange};
use crate::{Error, Result};

const THREAD_COLLECTIONS: [&str; 3] = [nsid::MEK, nsid::BATCH, nsid::ATTACHMENT_MANIFEST];

fn overlay_author_redactions(
    thread_id: &str,
    author: &str,
    batches: &mut Vec<Stored<Batch>>,
    redactions: Vec<(String, AuthorRedaction)>,
) -> Result<()> {
    for (rkey, record) in redactions {
        if record.thread_id != thread_id || record.rkey() != rkey {
            return Err(Error::Malformed("authorRedaction coordinates or rkey"));
        }
        let redaction = record.to_redaction()?;
        redaction.verify(author, thread_id, &record.message_id)?;
        let mut found = false;
        for batch in batches.iter_mut() {
            for item in batch
                .value
                .items
                .iter_mut()
                .filter(|item| item.message_id == record.message_id)
            {
                item.redaction = Some(record.redaction.clone());
                found = true;
            }
        }
        if !found {
            batches.push(Stored {
                author: author.to_owned(),
                rkey: format!("redaction-{rkey}"),
                order: None,
                value: Batch {
                    type_: nsid::BATCH.into(),
                    thread_id: thread_id.to_owned(),
                    items: vec![SealedMessageDef {
                        message_id: record.message_id,
                        seq: None,
                        timestamp: ms_from_datetime(&record.created_at).unwrap_or(0),
                        mek_id: Bytes::default(),
                        sender_transport_pubkey: Bytes::default(),
                        signed_enc_message: Bytes::default(),
                        sequencer_receipt: None,
                        redaction: Some(record.redaction),
                    }],
                    created_at: record.created_at,
                },
            });
        }
    }
    Ok(())
}

/// Canonical DRISL bytes and CID v1 (DAG-CBOR, SHA-256) of a sender batch record.
pub fn batch_cid(batch: &Batch) -> Result<String> {
    batch.entries()?;
    let encoded = serde_ipld_dagcbor::to_vec(batch)
        .map_err(|_| Error::Malformed("conversation batch DRISL"))?;
    if encoded.len() > 1_048_576 {
        return Err(Error::Malformed("conversation batch exceeds 1 MiB"));
    }
    let digest = cid::multihash::Multihash::<64>::wrap(0x12, &sha256(&encoded))
        .map_err(|_| Error::Malformed("conversation batch CID"))?;
    Ok(cid::Cid::new_v1(0x71, digest).to_string())
}

fn system_now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct ListReposOut {
    #[serde(default)]
    repos: Vec<RepoView>,
}

#[derive(Deserialize)]
struct RepoView {
    did: String,
}

/// Spaces-only [`ThreadStore`] reading and writing directly against conversation Spaces.
pub struct SpaceThreadStore {
    did: String,
    t: Arc<dyn SpaceRpc>,
    spaces: Mutex<HashMap<String, SpaceRef>>,
    default_authority_did: Option<String>,
    tid_counter: AtomicU64,
    now_ms: crate::store::ClockFn,
    page: usize,
}

impl SpaceThreadStore {
    pub fn new(transport: impl Into<Arc<dyn SpaceRpc>>, did: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            t: transport.into(),
            spaces: Mutex::new(HashMap::new()),
            default_authority_did: None,
            tid_counter: AtomicU64::new(1),
            now_ms: Arc::new(system_now_ms),
            page: LIST_LIMIT,
        }
    }

    pub fn with_authority_did(mut self, authority_did: impl Into<String>) -> Self {
        self.default_authority_did = Some(authority_did.into());
        self
    }

    pub fn with_page_size(mut self, n: usize) -> Self {
        self.page = n.clamp(1, 100);
        self
    }

    pub fn with_clock(mut self, now_ms: crate::store::ClockFn) -> Self {
        self.now_ms = now_ms;
        self
    }

    pub fn register_thread_space(&mut self, thread_id: &str, space: SpaceRef) {
        self.spaces
            .lock()
            .unwrap()
            .insert(thread_id.to_owned(), space);
    }

    pub fn set_thread_space(&self, thread_id: &str, space: SpaceRef) {
        self.spaces
            .lock()
            .unwrap()
            .insert(thread_id.to_owned(), space);
    }

    fn space_for(&self, thread_id: &str) -> Result<SpaceRef> {
        if let Some(s) = self.spaces.lock().unwrap().get(thread_id).cloned() {
            return Ok(s);
        }
        if let Some(auth) = &self.default_authority_did {
            return Ok(SpaceRef::conversation(auth, thread_id));
        }
        Err(Error::NotFound("thread space"))
    }

    fn next_tid(&self) -> String {
        const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
        let c = self.tid_counter.fetch_add(1, Ordering::Relaxed);
        let us = (self.now_ms)().saturating_mul(1_000).wrapping_add(c);
        let v = ((us & ((1u64 << 53) - 1)) << 10) | (c & 0x3ff);
        (0..13)
            .rev()
            .map(|i| S32[((v >> (5 * i)) & 31) as usize] as char)
            .collect()
    }

    async fn apply(&self, space: &SpaceRef, writes: &[WriteOp]) -> Result<Vec<Option<String>>> {
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
            space: space.to_string(),
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
            .map_err(map_member_repo_space_error)?;
        let out: ApplyWritesOut = decode_body(&body)?;
        Ok(out.results.into_iter().map(|r| r.uri).collect())
    }

    async fn get_from<T: DeserializeOwned>(
        &self,
        space: &SpaceRef,
        repo: &str,
        collection: &str,
        rkey: &str,
    ) -> Result<Option<T>> {
        let p = [
            ("space", space.to_string()),
            ("repo", repo.to_owned()),
            ("collection", collection.to_owned()),
            ("rkey", rkey.to_owned()),
        ];
        match self
            .t
            .query(endpoint::GET_RECORD, &p)
            .await
            .map_err(map_member_repo_space_error)
        {
            Ok(body) => decode(decode_body::<GetRecordOut>(&body)?.value).map(Some),
            Err(Error::NotFound("record" | "repo")) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn list_repos(&self, space: &SpaceRef) -> Result<Vec<String>> {
        let p = [("space", space.to_string())];
        let body = self
            .t
            .query(endpoint::LIST_REPOS, &p)
            .await
            .map_err(map_member_repo_space_error)?;
        let out: ListReposOut = decode_body(&body)?;
        let mut dids: Vec<String> = out.repos.into_iter().map(|r| r.did).collect();
        dids.sort();
        dids.dedup();
        Ok(dids)
    }

    async fn list_repo_raw(
        &self,
        space: &SpaceRef,
        repo: &str,
        collection: &str,
        values: bool,
    ) -> Result<Vec<(String, Value)>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        let mut response_bytes = 0usize;
        for _ in 0..MAX_SPACE_PAGES {
            let mut p = vec![
                ("space", space.to_string()),
                ("repo", repo.to_owned()),
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
                .map_err(map_member_repo_space_error)
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

    async fn list_repo<T: DeserializeOwned>(
        &self,
        space: &SpaceRef,
        repo: &str,
        collection: &str,
    ) -> Result<Vec<(String, T)>> {
        self.list_repo_raw(space, repo, collection, true)
            .await?
            .into_iter()
            .map(|(k, v)| Ok((k, decode(v)?)))
            .collect()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ThreadStore for SpaceThreadStore {
    fn author(&self) -> &str {
        &self.did
    }

    async fn create_mek(&self, mek: &MekDistribution) -> Result<()> {
        let space = self.space_for(&mek.thread_id)?;
        self.apply(
            &space,
            &[WriteOp::Create {
                collection: nsid::MEK,
                rkey: Some(mek.rkey()),
                value: encode(mek)?,
            }],
        )
        .await?;
        Ok(())
    }

    async fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> Result<Vec<Stored<MekDistribution>>> {
        let space = self.space_for(thread_id)?;
        let rkey = hex::encode(mek_id);
        let repos = self.list_repos(&space).await?;
        let mut out = Vec::new();
        for did in repos {
            if let Some(m) = self
                .get_from::<MekDistribution>(&space, &did, nsid::MEK, &rkey)
                .await?
            {
                out.push(Stored {
                    author: did,
                    rkey: rkey.clone(),
                    value: m,
                    order: None,
                });
            }
        }
        Ok(out)
    }

    async fn append_batch(&self, batch: &Batch) -> Result<String> {
        let space = self.space_for(&batch.thread_id)?;
        let explicit_rkey = batch
            .items
            .first()
            .and_then(|i| i.seq)
            .map(|seq| format!("{seq:016x}-{}", self.next_tid()));
        let uris = self
            .apply(
                &space,
                &[WriteOp::Create {
                    collection: nsid::BATCH,
                    rkey: explicit_rkey,
                    value: encode(batch)?,
                }],
            )
            .await?;
        match uris.as_slice() {
            [Some(uri)] => uri_rkey(uri),
            _ => Err(Error::Backend(
                "space applyWrites returned no create result".into(),
            )),
        }
    }

    async fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<Stored<Batch>>> {
        let space = self.space_for(thread_id)?;
        let repos = self.list_repos(&space).await?;
        let mut out = Vec::new();
        for did in repos {
            if sender.is_some_and(|s| s != did.as_str()) {
                continue;
            }
            let mut batches: Vec<Stored<Batch>> = self
                .list_repo::<Batch>(&space, &did, nsid::BATCH)
                .await?
                .into_iter()
                .map(|(rkey, value)| Stored {
                    author: did.clone(),
                    rkey,
                    value,
                    order: None,
                })
                .collect();
            overlay_author_redactions(
                thread_id,
                &did,
                &mut batches,
                self.list_repo(&space, &did, nsid::AUTHOR_REDACTION).await?,
            )?;
            out.extend(batches.into_iter().filter(|batch| {
                batch.value.thread_id == thread_id
                    && batch
                        .value
                        .items
                        .iter()
                        .any(|item| range.contains(item.timestamp))
            }));
        }
        Ok(out)
    }

    async fn list_threads(&self) -> Result<Vec<String>> {
        let mut ids: Vec<String> = self.spaces.lock().unwrap().keys().cloned().collect();
        ids.sort();
        Ok(ids)
    }

    async fn redact_item(
        &self,
        thread_id: &str,
        message_id: &str,
        redaction: &Redaction,
    ) -> Result<usize> {
        redaction.verify(&self.did, thread_id, message_id)?;
        let space = self.space_for(thread_id)?;
        let mut stamped = redaction.clone();
        if stamped.redacted_at.is_none() {
            stamped.redacted_at = Some(datetime_from_ms((self.now_ms)()));
        }
        let record = AuthorRedaction::new(
            thread_id,
            message_id,
            &stamped,
            stamped
                .redacted_at
                .clone()
                .ok_or(Error::Malformed("redaction timestamp"))?,
        );
        let rkey = record.rkey();
        let batches = self
            .list_repo::<Batch>(&space, &self.did, nsid::BATCH)
            .await?;
        let count = batches
            .iter()
            .flat_map(|(_, batch)| &batch.items)
            .filter(|item| item.message_id == message_id)
            .count();

        if let Some(existing) = self
            .get_from::<AuthorRedaction>(&space, &self.did, nsid::AUTHOR_REDACTION, &rkey)
            .await?
        {
            existing
                .to_redaction()?
                .verify(&self.did, thread_id, message_id)?;
            if existing.thread_id != thread_id
                || existing.message_id != message_id
                || existing.rkey() != rkey
            {
                return Err(Error::Conflict);
            }
            return Ok(count);
        }

        match self
            .apply(
                &space,
                &[WriteOp::Create {
                    collection: nsid::AUTHOR_REDACTION,
                    rkey: Some(rkey.clone()),
                    value: encode(&record)?,
                }],
            )
            .await
        {
            Ok(_) => Ok(count),
            Err(Error::Conflict) => {
                let existing = self
                    .get_from::<AuthorRedaction>(&space, &self.did, nsid::AUTHOR_REDACTION, &rkey)
                    .await?
                    .ok_or(Error::Conflict)?;
                existing
                    .to_redaction()?
                    .verify(&self.did, thread_id, message_id)?;
                if existing.thread_id == thread_id
                    && existing.message_id == message_id
                    && existing.rkey() == rkey
                {
                    Ok(count)
                } else {
                    Err(Error::Conflict)
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn upload_and_commit_attachment(
        &self,
        thread_id: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> Result<String> {
        verify_attachment_ciphertext(ciphertext, meta)?;
        let space = self.space_for(thread_id)?;
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
        let uris = self
            .apply(
                &space,
                &[WriteOp::Create {
                    collection: nsid::ATTACHMENT_MANIFEST,
                    rkey: None,
                    value: encode(&manifest)?,
                }],
            )
            .await?;
        match uris.as_slice() {
            [Some(uri)] => uri_rkey(uri),
            _ => Err(Error::Backend(
                "space applyWrites returned no create result".into(),
            )),
        }
    }

    async fn get_attachment_manifest(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> Result<Option<AttachmentManifest>> {
        let space = self.space_for(thread_id)?;
        self.get_from(&space, author_did, nsid::ATTACHMENT_MANIFEST, rkey)
            .await
    }

    async fn get_attachment_verified(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> Result<Vec<u8>> {
        let space = self.space_for(thread_id)?;
        let manifest: AttachmentManifest = self
            .get_from(&space, author_did, nsid::ATTACHMENT_MANIFEST, rkey)
            .await?
            .ok_or(Error::NotFound("attachmentManifest"))?;
        let (cid, meta) = manifest.to_meta()?;
        let bytes = self
            .t
            .get_blob(&space.to_string(), author_did, &cid)
            .await
            .map_err(map_member_repo_space_error)?;
        verify_attachment_ciphertext(&bytes, &meta)?;
        Ok(bytes)
    }

    async fn list_own_attachment_manifests(
        &self,
        thread_id: &str,
    ) -> Result<Vec<(String, AttachmentManifest)>> {
        let space = self.space_for(thread_id)?;
        self.list_repo(&space, &self.did, nsid::ATTACHMENT_MANIFEST)
            .await
    }

    /// Account cleanup: deletes this account's ciphertext and key material.
    /// Immutable `authorRedaction` records survive. Leaving a conversation
    /// never calls this: remaining members may hold no other copy.
    async fn clear_records(&self, thread_id: &str) -> Result<()> {
        let space = self.space_for(thread_id)?;
        for collection in THREAD_COLLECTIONS {
            let rkeys: Vec<String> = self
                .list_repo_raw(&space, &self.did, collection, false)
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
                self.apply(&space, &writes).await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;

    use super::*;
    use crate::store::space::SpaceError;

    struct GrantedRelay(u16);

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl SpaceRpc for GrantedRelay {
        async fn query(
            &self,
            nsid: &str,
            _: &[(&str, String)],
        ) -> core::result::Result<Vec<u8>, SpaceError> {
            assert_eq!(nsid, endpoint::LIST_REPOS);
            Err(SpaceError::named(
                self.0,
                "SpaceNotFound",
                "unsigned refusal after credential grant",
            ))
        }

        async fn procedure(
            &self,
            nsid: &str,
            _: &[u8],
        ) -> core::result::Result<Vec<u8>, SpaceError> {
            assert_eq!(nsid, endpoint::APPLY_WRITES);
            Err(SpaceError::named(
                self.0,
                "SpaceNotFound",
                "unsigned refusal after credential grant",
            ))
        }
    }

    #[test]
    fn unsigned_space_not_found_is_not_member_repo_denial_at_read_or_write_boundary() {
        let space = SpaceRef::conversation("did:web:ds.example", "thread");
        for status in [400, 404] {
            let rpc: Arc<dyn SpaceRpc> = Arc::new(GrantedRelay(status));
            let store = SpaceThreadStore::new(rpc, "did:plc:alice");
            assert_eq!(
                block_on(store.list_repos(&space)).unwrap_err(),
                Error::NotFound("space")
            );
            assert_eq!(
                block_on(store.apply(
                    &space,
                    &[WriteOp::Delete {
                        collection: nsid::BATCH,
                        rkey: "pending".into(),
                    }],
                ))
                .unwrap_err(),
                Error::NotFound("space")
            );
        }
    }
}

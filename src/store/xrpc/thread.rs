//! [`ThreadStore`] over the mls-ds thread endpoints (design §2, "Thread").
//! `threadId` is the chat conversation id; the server stamps every MEK and
//! batch with a [`crate::store::ServerOrder`].
//!
//! Newest-first reads (`reverse=true`) page by server seq, not by sender
//! timestamp, so they cannot stop early at `limit` items: the stores read
//! every page in the window and sort locally by newest item.

use std::sync::Arc;

use super::mailbox::range_params;
use super::wire::{AuthoredView, RecordBody, RedactIn, RedactOut, RkeyOrderOut, ThreadView};
use super::{Xrpc, XrpcTransport};
use crate::Result;
use crate::deletion::Redaction;
use crate::records::{Batch, MekDistribution, RedactionDef};
use crate::store::{Stored, ThreadStore, TimeRange};

/// The conversation records on the sequencer DS, writing as one DID.
pub struct XrpcThreadStore {
    did: String,
    x: Xrpc,
}

impl XrpcThreadStore {
    pub fn new(did: &str, transport: Arc<dyn XrpcTransport>) -> Self {
        Self {
            did: did.to_owned(),
            x: Xrpc::new(transport),
        }
    }
}

fn stored<T>(v: AuthoredView<T>) -> Result<Stored<T>> {
    Ok(Stored {
        order: Some(v.order.to_order()?),
        author: v.author,
        rkey: v.rkey,
        value: v.record,
    })
}

impl ThreadStore for XrpcThreadStore {
    fn author(&self) -> &str {
        &self.did
    }

    fn create_mek(&self, mek: &MekDistribution) -> Result<()> {
        let _: RkeyOrderOut = self.x.post("createMek", &RecordBody { record: mek })?;
        Ok(())
    }

    fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> Result<Vec<Stored<MekDistribution>>> {
        let p = [
            ("threadId", thread_id.to_owned()),
            ("mekId", hex::encode(mek_id)),
        ];
        let v: Vec<AuthoredView<MekDistribution>> = self.x.list_all("findMeks", &p)?;
        v.into_iter().map(stored).collect()
    }

    fn append_batch(&self, batch: &Batch) -> Result<String> {
        let out: RkeyOrderOut = self.x.post("appendBatch", &RecordBody { record: batch })?;
        Ok(out.rkey)
    }

    fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<Stored<Batch>>> {
        let mut p = vec![("threadId", thread_id.to_owned())];
        if let Some(s) = sender {
            p.push(("sender", s.to_owned()));
        }
        range_params(range, &mut p);
        let v: Vec<AuthoredView<Batch>> = self.x.list_all("listBatches", &p)?;
        v.into_iter().map(stored).collect()
    }

    /// `redactMessage`. mls-ds counts an unknown or already-redacted id as
    /// zero (idempotent), so this returns `Ok(0)` where the memory store
    /// says [`crate::Error::NotFound`]. `redaction.redacted_at` must be
    /// `None`: the server stamps it.
    fn redact_item(
        &self,
        thread_id: &str,
        message_id: &str,
        redaction: &Redaction,
    ) -> Result<usize> {
        let mut def = RedactionDef::from_redaction(redaction);
        def.redacted_at = None;
        let input = RedactIn {
            thread_id: thread_id.to_owned(),
            message_id: message_id.to_owned(),
            redaction: def,
        };
        let out: RedactOut = self.x.post("redactMessage", &input)?;
        Ok(out.redacted)
    }

    /// `getMessages` (100 ids per call), deduplicated by batch.
    fn get_messages(&self, thread_id: &str, message_ids: &[&str]) -> Result<Vec<Stored<Batch>>> {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for chunk in message_ids.chunks(super::MAX_PAGE) {
            let mut p = vec![("threadId", thread_id.to_owned())];
            p.extend(chunk.iter().map(|id| ("messageIds", (*id).to_owned())));
            let v: Vec<AuthoredView<Batch>> = self.x.list_all("getMessages", &p)?;
            for b in v {
                if seen.insert((b.author.clone(), b.rkey.clone())) {
                    out.push(stored(b)?);
                }
            }
        }
        Ok(out)
    }

    /// `listBatches` with `reverse=true` and `untilMs`, then sorted by
    /// newest item (see the module docs; `limit` cannot stop it early).
    fn list_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Stored<Batch>>> {
        let _ = limit;
        let mut p = vec![
            ("threadId", thread_id.to_owned()),
            ("reverse", "true".to_owned()),
        ];
        if let Some(b) = before_ms {
            p.push(("untilMs", b.to_string()));
        }
        let v: Vec<AuthoredView<Batch>> = self.x.list_all("listBatches", &p)?;
        let mut v = v.into_iter().map(stored).collect::<Result<Vec<_>>>()?;
        v.sort_by_key(|b| core::cmp::Reverse(b.value.items.iter().map(|i| i.timestamp).max()));
        Ok(v)
    }

    /// `listThreads` (merged across sequencers by the home DS).
    fn list_threads(&self) -> Result<Vec<String>> {
        let v: Vec<ThreadView> = self.x.list_all("listThreads", &[])?;
        Ok(v.into_iter().map(|t| t.thread_id).collect())
    }
}

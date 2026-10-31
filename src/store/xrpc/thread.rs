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
use crate::deletion::Redaction;
use crate::records::{Batch, MekDistribution, RedactionDef};
use crate::store::{Stored, ThreadListing, ThreadStore, TimeRange};
use crate::{Error, Result};

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
        if message_ids.len() > super::MAX_LIST_ITEMS {
            return Err(Error::Backend(format!(
                "xrpc message lookup exceeds {} ids",
                super::MAX_LIST_ITEMS
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for chunk in message_ids.chunks(super::MAX_PAGE) {
            let mut p = vec![("threadId", thread_id.to_owned())];
            p.extend(chunk.iter().map(|id| ("messageIds", (*id).to_owned())));
            let v: Vec<AuthoredView<Batch>> = self.x.list_all("getMessages", &p)?;
            for b in v {
                if seen.insert((b.author.clone(), b.rkey.clone())) {
                    if out.len() == super::MAX_LIST_ITEMS {
                        return Err(Error::Backend(format!(
                            "xrpc message lookup exceeds {} batches",
                            super::MAX_LIST_ITEMS
                        )));
                    }
                    out.push(stored(b)?);
                }
            }
        }
        Ok(out)
    }

    /// `listBatches` with `reverse=true` and `untilMs`, stopping unbounded
    /// seq pagination once `limit + 1` eligible items are collected and
    /// finishing with a bounded `[floor_ts, before_ms)` sweep.
    fn list_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Stored<Batch>>> {
        let target = limit.max(1).saturating_add(1);
        let mut p = vec![
            ("threadId", thread_id.to_owned()),
            ("reverse", "true".to_owned()),
        ];
        if let Some(b) = before_ms {
            p.push(("untilMs", b.to_string()));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut eligible = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        let mut floor_ts = None;
        self.x.list_pages(
            "listBatches",
            &p,
            |views: Vec<AuthoredView<Batch>>, has_more| {
                for v in views {
                    let b = stored(v)?;
                    for i in &b.value.items {
                        if before_ms.is_none_or(|u| i.timestamp < u.saturating_sub(1)) {
                            eligible.insert((i.timestamp, i.message_id.clone()));
                        }
                    }
                    if seen.insert((b.author.clone(), b.rkey.clone())) {
                        out.push(b);
                    }
                }
                if has_more && eligible.len() >= target {
                    floor_ts = eligible.iter().rev().nth(target - 1).map(|(ts, _)| *ts);
                    return Ok(false);
                }
                Ok(true)
            },
        )?;
        if let Some(floor) = floor_ts {
            let mut sweep = p;
            sweep.push(("fromMs", floor.to_string()));
            let extra: Vec<AuthoredView<Batch>> = self.x.list_all("listBatches", &sweep)?;
            for v in extra {
                let b = stored(v)?;
                if seen.insert((b.author.clone(), b.rkey.clone())) {
                    if out.len() >= super::MAX_LIST_ITEMS {
                        return Err(Error::Backend(format!(
                            "xrpc listing exceeds {} items",
                            super::MAX_LIST_ITEMS
                        )));
                    }
                    out.push(b);
                }
            }
        }
        out.sort_by_key(|b| core::cmp::Reverse(b.value.items.iter().map(|i| i.timestamp).max()));
        Ok(out)
    }

    /// `listThreads` (merged across sequencers by the home DS). Fails
    /// when a sequencer was unreachable; see
    /// [`list_threads_report`](ThreadStore::list_threads_report).
    fn list_threads(&self) -> Result<Vec<String>> {
        let v: Vec<ThreadView> = self.x.list_all("listThreads", &[])?;
        Ok(v.into_iter().map(|t| t.thread_id).collect())
    }

    fn list_threads_report(&self) -> Result<ThreadListing> {
        let (v, incomplete): (Vec<ThreadView>, _) = self.x.list_all_report("listThreads", &[])?;
        Ok(ThreadListing {
            threads: v.into_iter().map(|t| t.thread_id).collect(),
            incomplete,
        })
    }
}

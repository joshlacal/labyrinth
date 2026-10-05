//! Lookups beyond a time range (gap audit 2.2, 2.3, 1.3): one message by
//! id, newest-first pages, and the threads this account has history in.

use std::collections::BTreeSet;

use super::Labyrinth;
use super::read::{ThreadHistory, finish};
use crate::{Error, Result};

/// Where a newest-first page ended: the oldest `(timestamp, messageId)`
/// it returned. The next page holds only items strictly older (by
/// timestamp, then message id). Serializes as `"<timestamp>:<messageId>"`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadCursor {
    pub timestamp: u64,
    pub message_id: String,
}

impl ThreadCursor {
    fn key(&self) -> (u64, &str) {
        (self.timestamp, &self.message_id)
    }

    /// Parses [`ToString`] output.
    pub fn parse(s: &str) -> Result<Self> {
        let (ts, id) = s.split_once(':').ok_or(Error::Malformed("thread cursor"))?;
        Ok(Self {
            timestamp: ts.parse().map_err(|_| Error::Malformed("thread cursor"))?,
            message_id: id.to_owned(),
        })
    }
}

impl core::fmt::Display for ThreadCursor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.timestamp, self.message_id)
    }
}

/// One newest-first page of a thread.
#[derive(Clone, Debug, Default)]
pub struct ThreadPage {
    /// The page, every list ordered **newest first**.
    pub history: ThreadHistory,
    /// Pass back as `before` for the next (older) page; `None` once the
    /// thread is exhausted.
    pub next: Option<ThreadCursor>,
}

/// A thread this account has history in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadSummary {
    pub thread_id: String,
    /// It holds a MEK this account wrote or was addressed in.
    pub sender_history: bool,
    /// This account's mailbox holds owner records for it (re-archive on
    /// leave, delete-for-me tombstones).
    pub owner_archive: bool,
}

impl Labyrinth {
    /// Every copy of message `message_id` in `thread_id` (sender copies,
    /// owner copies, a redaction), with delete-for-me applied: an empty
    /// result means it is unknown, unsent ([`ThreadHistory::redacted`]) or
    /// deleted for me ([`ThreadHistory::deleted_for_me`]).
    pub fn load_message(&mut self, thread_id: &str, message_id: &str) -> Result<ThreadHistory> {
        let mut h = ThreadHistory {
            space_readable: true,
            ..ThreadHistory::default()
        };
        let ids = [message_id];
        let batches = self.readable(&mut h, self.b.threads.get_messages(thread_id, &ids))?;
        let keep = |id: &str, _| id == message_id;
        self.open_batches(thread_id, batches, &keep, &mut h);
        let owner = self.b.mailbox.get_owner_messages(thread_id, &ids)?;
        let tombstones = self.open_owner_batches(thread_id, owner, &keep, &mut h)?;
        finish(&mut h, &tombstones);
        Ok(h)
    }

    /// The `limit` newest distinct `(timestamp, messageId)` positions of
    /// `thread_id` older than `before` (the newest overall without it),
    /// decrypted, newest first. Only the selected items are decrypted.
    ///
    /// All copies sharing a position stay on one page, so merging works
    /// as in [`load_thread`](Self::load_thread). A page can come back
    /// shorter than `limit` when delete-for-me tombstones hide some of its
    /// positions (tombstones carry their target's position).
    pub fn load_thread_page(
        &mut self,
        thread_id: &str,
        before: Option<&ThreadCursor>,
        limit: usize,
    ) -> Result<ThreadPage> {
        let limit = limit.max(1);
        let before_ms = before.map(|c| c.timestamp.saturating_add(1));
        let older = |ts: u64, id: &str| before.is_none_or(|c| (ts, id) < c.key());
        let mut h = ThreadHistory {
            space_readable: true,
            ..ThreadHistory::default()
        };
        let batches = self.readable(
            &mut h,
            self.b
                .threads
                .list_batches_before(thread_id, before_ms, limit),
        )?;
        let owner = self
            .b
            .mailbox
            .list_owner_batches_before(thread_id, before_ms, limit)?;
        let mut positions: BTreeSet<(u64, String)> = BTreeSet::new();
        let sender_items = batches
            .iter()
            .filter(|b| b.value.thread_id == thread_id)
            .flat_map(|b| b.value.items.iter().map(|i| (i.timestamp, &i.message_id)));
        let owner_items = owner
            .iter()
            .flat_map(|b| b.value.items.iter().map(|i| (i.timestamp, &i.message_id)));
        for (ts, id) in sender_items.chain(owner_items) {
            if older(ts, id) {
                positions.insert((ts, id.clone()));
            }
        }
        let selected: BTreeSet<(u64, String)> =
            positions.iter().rev().take(limit).cloned().collect();
        let next = (positions.len() > limit)
            .then(|| selected.first())
            .flatten()
            .map(|(ts, id)| ThreadCursor {
                timestamp: *ts,
                message_id: id.clone(),
            });
        let keep = |id: &str, ts: u64| selected.contains(&(ts, id.to_owned()));
        self.open_batches(thread_id, batches, &keep, &mut h);
        let tombstones = self.open_owner_batches(thread_id, owner, &keep, &mut h)?;
        finish(&mut h, &tombstones);
        h.messages.reverse();
        h.undecryptable.reverse();
        h.redacted.reverse();
        Ok(ThreadPage { history: h, next })
    }

    /// Every thread this account has history in, from its own records:
    /// MEKs it wrote or was addressed in, and its owner archive. A device
    /// restored after leaving a conversation still finds it here.
    /// Fails with [`Error::NotSupported`] only if neither store can list.
    pub fn list_threads(&self) -> Result<Vec<ThreadSummary>> {
        let unsupported = |r: Result<Vec<String>>| match r {
            Err(Error::NotSupported(_)) => Ok(None),
            r => r.map(Some),
        };
        let sender = unsupported(self.b.threads.list_threads())?;
        let owner = unsupported(self.b.mailbox.list_owner_threads())?;
        if sender.is_none() && owner.is_none() {
            return Err(Error::NotSupported("listThreads"));
        }
        let (sender, owner) = (sender.unwrap_or_default(), owner.unwrap_or_default());
        let all: BTreeSet<&String> = sender.iter().chain(owner.iter()).collect();
        Ok(all
            .into_iter()
            .map(|t| ThreadSummary {
                thread_id: t.clone(),
                sender_history: sender.contains(t),
                owner_archive: owner.contains(t),
            })
            .collect())
    }
}

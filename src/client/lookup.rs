//! Lookups beyond a time range (gap audit 2.2, 2.3, 1.3): one message by
//! id, newest-first pages, and the threads this account has history in.

use std::collections::{BTreeMap, BTreeSet};

use super::Labyrinth;
use super::read::ThreadHistory;
use crate::{Error, Result};

/// Where a newest-first page ended: the oldest message position
/// `(timestamp, messageId)` it covered. The next page holds only messages
/// positioned strictly older (by timestamp, then message id). Serializes as
/// `"<timestamp>:<messageId>"`.
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

/// [`Labyrinth::list_threads_report`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadList {
    pub threads: Vec<ThreadSummary>,
    /// Sequencer DS DIDs the server could not reach: conversations they
    /// sequence may be missing from `threads`. Show the list as partial.
    pub incomplete: Vec<String>,
}

fn project_history(h: &mut ThreadHistory, keep: impl Fn(&str) -> bool) {
    h.messages.retain(|m| keep(&m.message_id));
    h.undecryptable.retain(|m| keep(&m.message_id));
    h.redacted.retain(|m| keep(&m.message_id));
    h.deleted_for_me.retain(|id| keep(id));
    h.rejected.retain(|m| keep(&m.message_id));
}

impl Labyrinth {
    /// Every accepted copy of `message_id` in `thread_id`, with redactions,
    /// delete-for-me and conversation-wide receipt replay admission applied.
    pub async fn load_message(
        &mut self,
        thread_id: &str,
        message_id: &str,
    ) -> Result<ThreadHistory> {
        // Receipt identity is conversation-wide: projecting before admission
        // lets one receipt be accepted under a different id on each lookup.
        let mut h = self
            .load_thread(thread_id, crate::store::TimeRange::ALL)
            .await?;
        project_history(&mut h, |id| id == message_id);
        Ok(h)
    }

    /// The `limit` newest messages of `thread_id` older than `before` (the
    /// newest overall without it), decrypted, newest first. Only their copies
    /// are decrypted.
    ///
    /// A message's copies can sit at different timestamps (a witness stamps
    /// its receive time), so each message has one position, taken from all
    /// of its copies: its sender copy's earliest timestamp, else its earliest
    /// witness copy's, else its earliest owner copy's. A message appears on
    /// exactly one page, with every copy, so merging works as in
    /// [`load_thread`](Self::load_thread). A page can come back shorter than
    /// `limit` when delete-for-me tombstones hide some of its messages, or
    /// when its window holds copies of messages positioned on other pages.
    pub async fn load_thread_page(
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
        self.seed_store_writer_floors();
        let window = self.readable_quarantined(
            &mut h,
            self.b
                .threads
                .list_batches_before_quarantined(thread_id, before_ms, limit)
                .await,
        )?;
        let owner_window = self
            .b
            .mailbox
            .list_owner_batches_before(thread_id, before_ms, limit)
            .await?;
        self.sync_store_writer_floors()?;
        let mut raw: BTreeSet<(u64, &str)> = BTreeSet::new();
        let sender_items = window
            .iter()
            .filter(|b| b.value.thread_id == thread_id)
            .flat_map(|b| b.value.items.iter().map(|i| (i.timestamp, &*i.message_id)));
        let owner_items = owner_window
            .iter()
            .flat_map(|b| b.value.items.iter().map(|i| (i.timestamp, &*i.message_id)));
        raw.extend(
            sender_items
                .chain(owner_items)
                .filter(|&(ts, id)| ts <= i64::MAX as u64 && older(ts, id)),
        );
        // A store returns at least the newest `limit + 1` copy positions
        // below `before_ms` in full; only that span is known to be complete.
        let span: Vec<(u64, &str)> = raw.iter().rev().take(limit + 1).copied().collect();
        let Some(&(floor_ts, floor_id)) = span.last() else {
            return Ok(ThreadPage {
                history: h,
                next: None,
            });
        };
        let mut ids: Vec<&str> = span.iter().map(|&(_, id)| id).collect();
        ids.sort_unstable();
        ids.dedup();
        let batches = self.readable_quarantined(
            &mut h,
            self.b
                .threads
                .get_messages_quarantined(thread_id, &ids)
                .await,
        )?;
        let owner = self.b.mailbox.get_owner_messages(thread_id, &ids).await?;
        self.sync_store_writer_floors()?;
        // (rank, timestamp) of each message's positioning copy.
        let mut rank: BTreeMap<&str, (u8, u64)> = BTreeMap::new();
        let mut note = |id: &str, r: (u8, u64)| {
            if let Ok(i) = ids.binary_search(&id) {
                let e = rank.entry(ids[i]).or_insert(r);
                *e = (*e).min(r);
            }
        };
        for b in batches.iter().filter(|b| b.value.thread_id == thread_id) {
            for i in &b.value.items {
                let witness = i
                    .sequencer_receipt
                    .as_ref()
                    .is_some_and(|r| r.sender_did != b.author);
                note(&i.message_id, (u8::from(witness), i.timestamp));
            }
        }
        for i in owner.iter().flat_map(|b| &b.value.items) {
            if i.thread_id == thread_id {
                note(&i.message_id, (2, i.timestamp));
            }
        }
        let mut candidates: Vec<(u64, &str)> = rank
            .into_iter()
            .map(|(id, (_, ts))| (ts, id))
            .filter(|&(ts, id)| (ts, id) >= (floor_ts, floor_id) && older(ts, id))
            .collect();
        candidates.sort_unstable_by(|a, b| b.cmp(a));
        let cursor = |(ts, id): (u64, &str)| ThreadCursor {
            timestamp: ts,
            message_id: id.to_owned(),
        };
        let next = if candidates.len() > limit {
            Some(cursor(candidates[limit - 1]))
        } else if raw.len() > limit {
            Some(cursor((floor_ts, floor_id)))
        } else {
            None
        };
        let selected: BTreeSet<&str> = candidates.iter().take(limit).map(|&(_, id)| id).collect();
        // Keep the store window for cursor positioning, but decide receipt
        // identity, redactions and tombstones against the authenticated whole
        // thread before projecting this page.
        let mut history = self
            .load_thread(thread_id, crate::store::TimeRange::ALL)
            .await?;
        project_history(&mut history, |id| selected.contains(id));
        history.messages.reverse();
        history.undecryptable.reverse();
        history.redacted.reverse();
        history.rejected.reverse();
        Ok(ThreadPage { history, next })
    }

    /// Every thread this account has history in, from its own records:
    /// MEKs it wrote or was addressed in, and its owner archive. A device
    /// restored after leaving a conversation still finds it here.
    /// Fails with [`Error::NotSupported`] only if neither store can list,
    /// and with [`Error::Backend`] if a sequencer was unreachable (use
    /// [`list_threads_report`](Self::list_threads_report) for the partial
    /// list).
    pub async fn list_threads(&self) -> Result<Vec<ThreadSummary>> {
        let list = self.list_threads_report().await?;
        if list.incomplete.is_empty() {
            Ok(list.threads)
        } else {
            Err(Error::Backend(format!(
                "listThreads incomplete: unreachable sequencers {}",
                list.incomplete.join(", ")
            )))
        }
    }

    /// [`list_threads`](Self::list_threads), returning a partial list with
    /// the unreachable sequencers named instead of failing.
    pub async fn list_threads_report(&self) -> Result<ThreadList> {
        let unsupported = |r: Result<Vec<String>>| match r {
            Err(Error::NotSupported(_)) => Ok(None),
            r => r.map(Some),
        };
        let (sender, incomplete) = match self.b.threads.list_threads_report().await {
            Ok(l) => (Some(l.threads), l.incomplete),
            Err(Error::NotSupported(_)) => (None, Vec::new()),
            Err(e) => return Err(e),
        };
        let owner = unsupported(self.b.mailbox.list_owner_threads().await)?;
        if sender.is_none() && owner.is_none() {
            return Err(Error::NotSupported("listThreads"));
        }
        let (sender, owner) = (sender.unwrap_or_default(), owner.unwrap_or_default());
        let all: BTreeSet<&String> = sender.iter().chain(owner.iter()).collect();
        let threads = all
            .into_iter()
            .map(|t| ThreadSummary {
                thread_id: t.clone(),
                sender_history: sender.contains(t),
                owner_archive: owner.contains(t),
            })
            .collect();
        Ok(ThreadList {
            threads,
            incomplete,
        })
    }
}

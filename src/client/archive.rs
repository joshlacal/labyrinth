//! Owner-mode archiving into this account's mailbox (SPEC §7.1, [CB-22],
//! [CB-37]).

use std::collections::HashSet;

use super::Labyrinth;
use super::read::{MessageSource, ThreadHistory};
use crate::epoch::EpochKeys as _;
use crate::message::seal_owner;
use crate::records::{BATCH_BYTE_BUDGET, MAX_BATCH_ITEMS};
use crate::store::TimeRange;
use crate::{Error, Result};

impl Labyrinth {
    /// Archive a message into my own mailbox in owner mode (cipher version
    /// 5, [CB-37]) under my latest epoch. Buffered like sender batches.
    pub fn archive_owner(
        &mut self,
        thread_id: &str,
        message_id: &str,
        timestamp: u64,
        frame: &[u8],
    ) -> Result<Option<super::FlushedBatch>> {
        self.sync_epochs()?;
        self.archive_owner_synced(thread_id, message_id, timestamp, frame)
    }

    /// Owner-mode archive after the caller has completed the epoch/revocation
    /// safety check. Kept private so public callers cannot skip it.
    fn archive_owner_synced(
        &mut self,
        thread_id: &str,
        message_id: &str,
        timestamp: u64,
        frame: &[u8],
    ) -> Result<Option<super::FlushedBatch>> {
        let e = self.epoch_secret(self.latest)?;
        let m = seal_owner(e.root(), e.seq, thread_id, message_id, timestamp, frame)?;
        self.queue_owner(thread_id, m)
    }

    /// Buffers one owner record, flushing at the batch limits.
    pub(super) fn queue_owner(
        &mut self,
        thread_id: &str,
        m: crate::message::OwnerMessage,
    ) -> Result<Option<super::FlushedBatch>> {
        if m.epoch_seq != self.latest
            || self
                .owner_outbox
                .values()
                .flatten()
                .any(|item| item.epoch_seq != self.latest)
        {
            return Err(Error::WrongEpoch);
        }
        let size = |m: &crate::message::OwnerMessage| m.encrypted.len().div_ceil(3) * 4 + 200;
        let mut flushed = None;
        let pending: usize = self
            .owner_outbox
            .get(thread_id)
            .map_or(0, |v| v.iter().map(size).sum());
        if pending > 0 && pending + size(&m) > BATCH_BYTE_BUDGET {
            flushed = self.flush_owner(thread_id)?;
        }
        let queue = self.owner_outbox.entry(thread_id.to_owned()).or_default();
        queue.push(m);
        if queue.len() >= MAX_BATCH_ITEMS {
            flushed = self.flush_owner(thread_id)?;
        }
        Ok(flushed)
    }

    /// [CB-22]: before leaving a conversation (and losing read access to
    /// its space), copy every message I can read that is not already in my
    /// owner archive into my mailbox. Returns how many were archived.
    ///
    /// Owner records carry no sender DID; a client that needs it must keep
    /// it inside the frame.
    pub fn rearchive_thread_before_leave(&mut self, thread_id: &str) -> Result<usize> {
        // One safety check covers the whole local batch. No external call in
        // the loop can advance this client's epoch; re-running a full member
        // audit for every historical message would make this path quadratic
        // in remote work.
        self.sync_epochs()?;
        if self
            .owner_outbox
            .values()
            .flatten()
            .any(|item| item.epoch_seq != self.latest)
        {
            return Err(Error::WrongEpoch);
        }
        let history = self.load_thread(thread_id, TimeRange::ALL)?;
        // What the owner archive already holds, by (messageId, frame): a
        // copy counts as archived only if its plaintext is byte-equal, so
        // two distinct messages sharing an id are both kept.
        let mut owner = ThreadHistory::default();
        let batches = self
            .b
            .mailbox
            .list_owner_batches(thread_id, TimeRange::ALL)?;
        self.open_owner_batches(thread_id, batches, &|_, _| true, &mut owner)?;
        let mut archived: HashSet<(String, Vec<u8>)> = owner
            .messages
            .into_iter()
            .map(|m| (m.message_id, m.frame))
            .collect();
        let mut n = 0;
        for m in history.messages {
            if m.source != MessageSource::Sender {
                continue;
            }
            let key = (m.message_id, m.frame);
            if archived.contains(&key) {
                continue;
            }
            self.archive_owner_synced(thread_id, &key.0, m.timestamp, &key.1)?;
            archived.insert(key);
            n += 1;
        }
        self.flush_owner(thread_id)?;
        Ok(n)
    }
}

//! Deleting history ([CB-38]; see [`crate::deletion`] for the model).

use std::collections::BTreeSet;

use super::Labyrinth;
use crate::deletion::Redaction;
use crate::epoch::EpochKeys as _;
use crate::message::seal_owner_tombstone;
use crate::store::TimeRange;
use crate::{Error, Result};

/// What [`Labyrinth::purge_account`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Threads this account had history in.
    pub threads: usize,
    /// Authored items redacted.
    pub redacted: usize,
    /// Threads whose space refused this account (left a Space): their
    /// authored items could not be redacted by the client.
    pub unreachable_threads: Vec<String>,
    /// Extra key publishers that cannot retract yet
    /// ([`Error::NotSupported`]); their published epochs remain.
    pub publishers_not_retracted: usize,
    /// The server did the redaction and purge (mls-ds
    /// `deleteAccountData`); `threads` and `redacted` are then unknown and
    /// left at zero.
    pub server_side: bool,
}

impl Labyrinth {
    /// Delete for me: hide `message_id` (sent at `timestamp`) of
    /// `thread_id` on every device of this account, through an encrypted
    /// owner-mode tombstone. With `author`, only that sender's copies are
    /// hidden (another member reusing the id stays visible, [CB-31]).
    /// `blob_ids` are the message's attachments; their references in this
    /// mailbox are deleted, so this account can no longer fetch them.
    pub fn delete_for_me(
        &mut self,
        thread_id: &str,
        message_id: &str,
        timestamp: u64,
        author: Option<&str>,
        blob_ids: &[&str],
    ) -> Result<()> {
        let e = self.epoch_secret(self.latest)?;
        let t = seal_owner_tombstone(e.root(), e.seq, thread_id, message_id, timestamp, author)?;
        self.queue_owner(thread_id, t)?;
        self.flush_owner(thread_id)?;
        for b in blob_ids {
            self.delete_attachment_reference(thread_id, b)?;
        }
        Ok(())
    }

    /// Unsend: drop any unflushed copy of my message `message_id` and ask
    /// the server to redact the stored ones, under a redaction signed by
    /// this device's chat key. Returns how many copies went away.
    pub fn unsend(&mut self, thread_id: &str, message_id: &str) -> Result<usize> {
        let mut dropped = 0;
        if let Some(q) = self.outbox.get_mut(thread_id) {
            let before = q.len();
            q.retain(|m| m.message_id != message_id);
            dropped = before - q.len();
        }
        let r = Redaction::sign(&self.did, thread_id, message_id, self.transport.as_ref());
        match self.b.threads.redact_item(thread_id, message_id, &r) {
            Ok(n) => Ok(dropped + n),
            Err(Error::NotFound(_)) if dropped > 0 => Ok(dropped),
            Err(e) => Err(e),
        }
    }

    /// Account deletion, client-orchestrated: redact every item this
    /// account authored in every thread it has history in, retract the
    /// published epochs from every extra publisher, then purge the mailbox
    /// (devices, epochs, recovery bundles, owner archive, ORF states,
    /// attachment references, `mailboxKeys`). Rerunnable after a failure.
    /// Drop this client afterwards.
    ///
    /// When the mailbox offers a server-side account deletion
    /// ([`crate::store::MailboxStore::delete_account_data`], mls-ds
    /// `deleteAccountData`), that runs instead, after the publishers are
    /// retracted: it redacts across delivery services atomically, which a
    /// client loop cannot. The report then says `server_side`.
    pub fn purge_account(&mut self) -> Result<PurgeReport> {
        self.outbox.clear();
        self.owner_outbox.clear();
        let not_retracted = self.retract_publishers()?;
        match self.b.mailbox.delete_account_data() {
            Ok(()) => {
                self.meks.clear();
                self.pins.clear();
                return Ok(PurgeReport {
                    publishers_not_retracted: not_retracted,
                    server_side: true,
                    ..PurgeReport::default()
                });
            }
            Err(Error::NotSupported(_)) => {}
            Err(e) => return Err(e),
        }
        let threads = self.b.threads.list_threads()?;
        let mut report = PurgeReport {
            threads: threads.len(),
            ..PurgeReport::default()
        };
        for t in &threads {
            let mine = match self
                .b
                .threads
                .list_batches(t, Some(&self.did), TimeRange::ALL)
            {
                Ok(b) => b,
                Err(Error::Forbidden) => {
                    report.unreachable_threads.push(t.clone());
                    continue;
                }
                Err(e) => return Err(e),
            };
            let ids: BTreeSet<String> = mine
                .iter()
                .flat_map(|b| b.value.items.iter())
                .filter(|i| i.redaction.is_none())
                .map(|i| i.message_id.clone())
                .collect();
            for id in ids {
                let r = Redaction::sign(&self.did, t, &id, self.transport.as_ref());
                report.redacted += self.b.threads.redact_item(t, &id, &r)?;
            }
        }
        report.publishers_not_retracted = not_retracted;
        self.b.mailbox.purge_mailbox()?;
        self.meks.clear();
        self.pins.clear();
        Ok(report)
    }

    /// Retracts every extra publisher; returns how many cannot.
    fn retract_publishers(&self) -> Result<usize> {
        let mut not_retracted = 0;
        for p in &self.b.publishers {
            match p.retract() {
                Ok(()) => {}
                Err(Error::NotSupported(_)) => not_retracted += 1,
                Err(e) => return Err(e),
            }
        }
        Ok(not_retracted)
    }
}

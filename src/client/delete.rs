//! Deleting history ([CB-38]; see [`crate::deletion`] for the model).

use std::collections::BTreeSet;

use super::Labyrinth;
use crate::deletion::Redaction;
use crate::epoch::EpochKeys as _;
use crate::message::seal_owner_tombstone;
use crate::store::{KeyPublisher, MailboxStore, TimeRange};
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
    /// The remote half failed with this error. Local state was still
    /// cleared: the caller deletes its saved state anyway and retries the
    /// remote half later with [`delete_account_remote`], so a user can
    /// always delete their account on this device.
    pub remote_pending: Option<Error>,
}

/// The remote half of an account deletion, without any client state (a
/// retry after [`Labyrinth::purge_account`] reported
/// [`PurgeReport::remote_pending`]): retract every publisher, then the
/// server-side `deleteAccountData`. Idempotent. A mailbox without
/// `deleteAccountData` fails with [`Error::NotSupported`] (only a client
/// with state can redact item by item).
pub async fn delete_account_remote(
    mailbox: &dyn MailboxStore,
    publishers: &[&dyn KeyPublisher],
) -> Result<()> {
    for p in publishers {
        match p.retract().await {
            Ok(()) | Err(Error::NotSupported(_)) => {}
            Err(e) => return Err(e),
        }
    }
    match mailbox.delete_account_data().await {
        Ok(()) => Ok(()),
        Err(Error::NotSupported(_)) => mailbox.purge_mailbox().await,
        Err(e) => Err(e),
    }
}

impl Labyrinth {
    /// Delete for me: hide `message_id` (sent at `timestamp`) of
    /// `thread_id` on every device of this account, through an encrypted
    /// owner-mode tombstone.
    pub async fn delete_for_me(
        &mut self,
        thread_id: &str,
        message_id: &str,
        timestamp: u64,
        author: Option<&str>,
        blob_ids: &[&str],
    ) -> Result<()> {
        self.sync_epochs().await?;
        let e = self.epoch_secret(self.latest).await?;
        let t = seal_owner_tombstone(e.root(), e.seq, thread_id, message_id, timestamp, author)?;
        self.queue_owner(thread_id, t).await?;
        self.flush_owner(thread_id).await?;
        let _ = blob_ids;
        Ok(())
    }

    /// Unsend: durably publish an author-signed redaction, then remove any
    /// matching unflushed ciphertext from the local sender queue.
    pub async fn unsend(&mut self, thread_id: &str, message_id: &str) -> Result<usize> {
        let pending: Vec<_> = self
            .outbox
            .get(thread_id)
            .into_iter()
            .flatten()
            .filter(|m| m.message_id == message_id)
            .cloned()
            .collect();
        let mut redaction =
            Redaction::sign(&self.did, thread_id, message_id, self.transport.as_ref());
        redaction.redacted_at = Some(self.now());

        let stored = self
            .b
            .threads
            .redact_item(thread_id, message_id, &redaction)
            .await?;

        if !pending.is_empty()
            && let Some(q) = self.outbox.get_mut(thread_id)
        {
            q.retain(|m| m.message_id != message_id);
            if q.is_empty() {
                self.outbox_rosters.remove(thread_id);
            }
        }
        Ok(stored + pending.len())
    }

    /// Account deletion, client-orchestrated.
    pub async fn purge_account(&mut self) -> Result<PurgeReport> {
        self.outbox.clear();
        self.outbox_rosters.clear();
        self.owner_outbox.clear();
        let out = self.purge_remote().await;
        self.meks.clear();
        self.pins.clear();
        Ok(out.unwrap_or_else(|e| PurgeReport {
            remote_pending: Some(e),
            ..PurgeReport::default()
        }))
    }

    async fn purge_remote(&mut self) -> Result<PurgeReport> {
        let not_retracted = self.retract_publishers().await?;
        match self.b.mailbox.delete_account_data().await {
            Ok(()) => {
                return Ok(PurgeReport {
                    publishers_not_retracted: not_retracted,
                    server_side: true,
                    ..PurgeReport::default()
                });
            }
            Err(Error::NotSupported(_)) => {}
            Err(e) => return Err(e),
        }
        let threads = self.b.threads.list_threads().await?;
        let mut report = PurgeReport {
            threads: threads.len(),
            ..PurgeReport::default()
        };
        for t in &threads {
            let mine = match self
                .b
                .threads
                .list_batches(t, Some(&self.did), TimeRange::ALL)
                .await
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
                report.redacted += self.b.threads.redact_item(t, &id, &r).await?;
            }
        }
        report.publishers_not_retracted = not_retracted;
        self.b.mailbox.purge_mailbox().await?;
        Ok(report)
    }

    /// Retracts every extra publisher; returns how many cannot.
    async fn retract_publishers(&self) -> Result<usize> {
        let mut not_retracted = 0;
        for p in &self.b.publishers {
            match p.retract().await {
                Ok(()) => {}
                Err(Error::NotSupported(_)) => not_retracted += 1,
                Err(e) => return Err(e),
            }
        }
        Ok(not_retracted)
    }
}

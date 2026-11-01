//! Owner-mode archiving into this account's mailbox (SPEC §7.1, [CB-22],
//! [CB-37]).

use std::collections::HashSet;

use super::Labyrinth;
use super::read::{MessageSource, OpenedSealed, ThreadHistory};
use crate::epoch::EpochKeys as _;
use crate::message::{ArchivedReceipt, seal_owner, seal_owner_attributed, seal_owner_committed};
use crate::records::{BATCH_BYTE_BUDGET, BatchEntry, MAX_BATCH_ITEMS};
use crate::store::{LeaveArchiveReport, TimeRange, VouchAt};
use crate::{Error, Result};

impl Labyrinth {
    /// Archive a message into my own mailbox in owner mode (cipher version
    /// 5, [CB-37]) under my latest epoch. Buffered like sender batches.
    pub async fn archive_owner(
        &mut self,
        thread_id: &str,
        message_id: &str,
        timestamp: u64,
        frame: &[u8],
    ) -> Result<Option<super::FlushedBatch>> {
        self.sync_epochs().await?;
        self.archive_owner_synced(thread_id, message_id, timestamp, frame)
            .await
    }

    /// Archive a message into my own mailbox in owner mode (`v5`, `[CB-37]`)
    /// with authenticated `sender_did` preserved inside ciphertext (`[CB-22]`
    /// involuntary kick / outbox fallback and local history rescue).
    pub async fn archive_owner_attributed(
        &mut self,
        thread_id: &str,
        message_id: &str,
        timestamp: u64,
        sender_did: &str,
        frame: &[u8],
    ) -> Result<Option<super::FlushedBatch>> {
        self.sync_epochs().await?;
        let e = self.epoch_secret(self.latest).await?;
        let m = seal_owner_attributed(
            e.root(),
            e.seq,
            thread_id,
            message_id,
            timestamp,
            sender_did,
            frame,
        )?;
        self.queue_owner(thread_id, m).await
    }

    /// Archive an `I13` receipt-committed message into my own mailbox in owner
    /// mode (`v5`, `[CB-37]`), preserving `frame_nonce` inside ciphertext and
    /// attaching `receipt` (`[CB-22]` involuntary kick fallback).
    #[allow(clippy::too_many_arguments)]
    pub async fn archive_owner_committed(
        &mut self,
        thread_id: &str,
        message_id: &str,
        timestamp: u64,
        frame_nonce: &[u8; 32],
        frame: &[u8],
        receipt: &labyrinth_protocol::SignedSequencerReceipt,
    ) -> Result<Option<super::FlushedBatch>> {
        if receipt.payload.conversation_id != thread_id {
            return Err(Error::Malformed("receipt conversation_id mismatch"));
        }
        labyrinth_protocol::verify_archived_item_commitment(receipt, frame_nonce, frame)
            .map_err(|_| Error::ReceiptCommitmentMismatch)?;
        self.sync_epochs().await?;
        let e = self.epoch_secret(self.latest).await?;
        let archived = ArchivedReceipt::new(receipt.clone());
        let m = seal_owner_committed(
            e.root(),
            e.seq,
            thread_id,
            message_id,
            timestamp,
            frame_nonce,
            frame,
            &archived,
        )?;
        self.queue_owner(thread_id, m).await
    }

    /// Owner-mode archive after the caller has completed the epoch/revocation
    /// safety check. Kept private so public callers cannot skip it.
    async fn archive_owner_synced(
        &mut self,
        thread_id: &str,
        message_id: &str,
        timestamp: u64,
        frame: &[u8],
    ) -> Result<Option<super::FlushedBatch>> {
        let e = self.epoch_secret(self.latest).await?;
        let m = seal_owner(e.root(), e.seq, thread_id, message_id, timestamp, frame)?;
        self.queue_owner(thread_id, m).await
    }

    /// Buffers one owner record, flushing at the batch limits.
    pub(super) async fn queue_owner(
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
            flushed = self.flush_owner(thread_id).await?;
        }
        let queue = self.owner_outbox.entry(thread_id.to_owned()).or_default();
        queue.push(m);
        if queue.len() >= MAX_BATCH_ITEMS {
            flushed = self.flush_owner(thread_id).await?;
        }
        Ok(flushed)
    }

    /// [CB-22]: before leaving a conversation (and losing read access to
    /// its space), copy every message I can read that is not already in my
    /// owner archive into my mailbox. Returns how many were archived.
    pub async fn rearchive_thread_before_leave(&mut self, thread_id: &str) -> Result<usize> {
        self.rearchive_messages_before_leave_inner(thread_id).await
    }

    /// `Gate 5`: before leaving a conversation Space, flush pending writes,
    /// re-archive all readable messages (preserving `I13` committed frames
    /// and sequencer receipts) and own encrypted attachments into the
    /// personal mailbox Space, then call `clear_records` to purge this
    /// caller's repo in the conversation Space.
    pub async fn rearchive_and_clear_before_leave(
        &mut self,
        thread_id: &str,
    ) -> Result<LeaveArchiveReport> {
        self.flush_thread(thread_id).await?;
        let messages_archived = self
            .rearchive_messages_before_leave_inner(thread_id)
            .await?;

        let mut attachments_archived = 0;
        let mut rearchived_blob_cids = Vec::new();
        let own_manifests = self
            .b
            .threads
            .list_own_attachment_manifests(thread_id)
            .await?;
        for (rkey, manifest) in own_manifests {
            let (_, meta) = manifest.to_meta()?;
            let ciphertext = self
                .b
                .threads
                .get_attachment_verified(thread_id, &self.did, &rkey)
                .await?;
            let new_cid = self
                .b
                .mailbox
                .upload_and_commit_owner_attachment(&rkey, &ciphertext, &meta, &manifest.created_at)
                .await?;
            rearchived_blob_cids.push(new_cid);
            attachments_archived += 1;
        }

        self.b.threads.clear_records(thread_id).await?;

        Ok(LeaveArchiveReport {
            messages_archived,
            attachments_archived,
            rearchived_blob_cids,
        })
    }

    async fn rearchive_messages_before_leave_inner(&mut self, thread_id: &str) -> Result<usize> {
        self.sync_epochs().await?;
        if self
            .owner_outbox
            .values()
            .flatten()
            .any(|item| item.epoch_seq != self.latest)
        {
            return Err(Error::WrongEpoch);
        }

        let mut h = ThreadHistory {
            space_readable: true,
            ..ThreadHistory::default()
        };
        let batches = self.readable(
            &mut h,
            self.b
                .threads
                .list_batches(thread_id, None, TimeRange::ALL)
                .await,
        )?;
        let owner_batches = self
            .b
            .mailbox
            .list_owner_batches(thread_id, TimeRange::ALL)
            .await?;
        let mut owner = ThreadHistory::default();
        let tombstones = self
            .open_owner_batches(thread_id, owner_batches, &|_, _| true, &mut owner)
            .await?;

        let hidden = |id: &str, sender: Option<&str>| {
            tombstones
                .iter()
                .any(|(t, author)| t == id && (author.is_none() || author.as_deref() == sender))
        };

        let mut archived: HashSet<(String, Vec<u8>)> = owner
            .messages
            .into_iter()
            .filter(|m| m.source == MessageSource::Owner)
            .map(|m| (m.message_id, m.frame))
            .collect();

        let epoch = self.epoch_secret(self.latest).await?;
        let mut candidates: Vec<(u64, String, String, OpenedSealed)> = Vec::new();
        for b in batches {
            if b.value.thread_id != thread_id {
                continue;
            }
            let Ok(entries) = b.value.entries() else {
                continue;
            };
            for entry in entries {
                let BatchEntry::Sealed(s) = entry else {
                    continue;
                };
                if hidden(&s.message_id, Some(&b.author)) {
                    continue;
                }
                let at = VouchAt::of(b.order, s.timestamp);
                if let Ok(opened) = self.open_sealed_inner(thread_id, &b.author, &s, at).await {
                    candidates.push((s.timestamp, s.message_id, b.author.clone(), opened));
                }
            }
        }
        candidates.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));

        let mut n = 0;
        for (timestamp, message_id, author, opened) in candidates {
            match opened {
                OpenedSealed::Plain(frame) => {
                    let key = (message_id, frame);
                    if archived.contains(&key) {
                        continue;
                    }
                    let m = if author.starts_with("did:") {
                        seal_owner_attributed(
                            epoch.root(),
                            epoch.seq,
                            thread_id,
                            &key.0,
                            timestamp,
                            &author,
                            &key.1,
                        )?
                    } else {
                        seal_owner(
                            epoch.root(),
                            epoch.seq,
                            thread_id,
                            &key.0,
                            timestamp,
                            &key.1,
                        )?
                    };
                    self.queue_owner(thread_id, m).await?;
                    archived.insert(key);
                    n += 1;
                }
                OpenedSealed::Committed {
                    frame_nonce,
                    frame,
                    receipt,
                } => {
                    let key = (message_id, frame);
                    if archived.contains(&key) {
                        continue;
                    }
                    let m = seal_owner_committed(
                        epoch.root(),
                        epoch.seq,
                        thread_id,
                        &key.0,
                        timestamp,
                        &frame_nonce,
                        &key.1,
                        &receipt,
                    )?;
                    self.queue_owner(thread_id, m).await?;
                    archived.insert(key);
                    n += 1;
                }
            }
        }
        self.flush_owner(thread_id).await?;
        Ok(n)
    }
}

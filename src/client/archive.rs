//! Owner-mode archiving into this account's mailbox (SPEC §7.1, [CB-22],
//! [CB-37]).

use std::collections::{BTreeMap, HashSet};

use super::Labyrinth;
use super::read::{ThreadHistory, finish};
use crate::epoch::EpochKeys as _;
use crate::message::{
    ArchivedReceipt, seal_owner, seal_owner_attributed, seal_owner_committed, seal_owner_tombstone,
};
use crate::records::{BATCH_BYTE_BUDGET, MAX_BATCH_ITEMS};
use crate::store::{LeaveArchiveReport, TimeRange};
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
        if self.receipt_required(thread_id).await? {
            return Err(Error::ReceiptCommitmentMismatch);
        }
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
        if self.receipt_required(thread_id).await? {
            return Err(Error::ReceiptCommitmentMismatch);
        }
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
        receipt: &ArchivedReceipt,
    ) -> Result<Option<super::FlushedBatch>> {
        if receipt.signed.payload.conversation_id != thread_id {
            return Err(Error::Malformed("receipt conversation_id mismatch"));
        }
        let (sender_did, sender_device_id) = receipt
            .signed
            .payload
            .split_sender_device()
            .map_err(|_| Error::Malformed("invalid senderDevice in receipt"))?;
        if receipt.original_sender_attestation.sender_did != sender_did
            || receipt.original_sender_attestation.sender_device_id != sender_device_id
        {
            return Err(Error::BadSignature);
        }
        receipt.original_sender_attestation.verify(
            thread_id,
            message_id,
            &receipt.signed.payload.archive_commitment,
        )?;
        labyrinth_protocol::verify_archived_item_commitment(&receipt.signed, frame_nonce, frame)
            .map_err(|_| Error::ReceiptCommitmentMismatch)?;
        self.verify_and_remember_receipt(thread_id, &receipt.signed)
            .await?;
        self.sync_epochs().await?;
        let e = self.epoch_secret(self.latest).await?;
        let m = seal_owner_committed(
            e.root(),
            e.seq,
            thread_id,
            message_id,
            timestamp,
            frame_nonce,
            frame,
            receipt,
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
    /// personal mailbox Space. Nothing in the conversation Space is deleted:
    /// my batches, MEKs and attachment manifests may be the only copy the
    /// remaining members can restore from (a witness flush may never have
    /// run).
    pub async fn rearchive_before_leave(&mut self, thread_id: &str) -> Result<LeaveArchiveReport> {
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

        // The same acceptance as reading: redactions, tombstones and ruling 3
        // decide what survives; only those copies are re-archived.
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
        let receipts_required = self.receipt_required(thread_id).await?
            || batches.iter().any(|batch| {
                batch
                    .value
                    .items
                    .iter()
                    .any(|item| item.sequencer_receipt.is_some())
            })
            || owner_batches.iter().any(|batch| {
                batch
                    .value
                    .items
                    .iter()
                    .any(|item| item.sequencer_receipt.is_some())
            });
        self.open_batches(
            thread_id,
            batches,
            &|_, _| true,
            &mut h,
            false,
            receipts_required,
        )
        .await?;
        let mut owner = ThreadHistory::default();
        let tombstones = self
            .open_owner_batches(
                thread_id,
                owner_batches,
                &|_, _| true,
                &mut owner,
                receipts_required,
            )
            .await?;
        // A verified author redaction in the Space hides my earlier owner
        // copies only while I can read the Space. After leaving, only my
        // mailbox remains, so those copies need their own tombstones.
        let mut unsent: BTreeMap<(String, String), u64> = BTreeMap::new();
        for m in &owner.messages {
            let Some(sender) = m.sender.as_deref() else {
                continue;
            };
            let redacted = h
                .redacted
                .iter()
                .any(|r| r.message_id == m.message_id && r.sender == sender);
            let tombstoned = tombstones.iter().any(|(id, author)| {
                *id == m.message_id && author.as_deref().is_none_or(|a| a == sender)
            });
            if redacted && !tombstoned {
                unsent
                    .entry((m.message_id.clone(), sender.to_owned()))
                    .or_insert(m.timestamp);
            }
        }
        let mut archived: HashSet<(String, Vec<u8>)> = owner
            .messages
            .iter()
            .map(|m| (m.message_id.clone(), m.frame.clone()))
            .collect();
        h.messages.append(&mut owner.messages);
        finish(&mut h, &tombstones);

        let epoch = self.epoch_secret(self.latest).await?;
        for ((message_id, sender), timestamp) in &unsent {
            let tombstone = seal_owner_tombstone(
                epoch.root(),
                epoch.seq,
                thread_id,
                message_id,
                *timestamp,
                Some(sender),
            )?;
            self.queue_owner(thread_id, tombstone).await?;
        }
        let mut n = 0;
        for m in h.messages {
            let key = (m.message_id, m.frame);
            if archived.contains(&key) {
                continue;
            }
            let sealed = match (&m.archived_receipt, &m.frame_nonce, m.sender.as_deref()) {
                (Some(receipt), Some(frame_nonce), _) => seal_owner_committed(
                    epoch.root(),
                    epoch.seq,
                    thread_id,
                    &key.0,
                    m.timestamp,
                    frame_nonce,
                    &key.1,
                    receipt,
                )?,
                (_, _, Some(author)) if author.starts_with("did:") => seal_owner_attributed(
                    epoch.root(),
                    epoch.seq,
                    thread_id,
                    &key.0,
                    m.timestamp,
                    author,
                    &key.1,
                )?,
                _ => seal_owner(
                    epoch.root(),
                    epoch.seq,
                    thread_id,
                    &key.0,
                    m.timestamp,
                    &key.1,
                )?,
            };
            self.queue_owner(thread_id, sealed).await?;
            archived.insert(key);
            n += 1;
        }
        self.flush_owner(thread_id).await?;
        Ok(n)
    }
}

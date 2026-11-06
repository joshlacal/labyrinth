//! Reader path: loading a thread's history, and owner-mode archiving
//! (SPEC §7.1, §7.4, [CB-22]).

use std::collections::{HashMap, HashSet};

use super::Labyrinth;
use crate::deletion::StoredRedaction;
use crate::epoch::EpochKeys as _;
use crate::mek::{self, Mek, MekSender};
use crate::message::{
    ArchivedReceipt, OwnerContent, SealedMessage, open_owner_content, open_sender,
    open_sender_committed, verify_sender_device,
};
use crate::records::{Batch, BatchEntry, MekDistribution, OwnerBatch};
use crate::store::{ServerOrder, Stored, TimeRange, VouchAt, keys_valid_for};
use crate::{Error, Result};

/// Where a loaded message came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageSource {
    /// The author's own sender `batch` in the conversation space (v1.1).
    Sender,
    /// A witness copy: another member's receipt-committed message, archived
    /// in the conversation space by a member that received it. Attributed to
    /// the receipt's sender, never to the witness.
    Witness,
    /// An `ownerBatch` in this account's mailbox (v1.0 / re-archive).
    Owner,
}

/// One decrypted message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedMessage {
    pub thread_id: String,
    pub message_id: String,
    pub timestamp: u64,
    /// Sender DID: the batch author, or the receipt's sender for a witness
    /// copy. Unattributed legacy owner records carry none.
    pub sender: Option<String>,
    pub frame: Vec<u8>,
    /// Sequencer receipt whose signature and frame commitment were verified.
    /// Absent for uncommitted legacy frames.
    pub archived_receipt: Option<ArchivedReceipt>,
    /// Blinding nonce authenticated together with `archived_receipt`.
    pub frame_nonce: Option<[u8; 32]>,
    pub source: MessageSource,
    /// True when another, different sender or owner copy with the same
    /// `message_id` was also loaded (from another author, or a differing
    /// owner copy). Both copies are returned; the caller decides which one
    /// MLS vouches for. A witness copy never sets it: one that contradicts
    /// an accepted copy is in [`ThreadHistory::rejected`] instead.
    pub conflict: bool,
}

/// A verified witness copy that was not accepted (ruling 3). The original
/// sender attestation authenticates its message id, but a conflicting copy
/// still never replaces, flags or re-attributes an accepted copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedCopy {
    pub message_id: String,
    pub timestamp: u64,
    /// The receipt's sender the copy names.
    pub sender: Option<String>,
    pub reason: Rejection,
}

/// Why a witness copy was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// An accepted copy with its message id has another frame, nonce,
    /// receipt or sender.
    Contradicts,
    /// An accepted copy with another message id holds its sequencer receipt.
    ReceiptReused,
}

/// A message this device could see but not open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Undecryptable {
    pub message_id: String,
    pub timestamp: u64,
    pub sender: Option<String>,
    /// [`Error::NotRecipient`] when the MEK was never addressed to this
    /// account (e.g. sent before it joined or after it left).
    pub error: Error,
}

/// A redacted message ([CB-38]): render it as removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedMessage {
    pub message_id: String,
    pub timestamp: u64,
    pub sender: String,
    /// The redaction is signed by one of the author's chat devices:
    /// "unsent".
    pub by_author: bool,
    /// The conversation's sequencer DS redacted it because the author's
    /// account was deleted, and its signature verifies under the
    /// sequencer's key ([`crate::store::MailboxDirectory::sequencer_key`]):
    /// "deleted (account removed)".
    pub account_deleted: bool,
    /// Neither of the above: the server removed it, and nothing proves
    /// why: "removed by server". Exactly one of the three flags is set.
    pub removed_by_server: bool,
}

/// Result of [`Labyrinth::load_thread`], ordered by `(timestamp, messageId)`.
#[derive(Clone, Debug, Default)]
pub struct ThreadHistory {
    pub messages: Vec<LoadedMessage>,
    pub undecryptable: Vec<Undecryptable>,
    /// Items unsent by their author ([CB-38]).
    pub redacted: Vec<RedactedMessage>,
    /// Message ids hidden by this account's delete-for-me tombstones
    /// ([CB-38]).
    pub deleted_for_me: Vec<String>,
    /// Witness copies that contradict an accepted copy (ruling 3).
    pub rejected: Vec<RejectedCopy>,
    /// False if the conversation space refused reads ([`Error::Forbidden`]);
    /// only owner-archived messages are then included.
    pub space_readable: bool,
}

/// A delete-for-me tombstone: `(messageId, only copies from this author)`.
pub(super) type Tombstone = (String, Option<String>);

/// Selects items by `(messageId, timestamp)` before any decryption.
pub(super) type Keep<'a> = &'a (dyn Fn(&str, u64) -> bool + Sync);

#[allow(clippy::large_enum_variant)]
pub(super) enum OpenedSealed {
    Plain(Vec<u8>),
    Committed {
        frame_nonce: [u8; 32],
        frame: Vec<u8>,
        receipt: ArchivedReceipt,
        /// The receipt's sender DID: the batch author, or the original
        /// sender of a witness copy.
        sender: String,
    },
}

impl Labyrinth {
    /// Read only this account's authenticated owner archive, without consulting
    /// a conversation Space that may no longer exist or admit this account.
    pub async fn load_owner_thread(&mut self, thread_id: &str) -> Result<ThreadHistory> {
        let batches = self
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
            });
        let mut history = ThreadHistory::default();
        let tombstones = self
            .open_owner_batches(
                thread_id,
                batches,
                &|_, _| true,
                &mut history,
                receipts_required,
            )
            .await?;
        finish(&mut history, &tombstones);
        Ok(history)
    }

    /// Open an explicitly supplied owner record with the same checks as history.
    pub async fn open_owner_record(&mut self, batch: OwnerBatch) -> Result<ThreadHistory> {
        let thread_id = batch.thread_id.clone();
        let stored = Stored {
            author: self.did.clone(),
            rkey: String::new(),
            order: None,
            value: batch,
        };
        let receipts_required = self.receipt_required(&thread_id).await?
            || stored
                .value
                .items
                .iter()
                .any(|item| item.sequencer_receipt.is_some());
        let mut history = ThreadHistory::default();
        let tombstones = self
            .open_owner_batches(
                &thread_id,
                vec![stored],
                &|_, _| true,
                &mut history,
                receipts_required,
            )
            .await?;
        finish(&mut history, &tombstones);
        Ok(history)
    }

    /// Load and decrypt every message of `thread_id` in `range`.
    ///
    /// Redactions and owner tombstones are reconciled over the complete thread
    /// before the display range is applied. Otherwise an older unsend/delete
    /// can be omitted while a newer witness copy is returned.
    pub async fn load_thread(
        &mut self,
        thread_id: &str,
        range: TimeRange,
    ) -> Result<ThreadHistory> {
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
        let owner = self
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
            || owner.iter().any(|batch| {
                batch
                    .value
                    .items
                    .iter()
                    .any(|item| item.sequencer_receipt.is_some())
            });
        let keep = |_: &str, ts: u64| range.contains(ts);
        self.open_batches(thread_id, batches, &keep, &mut h, true, receipts_required)
            .await?;
        let tombstones = self
            .open_owner_batches(thread_id, owner, &keep, &mut h, receipts_required)
            .await?;
        // An admitted Space is authoritative for message copies. Owner records
        // still contribute account-private tombstones, but must not reserve a
        // message id or sequencer receipt ahead of sender/witness copies.
        if h.space_readable {
            h.messages.retain(|m| m.source != MessageSource::Owner);
        }
        finish(&mut h, &tombstones);
        Ok(h)
    }

    /// A sender-batch listing; `Forbidden` (removed from a Space) degrades
    /// to the owner archive and clears `h.space_readable`.
    pub(super) fn readable(
        &self,
        h: &mut ThreadHistory,
        r: Result<Vec<Stored<Batch>>>,
    ) -> Result<Vec<Stored<Batch>>> {
        match r {
            Ok(b) => Ok(b),
            Err(Error::Forbidden) => {
                h.space_readable = false;
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// Opens every item of `batches` that `keep(messageId, timestamp)`
    /// selects into `h`, in server admission order, so witness copies reach
    /// [`finish`] earliest-admitted first. An unverifiable redaction fails
    /// the read with [`Error::BadSignature`] when `strict`; otherwise it is
    /// skipped.
    pub(super) async fn open_batches(
        &mut self,
        thread_id: &str,
        mut batches: Vec<Stored<Batch>>,
        keep: Keep<'_>,
        h: &mut ThreadHistory,
        strict: bool,
        receipts_required: bool,
    ) -> Result<()> {
        batches.sort_by_key(|b| b.order.map(|o| o.labyrinth_seq));
        let mut roster_membership = HashMap::new();
        for b in batches {
            if receipts_required {
                let is_member = if let Some(is_member) = roster_membership.get(&b.author) {
                    *is_member
                } else {
                    let leaves = self
                        .b
                        .directory
                        .member_device_keys(thread_id, &b.author)
                        .await?
                        .ok_or(Error::DirectoryIncomplete {
                            pds_present: true,
                            ds_present: false,
                        })?;
                    let is_member = !leaves.is_empty();
                    roster_membership.insert(b.author.clone(), is_member);
                    is_member
                };
                if !is_member {
                    continue;
                }
            }
            let author = Some(b.author.clone());
            let items = if b.value.thread_id == thread_id {
                b.value.entries()
            } else {
                Err(Error::Malformed("batch filed under another thread"))
            };
            let items = match items {
                Ok(items) => items,
                Err(error) => {
                    h.undecryptable.push(Undecryptable {
                        message_id: format!("batch:{}", b.rkey),
                        timestamp: 0,
                        sender: author,
                        error,
                    });
                    continue;
                }
            };
            for (entry, raw) in items.into_iter().zip(&b.value.items) {
                if matches!(&entry, BatchEntry::Sealed(s) if !keep(&s.message_id, s.timestamp)) {
                    continue;
                }
                let s = match entry {
                    BatchEntry::Sealed(s) => s,
                    BatchEntry::Redacted {
                        message_id,
                        timestamp,
                        redaction,
                    } => {
                        let receipt_sender = raw.sequencer_receipt.as_ref().map(|r| &*r.sender_did);
                        match self
                            .verify_redaction(
                                thread_id,
                                &b.author,
                                receipt_sender,
                                &message_id,
                                &redaction,
                            )
                            .await
                        {
                            Some((sender, by_author, account_deleted)) => {
                                h.redacted.push(RedactedMessage {
                                    message_id,
                                    timestamp,
                                    sender,
                                    by_author,
                                    account_deleted,
                                    removed_by_server: false,
                                })
                            }
                            None if strict => return Err(Error::BadSignature),
                            None => {}
                        }
                        continue;
                    }
                };
                let at = VouchAt::of(b.order, s.timestamp);
                match self
                    .open_sealed_inner(thread_id, &b.author, &s, at, receipts_required)
                    .await
                {
                    Ok(opened) => {
                        let (frame, archived_receipt, frame_nonce, sender) = match opened {
                            OpenedSealed::Plain(frame) => (frame, None, None, b.author.clone()),
                            OpenedSealed::Committed {
                                frame,
                                receipt,
                                frame_nonce,
                                sender,
                            } => (frame, Some(receipt), Some(frame_nonce), sender),
                        };
                        let source = if sender == b.author {
                            MessageSource::Sender
                        } else {
                            MessageSource::Witness
                        };
                        h.messages.push(LoadedMessage {
                            thread_id: thread_id.to_owned(),
                            message_id: s.message_id.clone(),
                            timestamp: s.timestamp,
                            sender: Some(sender),
                            frame,
                            archived_receipt,
                            frame_nonce,
                            source,
                            conflict: false,
                        });
                    }
                    Err(error) => h.undecryptable.push(Undecryptable {
                        message_id: s.message_id.clone(),
                        timestamp: s.timestamp,
                        sender: author.clone(),
                        error,
                    }),
                }
            }
        }
        Ok(())
    }

    /// The attributed sender and `(by_author, account_deleted)` of a
    /// verified redaction of `message_id` on `author`'s item ([CB-38]);
    /// `None` otherwise. A witness copy of a deleted account's message
    /// (`receipt_sender` ≠ `author`) carries the sequencer's
    /// account-deletion redaction for the receipt's sender.
    async fn verify_redaction(
        &self,
        thread_id: &str,
        author: &str,
        receipt_sender: Option<&str>,
        message_id: &str,
        redaction: &StoredRedaction,
    ) -> Option<(String, bool, bool)> {
        match redaction {
            StoredRedaction::Author(r)
                if self
                    .redaction_by_author(thread_id, author, message_id, r)
                    .await =>
            {
                Some((author.to_owned(), true, false))
            }
            StoredRedaction::Server(r) => {
                for sender in
                    core::iter::once(author).chain(receipt_sender.filter(|s| *s != author))
                {
                    if self
                        .redaction_by_sequencer(thread_id, sender, message_id, r)
                        .await
                    {
                        return Some((sender.to_owned(), false, true));
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// [CB-38]: the redaction is signed by a chat device of `author` that
    /// was valid when the server applied it (now, without a stamp).
    async fn redaction_by_author(
        &self,
        thread_id: &str,
        author: &str,
        message_id: &str,
        r: &crate::deletion::Redaction,
    ) -> bool {
        let at = r
            .redacted_at
            .as_deref()
            .and_then(|t| crate::records::ms_from_datetime(t).ok())
            .map_or(VouchAt::Current, VouchAt::SenderClaim);
        r.verify(author, thread_id, message_id).is_ok()
            && self
                .transport_keys(author, None, at)
                .await
                .is_ok_and(|k| k.contains(&r.transport_public_key))
    }

    /// [CB-38]: an account-deletion redaction signed by the DS that
    /// sequences `thread_id`, under the key the directory reports for it.
    async fn redaction_by_sequencer(
        &self,
        thread_id: &str,
        author: &str,
        message_id: &str,
        r: &crate::deletion::ServerRedaction,
    ) -> bool {
        match self.b.directory.sequencer_key(thread_id).await {
            Ok(Some(k)) => {
                k.did == r.by
                    && r.verify_account_deletion(author, thread_id, message_id, &k.key)
                        .is_ok()
            }
            _ => false,
        }
    }

    /// Opens my owner batches into `h`; returns the delete-for-me
    /// tombstones among them.
    pub(super) async fn open_owner_batches(
        &mut self,
        thread_id: &str,
        batches: Vec<Stored<OwnerBatch>>,
        keep: Keep<'_>,
        h: &mut ThreadHistory,
        receipts_required: bool,
    ) -> Result<Vec<Tombstone>> {
        let mut tombstones = Vec::new();
        for b in batches {
            for m in b.value.to_messages()? {
                if m.thread_id != thread_id {
                    continue;
                }
                let selected = keep(&m.message_id, m.timestamp);
                let opened = match self.epoch_secret(m.epoch_seq).await {
                    Ok(e) => open_owner_content(e.root(), &m),
                    Err(err) => Err(err),
                };
                match opened {
                    Ok(OwnerContent::Frame(frame)) if selected => {
                        if m.sequencer_receipt.is_some() || receipts_required {
                            h.undecryptable.push(Undecryptable {
                                message_id: m.message_id,
                                timestamp: m.timestamp,
                                sender: None,
                                error: Error::ReceiptCommitmentMismatch,
                            });
                        } else {
                            h.messages.push(LoadedMessage {
                                thread_id: thread_id.to_owned(),
                                message_id: m.message_id,
                                timestamp: m.timestamp,
                                sender: None,
                                frame,
                                archived_receipt: None,
                                frame_nonce: None,
                                source: MessageSource::Owner,
                                conflict: false,
                            });
                        }
                    }
                    Ok(OwnerContent::AttributedFrame { sender_did, frame }) if selected => {
                        if m.sequencer_receipt.is_some() || receipts_required {
                            h.undecryptable.push(Undecryptable {
                                message_id: m.message_id,
                                timestamp: m.timestamp,
                                sender: Some(sender_did),
                                error: Error::ReceiptCommitmentMismatch,
                            });
                        } else {
                            h.messages.push(LoadedMessage {
                                thread_id: thread_id.to_owned(),
                                message_id: m.message_id,
                                timestamp: m.timestamp,
                                sender: Some(sender_did),
                                frame,
                                archived_receipt: None,
                                frame_nonce: None,
                                source: MessageSource::Owner,
                                conflict: false,
                            });
                        }
                    }
                    Ok(OwnerContent::CommittedFrame { frame_nonce, frame }) if selected => {
                        let verified = async {
                            let archived = m
                                .sequencer_receipt
                                .as_ref()
                                .ok_or(Error::ReceiptCommitmentMismatch)?;
                            self.verify_and_remember_receipt(thread_id, &archived.signed)
                                .await?;
                            labyrinth_protocol::verify_archived_item_commitment(
                                &archived.signed,
                                &frame_nonce,
                                &frame,
                            )
                            .map_err(|_| Error::ReceiptCommitmentMismatch)?;
                            self.verify_original_sender_attestation(
                                thread_id,
                                &m.message_id,
                                archived,
                            )
                            .await
                        }
                        .await;
                        match verified {
                            Ok(sender_did) => h.messages.push(LoadedMessage {
                                thread_id: thread_id.to_owned(),
                                message_id: m.message_id,
                                timestamp: m.timestamp,
                                sender: Some(sender_did),
                                frame,
                                archived_receipt: m.sequencer_receipt,
                                frame_nonce: Some(frame_nonce),
                                source: MessageSource::Owner,
                                conflict: false,
                            }),
                            Err(error) => h.undecryptable.push(Undecryptable {
                                message_id: m.message_id,
                                timestamp: m.timestamp,
                                sender: None,
                                error,
                            }),
                        }
                    }
                    Ok(OwnerContent::Tombstone { author }) => {
                        tombstones.push((m.message_id, author));
                    }
                    Ok(_) => {}
                    Err(error) if selected => h.undecryptable.push(Undecryptable {
                        message_id: m.message_id,
                        timestamp: m.timestamp,
                        sender: None,
                        error,
                    }),
                    Err(_) => {}
                }
            }
        }
        Ok(tombstones)
    }

    /// SPEC §7.4 + Gate 1 (`I13`): verifies sequencer receipt + blinded
    /// `archiveCommitment` when present (or required by `sequencer_receipt_key`),
    /// checks sender chat device validity, opens the MEK, and decrypts.
    ///
    /// A receipt naming another sender is a witness copy: `author` received
    /// that member's message and archived it. Every check is unchanged (the
    /// sealing key must still be one of `author`'s chat devices at the
    /// receipt's order); the result names the receipt's sender.
    pub(super) async fn open_sealed_inner(
        &mut self,
        thread_id: &str,
        author: &str,
        s: &SealedMessage,
        at: VouchAt,
        receipts_required: bool,
    ) -> Result<OpenedSealed> {
        if let Some(archived) = &s.sequencer_receipt {
            self.verify_and_remember_receipt(thread_id, &archived.signed)
                .await?;
            let sender = archived.original_sender_attestation.sender_did.clone();

            let issued_ms = u64::try_from(archived.signed.payload.issued_at_ms)
                .map_err(|_| Error::Malformed("negative receipt issuedAtMs"))?;
            let leaves = self
                .b
                .directory
                .member_device_keys(thread_id, author)
                .await?
                .ok_or(Error::DirectoryIncomplete {
                    pds_present: true,
                    ds_present: false,
                })?;
            let receipt_at = VouchAt::Server(ServerOrder {
                labyrinth_seq: archived.signed.payload.seq,
                chat_seq: Some(archived.signed.payload.seq),
                received_at_ms: issued_ms,
            });
            let author_keys = self.b.directory.device_transport_keys(author).await?;
            verify_sender_device(s, &keys_valid_for(&author_keys, Some(&leaves), receipt_at))?;
            let mek = self.mek_for(thread_id, &s.mek_id, issued_ms).await?;
            let (frame_nonce, frame) = open_sender_committed(s, thread_id, &mek)?;
            labyrinth_protocol::verify_archived_item_commitment(
                &archived.signed,
                &frame_nonce,
                &frame,
            )
            .map_err(|_| Error::ReceiptCommitmentMismatch)?;
            let verified_sender = self
                .verify_original_sender_attestation(thread_id, &s.message_id, archived)
                .await?;
            if verified_sender != sender {
                return Err(Error::BadSignature);
            }
            return Ok(OpenedSealed::Committed {
                frame_nonce,
                frame,
                receipt: archived.clone(),
                sender,
            });
        }

        if receipts_required {
            return Err(Error::ReceiptCommitmentMismatch);
        }

        verify_sender_device(s, &self.transport_keys(author, Some(thread_id), at).await?)?;
        let mek = self.mek_for(thread_id, &s.mek_id, s.timestamp).await?;
        open_sender(s, thread_id, &mek).map(OpenedSealed::Plain)
    }

    async fn verify_original_sender_attestation(
        &self,
        thread_id: &str,
        message_id: &str,
        archived: &ArchivedReceipt,
    ) -> Result<String> {
        let (sender_did, sender_device_id) = archived
            .signed
            .payload
            .split_sender_device()
            .map_err(|_| Error::Malformed("invalid senderDevice in receipt"))?;
        let attestation = &archived.original_sender_attestation;
        if attestation.sender_did != sender_did || attestation.sender_device_id != sender_device_id
        {
            return Err(Error::BadSignature);
        }
        attestation.verify(
            thread_id,
            message_id,
            &archived.signed.payload.archive_commitment,
        )?;

        let leaves = self
            .b
            .directory
            .member_device_keys(thread_id, sender_did)
            .await?
            .ok_or(Error::DirectoryIncomplete {
                pds_present: true,
                ds_present: false,
            })?;
        let issued_ms = u64::try_from(archived.signed.payload.issued_at_ms)
            .map_err(|_| Error::Malformed("negative receipt issuedAtMs"))?;
        let at = VouchAt::Server(ServerOrder {
            labyrinth_seq: archived.signed.payload.seq,
            chat_seq: Some(archived.signed.payload.seq),
            received_at_ms: issued_ms,
        });
        let account_keys = self.b.directory.device_transport_keys(sender_did).await?;
        if !keys_valid_for(&account_keys, Some(&leaves), at)
            .contains(&attestation.sender_transport_public_key)
        {
            return Err(Error::BadSignature);
        }
        Ok(sender_did.to_owned())
    }

    async fn mek_for(&mut self, thread_id: &str, mek_id: &[u8; 12], claim_ms: u64) -> Result<Mek> {
        if let Some(m) = self
            .meks
            .get(thread_id)
            .and_then(|v| v.iter().find(|m| m.id() == mek_id))
        {
            return Ok(m.clone());
        }
        let mut err = Error::NotFound("mek");
        for c in self.b.threads.find_meks(thread_id, mek_id).await? {
            let at = VouchAt::of(c.order, claim_ms);
            match self.open_mek_record(thread_id, &c, at).await {
                Ok(m) => {
                    self.meks
                        .entry(thread_id.to_owned())
                        .or_default()
                        .push(m.clone());
                    self.checkpoint_state()?;
                    return Ok(m);
                }
                Err(e) => err = e,
            }
        }
        Err(err)
    }

    async fn open_mek_record(
        &mut self,
        thread_id: &str,
        c: &Stored<MekDistribution>,
        at: VouchAt,
    ) -> Result<Mek> {
        let (rec, sender_epoch) = c.value.to_record()?;
        if rec.thread_id != thread_id {
            return Err(Error::Malformed("MEK filed under another thread"));
        }
        match (&rec.sender, &sender_epoch) {
            (MekSender::Labyrinth { did, .. }, Some(epoch)) => {
                if *did != c.author {
                    return Err(Error::Malformed("MEK sender is not the record author"));
                }
                self.check_attested(did, epoch, at).await?;
            }
            (MekSender::Transport { transport_pub, .. }, _) => {
                if !self
                    .transport_keys(&c.author, Some(thread_id), at)
                    .await?
                    .contains(transport_pub)
                {
                    return Err(Error::Unattested);
                }
            }
            (MekSender::Labyrinth { .. }, None) => return Err(Error::NotFound("sender epoch")),
        }
        let head = rec
            .recipients
            .iter()
            .find(|r| r.did == self.did)
            .ok_or(Error::NotRecipient)?
            .recipient_epoch_head;
        let seq = self.seq_for_head(&head).await?;
        let (_, keys) = self.my_keys(seq).await?;
        let my_public = self.epoch_record(seq).await?.1.public;
        mek::open(&rec, &self.did, &my_public, &keys, sender_epoch.as_ref())
    }

    async fn seq_for_head(&mut self, head: &[u8; 32]) -> Result<u64> {
        if let Some(s) = self.heads.get(head) {
            return Ok(*s);
        }
        for e in self.b.mailbox.list_epochs().await? {
            let h = e.value.public.epoch_head.array::<32>("epochHead length")?;
            self.heads.insert(h, e.value.seq());
        }
        self.heads.get(head).copied().ok_or(Error::WrongEpoch)
    }
}

/// Applies redactions and delete-for-me tombstones, merges copies and sorts.
pub(super) fn finish(h: &mut ThreadHistory, tombstones: &[Tombstone]) {
    // A verified unsend or account-deletion redaction ([CB-38]) replaces the
    // author's own item. Wherever it is stored, it also hides every other
    // copy attributed to that author: witness copies and owner copies.
    h.redacted.sort_by(|a, b| {
        (&a.message_id, &a.sender, !a.by_author, a.timestamp).cmp(&(
            &b.message_id,
            &b.sender,
            !b.by_author,
            b.timestamp,
        ))
    });
    h.redacted
        .dedup_by(|later, kept| later.message_id == kept.message_id && later.sender == kept.sender);
    let gone: HashSet<(&str, &str)> = h
        .redacted
        .iter()
        .map(|r| (r.message_id.as_str(), r.sender.as_str()))
        .collect();
    h.messages.retain(|m| {
        !m.sender
            .as_deref()
            .is_some_and(|s| gone.contains(&(m.message_id.as_str(), s)))
    });
    let hidden = |id: &str, sender: Option<&String>| {
        tombstones.iter().any(|(t, author)| {
            t == id && (sender.is_none() || author.is_none() || author.as_ref() == sender)
        })
    };
    let mut deleted: Vec<String> = Vec::new();
    h.messages.retain(|m| {
        let hide = hidden(&m.message_id, m.sender.as_ref());
        if hide {
            deleted.push(m.message_id.clone());
        }
        !hide
    });
    h.undecryptable
        .retain(|u| !hidden(&u.message_id, u.sender.as_ref()));
    h.redacted
        .retain(|r| !hidden(&r.message_id, Some(&r.sender)));
    deleted.sort();
    deleted.dedup();
    h.deleted_for_me = deleted;
    dedupe(h);
    h.messages
        .sort_by(|a, b| (a.timestamp, &a.message_id).cmp(&(b.timestamp, &b.message_id)));
    h.undecryptable
        .sort_by(|a, b| (a.timestamp, &a.message_id).cmp(&(b.timestamp, &b.message_id)));
    h.redacted
        .sort_by(|a, b| (a.timestamp, &a.message_id).cmp(&(b.timestamp, &b.message_id)));
    h.rejected
        .sort_by(|a, b| (a.timestamp, &a.message_id).cmp(&(b.timestamp, &b.message_id)));
}

fn committed(m: &LoadedMessage) -> bool {
    m.archived_receipt.is_some() || m.frame_nonce.is_some()
}

/// Copies of one message id that are provably the same message: equal
/// frames, no differing sender, and equal receipts and nonces when both are
/// committed.
fn same(k: &LoadedMessage, m: &LoadedMessage) -> bool {
    k.frame == m.frame
        && (k.sender.is_none() || m.sender.is_none() || k.sender == m.sender)
        && (!committed(k)
            || !committed(m)
            || (k.archived_receipt == m.archived_receipt && k.frame_nonce == m.frame_nonce))
}

/// The sequenced entry a committed copy's receipt names.
fn receipt_entry(m: &LoadedMessage) -> Option<(String, String)> {
    m.archived_receipt.as_ref().map(|r| {
        (
            r.signed.payload.sequencer_did.clone(),
            r.signed.payload.entry_id.clone(),
        )
    })
}

/// Accept, merge and flag copies (see [`Labyrinth::load_thread`]).
///
/// Sender and owner copies are accepted as they are. Neither a receipt nor a
/// frame authenticates the message id a witness files a copy under (the
/// sequencer's `entryId` is its own), so a witness copy is a third party's
/// claim: in admission order it is accepted only if it equals an accepted
/// copy with its message id, or if it is the first claim on both that id and
/// its receipt's entry. Otherwise it is rejected (ruling 3). Accepted copies
/// then merge: the author's own sender copy is kept first, then the earliest
/// witness copy, then attributed owner copies, then unattributed legacy
/// owner copies. Differing sender or owner copies of one id are flagged.
fn dedupe(h: &mut ThreadHistory) {
    let (witnesses, mut accepted): (Vec<_>, Vec<_>) = core::mem::take(&mut h.messages)
        .into_iter()
        .partition(|m| m.source == MessageSource::Witness);
    let mut ids: HashMap<String, Vec<usize>> = HashMap::new();
    let mut entries: HashSet<(String, String)> = HashSet::new();
    for (i, k) in accepted.iter().enumerate() {
        ids.entry(k.message_id.clone()).or_default().push(i);
        entries.extend(receipt_entry(k));
    }
    for w in witnesses {
        let reason = match ids.get(&w.message_id) {
            Some(ix) if ix.iter().any(|&i| same(&accepted[i], &w)) => None,
            Some(_) => Some(Rejection::Contradicts),
            None if receipt_entry(&w).is_some_and(|e| entries.contains(&e)) => {
                Some(Rejection::ReceiptReused)
            }
            None => None,
        };
        if let Some(reason) = reason {
            h.rejected.push(RejectedCopy {
                message_id: w.message_id,
                timestamp: w.timestamp,
                sender: w.sender,
                reason,
            });
            continue;
        }
        ids.entry(w.message_id.clone())
            .or_default()
            .push(accepted.len());
        entries.extend(receipt_entry(&w));
        accepted.push(w);
    }
    accepted.sort_by_key(|m| match m.source {
        MessageSource::Sender => (0, false, 0),
        MessageSource::Witness => (1, false, m.timestamp),
        MessageSource::Owner => (2, m.sender.is_none(), 0),
    });
    let mut by_id: HashMap<String, Vec<usize>> = HashMap::new();
    for m in accepted {
        let same_ix = by_id
            .get(&m.message_id)
            .and_then(|ix| ix.iter().copied().find(|&i| same(&h.messages[i], &m)));
        if let Some(i) = same_ix {
            if !committed(&h.messages[i]) {
                h.messages[i].archived_receipt = m.archived_receipt;
                h.messages[i].frame_nonce = m.frame_nonce;
            }
        } else {
            by_id
                .entry(m.message_id.clone())
                .or_default()
                .push(h.messages.len());
            h.messages.push(m);
        }
    }
    for ix in by_id.values().filter(|ix| ix.len() > 1) {
        for &i in ix {
            h.messages[i].conflict = true;
        }
    }
    let messages = &h.messages;
    h.undecryptable.retain(|u| {
        !messages
            .iter()
            .any(|m| m.message_id == u.message_id && (u.sender.is_none() || m.sender == u.sender))
    });
}

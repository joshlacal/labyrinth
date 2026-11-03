//! Reader path: loading a thread's history, and owner-mode archiving
//! (SPEC §7.1, §7.4, [CB-22]).

use std::collections::HashMap;

use super::Labyrinth;
use crate::deletion::StoredRedaction;
use crate::epoch::EpochKeys as _;
use crate::mek::{self, Mek, MekSender};
use crate::message::{
    ArchivedReceipt, OwnerContent, SealedMessage, open_owner_content, open_sender,
    open_sender_committed, verify_sender_device,
};
use crate::records::{Batch, BatchEntry, MekDistribution, OwnerBatch};
use crate::store::{ServerOrder, Stored, TimeRange, VouchAt};
use crate::{Error, Result};

/// Where a loaded message came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageSource {
    /// A sender `batch` in the conversation space (v1.1).
    Sender,
    /// An `ownerBatch` in this account's mailbox (v1.0 / re-archive).
    Owner,
}

/// One decrypted message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedMessage {
    pub thread_id: String,
    pub message_id: String,
    pub timestamp: u64,
    /// Sender DID for sender-mode messages; owner records carry none.
    pub sender: Option<String>,
    pub frame: Vec<u8>,
    pub source: MessageSource,
    /// True when another, different copy with the same `message_id` was
    /// also loaded (from another author, or a differing owner copy). Both
    /// copies are returned; the caller decides which one MLS vouches for.
    pub conflict: bool,
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
    },
}

impl OpenedSealed {
    pub(super) fn into_frame(self) -> Vec<u8> {
        match self {
            Self::Plain(f) | Self::Committed { frame: f, .. } => f,
        }
    }
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
        let mut history = ThreadHistory::default();
        let tombstones = self
            .open_owner_batches(thread_id, batches, &|_, _| true, &mut history)
            .await?;
        finish(&mut history, &tombstones);
        Ok(history)
    }

    /// Open an explicitly supplied owner record with the same checks as history.
    pub async fn open_owner_record(&mut self, batch: OwnerBatch) -> Result<ThreadHistory> {
        let messages = batch.to_messages()?;
        let mut history = ThreadHistory::default();
        for message in messages {
            let thread_id = message.thread_id.clone();
            let single = OwnerBatch::from_messages(&[message], batch.created_at.clone())?;
            let stored = Stored {
                author: self.did.clone(),
                rkey: String::new(),
                order: None,
                value: single,
            };
            let tombstones = self
                .open_owner_batches(&thread_id, vec![stored], &|_, _| true, &mut history)
                .await?;
            finish(&mut history, &tombstones);
        }
        Ok(history)
    }

    /// Load and decrypt every message of `thread_id` in `range`.
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
            self.b.threads.list_batches(thread_id, None, range).await,
        )?;
        let keep = |_: &str, ts: u64| range.contains(ts);
        self.open_batches(thread_id, batches, &keep, &mut h).await?;
        let owner = self.b.mailbox.list_owner_batches(thread_id, range).await?;
        let tombstones = self
            .open_owner_batches(thread_id, owner, &keep, &mut h)
            .await?;
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
            Err(Error::Forbidden | Error::NotFound("space" | "conversation")) => {
                h.space_readable = false;
                Ok(Vec::new())
            }
            Err(e) => Err(e),
        }
    }

    /// Opens every item of `batches` that `keep(messageId, timestamp)`
    /// selects into `h`.
    pub(super) async fn open_batches(
        &mut self,
        thread_id: &str,
        batches: Vec<Stored<Batch>>,
        keep: Keep<'_>,
        h: &mut ThreadHistory,
    ) -> Result<()> {
        for b in batches {
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
            for entry in items
                .into_iter()
                .filter(|e| keep(e.message_id(), e.timestamp()))
            {
                let s = match entry {
                    BatchEntry::Sealed(s) => s,
                    BatchEntry::Redacted {
                        message_id,
                        timestamp,
                        redaction,
                    } => {
                        let (by_author, account_deleted) = match &redaction {
                            StoredRedaction::Author(r)
                                if self
                                    .redaction_by_author(thread_id, &b.author, &message_id, r)
                                    .await =>
                            {
                                (true, false)
                            }
                            StoredRedaction::Server(r)
                                if self
                                    .redaction_by_sequencer(thread_id, &b.author, &message_id, r)
                                    .await =>
                            {
                                (false, true)
                            }
                            _ => return Err(Error::BadSignature),
                        };
                        h.redacted.push(RedactedMessage {
                            message_id,
                            timestamp,
                            sender: b.author.clone(),
                            by_author,
                            account_deleted,
                            removed_by_server: false,
                        });
                        continue;
                    }
                };
                let at = VouchAt::of(b.order, s.timestamp);
                match self
                    .open_sealed_inner(thread_id, &b.author, &s, at)
                    .await
                    .map(OpenedSealed::into_frame)
                {
                    Ok(frame) => h.messages.push(LoadedMessage {
                        thread_id: thread_id.to_owned(),
                        message_id: s.message_id.clone(),
                        timestamp: s.timestamp,
                        sender: author.clone(),
                        frame,
                        source: MessageSource::Sender,
                        conflict: false,
                    }),
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
    ) -> Result<Vec<Tombstone>> {
        let mut tombstones = Vec::new();
        let receipt_key = self.b.directory.sequencer_receipt_key(thread_id).await?;
        for b in batches {
            for m in b.value.to_messages()? {
                if m.thread_id != thread_id || !keep(&m.message_id, m.timestamp) {
                    continue;
                }
                let opened = match self.epoch_secret(m.epoch_seq).await {
                    Ok(e) => open_owner_content(e.root(), &m),
                    Err(err) => Err(err),
                };
                match opened {
                    Ok(OwnerContent::Frame(frame)) => {
                        if m.sequencer_receipt.is_some() {
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
                                source: MessageSource::Owner,
                                conflict: false,
                            });
                        }
                    }
                    Ok(OwnerContent::AttributedFrame { sender_did, frame }) => {
                        if m.sequencer_receipt.is_some() {
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
                                source: MessageSource::Owner,
                                conflict: false,
                            });
                        }
                    }
                    Ok(OwnerContent::CommittedFrame { frame_nonce, frame }) => {
                        let verified = (|| -> Result<String> {
                            let archived = m
                                .sequencer_receipt
                                .as_ref()
                                .ok_or(Error::ReceiptCommitmentMismatch)?;
                            if archived.signed.payload.conversation_id != thread_id {
                                return Err(Error::Malformed("receipt conversation_id mismatch"));
                            }
                            let (sender_did, _) =
                                archived.signed.payload.split_sender_device().map_err(|_| {
                                    Error::Malformed("invalid senderDevice in receipt")
                                })?;
                            if let Some(ref rk) = receipt_key {
                                labyrinth_protocol::verify_sequencer_receipt_sec1(
                                    &rk.public_key_sec1,
                                    &rk.did,
                                    &archived.signed,
                                )
                                .map_err(|_| Error::BadSignature)?;
                            }
                            labyrinth_protocol::verify_archived_item_commitment(
                                &archived.signed,
                                &frame_nonce,
                                &frame,
                            )
                            .map_err(|_| Error::ReceiptCommitmentMismatch)?;
                            Ok(sender_did.to_owned())
                        })();
                        match verified {
                            Ok(sender_did) => h.messages.push(LoadedMessage {
                                thread_id: thread_id.to_owned(),
                                message_id: m.message_id,
                                timestamp: m.timestamp,
                                sender: Some(sender_did),
                                frame,
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
                    Err(error) => h.undecryptable.push(Undecryptable {
                        message_id: m.message_id,
                        timestamp: m.timestamp,
                        sender: None,
                        error,
                    }),
                }
            }
        }
        Ok(tombstones)
    }

    /// SPEC §7.4 + Gate 1 (`I13`): verifies sequencer receipt + blinded
    /// `archiveCommitment` when present (or required by `sequencer_receipt_key`),
    /// checks sender chat device validity, opens the MEK, and decrypts.
    pub(super) async fn open_sealed_inner(
        &mut self,
        thread_id: &str,
        author: &str,
        s: &SealedMessage,
        at: VouchAt,
    ) -> Result<OpenedSealed> {
        let receipt_key = self.b.directory.sequencer_receipt_key(thread_id).await?;
        if let Some(ref archived) = s.sequencer_receipt {
            let rk = receipt_key.ok_or(Error::Unattested)?;
            if archived.signed.payload.conversation_id != thread_id {
                return Err(Error::Malformed("receipt conversation_id mismatch"));
            }
            let (receipt_sender_did, _) = archived
                .signed
                .payload
                .split_sender_device()
                .map_err(|_| Error::Malformed("invalid senderDevice in receipt"))?;
            if receipt_sender_did != author {
                return Err(Error::Malformed(
                    "receipt senderDevice DID does not match batch author",
                ));
            }
            labyrinth_protocol::verify_sequencer_receipt_sec1(
                &rk.public_key_sec1,
                &rk.did,
                &archived.signed,
            )
            .map_err(|_| Error::BadSignature)?;

            let issued_ms = u64::try_from(archived.signed.payload.issued_at_ms)
                .map_err(|_| Error::Malformed("negative receipt issuedAtMs"))?;
            let leaves = self
                .b
                .directory
                .member_device_keys(thread_id, author)
                .await?;
            let receipt_at = VouchAt::Server(ServerOrder {
                labyrinth_seq: archived.signed.payload.seq,
                chat_seq: leaves.as_ref().map(|_| archived.signed.payload.seq),
                received_at_ms: issued_ms,
            });
            verify_sender_device(
                s,
                &self
                    .transport_keys(author, Some(thread_id), receipt_at)
                    .await?,
            )?;
            let mek = self.mek_for(thread_id, &s.mek_id, issued_ms).await?;
            let (frame_nonce, frame) = open_sender_committed(s, thread_id, &mek)?;
            labyrinth_protocol::verify_archived_item_commitment(
                &archived.signed,
                &frame_nonce,
                &frame,
            )
            .map_err(|_| Error::ReceiptCommitmentMismatch)?;
            return Ok(OpenedSealed::Committed {
                frame_nonce,
                frame,
                receipt: archived.clone(),
            });
        }

        if receipt_key.is_some() {
            return Err(Error::ReceiptCommitmentMismatch);
        }

        verify_sender_device(s, &self.transport_keys(author, Some(thread_id), at).await?)?;
        let mek = self.mek_for(thread_id, &s.mek_id, s.timestamp).await?;
        open_sender(s, thread_id, &mek).map(OpenedSealed::Plain)
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

/// Applies delete-for-me tombstones, merges copies and sorts.
pub(super) fn finish(h: &mut ThreadHistory, tombstones: &[Tombstone]) {
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
}

/// Merge provably identical copies and flag the rest (see
/// [`Labyrinth::load_thread`]). Sender copies are considered first, followed
/// by attributed owner copies, then unattributed legacy owner copies.
fn dedupe(h: &mut ThreadHistory) {
    let mut all = core::mem::take(&mut h.messages);
    all.sort_by_key(|m| (m.source != MessageSource::Sender, m.sender.is_none()));
    let mut by_id: HashMap<String, Vec<usize>> = HashMap::new();
    for m in all {
        let same = by_id.get(&m.message_id).is_some_and(|ix| {
            ix.iter().any(|&i| {
                let k = &h.messages[i];
                k.frame == m.frame && (m.sender.is_none() || k.sender == m.sender)
            })
        });
        if !same {
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

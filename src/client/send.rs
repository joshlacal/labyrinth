//! Sender path: MEK reuse or minting, sealing, batching (SPEC §7.2–7.3,
//! [CB-15], [CB-16], [CB-20]).

use super::Labyrinth;
use crate::mailbox::EpochPublic;
use crate::mek::{self, Mek, MekRecord};
use crate::message::{ArchivedReceipt, seal_sender, seal_sender_committed};
use crate::records::defs::SealedMessageDef;
use crate::records::{BATCH_BYTE_BUDGET, Batch, MAX_BATCH_ITEMS, MekDistribution, OwnerBatch};
use crate::{Error, Result};

/// A batch record written to a store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlushedBatch {
    pub thread_id: String,
    pub rkey: String,
    pub count: usize,
    /// True for an `ownerBatch` in the personal mailbox, false for a
    /// sender `batch` in the conversation space.
    pub owner: bool,
}

/// What [`Labyrinth::archive_outgoing`] wrote.
#[derive(Clone, Debug, Default)]
pub struct ArchiveOutcome {
    /// The MEK distribution written because no cached MEK was reusable.
    pub mek_written: Option<MekRecord>,
    /// A batch flushed because it reached the size limits.
    pub flushed: Option<FlushedBatch>,
}

/// A conversation member left out of a roster, loudly: it gets no MEK
/// for the messages archived under this roster, so it cannot read them
/// from history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterExclusion {
    pub did: String,
    /// Why: [`Error::EpochRollback`] (the peer's chain was reset or is
    /// being replayed; see [`Labyrinth::propose_repin`]),
    /// [`Error::Unattested`], [`Error::DirectoryFork`], or a record that
    /// does not verify.
    pub error: Error,
}

/// [`Labyrinth::resolve_roster_report`]: the roster plus the members left
/// out of it.
#[derive(Clone, Debug, Default)]
pub struct ResolvedRoster {
    pub roster: Vec<(String, EpochPublic)>,
    pub excluded: Vec<RosterExclusion>,
}

enum OutgoingPayload<'a> {
    Plain(&'a [u8]),
    Committed {
        frame_nonce: &'a [u8; 32],
        payload_bytes: &'a [u8],
        receipt: &'a labyrinth_protocol::SignedSequencerReceipt,
        verify_commitment: bool,
    },
}

/// Only cryptographic/trust failures attributable to a peer's published
/// epoch may exclude that peer. Operational, authorization, missing-history
/// and version-skew errors abort the whole roster so backend failure cannot
/// silently turn an MLS member into a history omission.
fn is_roster_exclusion(e: &Error) -> bool {
    matches!(
        e,
        Error::BadSignature
            | Error::BadPublicKey
            | Error::Unsupported(_)
            | Error::EpochRollback { .. }
            | Error::DirectoryFork { .. }
            | Error::Unattested
    )
}

impl Labyrinth {
    /// Like [`resolve_roster`](Self::resolve_roster), but a member whose
    /// epoch fails a trust check ([CB-18], [CB-28], [CB-29], or a record
    /// that does not verify) is excluded and reported instead of failing
    /// the whole roster.
    pub async fn resolve_roster_report(&mut self, member_dids: &[&str]) -> Result<ResolvedRoster> {
        let mut out = ResolvedRoster::default();
        let me = self.did.clone();
        let own = self.own_latest_checked().await?;
        for did in member_dids.iter().filter(|d| **d != me) {
            let checked = match self.b.directory.latest(did).await {
                Ok(Some(epoch)) => self
                    .accept_for_addressing(did, &epoch)
                    .await
                    .map(|()| Some(epoch)),
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            };
            match checked {
                Ok(Some(epoch)) => out.roster.push(((*did).to_owned(), epoch)),
                Ok(None) => {}
                Err(error) if is_roster_exclusion(&error) => out.excluded.push(RosterExclusion {
                    did: (*did).to_owned(),
                    error,
                }),
                Err(error) => return Err(error),
            }
        }
        out.roster.push((self.did.clone(), own));
        Ok(out)
    }

    /// The roster ([CB-16]) for a conversation whose MLS members are
    /// `member_dids`: each enrolled member's latest published epoch,
    /// verified and attested by one of its current chat devices ([CB-18]),
    /// plus this account's own latest epoch.
    pub async fn resolve_roster(
        &mut self,
        member_dids: &[&str],
    ) -> Result<Vec<(String, EpochPublic)>> {
        let mut roster = Vec::with_capacity(member_dids.len() + 1);
        let me = self.did.clone();
        let own = self.own_latest_checked().await?;
        for did in member_dids.iter().filter(|d| **d != me) {
            if let Some(epoch) = self.b.directory.latest(did).await? {
                self.accept_for_addressing(did, &epoch).await?;
                roster.push(((*did).to_owned(), epoch));
            }
        }
        roster.push((self.did.clone(), own));
        Ok(roster)
    }

    /// Archive one outgoing MLS application frame for `thread_id`.
    pub async fn archive_outgoing(
        &mut self,
        thread_id: &str,
        roster: &[(String, EpochPublic)],
        message_id: &str,
        timestamp: u64,
        frame: &[u8],
    ) -> Result<ArchiveOutcome> {
        self.archive_outgoing_inner(
            thread_id,
            roster,
            message_id,
            timestamp,
            OutgoingPayload::Plain(frame),
        )
        .await
    }

    /// Archive one outgoing MLS application frame bound to an `I13` sequencer
    /// receipt (`Gate 1`). `frame_nonce` is sealed strictly inside the MEK
    /// AEAD ciphertext and never appears in cleartext Space records.
    #[allow(clippy::too_many_arguments)]
    pub async fn archive_outgoing_committed(
        &mut self,
        thread_id: &str,
        roster: &[(String, EpochPublic)],
        message_id: &str,
        timestamp: u64,
        frame_nonce: &[u8; 32],
        payload_bytes: &[u8],
        receipt: &labyrinth_protocol::SignedSequencerReceipt,
    ) -> Result<ArchiveOutcome> {
        self.archive_outgoing_inner(
            thread_id,
            roster,
            message_id,
            timestamp,
            OutgoingPayload::Committed {
                frame_nonce,
                payload_bytes,
                receipt,
                verify_commitment: true,
            },
        )
        .await
    }

    /// Test-only helper for `Gate 1` adversarial substitution tests: seals an
    /// item with a mismatched `(frame_nonce, payload_bytes)` against `receipt`
    /// so reader-side commitment rejection can be verified end-to-end.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub async fn archive_outgoing_committed_unchecked_for_test(
        &mut self,
        thread_id: &str,
        roster: &[(String, EpochPublic)],
        message_id: &str,
        timestamp: u64,
        frame_nonce: &[u8; 32],
        payload_bytes: &[u8],
        receipt: &labyrinth_protocol::SignedSequencerReceipt,
    ) -> Result<ArchiveOutcome> {
        self.archive_outgoing_inner(
            thread_id,
            roster,
            message_id,
            timestamp,
            OutgoingPayload::Committed {
                frame_nonce,
                payload_bytes,
                receipt,
                verify_commitment: false,
            },
        )
        .await
    }

    async fn archive_outgoing_inner(
        &mut self,
        thread_id: &str,
        roster: &[(String, EpochPublic)],
        message_id: &str,
        timestamp: u64,
        payload: OutgoingPayload<'_>,
    ) -> Result<ArchiveOutcome> {
        if let OutgoingPayload::Committed {
            frame_nonce,
            payload_bytes,
            receipt,
            verify_commitment: true,
        } = &payload
        {
            if receipt.payload.conversation_id != thread_id {
                return Err(Error::Malformed("receipt conversation_id mismatch"));
            }
            labyrinth_protocol::verify_archived_item_commitment(
                receipt,
                frame_nonce,
                payload_bytes,
            )
            .map_err(|_| Error::ReceiptCommitmentMismatch)?;
        }

        let me_public = self.own_latest_checked().await?;
        let mut full = Vec::with_capacity(roster.len() + 1);
        let me = self.did.clone();
        for (did, epoch) in roster.iter().filter(|(d, _)| *d != me) {
            let current = self
                .b
                .directory
                .latest(did)
                .await?
                .ok_or(Error::NotFound("recipient mailbox keys"))?;
            self.accept_for_addressing(did, &current).await?;
            if current.seq != epoch.seq || current.head != epoch.head {
                return Err(Error::Malformed("roster epoch is not the directory head"));
            }
            self.accept_for_addressing(did, epoch).await?;
            full.push((did.clone(), epoch.clone()));
        }
        full.push((self.did.clone(), me_public.clone()));
        let heads: Vec<[u8; 32]> = full.iter().map(|(_, e)| e.head).collect();
        let mut pending_roster: Vec<(String, [u8; 32])> = full
            .iter()
            .map(|(did, epoch)| (did.clone(), epoch.head))
            .collect();
        pending_roster.sort_unstable();

        let mut out = ArchiveOutcome::default();
        let cached = self.meks.get(thread_id).and_then(|v| {
            v.iter()
                .rev()
                .find(|m| m.reusable_for(&me, &heads))
                .cloned()
        });
        if self.outbox.get(thread_id).is_some_and(|v| !v.is_empty()) {
            let roster_changed = self.outbox_rosters.get(thread_id) != Some(&pending_roster);
            let mek_changed = cached.as_ref().is_none_or(|c| {
                self.outbox
                    .get(thread_id)
                    .and_then(|v| v.last())
                    .is_some_and(|m| m.mek_id != *c.id())
            });
            if roster_changed || mek_changed {
                out.flushed = self.flush_sender(thread_id).await?;
            }
        }
        let mek = match cached {
            Some(m) => m,
            None => {
                let (_, keys) = self.my_keys(self.latest).await?;
                let mut m = Mek::generate(&heads)?;
                let rec = mek::distribute_labyrinth(
                    thread_id, &mut m, &self.did, &me_public, &keys, &full,
                )?;
                let wire = MekDistribution::from_record(&rec, Some(&me_public), self.now())?;
                self.b.threads.create_mek(&wire).await?;
                self.meks
                    .entry(thread_id.to_owned())
                    .or_default()
                    .push(m.clone());
                out.mek_written = Some(rec);
                m
            }
        };
        let sealed = match payload {
            OutgoingPayload::Plain(frame) => seal_sender(
                &mek,
                thread_id,
                message_id,
                timestamp,
                frame,
                self.transport.as_ref(),
            )?,
            OutgoingPayload::Committed {
                frame_nonce,
                payload_bytes,
                receipt,
                ..
            } => {
                let archived = ArchivedReceipt::new(receipt.clone());
                seal_sender_committed(
                    &mek,
                    thread_id,
                    message_id,
                    timestamp,
                    frame_nonce,
                    payload_bytes,
                    &archived,
                    self.transport.as_ref(),
                )?
            }
        };

        let mek_changed = self
            .outbox
            .get(thread_id)
            .and_then(|v| v.last())
            .is_some_and(|m| m.mek_id != sealed.mek_id);
        if mek_changed {
            out.flushed = self.flush_sender(thread_id).await?;
        }
        let pending = self.outbox.get(thread_id).map_or(0, |v| {
            v.iter()
                .map(SealedMessageDef::approx_json_len)
                .sum::<usize>()
        });
        if pending > 0 && pending + SealedMessageDef::approx_json_len(&sealed) > BATCH_BYTE_BUDGET {
            out.flushed = self.flush_sender(thread_id).await?;
        }
        if self.outbox.get(thread_id).is_none_or(Vec::is_empty) {
            self.outbox_rosters
                .insert(thread_id.to_owned(), pending_roster);
        } else if self.outbox_rosters.get(thread_id) != Some(&pending_roster) {
            return Err(Error::RosterMismatch);
        }
        let queue = self.outbox.entry(thread_id.to_owned()).or_default();
        queue.push(sealed);
        if queue.len() >= MAX_BATCH_ITEMS {
            out.flushed = self.flush_sender(thread_id).await?;
        }
        Ok(out)
    }

    /// Write every buffered sender and owner batch.
    pub async fn flush(&mut self) -> Result<Vec<FlushedBatch>> {
        let mut out = Vec::new();
        let threads: Vec<String> = self.outbox.keys().cloned().collect();
        for t in threads {
            out.extend(self.flush_sender(&t).await?);
        }
        let threads: Vec<String> = self.owner_outbox.keys().cloned().collect();
        for t in threads {
            out.extend(self.flush_owner(&t).await?);
        }
        Ok(out)
    }

    /// Write the buffered sender and owner batches of `thread_id` only.
    pub async fn flush_thread(&mut self, thread_id: &str) -> Result<Vec<FlushedBatch>> {
        let mut out = Vec::new();
        out.extend(self.flush_sender(thread_id).await?);
        out.extend(self.flush_owner(thread_id).await?);
        Ok(out)
    }

    /// Drop every buffered, unwritten message of `thread_id`.
    pub fn discard_pending(&mut self, thread_id: &str) -> usize {
        let sender = self.outbox.remove(thread_id).map_or(0, |v| v.len());
        self.outbox_rosters.remove(thread_id);
        sender + self.owner_outbox.remove(thread_id).map_or(0, |v| v.len())
    }

    /// Messages buffered for `thread_id` but not yet written.
    pub fn pending(&self, thread_id: &str) -> usize {
        self.outbox.get(thread_id).map_or(0, Vec::len)
            + self.owner_outbox.get(thread_id).map_or(0, Vec::len)
    }

    /// Writes the sender buffer of one thread; on error the buffer is kept.
    pub(super) async fn flush_sender(&mut self, thread_id: &str) -> Result<Option<FlushedBatch>> {
        let Some(mek_id) = self
            .outbox
            .get(thread_id)
            .and_then(|items| items.first())
            .map(|item| item.mek_id)
        else {
            return Ok(None);
        };
        let roster = self
            .outbox_rosters
            .get(thread_id)
            .cloned()
            .ok_or(Error::Malformed("pending sender roster missing"))?;
        let own = self.own_latest_checked().await?;
        let me = self.did.clone();
        let mut heads = Vec::with_capacity(roster.len());
        for (did, expected) in &roster {
            let current = if *did == me {
                own.clone()
            } else {
                let current = self
                    .b
                    .directory
                    .latest(did)
                    .await?
                    .ok_or(Error::NotFound("recipient mailbox keys"))?;
                self.accept_for_addressing(did, &current).await?;
                current
            };
            if current.head != *expected {
                return Err(Error::RosterMismatch);
            }
            heads.push(current.head);
        }
        let valid_mek = self
            .meks
            .get(thread_id)
            .and_then(|meks| meks.iter().find(|mek| *mek.id() == mek_id))
            .is_some_and(|mek| mek.reusable_for(&self.did, &heads));
        if !valid_mek {
            return Err(Error::RosterMismatch);
        }
        let items = self
            .outbox
            .get(thread_id)
            .filter(|items| !items.is_empty())
            .expect("sender buffer checked above");
        if items.iter().any(|item| item.mek_id != mek_id) {
            return Err(Error::Malformed("pending sender batch mixes MEKs"));
        }
        let batch = Batch::from_messages(thread_id, items, self.now())?;
        let rkey = self.b.threads.append_batch(&batch).await?;
        let count = self.outbox.remove(thread_id).map_or(0, |v| v.len());
        self.outbox_rosters.remove(thread_id);
        Ok(Some(FlushedBatch {
            thread_id: thread_id.to_owned(),
            rkey,
            count,
            owner: false,
        }))
    }

    /// Writes the owner buffer of one thread; on error the buffer is kept.
    pub(super) async fn flush_owner(&mut self, thread_id: &str) -> Result<Option<FlushedBatch>> {
        if self.owner_outbox.get(thread_id).is_none_or(Vec::is_empty) {
            return Ok(None);
        }
        self.sync_epochs().await?;
        let items = self
            .owner_outbox
            .get(thread_id)
            .filter(|items| !items.is_empty())
            .expect("owner buffer checked above");
        if items.iter().any(|item| item.epoch_seq != self.latest) {
            return Err(Error::WrongEpoch);
        }
        let batch = OwnerBatch::from_messages(items, self.now())?;
        let rkey = self.b.mailbox.append_owner_batch(&batch).await?;
        let count = self.owner_outbox.remove(thread_id).map_or(0, |v| v.len());
        Ok(Some(FlushedBatch {
            thread_id: thread_id.to_owned(),
            rkey,
            count,
            owner: true,
        }))
    }
}

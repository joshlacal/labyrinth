//! Sender path: MEK reuse or minting, sealing, batching (SPEC §7.2–7.3,
//! [CB-15], [CB-16], [CB-20]).

use super::Labyrinth;
use crate::mailbox::EpochPublic;
use crate::mek::{self, Mek, MekRecord};
use crate::message::seal_sender;
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

/// True for failures that say nothing about the member (the backend did
/// not answer, no randomness): the whole roster must be retried rather
/// than the member dropped.
fn is_transient(e: &Error) -> bool {
    matches!(e, Error::Backend(_) | Error::Rng)
}

impl Labyrinth {
    /// Like [`resolve_roster`](Self::resolve_roster), but a member whose
    /// epoch fails a trust check ([CB-18], [CB-28], [CB-29], or a record
    /// that does not verify) is excluded and reported instead of failing
    /// the whole roster. Transient failures ([`Error::Backend`],
    /// [`Error::Rng`]) still fail it, so a network blip never drops a
    /// member. This account's own epoch is always included.
    pub fn resolve_roster_report(&mut self, member_dids: &[&str]) -> Result<ResolvedRoster> {
        let mut out = ResolvedRoster::default();
        let me = self.did.clone();
        for did in member_dids.iter().filter(|d| **d != me) {
            let checked = self.b.directory.latest(did).and_then(|e| match e {
                Some(epoch) => self
                    .accept_for_addressing(did, &epoch)
                    .map(|()| Some(epoch)),
                None => Ok(None),
            });
            match checked {
                Ok(Some(epoch)) => out.roster.push(((*did).to_owned(), epoch)),
                Ok(None) => {}
                Err(e) if is_transient(&e) => return Err(e),
                Err(error) => out.excluded.push(RosterExclusion {
                    did: (*did).to_owned(),
                    error,
                }),
            }
        }
        out.roster.push((self.did.clone(), self.latest_public()?));
        Ok(out)
    }

    /// The roster ([CB-16]) for a conversation whose MLS members are
    /// `member_dids`: each enrolled member's latest published epoch,
    /// verified and attested by one of its current chat devices ([CB-18]),
    /// plus this account's own latest epoch. Members with no `mailboxKeys`
    /// are not enrolled and are left out.
    ///
    /// Each member's epoch must also pass its [CB-29] pin: it may not be
    /// older than (or fork from) the newest epoch this client already
    /// accepted for that DID, and a newer one must chain to it
    /// ([`crate::Error::EpochRollback`] otherwise).
    pub fn resolve_roster(&mut self, member_dids: &[&str]) -> Result<Vec<(String, EpochPublic)>> {
        let mut roster = Vec::with_capacity(member_dids.len() + 1);
        let me = self.did.clone();
        for did in member_dids.iter().filter(|d| **d != me) {
            if let Some(epoch) = self.b.directory.latest(did)? {
                self.accept_for_addressing(did, &epoch)?;
                roster.push(((*did).to_owned(), epoch));
            }
        }
        roster.push((self.did.clone(), self.latest_public()?));
        Ok(roster)
    }

    /// Archive one outgoing MLS application frame for `thread_id`.
    ///
    /// `roster` lists the other enrolled members and their latest epochs
    /// (see [`resolve_roster`](Self::resolve_roster)); any entry for this
    /// account is replaced by its own latest epoch. Every other entry is
    /// verified and must be attested by a current chat device of its DID
    /// ([CB-18]) or the call fails with [`crate::Error::Unattested`], and
    /// must pass the DID's [CB-29] pin ([`crate::Error::EpochRollback`]).
    ///
    /// A cached MEK is reused only under the reuse rules (p.38–39,
    /// [CB-23]); otherwise a fresh MEK is distributed to the roster and its
    /// record written first. The sealed message is buffered and flushed as
    /// a `batch` record at [`MAX_BATCH_ITEMS`] items or
    /// [`BATCH_BYTE_BUDGET`] bytes, or on [`flush`](Self::flush). Every
    /// batch holds messages under a single MEK: a message under a new MEK
    /// first flushes the buffered ones (mls-ds rejects mixed-MEK batches).
    pub fn archive_outgoing(
        &mut self,
        thread_id: &str,
        roster: &[(String, EpochPublic)],
        message_id: &str,
        timestamp: u64,
        frame: &[u8],
    ) -> Result<ArchiveOutcome> {
        let me_public = self.latest_public()?;
        let mut full = Vec::with_capacity(roster.len() + 1);
        let me = self.did.clone();
        for (did, epoch) in roster.iter().filter(|(d, _)| *d != me) {
            self.accept_for_addressing(did, epoch)?;
            full.push((did.clone(), epoch.clone()));
        }
        full.push((self.did.clone(), me_public.clone()));
        let heads: Vec<[u8; 32]> = full.iter().map(|(_, e)| e.head).collect();

        let mut out = ArchiveOutcome::default();
        let cached = self
            .meks
            .get(thread_id)
            .and_then(|v| v.iter().rev().find(|m| m.reusable_for(&heads)).cloned());
        let mek = match cached {
            Some(m) => m,
            None => {
                let (_, keys) = self.my_keys(self.latest)?;
                let mut m = Mek::generate(&heads)?;
                let rec = mek::distribute_labyrinth(
                    thread_id, &mut m, &self.did, &me_public, &keys, &full,
                )?;
                let wire = MekDistribution::from_record(&rec, Some(&me_public), self.now())?;
                self.b.threads.create_mek(&wire)?;
                self.meks
                    .entry(thread_id.to_owned())
                    .or_default()
                    .push(m.clone());
                out.mek_written = Some(rec);
                m
            }
        };
        let sealed = seal_sender(
            &mek,
            thread_id,
            message_id,
            timestamp,
            frame,
            self.transport.as_ref(),
        )?;

        // Y4: a batch holds messages under one MEK only, so a server can
        // authorize reads per MEK with a row filter.
        let mek_changed = self
            .outbox
            .get(thread_id)
            .and_then(|v| v.last())
            .is_some_and(|m| m.mek_id != sealed.mek_id);
        if mek_changed {
            out.flushed = self.flush_sender(thread_id)?;
        }
        let pending = self.outbox.get(thread_id).map_or(0, |v| {
            v.iter()
                .map(SealedMessageDef::approx_json_len)
                .sum::<usize>()
        });
        if pending > 0 && pending + SealedMessageDef::approx_json_len(&sealed) > BATCH_BYTE_BUDGET {
            out.flushed = self.flush_sender(thread_id)?;
        }
        let queue = self.outbox.entry(thread_id.to_owned()).or_default();
        queue.push(sealed);
        if queue.len() >= MAX_BATCH_ITEMS {
            out.flushed = self.flush_sender(thread_id)?;
        }
        Ok(out)
    }

    /// Write every buffered sender and owner batch.
    pub fn flush(&mut self) -> Result<Vec<FlushedBatch>> {
        let mut out = Vec::new();
        let threads: Vec<String> = self.outbox.keys().cloned().collect();
        for t in threads {
            out.extend(self.flush_sender(&t)?);
        }
        let threads: Vec<String> = self.owner_outbox.keys().cloned().collect();
        for t in threads {
            out.extend(self.flush_owner(&t)?);
        }
        Ok(out)
    }

    /// Write the buffered sender and owner batches of `thread_id` only.
    pub fn flush_thread(&mut self, thread_id: &str) -> Result<Vec<FlushedBatch>> {
        let mut out = Vec::new();
        out.extend(self.flush_sender(thread_id)?);
        out.extend(self.flush_owner(thread_id)?);
        Ok(out)
    }

    /// Drop every buffered, unwritten message of `thread_id` (a caller
    /// that failed part-way through a thread and will retry it from its
    /// own queue). Returns how many were dropped.
    pub fn discard_pending(&mut self, thread_id: &str) -> usize {
        self.outbox.remove(thread_id).map_or(0, |v| v.len())
            + self.owner_outbox.remove(thread_id).map_or(0, |v| v.len())
    }

    /// Messages buffered for `thread_id` but not yet written.
    pub fn pending(&self, thread_id: &str) -> usize {
        self.outbox.get(thread_id).map_or(0, Vec::len)
            + self.owner_outbox.get(thread_id).map_or(0, Vec::len)
    }

    /// Writes the sender buffer of one thread; on error the buffer is kept.
    pub(super) fn flush_sender(&mut self, thread_id: &str) -> Result<Option<FlushedBatch>> {
        let Some(items) = self.outbox.get(thread_id).filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let batch = Batch::from_messages(thread_id, items, self.now())?;
        let rkey = self.b.threads.append_batch(&batch)?;
        let count = self.outbox.remove(thread_id).map_or(0, |v| v.len());
        Ok(Some(FlushedBatch {
            thread_id: thread_id.to_owned(),
            rkey,
            count,
            owner: false,
        }))
    }

    /// Writes the owner buffer of one thread; on error the buffer is kept.
    pub(super) fn flush_owner(&mut self, thread_id: &str) -> Result<Option<FlushedBatch>> {
        let Some(items) = self.owner_outbox.get(thread_id).filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let batch = OwnerBatch::from_messages(items, self.now())?;
        let rkey = self.b.mailbox.append_owner_batch(&batch)?;
        let count = self.owner_outbox.remove(thread_id).map_or(0, |v| v.len());
        Ok(Some(FlushedBatch {
            thread_id: thread_id.to_owned(),
            rkey,
            count,
            owner: true,
        }))
    }
}

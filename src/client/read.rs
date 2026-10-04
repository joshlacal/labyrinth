//! Reader path: loading a thread's history, and owner-mode archiving
//! (SPEC §7.1, §7.4, [CB-22]).

use std::collections::{HashMap, HashSet};

use super::Labyrinth;
use crate::epoch::EpochKeys as _;
use crate::mek::{self, Mek, MekSender};
use crate::message::{SealedMessage, open_owner, open_sender, seal_owner, verify_sender_device};
use crate::records::{BATCH_BYTE_BUDGET, MAX_BATCH_ITEMS, MekDistribution};
use crate::store::{Stored, TimeRange};
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

/// Result of [`Labyrinth::load_thread`], ordered by `(timestamp, messageId)`.
#[derive(Clone, Debug, Default)]
pub struct ThreadHistory {
    pub messages: Vec<LoadedMessage>,
    pub undecryptable: Vec<Undecryptable>,
    /// False if the conversation space refused reads ([`Error::Forbidden`]);
    /// only owner-archived messages are then included.
    pub space_readable: bool,
}

impl Labyrinth {
    /// Load and decrypt every message of `thread_id` in `range`: sender
    /// batches via any MEK addressed to any of my epochs (backward-chaining
    /// as needed), plus my owner batches.
    ///
    /// Copies are merged only when they are provably the same message: a
    /// sender copy is deduplicated on `(author DID, messageId)` with a
    /// byte-equal frame, and an owner copy is dropped only when its frame
    /// is byte-equal to a loaded copy with the same `messageId`. Anything
    /// else that shares a `messageId` is returned with
    /// [`LoadedMessage::conflict`] set, so a group member who reuses
    /// another member's id cannot suppress the genuine message.
    pub fn load_thread(&mut self, thread_id: &str, range: TimeRange) -> Result<ThreadHistory> {
        let mut h = ThreadHistory {
            space_readable: true,
            ..ThreadHistory::default()
        };
        let batches = match self.b.threads.list_batches(thread_id, None, range) {
            Ok(b) => b,
            Err(Error::Forbidden) => {
                h.space_readable = false;
                Vec::new()
            }
            Err(e) => return Err(e),
        };
        for b in batches {
            let author = Some(b.author.clone());
            let items = if b.value.thread_id == thread_id {
                b.value.to_messages()
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
            for s in items.iter().filter(|s| range.contains(s.timestamp)) {
                match self.open_sealed(thread_id, &b.author, s) {
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
        self.load_owner(thread_id, range, &mut h)?;

        dedupe(&mut h);
        h.messages
            .sort_by(|a, b| (a.timestamp, &a.message_id).cmp(&(b.timestamp, &b.message_id)));
        h.undecryptable
            .sort_by(|a, b| (a.timestamp, &a.message_id).cmp(&(b.timestamp, &b.message_id)));
        Ok(h)
    }

    fn load_owner(
        &mut self,
        thread_id: &str,
        range: TimeRange,
        h: &mut ThreadHistory,
    ) -> Result<()> {
        for b in self.b.mailbox.list_owner_batches(thread_id, range)? {
            for m in b.value.to_messages()? {
                if m.thread_id != thread_id || !range.contains(m.timestamp) {
                    continue;
                }
                let opened = self
                    .epoch_secret(m.epoch_seq)
                    .and_then(|e| open_owner(e.root(), &m));
                match opened {
                    Ok(frame) => h.messages.push(LoadedMessage {
                        thread_id: thread_id.to_owned(),
                        message_id: m.message_id,
                        timestamp: m.timestamp,
                        sender: None,
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
        }
        Ok(())
    }

    /// SPEC §7.4: the sender key must be one of the author's chat devices,
    /// then the MEK opens and the signature and AEAD verify.
    fn open_sealed(&mut self, thread_id: &str, author: &str, s: &SealedMessage) -> Result<Vec<u8>> {
        verify_sender_device(s, &self.b.directory.historical_transport_keys(author)?)?;
        let mek = self.mek_for(thread_id, &s.mek_id)?;
        open_sender(s, thread_id, &mek)
    }

    fn mek_for(&mut self, thread_id: &str, mek_id: &[u8; 12]) -> Result<Mek> {
        if let Some(m) = self
            .meks
            .get(thread_id)
            .and_then(|v| v.iter().find(|m| m.id() == mek_id))
        {
            return Ok(m.clone());
        }
        let mut err = Error::NotFound("mek");
        for c in self.b.threads.find_meks(thread_id, mek_id)? {
            match self.open_mek_record(thread_id, &c) {
                Ok(m) => {
                    self.meks
                        .entry(thread_id.to_owned())
                        .or_default()
                        .push(m.clone());
                    return Ok(m);
                }
                Err(e) => err = e,
            }
        }
        Err(err)
    }

    /// Opens a MEK distribution under whichever of my epochs it names,
    /// after checking the record's author and [CB-18] for the sender.
    fn open_mek_record(&mut self, thread_id: &str, c: &Stored<MekDistribution>) -> Result<Mek> {
        let (rec, sender_epoch) = c.value.to_record()?;
        if rec.thread_id != thread_id {
            return Err(Error::Malformed("MEK filed under another thread"));
        }
        match (&rec.sender, &sender_epoch) {
            (MekSender::Labyrinth { did, .. }, Some(epoch)) => {
                if *did != c.author {
                    return Err(Error::Malformed("MEK sender is not the record author"));
                }
                self.check_attested(did, epoch, true)?;
            }
            (MekSender::Transport { transport_pub, .. }, _) => {
                let keys = self.b.directory.historical_transport_keys(&c.author)?;
                if !keys.contains(transport_pub) {
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
        let seq = self.seq_for_head(&head)?;
        let (_, keys) = self.my_keys(seq)?;
        let my_public = self.epoch_record(seq)?.1.public;
        mek::open(&rec, &self.did, &my_public, &keys, sender_epoch.as_ref())
    }

    fn seq_for_head(&mut self, head: &[u8; 32]) -> Result<u64> {
        if let Some(s) = self.heads.get(head) {
            return Ok(*s);
        }
        for e in self.b.mailbox.list_epochs()? {
            let h = e.value.public.epoch_head.array::<32>("epochHead length")?;
            self.heads.insert(h, e.value.seq());
        }
        self.heads.get(head).copied().ok_or(Error::WrongEpoch)
    }

    /// Archive a message into my own mailbox in owner mode (v1.0, cipher
    /// version 3) under my latest epoch. Buffered like sender batches.
    pub fn archive_owner(
        &mut self,
        thread_id: &str,
        message_id: &str,
        timestamp: u64,
        frame: &[u8],
    ) -> Result<Option<super::FlushedBatch>> {
        let e = self.epoch_secret(self.latest)?;
        let m = seal_owner(e.root(), e.seq, thread_id, message_id, timestamp, frame)?;
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
        let history = self.load_thread(thread_id, TimeRange::ALL)?;
        // What the owner archive already holds, by (messageId, frame): a
        // copy counts as archived only if its plaintext is byte-equal, so
        // two distinct messages sharing an id are both kept.
        let mut owner = ThreadHistory::default();
        self.load_owner(thread_id, TimeRange::ALL, &mut owner)?;
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
            self.archive_owner(thread_id, &key.0, m.timestamp, &key.1)?;
            archived.insert(key);
            n += 1;
        }
        self.flush_owner(thread_id)?;
        Ok(n)
    }
}

/// Merge provably identical copies and flag the rest (see
/// [`Labyrinth::load_thread`]). Sender copies are considered first.
fn dedupe(h: &mut ThreadHistory) {
    let mut all = core::mem::take(&mut h.messages);
    all.sort_by_key(|m| m.source != MessageSource::Sender);
    let mut by_id: HashMap<String, Vec<usize>> = HashMap::new();
    for m in all {
        let same = by_id.get(&m.message_id).is_some_and(|ix| {
            ix.iter().any(|&i| {
                let k = &h.messages[i];
                k.frame == m.frame && (m.source == MessageSource::Owner || k.sender == m.sender)
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
    // An unopenable copy is hidden only behind an opened copy from the
    // same author (or, for my own owner archive, any opened copy).
    let messages = &h.messages;
    h.undecryptable.retain(|u| {
        !messages
            .iter()
            .any(|m| m.message_id == u.message_id && (u.sender.is_none() || m.sender == u.sender))
    });
}

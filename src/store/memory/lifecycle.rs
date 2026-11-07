//! Deletion and listing on the in-memory backend: unsend redaction,
//! thread listings, recovery-bundle touch/delete and mailbox purge
//! ([CB-38], [CB-39]).

use super::{MemoryBackend, State};
use crate::deletion::Redaction;
use crate::records::{AuthorRedaction, RedactionDef, datetime_from_ms};
use crate::{Error, Result};

impl State {
    /// Publishes one immutable per-message author redaction. The source batch
    /// remains untouched; readers overlay this record on every copy.
    pub(super) fn redact(
        &mut self,
        did: &str,
        thread_id: &str,
        message_id: &str,
        redaction: &Redaction,
    ) -> Result<usize> {
        if self
            .threads
            .get(thread_id)
            .is_some_and(|thread| thread.no_read.contains(did))
        {
            return Err(Error::Forbidden);
        }
        redaction.verify(did, thread_id, message_id)?;
        let current = self
            .chat_devices
            .get(did)
            .is_some_and(|d| d.current.contains(&redaction.transport_public_key));
        if !current {
            return Err(Error::Forbidden);
        }
        let mut stamped = redaction.clone();
        stamped.redacted_at = Some(datetime_from_ms(self.server_now));
        let record = AuthorRedaction::new(
            thread_id,
            message_id,
            &stamped,
            stamped
                .redacted_at
                .clone()
                .ok_or(Error::Malformed("redaction timestamp"))?,
        );
        let thread = self.threads.entry(thread_id.to_owned()).or_default();
        let count = thread
            .repos
            .get(did)
            .into_iter()
            .flat_map(|repo| repo.batches.values())
            .flat_map(|(batch, _)| &batch.items)
            .filter(|item| item.message_id == message_id)
            .count();
        let key = (did.to_owned(), message_id.to_owned());
        if let Some(existing) = thread.author_redactions.get(&key) {
            existing
                .to_redaction()?
                .verify(did, thread_id, message_id)?;
            if existing.thread_id != thread_id
                || existing.message_id != message_id
                || existing.rkey() != record.rkey()
            {
                return Err(Error::Conflict);
            }
            return Ok(count);
        }
        thread.author_redactions.insert(key, record);
        Ok(count)
    }

    /// See [`MemoryBackend::strip_items_for_test`].
    fn strip_items(&mut self, did: &str) -> usize {
        let at = datetime_from_ms(self.server_now);
        let mut n = 0;
        for t in self.threads.values_mut() {
            let Some(r) = t.repos.get_mut(did) else {
                continue;
            };
            for (b, _) in r.batches.values_mut() {
                for i in b.items.iter_mut().filter(|i| i.redaction.is_none()) {
                    i.signed_enc_message.0.clear();
                    i.redaction = Some(RedactionDef {
                        transport_pubkey: None,
                        sig: None,
                        redacted_at: Some(at.clone()),
                    });
                    n += 1;
                }
            }
        }
        n
    }

    /// Threads where `did` wrote a MEK or is a MEK recipient.
    pub(super) fn threads_of(&self, did: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .threads
            .iter()
            .filter(|(_, t)| {
                t.repos.iter().any(|(author, r)| {
                    author == did && !r.meks.is_empty()
                        || r.meks
                            .values()
                            .any(|(m, _)| m.recipients.iter().any(|x| x.did == did))
                })
            })
            .map(|(id, _)| id.clone())
            .collect();
        v.sort();
        v
    }

    pub(super) fn owner_threads(&self, did: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .mailboxes
            .get(did)
            .map(|m| {
                m.owner_batches
                    .values()
                    .map(|(b, _)| b.thread_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v.dedup();
        v
    }

    pub(super) fn touch_vdevice(&mut self, did: &str, id: &[u8; 16]) -> Result<()> {
        let now_ms = self.server_now;
        let now = datetime_from_ms(now_ms);
        let vd = self
            .mailboxes
            .get_mut(did)
            .and_then(|m| m.vdevices.get_mut(&hex::encode(id)))
            .ok_or(Error::NotFound("virtual device"))?;
        vd.last_used_at = Some(now);
        Ok(())
    }

    pub(super) fn delete_vdevice(&mut self, did: &str, id: &[u8; 16]) -> Result<()> {
        let m = self.mailboxes.get_mut(did);
        let _vd = m
            .and_then(|m| m.vdevices.remove(&hex::encode(id)))
            .ok_or(Error::NotFound("virtual device"))?;
        Ok(())
    }

    /// Erases `did`'s mailbox, public keys, and head chain.
    pub(super) fn purge(&mut self, did: &str) {
        self.mailboxes.remove(did);
        self.public_keys.remove(did);
        self.public_history.remove(did);
        self.ds_heads.remove(did);
    }
}

impl MemoryBackend {
    /// Adversarial server for tests: replaces every live item `did` wrote
    /// with a bare `{redactedAt}` removal and returns how many. mls-ds
    /// never writes redactions (G16); readers must refuse these.
    pub fn strip_items_for_test(&self, did: &str) -> usize {
        self.lock().strip_items(did)
    }
}

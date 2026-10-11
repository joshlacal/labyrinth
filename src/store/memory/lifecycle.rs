//! Deletion and listing on the in-memory backend: unsend redaction,
//! thread listings, recovery-bundle touch/delete and mailbox purge
//! ([CB-38], [CB-39]).

use super::{MemoryBackend, State};
use crate::deletion::{Redaction, ServerRedaction};
use crate::records::{RedactionDef, datetime_from_ms};
use crate::sign::{Ed25519Transport, TransportSigner};
use crate::{Error, Result};

impl State {
    /// Redacts every item of `did` with `message_id` in `thread_id`.
    pub(super) fn redact(
        &mut self,
        did: &str,
        thread_id: &str,
        message_id: &str,
        redaction: &Redaction,
    ) -> Result<usize> {
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
        let def = RedactionDef::from_redaction(&stamped);
        let mut n = 0;
        let repo = self
            .threads
            .get_mut(thread_id)
            .and_then(|t| t.repos.get_mut(did));
        for (b, _) in repo.into_iter().flat_map(|r| r.batches.values_mut()) {
            for i in b
                .items
                .iter_mut()
                .filter(|i| i.message_id == message_id && i.redaction.is_none())
            {
                i.signed_enc_message.0.clear();
                i.redaction = Some(def.clone());
                n += 1;
            }
        }
        if n == 0 {
            return Err(Error::NotFound("message"));
        }
        Ok(n)
    }

    /// mls-ds `deleteAccountData`: redact every live item `did` authored
    /// with the sequencer's account-deletion redaction (signed when it has
    /// a key; a bare `{redactedAt}` without [`MemoryBackend::set_sequencer`]),
    /// then purge.
    pub(super) fn delete_account_data(&mut self, did: &str) -> usize {
        let at = datetime_from_ms(self.server_now);
        let sequencer = self.sequencer.clone();
        let mut n = 0;
        for (thread_id, t) in self.threads.iter_mut() {
            for (b, _) in t
                .repos
                .get_mut(did)
                .into_iter()
                .flat_map(|r| r.batches.values_mut())
            {
                for i in b.items.iter_mut().filter(|i| i.redaction.is_none()) {
                    let def = match &sequencer {
                        None => RedactionDef::account_deletion(Some(at.clone())),
                        Some((by, seed)) => {
                            let signer = seed.map(|s| {
                                Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&s))
                            });
                            RedactionDef::from_server(&ServerRedaction::account_deletion(
                                by,
                                did,
                                thread_id,
                                &i.message_id,
                                &at,
                                signer.as_ref().map(|s| s as &dyn TransportSigner),
                            ))
                        }
                    };
                    i.signed_enc_message.0.clear();
                    i.redaction = Some(def);
                    n += 1;
                }
            }
        }
        self.purge(did);
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
        let now = datetime_from_ms(self.server_now);
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
        let vd = m
            .and_then(|m| m.vdevices.remove(&hex::encode(id)))
            .ok_or(Error::NotFound("virtual device"))?;
        if let Ok(k) = vd.device_key_pubkey.array::<32>("key") {
            self.orf.remove(&(did.to_owned(), k));
        }
        Ok(())
    }

    /// Erases `did`'s mailbox, public keys, head chain, ORF states and
    /// attachment references.
    pub(super) fn purge(&mut self, did: &str) {
        self.mailboxes.remove(did);
        self.public_keys.remove(did);
        self.public_history.remove(did);
        self.ds_heads.remove(did);
        self.orf.retain(|(owner, _), _| owner != did);
        self.purge_attachments(did);
    }
}

impl MemoryBackend {
    /// The server-side account deletion (mls-ds `deleteAccountData`):
    /// unsigned redactions of every item `did` authored, then a mailbox
    /// purge. Returns how many items were redacted.
    pub fn delete_account_data(&self, did: &str) -> usize {
        self.lock().delete_account_data(did)
    }
}

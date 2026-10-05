//! Attachment references on the in-memory ORF server ([CB-33]), with the
//! checks mls-ds makes: the caller has an ORF state, one message per blob,
//! the token MAC recomputes from the presented thread and message, and the
//! message still exists unredacted where the caller can read it.

use std::collections::HashMap;

use super::{MemoryBackend, State};
use crate::attachment::{INDEX_DOMAIN, TOKEN_DOMAIN, token_mac};
use crate::encoding::sha256;
use crate::orf::orf_server_map;
use crate::store::{AttachmentFetch, AttachmentPut};
use crate::{Error, Result};

#[derive(Default)]
pub(super) struct AttachState {
    /// (owner DID, index) → reference.
    refs: HashMap<(String, [u8; 32]), Ref>,
    /// blobId → digest of the one (thread, message) it may belong to.
    bound: HashMap<String, [u8; 32]>,
    /// The chat blob store (ciphertext bytes by blob id).
    pub(super) blobs: HashMap<String, Vec<u8>>,
}

struct Ref {
    blob_id: String,
    token_mac: [u8; 32],
}

fn message_digest(thread_id: &str, message_id: &str) -> [u8; 32] {
    sha256(crate::attachment::json_pair(thread_id, message_id).as_bytes())
}

impl State {
    fn orf_state(&self, did: &str, device: &[u8; 32]) -> Result<&crate::orf::OrfServerState> {
        self.orf
            .get(&(did.to_owned(), *device))
            .ok_or(Error::NotFound("orf state"))
    }

    /// The message exists unredacted in a thread item the caller can read,
    /// or in the caller's owner archive.
    fn message_live(&self, did: &str, thread_id: &str, message_id: &str) -> bool {
        let in_thread = self.threads.get(thread_id).is_some_and(|t| {
            !t.no_read.contains(did)
                && t.repos.values().any(|r| {
                    r.batches.values().any(|(b, _)| {
                        b.items
                            .iter()
                            .any(|i| i.message_id == message_id && i.redaction.is_none())
                    })
                })
        });
        in_thread
            || self.mailboxes.get(did).is_some_and(|m| {
                m.owner_batches.values().any(|(b, _)| {
                    b.thread_id == thread_id && b.items.iter().any(|i| i.message_id == message_id)
                })
            })
    }

    pub(super) fn put_attachment(
        &mut self,
        did: &str,
        device: &[u8; 32],
        p: &AttachmentPut,
    ) -> Result<()> {
        let s = self.orf_state(did, device)?;
        let index = orf_server_map(s, INDEX_DOMAIN, &p.blinded_index)?;
        let salt = orf_server_map(s, TOKEN_DOMAIN, &p.blinded_token_salt)?;
        if !self.attach.blobs.contains_key(&p.blob_id) {
            return Err(Error::NotFound("blob"));
        }
        if !self.message_live(did, &p.thread_id, &p.message_id) {
            return Err(Error::Forbidden);
        }
        let digest = message_digest(&p.thread_id, &p.message_id);
        if self
            .attach
            .bound
            .get(&p.blob_id)
            .is_some_and(|d| *d != digest)
        {
            return Err(Error::Conflict);
        }
        let mac = token_mac(&salt, &p.thread_id, &p.message_id);
        let key = (did.to_owned(), index);
        if let Some(r) = self.attach.refs.get(&key) {
            return if r.blob_id == p.blob_id && r.token_mac == mac {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        self.attach.bound.insert(p.blob_id.clone(), digest);
        self.attach.refs.insert(
            key,
            Ref {
                blob_id: p.blob_id.clone(),
                token_mac: mac,
            },
        );
        Ok(())
    }

    pub(super) fn fetch_attachment(
        &self,
        did: &str,
        device: &[u8; 32],
        f: &AttachmentFetch,
    ) -> Result<Vec<u8>> {
        let s = self.orf_state(did, device)?;
        let index = orf_server_map(s, INDEX_DOMAIN, &f.blinded_index)?;
        let salt = orf_server_map(s, TOKEN_DOMAIN, &f.blinded_token_salt)?;
        let r = self
            .attach
            .refs
            .get(&(did.to_owned(), index))
            .ok_or(Error::NotFound("attachment"))?;
        let mac = token_mac(&salt, &f.thread_id, &f.message_id);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&mac[..], &r.token_mac[..])) {
            return Err(Error::Forbidden);
        }
        if !self.message_live(did, &f.thread_id, &f.message_id) {
            return Err(Error::Forbidden);
        }
        self.attach
            .blobs
            .get(&r.blob_id)
            .cloned()
            .ok_or(Error::NotFound("blob"))
    }

    pub(super) fn delete_attachment(
        &mut self,
        did: &str,
        device: &[u8; 32],
        blinded: &crate::orf::ObliviousId,
    ) -> Result<()> {
        let s = self.orf_state(did, device)?;
        let index = orf_server_map(s, INDEX_DOMAIN, blinded)?;
        self.attach.refs.remove(&(did.to_owned(), index));
        Ok(())
    }

    /// Drops every reference of `did` (mailbox purge).
    pub(super) fn purge_attachments(&mut self, did: &str) {
        self.attach.refs.retain(|(owner, _), _| owner != did);
    }
}

impl MemoryBackend {
    /// Stores chat blob ciphertext under `blob_id` (models `chat.blobs`).
    pub fn put_blob(&self, blob_id: &str, bytes: &[u8]) {
        self.lock()
            .attach
            .blobs
            .insert(blob_id.to_owned(), bytes.to_vec());
    }

    /// How many attachment references `did` holds (for tests).
    pub fn attachment_ref_count(&self, did: &str) -> usize {
        self.lock()
            .attach
            .refs
            .keys()
            .filter(|(owner, _)| owner == did)
            .count()
    }
}

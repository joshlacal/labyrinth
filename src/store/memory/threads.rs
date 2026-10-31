//! [`ThreadStore`] over the in-memory conversation spaces.

use super::{MemoryBackend, ThreadSpace, create};
use crate::attachment::{AttachmentCiphertextMeta, verify_attachment_ciphertext};
use crate::deletion::Redaction;
use crate::records::{AttachmentManifest, Batch, MekDistribution};
use crate::store::{Stored, ThreadStore, TimeRange};
use crate::{Error, Result};

/// [`ThreadStore`] handle bound to one DID.
pub struct MemoryThreads {
    did: String,
    backend: MemoryBackend,
}

impl MemoryThreads {
    pub(super) fn new(did: &str, backend: MemoryBackend) -> Self {
        Self {
            did: did.to_owned(),
            backend,
        }
    }

    fn space<T>(
        &self,
        thread_id: &str,
        f: impl FnOnce(&mut ThreadSpace) -> Result<T>,
    ) -> Result<T> {
        let mut s = self.backend.lock();
        let t = s.threads.entry(thread_id.to_owned()).or_default();
        if t.no_read.contains(&self.did) {
            return Err(Error::Forbidden);
        }
        f(t)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ThreadStore for MemoryThreads {
    fn author(&self) -> &str {
        &self.did
    }

    async fn create_mek(&self, mek: &MekDistribution) -> Result<()> {
        let mut s = self.backend.lock();
        if s.threads
            .get(&mek.thread_id)
            .is_some_and(|t| t.no_read.contains(&self.did))
        {
            return Err(Error::Forbidden);
        }
        let exists = s.threads.get(&mek.thread_id).is_some_and(|t| {
            t.repos
                .get(&self.did)
                .is_some_and(|r| r.meks.contains_key(&mek.rkey()))
        });
        if exists {
            return Err(Error::Conflict);
        }
        let order = s.stamp_thread(&mek.thread_id);
        let t = s.threads.entry(mek.thread_id.clone()).or_default();
        let repo = t.repos.entry(self.did.clone()).or_default();
        create(&mut repo.meks, mek.rkey(), &(mek.clone(), order))
    }

    async fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> Result<Vec<Stored<MekDistribution>>> {
        let rkey = hex::encode(mek_id);
        self.space(thread_id, |t| {
            Ok(t.repos
                .iter()
                .filter_map(|(did, r)| {
                    r.meks.get(&rkey).map(|(m, order)| Stored {
                        author: did.clone(),
                        rkey: rkey.clone(),
                        value: m.clone(),
                        order: *order,
                    })
                })
                .collect())
        })
    }

    async fn append_batch(&self, batch: &Batch) -> Result<String> {
        let mut s = self.backend.lock();
        if s.threads
            .get(&batch.thread_id)
            .is_some_and(|t| t.no_read.contains(&self.did))
        {
            return Err(Error::Forbidden);
        }
        let tid = s.next_tid();
        let rkey = match batch.items.first().and_then(|i| i.seq) {
            Some(first_seq) => format!("{first_seq:016x}-{tid}"),
            None => tid,
        };
        let order = s.stamp_thread(&batch.thread_id);
        let t = s.threads.entry(batch.thread_id.clone()).or_default();
        let repo = t.repos.entry(self.did.clone()).or_default();
        create(&mut repo.batches, rkey.clone(), &(batch.clone(), order))?;
        Ok(rkey)
    }

    async fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<Stored<Batch>>> {
        self.space(thread_id, |t| {
            Ok(t.repos
                .iter()
                .filter(|(did, _)| sender.is_none_or(|s| s == did.as_str()))
                .flat_map(|(did, r)| {
                    r.batches
                        .iter()
                        .filter(|(_, (b, _))| b.items.iter().any(|i| range.contains(i.timestamp)))
                        .map(|(k, (b, order))| Stored {
                            author: did.clone(),
                            rkey: k.clone(),
                            value: b.clone(),
                            order: *order,
                        })
                })
                .collect())
        })
    }

    async fn list_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Stored<Batch>>> {
        let target = limit.max(1).saturating_add(1);
        let range = TimeRange {
            from_ms: None,
            until_ms: before_ms,
        };
        self.space(thread_id, |t| {
            let mut candidates: Vec<Stored<Batch>> = t
                .repos
                .iter()
                .flat_map(|(did, r)| {
                    r.batches
                        .iter()
                        .rev()
                        .filter(|(_, (b, _))| b.items.iter().any(|i| range.contains(i.timestamp)))
                        .map(|(k, (b, order))| Stored {
                            author: did.clone(),
                            rkey: k.clone(),
                            value: b.clone(),
                            order: *order,
                        })
                })
                .collect();
            candidates.sort_by_key(|b| core::cmp::Reverse(b.order.map(|o| o.labyrinth_seq)));
            let mut eligible = std::collections::BTreeSet::new();
            for b in &candidates {
                for i in &b.value.items {
                    if before_ms.is_none_or(|u| i.timestamp < u.saturating_sub(1)) {
                        eligible.insert((i.timestamp, i.message_id.clone()));
                    }
                }
                if eligible.len() >= target {
                    break;
                }
            }
            if let Some((floor, _)) = (eligible.len() >= target)
                .then(|| eligible.iter().rev().nth(target - 1))
                .flatten()
            {
                let floor = *floor;
                candidates.retain(|b| {
                    b.value
                        .items
                        .iter()
                        .any(|i| i.timestamp >= floor && before_ms.is_none_or(|u| i.timestamp < u))
                });
            }
            candidates.sort_by_key(|b| {
                core::cmp::Reverse(b.value.items.iter().map(|i| i.timestamp).max())
            });
            Ok(candidates)
        })
    }

    async fn list_threads(&self) -> Result<Vec<String>> {
        Ok(self.backend.lock().threads_of(&self.did))
    }

    async fn redact_item(
        &self,
        thread_id: &str,
        message_id: &str,
        redaction: &Redaction,
    ) -> Result<usize> {
        self.backend
            .lock()
            .redact(&self.did, thread_id, message_id, redaction)
    }

    async fn upload_and_commit_attachment(
        &self,
        thread_id: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> Result<String> {
        verify_attachment_ciphertext(ciphertext, meta)?;
        let mut s = self.backend.lock();
        if s.threads
            .get(thread_id)
            .is_some_and(|t| t.no_read.contains(&self.did))
        {
            return Err(Error::Forbidden);
        }
        let rkey = s.next_tid();
        let cid = s.store_blob(&self.did, ciphertext);
        let manifest = AttachmentManifest::from_meta(&cid, meta, created_at.to_owned());
        let t = s.threads.entry(thread_id.to_owned()).or_default();
        let repo = t.repos.entry(self.did.clone()).or_default();
        repo.attachments.insert(rkey.clone(), manifest);
        Ok(rkey)
    }

    async fn get_attachment_manifest(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> Result<Option<AttachmentManifest>> {
        self.space(thread_id, |t| {
            Ok(t.repos
                .get(author_did)
                .and_then(|r| r.attachments.get(rkey))
                .cloned())
        })
    }

    async fn get_attachment_verified(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> Result<Vec<u8>> {
        let s = self.backend.lock();
        let t = s.threads.get(thread_id).ok_or(Error::NotFound("thread"))?;
        if t.no_read.contains(&self.did) {
            return Err(Error::Forbidden);
        }
        let manifest = t
            .repos
            .get(author_did)
            .and_then(|r| r.attachments.get(rkey))
            .ok_or(Error::NotFound("attachmentManifest"))?;
        let (cid, meta) = manifest.to_meta()?;
        let bytes = s
            .blobs
            .get(&(author_did.to_owned(), cid))
            .ok_or(Error::NotFound("attachment blob"))?
            .clone();
        verify_attachment_ciphertext(&bytes, &meta)?;
        Ok(bytes)
    }

    async fn list_own_attachment_manifests(
        &self,
        thread_id: &str,
    ) -> Result<Vec<(String, AttachmentManifest)>> {
        self.space(thread_id, |t| {
            Ok(t.repos
                .get(&self.did)
                .map(|r| {
                    r.attachments
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .unwrap_or_default())
        })
    }

    async fn clear_records(&self, thread_id: &str) -> Result<()> {
        let mut s = self.backend.lock();
        if let Some(t) = s.threads.get_mut(thread_id) {
            if t.no_read.contains(&self.did) {
                return Err(Error::Forbidden);
            }
            t.repos.remove(&self.did);
        }
        Ok(())
    }
}

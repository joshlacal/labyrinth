//! [`ThreadStore`] over the in-memory conversation spaces.

use super::{MemoryBackend, ThreadSpace, create};
use crate::deletion::Redaction;
use crate::records::{Batch, MekDistribution};
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

impl ThreadStore for MemoryThreads {
    fn author(&self) -> &str {
        &self.did
    }

    fn create_mek(&self, mek: &MekDistribution) -> Result<()> {
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

    fn find_meks(
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

    fn append_batch(&self, batch: &Batch) -> Result<String> {
        let mut s = self.backend.lock();
        if s.threads
            .get(&batch.thread_id)
            .is_some_and(|t| t.no_read.contains(&self.did))
        {
            return Err(Error::Forbidden);
        }
        let tid = s.next_tid();
        let order = s.stamp_thread(&batch.thread_id);
        let t = s.threads.entry(batch.thread_id.clone()).or_default();
        let repo = t.repos.entry(self.did.clone()).or_default();
        create(&mut repo.batches, tid.clone(), &(batch.clone(), order))?;
        Ok(tid)
    }

    fn list_batches(
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

    fn list_threads(&self) -> Result<Vec<String>> {
        Ok(self.backend.lock().threads_of(&self.did))
    }

    fn redact_item(
        &self,
        thread_id: &str,
        message_id: &str,
        redaction: &Redaction,
    ) -> Result<usize> {
        self.backend
            .lock()
            .redact(&self.did, thread_id, message_id, redaction)
    }
}

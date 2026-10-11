//! The mls-ds epoch-head directory and the two head publishers (design
//! `docs/MLSDS_BACKEND.md` §1a): an append-only chain of every enrolled
//! DID's epoch heads, independent of the PDS `mailboxKeys` record.

use super::MemoryBackend;
use crate::mailbox::EpochPublic;
use crate::records::MailboxKeysRecord;
use crate::store::{ChatDeviceKey, KeyPublisher, MailboxDirectory, MemberDeviceKey, SequencerKey};
use crate::{Error, Result};

/// [`MailboxDirectory`] over the mls-ds head chain and the MLS device view.
pub struct MemoryDsDirectory {
    backend: MemoryBackend,
}

impl MemoryDsDirectory {
    pub(super) fn new(backend: MemoryBackend) -> Self {
        Self { backend }
    }
}

impl MailboxDirectory for MemoryDsDirectory {
    fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        let s = self.backend.lock();
        Ok(s.ds_heads
            .get(did)
            .and_then(|h| h.values().next_back())
            .cloned())
    }

    fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        let s = self.backend.lock();
        Ok(s.ds_heads.get(did).and_then(|h| h.get(&seq)).cloned())
    }

    fn device_transport_keys(&self, did: &str) -> Result<Vec<ChatDeviceKey>> {
        Ok(self.backend.chat_keys(did))
    }

    fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> Result<Option<Vec<MemberDeviceKey>>> {
        Ok(self.backend.member_keys(thread_id, did))
    }

    fn sequencer_key(&self, _thread_id: &str) -> Result<Option<SequencerKey>> {
        Ok(self.backend.sequencer_key())
    }
}

/// `publishEpochHead` for one DID.
pub struct MemoryDsPublisher {
    did: String,
    backend: MemoryBackend,
}

impl MemoryDsPublisher {
    pub(super) fn new(did: &str, backend: MemoryBackend) -> Self {
        Self {
            did: did.to_owned(),
            backend,
        }
    }
}

impl MemoryBackend {
    /// Records `epoch` as `did`'s next head with mls-ds's checks: the head
    /// verifies, a current chat device of `did` attested it, the number is
    /// 0 or the latest + 1 and its previous head is the stored one.
    /// Identical bytes for a recorded number succeed; different bytes fail
    /// with [`Error::Conflict`] (`EpochHeadConflict`).
    pub(crate) fn record_ds_head(&self, did: &str, epoch: &EpochPublic) -> Result<()> {
        epoch.verify(did, None)?;
        let current = self
            .chat_keys(did)
            .iter()
            .any(|k| k.is_current() && k.key == epoch.attestation.transport_public_key);
        if !current {
            return Err(Error::Unattested);
        }
        let mut s = self.lock();
        let chain = s.ds_heads.entry(did.to_owned()).or_default();
        if let Some(have) = chain.get(&epoch.seq) {
            return if have == epoch {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let contiguous = match chain.iter().next_back() {
            None => epoch.seq == 0,
            Some((n, prev)) => epoch.seq == n + 1 && epoch.prev_head == Some(prev.head),
        };
        if !contiguous {
            return Err(Error::Malformed("InvalidEpochChain"));
        }
        chain.insert(epoch.seq, epoch.clone());
        Ok(())
    }
}

impl KeyPublisher for MemoryDsPublisher {
    fn publish(&self, record: &MailboxKeysRecord) -> Result<()> {
        self.backend.record_ds_head(&self.did, &record.to_public()?)
    }

    fn retract(&self) -> Result<()> {
        self.backend.lock().ds_heads.remove(&self.did);
        Ok(())
    }
}

/// Writes one DID's public `mailboxKeys` records.
pub struct MemoryPdsPublisher {
    did: String,
    backend: MemoryBackend,
}

impl MemoryPdsPublisher {
    pub(super) fn new(did: &str, backend: MemoryBackend) -> Self {
        Self {
            did: did.to_owned(),
            backend,
        }
    }
}

impl KeyPublisher for MemoryPdsPublisher {
    fn publish(&self, record: &MailboxKeysRecord) -> Result<()> {
        self.backend.lock().publish_pds(&self.did, record)
    }

    fn retract(&self) -> Result<()> {
        let mut s = self.backend.lock();
        s.public_keys.remove(&self.did);
        s.public_history.remove(&self.did);
        Ok(())
    }
}

//! The `mls-ds` epoch-head directory and the two head publishers (`Gate 6`):
//! an append-only chain of every enrolled DID's `EpochPublicHeader`s with `floor_seq`,
//! independent of the PDS `mailboxKeys` record.

use super::MemoryBackend;
use crate::mailbox::EpochPublic;
use crate::records::MailboxKeysRecord;
use crate::store::{
    ChatDeviceKey, KeyPublisher, MailboxDirectory, MemberDeviceKey, SequencerKey,
    SequencerReceiptKey,
};
use crate::{Error, Result};

/// [`MailboxDirectory`] over the `mls-ds` head chain and the MLS device view.
pub struct MemoryDsDirectory {
    backend: MemoryBackend,
}

impl MemoryDsDirectory {
    pub(super) fn new(backend: MemoryBackend) -> Self {
        Self { backend }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for MemoryDsDirectory {
    async fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        let s = self.backend.lock();
        Ok(s.ds_heads
            .get(did)
            .and_then(|h| h.values().next_back())
            .cloned())
    }

    async fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        let s = self.backend.lock();
        Ok(s.ds_heads.get(did).and_then(|h| h.get(&seq)).cloned())
    }

    async fn epoch_chain(
        &self,
        did: &str,
    ) -> Result<Option<(Vec<labyrinth_protocol::EpochPublicHeader>, u64)>> {
        let s = self.backend.lock();
        let Some(chain) = s.ds_heads.get(did) else {
            return Ok(None);
        };
        if chain.is_empty() && !s.ds_floor_overrides.contains_key(did) {
            return Ok(None);
        }
        let headers = chain
            .values()
            .map(EpochPublic::to_protocol_header)
            .collect::<Vec<_>>();
        let floor_seq = s
            .ds_floor_overrides
            .get(did)
            .copied()
            .or_else(|| s.ds_floors.get(did).copied())
            .unwrap_or(0);
        Ok(Some((headers, floor_seq)))
    }

    async fn device_transport_keys(&self, did: &str) -> Result<Vec<ChatDeviceKey>> {
        Ok(self.backend.chat_keys(did))
    }

    async fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> Result<Option<Vec<MemberDeviceKey>>> {
        Ok(self.backend.member_keys(thread_id, did))
    }

    async fn sequencer_key(&self, _thread_id: &str) -> Result<Option<SequencerKey>> {
        Ok(self.backend.sequencer_key())
    }

    async fn sequencer_receipt_key(&self, thread_id: &str) -> Result<Option<SequencerReceiptKey>> {
        Ok(self.backend.receipt_key(thread_id))
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
    /// Records `epoch` as `did`'s next head with `mls-ds`'s checks.
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
            Some((n, prev)) => {
                epoch.seq == n + 1
                    && epoch.prev_head == Some(prev.head)
                    && epoch
                        .verify_link(prev.seq, &prev.head, &prev.keys.sig)
                        .is_ok()
            }
        };
        if !contiguous {
            return Err(Error::Malformed("InvalidEpochChain"));
        }
        chain.insert(epoch.seq, epoch.clone());
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyPublisher for MemoryDsPublisher {
    async fn publish(&self, record: &MailboxKeysRecord) -> Result<()> {
        self.backend.record_ds_head(&self.did, &record.to_public()?)
    }

    async fn retract(&self) -> Result<()> {
        let mut s = self.backend.lock();
        s.ds_heads.remove(&self.did);
        s.ds_floors.remove(&self.did);
        s.ds_floor_overrides.remove(&self.did);
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

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyPublisher for MemoryPdsPublisher {
    async fn publish(&self, record: &MailboxKeysRecord) -> Result<()> {
        self.backend.lock().publish_pds(&self.did, record)
    }

    async fn retract(&self) -> Result<()> {
        let mut s = self.backend.lock();
        s.public_keys.remove(&self.did);
        s.public_history.remove(&self.did);
        Ok(())
    }
}

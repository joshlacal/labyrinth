//! [`MailboxDirectory`] over the in-memory public repos and MLS view.

use super::MemoryBackend;
use crate::Result;
use crate::mailbox::EpochPublic;
use crate::store::{
    ChatDeviceKey, MailboxDirectory, MemberDeviceKey, SequencerKey, SequencerReceiptKey,
};

/// [`MailboxDirectory`] over the backend's public `mailboxKeys` records
/// (the PDS view) and its MLS device view.
pub struct MemoryDirectory {
    backend: MemoryBackend,
}

impl MemoryDirectory {
    pub(super) fn new(backend: MemoryBackend) -> Self {
        Self { backend }
    }

    /// Synchronous helper for test harnesses setting up chat device keys.
    pub fn device_transport_keys_sync(&self, did: &str) -> Vec<ChatDeviceKey> {
        self.backend.chat_keys(did)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for MemoryDirectory {
    async fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        let s = self.backend.lock();
        s.public_keys.get(did).map(|r| r.to_public()).transpose()
    }

    async fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        let s = self.backend.lock();
        s.public_history
            .get(did)
            .and_then(|h| h.get(&seq))
            .map(|r| r.to_public())
            .transpose()
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

//! [`MailboxDirectory`] over the in-memory public repos and MLS view.

use super::MemoryBackend;
use crate::Result;
use crate::mailbox::EpochPublic;
use crate::store::{ChatDeviceKey, MailboxDirectory, MemberDeviceKey, SequencerKey};

/// [`MailboxDirectory`] over the backend's public `mailboxKeys` records
/// (the PDS view) and its MLS device view.
pub struct MemoryDirectory {
    backend: MemoryBackend,
}

impl MemoryDirectory {
    pub(super) fn new(backend: MemoryBackend) -> Self {
        Self { backend }
    }
}

impl MailboxDirectory for MemoryDirectory {
    fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        let s = self.backend.lock();
        s.public_keys.get(did).map(|r| r.to_public()).transpose()
    }

    fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        let s = self.backend.lock();
        s.public_history
            .get(did)
            .and_then(|h| h.get(&seq))
            .map(|r| r.to_public())
            .transpose()
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

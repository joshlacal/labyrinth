//! [`OrfServer`] over in-memory server states ([CB-17]).

use super::MemoryBackend;
use crate::orf::{EvolveToken, ObliviousId, orf_server_evolve, orf_server_init, orf_server_map};
use crate::sign::XVerifyingKey;
use crate::store::OrfServer;
use crate::{Error, Result};

/// [`OrfServer`] handle bound to one DID.
pub struct MemoryOrf {
    did: String,
    backend: MemoryBackend,
}

impl MemoryOrf {
    pub(super) fn new(did: &str, backend: MemoryBackend) -> Self {
        Self {
            did: did.to_owned(),
            backend,
        }
    }

    fn key(&self, k: &XVerifyingKey) -> (String, [u8; 32]) {
        (self.did.clone(), k.0)
    }

    /// Whether `device_key` has a server state (for tests).
    pub fn has_state(&self, device_key: &XVerifyingKey) -> bool {
        self.backend.lock().orf.contains_key(&self.key(device_key))
    }
}

impl OrfServer for MemoryOrf {
    fn register(
        &self,
        device_key: &XVerifyingKey,
        parent: Option<(&XVerifyingKey, &EvolveToken)>,
    ) -> Result<()> {
        let mut s = self.backend.lock();
        if s.orf.contains_key(&self.key(device_key)) {
            return Err(Error::Conflict);
        }
        let state = match parent {
            None => orf_server_init()?,
            Some((p, token)) => {
                let parent = s
                    .orf
                    .get(&self.key(p))
                    .ok_or(Error::NotFound("orf state"))?;
                orf_server_evolve(parent, token)?
            }
        };
        s.orf.insert(self.key(device_key), state);
        Ok(())
    }

    fn map(&self, device_key: &XVerifyingKey, domain: &[u8], id: &ObliviousId) -> Result<[u8; 32]> {
        let s = self.backend.lock();
        let state = s
            .orf
            .get(&self.key(device_key))
            .ok_or(Error::NotFound("orf state"))?;
        orf_server_map(state, domain, id)
    }

    fn delete(&self, device_key: &XVerifyingKey) -> Result<()> {
        self.backend.lock().orf.remove(&self.key(device_key));
        Ok(())
    }
}

//! In-memory [`ShareStore`] for recovery-share tests: verifies the fetch
//! token like the delivery service does, logs every call, and can be told to
//! fail a given operation.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use labyrinth::recovery_share::{RecoveryShare, ShareStore, fetch_verifier};
use labyrinth::virtual_device::Mechanism;
use labyrinth::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Put([u8; 16]),
    Get([u8; 16]),
    Delete([u8; 16]),
}

#[derive(Default)]
struct Inner {
    shares: BTreeMap<[u8; 16], ([u8; 32], [u8; 32])>,
    log: Vec<Op>,
    fail_put: bool,
    fail_delete: bool,
    drop_on_put: bool,
}

/// Shared handle; clones see the same state.
#[derive(Clone)]
pub struct MemoryShares {
    did: String,
    inner: Arc<Mutex<Inner>>,
}

impl MemoryShares {
    pub fn new(did: &str) -> Self {
        Self {
            did: did.to_owned(),
            inner: Arc::default(),
        }
    }

    pub fn boxed(&self) -> Box<dyn ShareStore> {
        Box::new(self.clone())
    }

    pub fn log(&self) -> Vec<Op> {
        self.inner.lock().unwrap().log.clone()
    }

    pub fn ids(&self) -> Vec<[u8; 16]> {
        self.inner.lock().unwrap().shares.keys().copied().collect()
    }

    pub fn contains(&self, id: &[u8; 16]) -> bool {
        self.inner.lock().unwrap().shares.contains_key(id)
    }

    pub fn fail_put(&self, on: bool) {
        self.inner.lock().unwrap().fail_put = on;
    }

    pub fn fail_delete(&self, on: bool) {
        self.inner.lock().unwrap().fail_delete = on;
    }

    /// Acknowledge puts without storing anything.
    pub fn drop_on_put(&self, on: bool) {
        self.inner.lock().unwrap().drop_on_put = on;
    }

    pub fn remove(&self, id: &[u8; 16]) {
        self.inner.lock().unwrap().shares.remove(id);
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ShareStore for MemoryShares {
    async fn put_share(
        &self,
        vdevice_id: &[u8; 16],
        share: &RecoveryShare,
        verifier: &[u8; 32],
        _mechanism: Mechanism,
    ) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.log.push(Op::Put(*vdevice_id));
        if g.fail_put {
            return Err(Error::Backend("putRecoveryShare refused".into()));
        }
        if !g.drop_on_put {
            g.shares.insert(*vdevice_id, (*share.as_bytes(), *verifier));
        }
        Ok(())
    }

    async fn get_share(
        &self,
        vdevice_id: &[u8; 16],
        fetch_token: &[u8; 32],
    ) -> Result<Option<RecoveryShare>> {
        let mut g = self.inner.lock().unwrap();
        g.log.push(Op::Get(*vdevice_id));
        Ok(g.shares.get(vdevice_id).and_then(|(share, verifier)| {
            (fetch_verifier(&self.did, vdevice_id, fetch_token) == *verifier)
                .then(|| RecoveryShare::from_bytes(*share))
        }))
    }

    async fn delete_share(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        g.log.push(Op::Delete(*vdevice_id));
        if g.fail_delete {
            return Err(Error::Backend("deleteRecoveryShare refused".into()));
        }
        g.shares.remove(vdevice_id);
        Ok(())
    }
}

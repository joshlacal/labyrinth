//! The PDS side of the directory ([CB-19], [CB-28], [CB-29], Gate 3): the public
//! `blue.catbird.labyrinth.mailboxKeys` records in each account's own ATProto
//! repo, with `swapRecord` optimistic CAS on `mailboxKeys/self`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::mailbox::EpochPublic;
use crate::records::MailboxKeysRecord;
use crate::store::{ChatDeviceKey, KeyPublisher, MailboxDirectory, MaybeSend, MaybeSync};
use crate::{Error, Result};

/// rkey of the latest-epoch record.
pub const SELF_RKEY: &str = "self";

/// rkey of the immutable copy of epoch `seq`.
pub fn epoch_rkey(seq: u64) -> String {
    format!("{seq:012}")
}

/// Transport for `blue.catbird.labyrinth.mailboxKeys` in public ATProto repos.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait PublicRepoBackend: MaybeSend + MaybeSync {
    /// Writes `rkey` in `did`'s repo with compare-and-swap semantics:
    /// - `swap_cid: None` enforces create-if-absent (`Conflict` if `rkey` exists);
    /// - `swap_cid: Some(cid)` enforces `swapRecord` CAS (`Conflict` on `InvalidSwap`).
    async fn put_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
        record: &[u8],
        swap_cid: Option<&str>,
    ) -> Result<String>;

    /// `getRecord` from `did`'s repo, returning `(record_json_bytes, cid)`.
    async fn get_mailbox_keys(&self, did: &str, rkey: &str) -> Result<Option<(Vec<u8>, String)>>;

    /// Delete every `mailboxKeys` record in the signed-in account's repo.
    async fn delete_all_mailbox_keys(&self, did: &str) -> Result<()>;
}

/// Typed helper over [`PublicRepoBackend`] exposing `swapRecord` CAS (`Gate 3`).
pub struct PdsRecords<'a> {
    backend: &'a dyn PublicRepoBackend,
}

impl<'a> PdsRecords<'a> {
    pub fn new(backend: &'a dyn PublicRepoBackend) -> Self {
        Self { backend }
    }

    pub async fn get_mailbox_keys_with_cid(
        &self,
        did: &str,
    ) -> Result<Option<(MailboxKeysRecord, String)>> {
        self.get_rkey_with_cid(did, SELF_RKEY).await
    }

    pub async fn get_rkey_with_cid(
        &self,
        did: &str,
        rkey: &str,
    ) -> Result<Option<(MailboxKeysRecord, String)>> {
        let Some((bytes, cid)) = self.backend.get_mailbox_keys(did, rkey).await? else {
            return Ok(None);
        };
        let rec: MailboxKeysRecord = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Malformed("pds mailboxKeys record"))?;
        Ok(Some((rec, cid)))
    }

    pub async fn put_mailbox_keys_cas(
        &self,
        did: &str,
        rkey: &str,
        record: &MailboxKeysRecord,
        swap_cid: Option<&str>,
    ) -> Result<String> {
        let bytes = serde_json::to_vec(record)
            .map_err(|e| Error::Backend(format!("pds serialize: {e}")))?;
        self.backend
            .put_mailbox_keys(did, rkey, &bytes, swap_cid)
            .await
    }
}

/// Reads any account's `mailboxKeys` records from PDS.
pub struct PdsDirectory {
    records: Arc<dyn PublicRepoBackend>,
}

impl PdsDirectory {
    pub fn new(records: impl Into<Arc<dyn PublicRepoBackend>>) -> Self {
        Self {
            records: records.into(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for PdsDirectory {
    async fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        PdsRecords::new(self.records.as_ref())
            .get_rkey_with_cid(did, SELF_RKEY)
            .await?
            .map(|(r, _)| r.to_public())
            .transpose()
    }

    async fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        let e = PdsRecords::new(self.records.as_ref())
            .get_rkey_with_cid(did, &epoch_rkey(seq))
            .await?
            .map(|(r, _)| r.to_public())
            .transpose()?;
        if e.as_ref().is_some_and(|e| e.seq != seq) {
            return Err(Error::Malformed("pds epoch record under the wrong number"));
        }
        Ok(e)
    }

    async fn device_transport_keys(&self, _did: &str) -> Result<Vec<ChatDeviceKey>> {
        Err(Error::NotSupported("chat device keys are not in the PDS"))
    }
}

/// Writes the signed-in account's `mailboxKeys` records using `swapRecord` CAS.
pub struct PdsPublisher {
    records: Arc<dyn PublicRepoBackend>,
    did: String,
}

impl PdsPublisher {
    pub fn new(records: impl Into<Arc<dyn PublicRepoBackend>>, did: &str) -> Self {
        Self {
            records: records.into(),
            did: did.to_owned(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyPublisher for PdsPublisher {
    async fn publish(&self, record: &MailboxKeysRecord) -> Result<()> {
        let helper = PdsRecords::new(self.records.as_ref());
        let rkey = epoch_rkey(record.current.epoch_number);
        match helper.get_rkey_with_cid(&self.did, &rkey).await? {
            Some((existing, _)) if existing.current != record.current => {
                return Err(Error::Conflict);
            }
            Some(_) => {}
            None => {
                helper
                    .put_mailbox_keys_cas(&self.did, &rkey, record, None)
                    .await?;
            }
        }
        let existing = helper.get_mailbox_keys_with_cid(&self.did).await?;
        let mut swap_cid: Option<String> = None;
        if let Some((existing_rec, cid)) = existing {
            if let Ok(existing_pub) = existing_rec.to_public()
                && existing_pub.verify(&self.did, None).is_ok()
                && existing_pub.seq > record.current.epoch_number
            {
                return Err(Error::EpochRollback {
                    pinned: existing_pub.seq,
                    offered: record.current.epoch_number,
                });
            }
            swap_cid = Some(cid);
        }
        helper
            .put_mailbox_keys_cas(&self.did, SELF_RKEY, record, swap_cid.as_deref())
            .await?;
        Ok(())
    }

    async fn retract(&self) -> Result<()> {
        self.records.delete_all_mailbox_keys(&self.did).await
    }
}

/// In-memory public ATProto repo host enforcing `swapRecord` CAS CID checks.
#[derive(Clone, Default)]
pub struct MemoryPublicRepoHost {
    #[allow(clippy::type_complexity)]
    repos: Arc<Mutex<HashMap<(String, String), (Vec<u8>, String)>>>,
    seq: Arc<AtomicU64>,
}

impl MemoryPublicRepoHost {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn client(&self, caller_did: &str) -> PublicRepoClient {
        PublicRepoClient {
            host: self.clone(),
            caller_did: caller_did.to_owned(),
        }
    }

    /// Overwrite a record directly for adversarial test scenarios (e.g. PDS rollback/tamper).
    pub fn force_overwrite(&self, did: &str, rkey: &str, record: &MailboxKeysRecord) {
        let bytes = serde_json::to_vec(record).expect("json");
        let cid = self.compute_cid(&bytes);
        self.repos
            .lock()
            .unwrap()
            .insert((did.to_owned(), rkey.to_owned()), (bytes, cid));
    }

    /// Remove a single record directly for adversarial/backfill test scenarios.
    pub fn remove_raw(&self, did: &str, rkey: &str) -> Option<Vec<u8>> {
        self.repos
            .lock()
            .unwrap()
            .remove(&(did.to_owned(), rkey.to_owned()))
            .map(|(b, _)| b)
    }

    fn compute_cid(&self, bytes: &[u8]) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut h = Sha256::new();
        h.update(bytes);
        h.update(n.to_be_bytes());
        format!("bafyreie{}", hex::encode(&h.finalize()[..16]))
    }
}

/// Authenticated client handle for [`MemoryPublicRepoHost`].
#[derive(Clone)]
pub struct PublicRepoClient {
    host: MemoryPublicRepoHost,
    caller_did: String,
}

impl From<PublicRepoClient> for Arc<dyn PublicRepoBackend> {
    fn from(c: PublicRepoClient) -> Self {
        Arc::new(c)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl PublicRepoBackend for PublicRepoClient {
    async fn put_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
        record: &[u8],
        swap_cid: Option<&str>,
    ) -> Result<String> {
        if did != self.caller_did {
            return Err(Error::Forbidden);
        }
        let mut repos = self.host.repos.lock().unwrap();
        let key = (did.to_owned(), rkey.to_owned());
        match swap_cid {
            Some(expected_cid) => match repos.get(&key) {
                Some((_, current_cid)) if current_cid == expected_cid => {}
                _ => return Err(Error::Conflict),
            },
            None => {
                if repos.contains_key(&key) {
                    return Err(Error::Conflict);
                }
            }
        }
        let cid = self.host.compute_cid(record);
        repos.insert(key, (record.to_vec(), cid.clone()));
        Ok(cid)
    }

    async fn get_mailbox_keys(&self, did: &str, rkey: &str) -> Result<Option<(Vec<u8>, String)>> {
        Ok(self
            .host
            .repos
            .lock()
            .unwrap()
            .get(&(did.to_owned(), rkey.to_owned()))
            .cloned())
    }

    async fn delete_all_mailbox_keys(&self, did: &str) -> Result<()> {
        if did != self.caller_did {
            return Err(Error::Forbidden);
        }
        self.host.repos.lock().unwrap().retain(|(d, _), _| d != did);
        Ok(())
    }
}

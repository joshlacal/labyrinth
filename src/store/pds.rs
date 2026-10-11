//! The PDS side of the directory ([CB-19], [CB-28], [CB-29]): the public
//! `blue.catbird.labyrinth.mailboxKeys` records in each account's own atproto
//! repo, as an independent [`MailboxDirectory`] and [`KeyPublisher`].
//!
//! The crate holds no atproto client. The embedding app implements
//! [`PdsRecords`] (catbird-mls forwards it to the platform, which owns the
//! PDS session): `putRecord`/`getRecord`/`deleteRecord` on
//! `blue.catbird.labyrinth.mailboxKeys` with the record JSON as bytes.
//!
//! Layout: `mailboxKeys/self` is the latest epoch and
//! `mailboxKeys/<12-digit epochNumber>` an immutable per-epoch copy, which
//! is what lets a reader walk the `prev_sig` chain ([CB-29]). Wrap a
//! [`PdsDirectory`] and the mls-ds directory in a
//! [`crate::client::CompositeDirectory`] so neither can lie alone.

use std::sync::Arc;

use crate::mailbox::EpochPublic;
use crate::records::MailboxKeysRecord;
use crate::store::{ChatDeviceKey, KeyPublisher, MailboxDirectory};
use crate::{Error, Result};

/// rkey of the latest-epoch record.
pub const SELF_RKEY: &str = "self";

/// rkey of the immutable copy of epoch `seq`.
pub fn epoch_rkey(seq: u64) -> String {
    format!("{seq:012}")
}

/// `blue.catbird.labyrinth.mailboxKeys` records in atproto repos. Every
/// method may block. Failures are strings; they surface as
/// [`Error::Backend`].
pub trait PdsRecords: Send + Sync {
    /// `putRecord` into the signed-in account's own repo (create or
    /// replace). `record` is the record JSON, `$type` included.
    fn put_mailbox_keys(&self, rkey: &str, record: &[u8]) -> core::result::Result<(), String>;
    /// `getRecord` from `did`'s repo; `None` if the record does not exist.
    fn get_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
    ) -> core::result::Result<Option<Vec<u8>>, String>;
    /// Delete every `mailboxKeys` record in the signed-in account's repo
    /// (account deletion).
    fn delete_all_mailbox_keys(&self) -> core::result::Result<(), String>;
}

fn backend(e: String) -> Error {
    Error::Backend(format!("pds: {e}"))
}

fn get(r: &dyn PdsRecords, did: &str, rkey: &str) -> Result<Option<MailboxKeysRecord>> {
    r.get_mailbox_keys(did, rkey)
        .map_err(backend)?
        .map(|b| serde_json::from_slice(&b).map_err(|_| Error::Malformed("pds mailboxKeys record")))
        .transpose()
}

/// Reads any account's `mailboxKeys` records. Chat device keys and the
/// leaf view are not in the PDS: those calls fail with
/// [`Error::NotSupported`], and [`crate::client::CompositeDirectory`] takes
/// them from mls-ds.
pub struct PdsDirectory {
    records: Arc<dyn PdsRecords>,
}

impl PdsDirectory {
    pub fn new(records: Arc<dyn PdsRecords>) -> Self {
        Self { records }
    }
}

impl MailboxDirectory for PdsDirectory {
    fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        get(self.records.as_ref(), did, SELF_RKEY)?
            .map(|r| r.to_public())
            .transpose()
    }

    fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        let e = get(self.records.as_ref(), did, &epoch_rkey(seq))?
            .map(|r| r.to_public())
            .transpose()?;
        if e.as_ref().is_some_and(|e| e.seq != seq) {
            return Err(Error::Malformed("pds epoch record under the wrong number"));
        }
        Ok(e)
    }

    fn device_transport_keys(&self, _did: &str) -> Result<Vec<ChatDeviceKey>> {
        Err(Error::NotSupported("chat device keys are not in the PDS"))
    }
}

/// Writes the signed-in account's `mailboxKeys` records.
pub struct PdsPublisher {
    records: Arc<dyn PdsRecords>,
    did: String,
}

impl PdsPublisher {
    /// `did` is the signed-in account whose repo `records` writes.
    pub fn new(did: &str, records: Arc<dyn PdsRecords>) -> Self {
        Self {
            records,
            did: did.to_owned(),
        }
    }
}

impl KeyPublisher for PdsPublisher {
    /// Writes the per-epoch copy first (create-if-absent by reading back:
    /// the same epoch is accepted, a different one under its number is
    /// [`Error::Conflict`]), then `self`.
    fn publish(&self, record: &MailboxKeysRecord) -> Result<()> {
        let rkey = epoch_rkey(record.current.epoch_number);
        match get(self.records.as_ref(), &self.did, &rkey)? {
            Some(existing) if existing.current != record.current => return Err(Error::Conflict),
            Some(_) => {}
            None => {
                let bytes = serde_json::to_vec(record).map_err(|e| backend(e.to_string()))?;
                self.records
                    .put_mailbox_keys(&rkey, &bytes)
                    .map_err(backend)?;
            }
        }
        let bytes = serde_json::to_vec(record).map_err(|e| backend(e.to_string()))?;
        self.records
            .put_mailbox_keys(SELF_RKEY, &bytes)
            .map_err(backend)
    }

    fn retract(&self) -> Result<()> {
        self.records.delete_all_mailbox_keys().map_err(backend)
    }
}

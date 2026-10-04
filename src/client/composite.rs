//! A [`MailboxDirectory`] that cross-checks two independent sources of
//! epoch heads ([CB-28], [CB-29]; design `docs/MLSDS_BACKEND.md` §1a, §1c).
//!
//! The two sources are the DID's PDS (`mailboxKeys/self` and the
//! per-epoch copies) and the mls-ds head chain (`getEpochHead`). Each can
//! lie alone; [`CompositeDirectory`] reports a head only if both agree
//! along a verified chain:
//!
//! - equal heads: accepted;
//! - one newer: accepted only through a verified `prev_sig` chain from
//!   the older one (intermediate epochs are fetched from both sources,
//!   which must agree on each);
//! - anything else, including two different heads for one number: a fork,
//!   [`Error::DirectoryFork`].
//!
//! A source with nothing for the DID defers to the other. Chat device keys
//! and the per-conversation leaf view come from mls-ds, which owns them.
//!
//! Used as the client's directory, this makes the [CB-28] truncation check
//! ([`super::Labyrinth::check_epoch_integrity`]) compare the mailbox
//! against the newest head *either* directory knows, so truncation needs
//! the mailbox host and the other directory to collude.

use super::pins::MAX_PIN_ADVANCE;
use crate::mailbox::EpochPublic;
use crate::store::{ChatDeviceKey, MailboxDirectory, MemberDeviceKey};
use crate::{Error, Result};

/// Cross-checking directory over the PDS and mls-ds. See the module docs.
pub struct CompositeDirectory {
    pds: Box<dyn MailboxDirectory + Send>,
    ds: Box<dyn MailboxDirectory + Send>,
}

impl CompositeDirectory {
    /// `pds` serves the public `mailboxKeys` records; `ds` the mls-ds head
    /// chain, chat device keys and leaf view.
    pub fn new(
        pds: Box<dyn MailboxDirectory + Send>,
        ds: Box<dyn MailboxDirectory + Send>,
    ) -> Self {
        Self { pds, ds }
    }

    /// The newer of two verified heads, if it chains from the older one.
    fn reconcile(&self, did: &str, pds: EpochPublic, ds: EpochPublic) -> Result<EpochPublic> {
        pds.verify(did, None)?;
        ds.verify(did, None)?;
        let fork = Error::DirectoryFork {
            pds: pds.seq,
            ds: ds.seq,
        };
        if pds.seq == ds.seq {
            return if pds.head == ds.head {
                Ok(ds)
            } else {
                Err(fork)
            };
        }
        let (older, newer) = if pds.seq < ds.seq {
            (pds, ds)
        } else {
            (ds, pds)
        };
        if newer.seq - older.seq > MAX_PIN_ADVANCE {
            return Err(Error::Malformed("directory epoch gap too long"));
        }
        let mut prev = older;
        for seq in prev.seq + 1..newer.seq {
            let e = self
                .epoch(did, seq)?
                .ok_or(Error::NotFound("intermediate directory epoch"))?;
            if e.seq != seq {
                return Err(Error::Malformed("directory epoch under the wrong number"));
            }
            e.verify(did, None)?;
            e.verify_link(prev.seq, &prev.head, &prev.keys.sig)
                .map_err(|_| fork.clone())?;
            prev = e;
        }
        newer
            .verify_link(prev.seq, &prev.head, &prev.keys.sig)
            .map_err(|_| fork)?;
        Ok(newer)
    }
}

impl MailboxDirectory for CompositeDirectory {
    fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        match (self.pds.latest(did)?, self.ds.latest(did)?) {
            (Some(p), Some(d)) => self.reconcile(did, p, d).map(Some),
            (p, d) => Ok(p.or(d)),
        }
    }

    fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        match (self.pds.epoch(did, seq)?, self.ds.epoch(did, seq)?) {
            (Some(p), Some(d)) if p.head != d.head => {
                Err(Error::DirectoryFork { pds: seq, ds: seq })
            }
            (p, d) => Ok(d.or(p)),
        }
    }

    fn device_transport_keys(&self, did: &str) -> Result<Vec<ChatDeviceKey>> {
        self.ds.device_transport_keys(did)
    }

    fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> Result<Option<Vec<MemberDeviceKey>>> {
        self.ds.member_device_keys(thread_id, did)
    }
}

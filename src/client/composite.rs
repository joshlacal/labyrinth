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
//! A head present in only one source is incomplete evidence and fails with
//! [`Error::DirectoryIncomplete`]. Both sources returning nothing still means
//! the DID is not enrolled. Callers that intentionally accept degraded,
//! single-source trust-on-first-use must opt in with
//! [`CompositeDirectory::new_allowing_single_source`]. Chat device keys and
//! the per-conversation leaf view come from mls-ds, which owns them.
//!
//! Used as the client's directory, this makes the [CB-28] truncation check
//! ([`super::Labyrinth::check_epoch_integrity`]) compare the mailbox against
//! the newest head the two directories can jointly anchor. An incomplete
//! view blocks the check instead of weakening it to one source, so truncation
//! needs the mailbox host and the other directory to collude.

use super::pins::MAX_PIN_ADVANCE;
use crate::mailbox::EpochPublic;
use crate::store::{ChatDeviceKey, MailboxDirectory, MemberDeviceKey, SequencerKey};
use crate::{Error, Result};

/// Cross-checking directory over the PDS and mls-ds. See the module docs.
pub struct CompositeDirectory {
    pds: Box<dyn MailboxDirectory + Send>,
    ds: Box<dyn MailboxDirectory + Send>,
    allow_single_source: bool,
}

impl CompositeDirectory {
    /// `pds` serves the public `mailboxKeys` records; `ds` the mls-ds head
    /// chain, chat device keys and leaf view.
    pub fn new(
        pds: Box<dyn MailboxDirectory + Send>,
        ds: Box<dyn MailboxDirectory + Send>,
    ) -> Self {
        Self {
            pds,
            ds,
            allow_single_source: false,
        }
    }

    /// A degraded, trust-on-first-use composition that accepts a head from
    /// one source when the other has no record. Prefer [`Self::new`]: this
    /// policy lets the sole source choose a first-contact epoch.
    pub fn new_allowing_single_source(
        pds: Box<dyn MailboxDirectory + Send>,
        ds: Box<dyn MailboxDirectory + Send>,
    ) -> Self {
        Self {
            pds,
            ds,
            allow_single_source: true,
        }
    }

    fn one_source(
        &self,
        did: &str,
        seq: Option<u64>,
        pds: Option<EpochPublic>,
        ds: Option<EpochPublic>,
    ) -> Result<Option<EpochPublic>> {
        debug_assert!(pds.is_some() ^ ds.is_some());
        if self.allow_single_source {
            let e = pds.or(ds).expect("one source present");
            if let Some(s) = seq
                && e.seq != s
            {
                return Err(Error::Malformed("directory epoch under the wrong number"));
            }
            e.verify(did, None)?;
            Ok(Some(e))
        } else {
            Err(Error::DirectoryIncomplete {
                pds_present: pds.is_some(),
                ds_present: ds.is_some(),
            })
        }
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
        // Strict composition requires independent evidence for the newer
        // endpoint too. A source whose mutable `latest` lags may still have
        // the immutable per-epoch record (the PDS publisher writes that
        // first), but the other source alone may not choose the recipient
        // epoch at first contact.
        if !self.allow_single_source {
            let endpoint = self
                .epoch(did, newer.seq)?
                .ok_or(Error::DirectoryIncomplete {
                    pds_present: false,
                    ds_present: false,
                })?;
            if endpoint.seq != newer.seq || endpoint.head != newer.head {
                return Err(fork);
            }
            endpoint.verify(did, None)?;
        }
        let mut prev = older;
        for seq in prev.seq + 1..newer.seq {
            let e = self.epoch(did, seq)?.ok_or(Error::DirectoryIncomplete {
                pds_present: false,
                ds_present: false,
            })?;
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
            (None, None) => Ok(None),
            (p, d) => self.one_source(did, None, p, d),
        }
    }

    fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        match (self.pds.epoch(did, seq)?, self.ds.epoch(did, seq)?) {
            (Some(p), Some(d)) => {
                if p.seq != seq || d.seq != seq {
                    return Err(Error::Malformed("directory epoch under the wrong number"));
                }
                p.verify(did, None)?;
                d.verify(did, None)?;
                if p.head != d.head {
                    Err(Error::DirectoryFork { pds: seq, ds: seq })
                } else {
                    Ok(Some(d))
                }
            }
            (None, None) => Ok(None),
            (p, d) => self.one_source(did, Some(seq), p, d),
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

    /// The DS's own answer first; the PDS side only if the DS has none.
    fn sequencer_key(&self, thread_id: &str) -> Result<Option<SequencerKey>> {
        match self.ds.sequencer_key(thread_id)? {
            Some(k) => Ok(Some(k)),
            None => self.pds.sequencer_key(thread_id),
        }
    }
}

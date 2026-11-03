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
use crate::store::{
    ChatDeviceKey, MailboxDirectory, MemberDeviceKey, SequencerKey, SequencerReceiptKey,
};
use crate::{Error, Result};

fn map_protocol_error(err: labyrinth_protocol::ProtocolError) -> Error {
    use labyrinth_protocol::ProtocolError as PE;
    match err {
        PE::EpochRollback {
            latest_seq,
            floor_seq,
        } => Error::EpochRollback {
            pinned: floor_seq,
            offered: latest_seq,
        },
        PE::BadPublicKey(_) => Error::BadPublicKey,
        PE::BadEpochSignature(_) | PE::BadReceiptSignature => Error::BadSignature,
        PE::ReceiptCommitmentMismatch => Error::ReceiptCommitmentMismatch,
        PE::ReceiptAuthorityMismatch { .. } | PE::ReceiptKeyIdMismatch { .. } => {
            Error::Malformed("sequencer receipt authority or key_id mismatch")
        }
        PE::MalformedEpochChain(msg) | PE::MalformedReceipt(msg) => Error::Malformed(msg),
    }
}

/// Cross-checking directory over the PDS and `mls-ds` (`Gate 6`).
pub struct CompositeDirectory {
    pds: Box<dyn MailboxDirectory>,
    ds: Box<dyn MailboxDirectory>,
    allow_single_source: bool,
}

impl CompositeDirectory {
    /// `pds` serves the public `mailboxKeys` records; `ds` the `mls-ds` head
    /// chain (`L-F01` `floor_seq`), chat device keys and leaf view.
    pub fn new(pds: Box<dyn MailboxDirectory>, ds: Box<dyn MailboxDirectory>) -> Self {
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
        pds: Box<dyn MailboxDirectory>,
        ds: Box<dyn MailboxDirectory>,
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
    async fn reconcile(&self, did: &str, pds: EpochPublic, ds: EpochPublic) -> Result<EpochPublic> {
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
        if !self.allow_single_source {
            let endpoint = self
                .epoch(did, newer.seq)
                .await?
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
            let e = self
                .epoch(did, seq)
                .await?
                .ok_or(Error::DirectoryIncomplete {
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

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for CompositeDirectory {
    async fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        let pds_opt = self.pds.latest(did).await?;
        if let Some((headers, floor_seq)) = self.ds.epoch_chain(did).await? {
            if headers.is_empty() {
                if floor_seq > 0 {
                    return Err(Error::EpochRollback {
                        pinned: floor_seq,
                        offered: pds_opt.as_ref().map_or(0, |p| p.seq),
                    });
                }
                return match pds_opt {
                    None => Ok(None),
                    Some(p) => self.one_source(did, None, Some(p), None),
                };
            }
            let verified = labyrinth_protocol::verify_epoch_public_chain(did, &headers, floor_seq)
                .map_err(map_protocol_error)?;
            let ds_latest = self
                .ds
                .latest(did)
                .await?
                .ok_or(Error::Malformed("ds epoch_chain non-empty without latest"))?;
            if ds_latest.seq != verified.latest.seq || ds_latest.head != verified.latest.head {
                return Err(Error::Malformed("ds latest diverges from ds epoch_chain"));
            }
            return match pds_opt {
                Some(p) => {
                    if p.seq < floor_seq {
                        return Err(Error::EpochRollback {
                            pinned: floor_seq,
                            offered: p.seq,
                        });
                    }
                    self.reconcile(did, p, ds_latest).await.map(Some)
                }
                None => self.one_source(did, None, None, Some(ds_latest)),
            };
        }

        match (pds_opt, self.ds.latest(did).await?) {
            (Some(p), Some(d)) => self.reconcile(did, p, d).await.map(Some),
            (None, None) => Ok(None),
            (p, d) => self.one_source(did, None, p, d),
        }
    }

    async fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        match (
            self.pds.epoch(did, seq).await?,
            self.ds.epoch(did, seq).await?,
        ) {
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

    async fn epoch_chain(
        &self,
        did: &str,
    ) -> Result<Option<(Vec<labyrinth_protocol::EpochPublicHeader>, u64)>> {
        self.ds.epoch_chain(did).await
    }

    async fn device_transport_keys(&self, did: &str) -> Result<Vec<ChatDeviceKey>> {
        self.ds.device_transport_keys(did).await
    }

    async fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> Result<Option<Vec<MemberDeviceKey>>> {
        self.ds.member_device_keys(thread_id, did).await
    }

    /// The DS's own answer first; the PDS side only if the DS has none.
    async fn sequencer_key(&self, thread_id: &str) -> Result<Option<SequencerKey>> {
        match self.ds.sequencer_key(thread_id).await? {
            Some(k) => Ok(Some(k)),
            None => self.pds.sequencer_key(thread_id).await,
        }
    }

    async fn sequencer_receipt_key(&self, thread_id: &str) -> Result<Option<SequencerReceiptKey>> {
        match self.ds.sequencer_receipt_key(thread_id).await? {
            Some(k) => Ok(Some(k)),
            None => self.pds.sequencer_receipt_key(thread_id).await,
        }
    }

    async fn sequencer_receipt_key_for_authority(
        &self,
        thread_id: &str,
        expected_authority: &str,
    ) -> Result<Option<SequencerReceiptKey>> {
        match self
            .ds
            .sequencer_receipt_key_for_authority(thread_id, expected_authority)
            .await?
        {
            Some(key) => Ok(Some(key)),
            None => {
                self.pds
                    .sequencer_receipt_key_for_authority(thread_id, expected_authority)
                    .await
            }
        }
    }
}

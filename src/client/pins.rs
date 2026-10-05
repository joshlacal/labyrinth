//! Peer epoch pinning ([CB-29]).
//!
//! A sender addresses MEKs to each roster member's *latest* epoch, as the
//! [`crate::store::MailboxDirectory`] reports it. A directory (the peer's
//! PDS) that replays an older, still-attested `epochPublic` would make the
//! sender encrypt to keys a revoked device still holds. So the client pins,
//! per DID it addresses, the newest `(seq, head)` it has accepted:
//!
//! - an offered epoch older than the pin, or with the pinned `seq` but a
//!   different head, fails with [`Error::EpochRollback`];
//! - a newer epoch is accepted only through a verified `prev_sig` chain
//!   from the pinned head, fetching every intermediate epoch from the
//!   directory ([`crate::store::MailboxDirectory::epoch`]);
//! - first contact is trust-on-first-use, anchored by the [CB-18]
//!   attestation the caller has already checked.
//!
//! A peer that legitimately resets its mailbox (account purge, then a new
//! genesis) fails the pin forever with [`Error::EpochRollback`]. The way
//! out is user-confirmed, like a Signal safety-number change:
//! [`Labyrinth::propose_repin`] verifies the new chain from its genesis,
//! which must be attested by a *current* chat device of the DID, and shows
//! the old and new safety numbers; [`Labyrinth::repin_peer`] replaces the
//! pin only with the head the user confirmed.
//!
//! Long term the latest heads should travel in MLS-authenticated group
//! state, which removes the first-contact gap.

use super::Labyrinth;
use crate::mailbox::EpochPublic;
use crate::sign::XVerifyingKey;
use crate::store::VouchAt;
use crate::{Error, Result};

/// The most epochs a client walks to advance one pin. A legitimate account
/// rotates only on revocation; a longer gap is treated as an attack on the
/// client's time rather than walked.
pub const MAX_PIN_ADVANCE: u64 = 4096;

/// The newest epoch of a peer this client has accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerPin {
    pub seq: u64,
    pub head: [u8; 32],
    /// That epoch's mailbox signing key: it signs the next epoch's `prev_sig`.
    pub sig_key: XVerifyingKey,
}

impl PeerPin {
    pub fn of(e: &EpochPublic) -> Self {
        Self {
            seq: e.seq,
            head: e.head,
            sig_key: e.keys.sig,
        }
    }
}

impl Labyrinth {
    /// The pinned epoch of `did`, if this client has addressed it.
    pub fn peer_pin(&self, did: &str) -> Option<&PeerPin> {
        self.pins.get(did)
    }

    /// Checks `epoch` (already verified and attested for `did`) against the
    /// pin for `did` and advances the pin. See the module docs.
    pub(super) fn pin_peer(&mut self, did: &str, epoch: &EpochPublic) -> Result<()> {
        let Some(pin) = self.pins.get(did).cloned() else {
            self.pins.insert(did.to_owned(), PeerPin::of(epoch));
            return Ok(());
        };
        let rollback = Error::EpochRollback {
            pinned: pin.seq,
            offered: epoch.seq,
        };
        if epoch.seq < pin.seq || (epoch.seq == pin.seq && epoch.head != pin.head) {
            return Err(rollback);
        }
        if epoch.seq == pin.seq {
            return Ok(());
        }
        if epoch.seq - pin.seq > MAX_PIN_ADVANCE {
            return Err(Error::Malformed("peer epoch chain gap too long"));
        }
        let mut prev = pin;
        for seq in prev.seq + 1..epoch.seq {
            let e = self
                .b
                .directory
                .epoch(did, seq)?
                .ok_or(Error::NotFound("intermediate peer epoch"))?;
            if e.seq != seq {
                return Err(Error::Malformed("directory epoch under the wrong number"));
            }
            e.verify(did, None)?;
            e.verify_link(prev.seq, &prev.head, &prev.sig_key)?;
            prev = PeerPin::of(&e);
        }
        epoch.verify_link(prev.seq, &prev.head, &prev.sig_key)?;
        self.pins.insert(did.to_owned(), PeerPin::of(epoch));
        Ok(())
    }
}

/// A peer's new epoch chain, verified and waiting for the user to accept
/// the safety-number change ([`Labyrinth::repin_peer`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepinProposal {
    pub did: String,
    /// The pinned epoch it replaces (`None` if the peer was never pinned).
    pub pinned_seq: Option<u64>,
    /// The safety number with the pinned head (`None` if never pinned).
    pub old_safety_number: Option<String>,
    /// The peer's latest epoch on the new chain.
    pub offered_seq: u64,
    pub offered_head: [u8; 32],
    /// The safety number with the new head: show it, and the change.
    pub new_safety_number: String,
}

impl Labyrinth {
    /// `did`'s latest published epoch, verified as a chain from its own
    /// genesis (epoch 0): the genesis must be attested by a *current* chat
    /// device of `did` per the directory ([CB-18]), every link must verify,
    /// and the latest epoch must itself be attested by a current device.
    fn verified_fresh_chain(&self, did: &str) -> Result<EpochPublic> {
        let latest = self
            .b
            .directory
            .latest(did)?
            .ok_or(Error::NotFound("peer epoch"))?;
        if latest.seq > MAX_PIN_ADVANCE {
            return Err(Error::Malformed("peer epoch chain gap too long"));
        }
        let genesis = self
            .b
            .directory
            .epoch(did, 0)?
            .ok_or(Error::NotFound("peer genesis epoch"))?;
        if genesis.seq != 0 {
            return Err(Error::Malformed("directory epoch under the wrong number"));
        }
        self.check_attested(did, &genesis, VouchAt::Current)?;
        let mut prev = PeerPin::of(&genesis);
        for seq in 1..=latest.seq {
            let e = if seq == latest.seq {
                latest.clone()
            } else {
                self.b
                    .directory
                    .epoch(did, seq)?
                    .ok_or(Error::NotFound("intermediate peer epoch"))?
            };
            if e.seq != seq {
                return Err(Error::Malformed("directory epoch under the wrong number"));
            }
            e.verify(did, None)?;
            e.verify_link(prev.seq, &prev.head, &prev.sig_key)?;
            prev = PeerPin::of(&e);
        }
        if prev.head != latest.head {
            return Err(Error::Malformed(
                "peer chain does not end at its latest epoch",
            ));
        }
        self.check_attested(did, &latest, VouchAt::Current)?;
        Ok(latest)
    }

    /// Verifies `did`'s current chain from its genesis (see
    /// [`repin_peer`](Self::repin_peer)) and returns the safety-number
    /// change to show the user. Changes nothing.
    pub fn propose_repin(&self, did: &str) -> Result<RepinProposal> {
        let latest = self.verified_fresh_chain(did)?;
        let me = self.latest_public()?.head;
        let pin = self.pins.get(did);
        Ok(RepinProposal {
            did: did.to_owned(),
            pinned_seq: pin.map(|p| p.seq),
            old_safety_number: pin
                .map(|p| crate::fingerprint::safety_number((&self.did, &me), (did, &p.head))),
            offered_seq: latest.seq,
            offered_head: latest.head,
            new_safety_number: crate::fingerprint::safety_number(
                (&self.did, &me),
                (did, &latest.head),
            ),
        })
    }

    /// User-confirmed re-pin after a peer reset its mailbox: re-verifies
    /// the chain as [`propose_repin`](Self::propose_repin) does and
    /// replaces the pin, but only if its latest head is still
    /// `confirmed_head` (the one whose safety number the user accepted);
    /// otherwise [`Error::Conflict`] and nothing changes.
    pub fn repin_peer(&mut self, did: &str, confirmed_head: &[u8; 32]) -> Result<PeerPin> {
        let latest = self.verified_fresh_chain(did)?;
        if latest.head != *confirmed_head {
            return Err(Error::Conflict);
        }
        let pin = PeerPin::of(&latest);
        self.pins.insert(did.to_owned(), pin.clone());
        Ok(pin)
    }
}

impl Labyrinth {
    /// This account's current fingerprint ([CB-41]): 30 digits over the
    /// newest epoch head this device reached.
    pub fn own_fingerprint(&self) -> Result<String> {
        let head = self.latest_public()?.head;
        Ok(crate::fingerprint::account_digits(&self.did, &head))
    }

    /// The 60-digit safety number between this account's current head and
    /// the head this client pinned for `did` ([CB-29]); both people should
    /// see the same number. [`crate::Error::NotFound`] until `did` was addressed.
    pub fn safety_number_with(&self, did: &str) -> Result<String> {
        let pin = self
            .pins
            .get(did)
            .ok_or(crate::Error::NotFound("peer pin"))?;
        let head = self.latest_public()?.head;
        Ok(crate::fingerprint::safety_number(
            (&self.did, &head),
            (did, &pin.head),
        ))
    }
}

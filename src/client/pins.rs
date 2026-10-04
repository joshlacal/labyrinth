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
//! Long term the latest heads should travel in MLS-authenticated group
//! state, which removes the first-contact gap.

use super::Labyrinth;
use crate::mailbox::EpochPublic;
use crate::sign::XVerifyingKey;
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

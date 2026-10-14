//! Message Encryption Keys (SPEC §7.3, paper p.38–41).
//!
//! A [`Mek`] is a 32-byte secret shared by every Labyrinth-enrolled DID in a
//! conversation, the sender included ([CB-16]). Its id binds it to the
//! *roster hash* of the recipients' epoch heads, so any roster change (add,
//! remove, or a member opening a new epoch) forces a fresh MEK.
//!
//! Distribution and opening live in [`distribute`].

pub mod distribute;

use zeroize::Zeroizing;

use crate::encoding::{hex, kdf, minos_salt, random, sha256};

pub use distribute::{
    MekRecipient, MekRecord, MekSender, distribute_labyrinth, distribute_transport, open,
};

/// `sha256("mek_recipient_list:" || hex(head_0) || hex(head_1) || …)` with the
/// hex strings sorted ascending (SPEC §7.3). Input order does not matter.
pub fn roster_hash(heads: &[[u8; 32]]) -> [u8; 32] {
    let mut hexes: Vec<String> = heads.iter().map(|h| hex(h)).collect();
    hexes.sort_unstable();
    let mut buf = b"mek_recipient_list:".to_vec();
    for h in &hexes {
        buf.extend_from_slice(h.as_bytes());
    }
    sha256(&buf)
}

/// `kdf(mek, MINOS_SALT, "minos.kdf.mek.mek_id:recipient_roster_hash=" || hex(rosterHash), 12)`.
pub fn mek_id(secret: &[u8; 32], roster_hash: &[u8; 32]) -> [u8; 12] {
    let info = format!(
        "minos.kdf.mek.mek_id:recipient_roster_hash={}",
        hex(roster_hash)
    );
    let mut id = [0u8; 12];
    kdf(secret, Some(&minos_salt()), info.as_bytes(), &mut id);
    id
}

/// How a MEK was authenticated; drives reuse rule 2 (p.38–39).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MekProvenance {
    /// Generated locally and not yet distributed. Never reusable.
    Unsent,
    /// Hawk-authenticated by the sender's mailbox auth key of this epoch.
    Labyrinth {
        sender_did: String,
        sender_epoch_head: [u8; 32],
    },
    /// Authenticated only by a chat transport key (non-enrolled sender).
    /// `created_here` is true on the device that minted it ([CB-23]).
    Transport {
        transport_pub: [u8; 32],
        created_here: bool,
    },
}

/// A Message Encryption Key with its id, roster hash and provenance.
#[derive(Clone)]
pub struct Mek {
    id: [u8; 12],
    secret: Zeroizing<[u8; 32]>,
    roster_hash: [u8; 32],
    provenance: MekProvenance,
}

impl core::fmt::Debug for Mek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mek")
            .field("id", &hex(&self.id))
            .field("roster_hash", &hex(&self.roster_hash))
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl Mek {
    /// A fresh random MEK for the roster whose latest epoch heads are `heads`.
    pub fn generate(heads: &[[u8; 32]]) -> crate::Result<Self> {
        let mut secret = Zeroizing::new([0u8; 32]);
        random(&mut *secret)?;
        Ok(Self::from_secret(
            secret,
            roster_hash(heads),
            MekProvenance::Unsent,
        ))
    }

    /// Rebuild a MEK from persisted parts (the id is re-derived).
    pub fn from_secret(
        secret: Zeroizing<[u8; 32]>,
        roster_hash: [u8; 32],
        provenance: MekProvenance,
    ) -> Self {
        Self {
            id: mek_id(&secret, &roster_hash),
            secret,
            roster_hash,
            provenance,
        }
    }

    pub fn id(&self) -> &[u8; 12] {
        &self.id
    }
    pub fn roster_hash(&self) -> &[u8; 32] {
        &self.roster_hash
    }
    pub fn provenance(&self) -> &MekProvenance {
        &self.provenance
    }
    /// The raw secret, for a MEK cache that persists it encrypted at rest.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub(crate) fn set_provenance(&mut self, p: MekProvenance) {
        self.provenance = p;
    }

    /// Reuse rule (p.38–39): a cached MEK may encrypt a new message only if
    ///
    /// 1. its roster hash equals `roster_hash(current_heads)`, where
    ///    `current_heads` is the caller's view of the latest epoch head of every
    ///    enrolled DID in the MLS group, the caller included ([CB-16]); and
    /// 2. it is authenticated to the latest epoch keys of some participant.
    ///    For a Labyrinth MEK that is the sender's epoch auth key, so rule 2
    ///    holds iff `sender_epoch_head` is one of `current_heads` (a rotated
    ///    sender epoch fails rule 1 as well). A transport MEK is authenticated
    ///    by no epoch; only the device that minted it may reuse it ([CB-23]).
    ///
    /// On top of the paper's rules, only a MEK that `my_did` minted (any of
    /// its devices) is reusable ([CB-42]): a reader can check only its own
    /// recipient entry, so a peer's MEK may be blackholed for another member.
    pub fn reusable_for(&self, my_did: &str, current_heads: &[[u8; 32]]) -> bool {
        if roster_hash(current_heads) != self.roster_hash {
            return false;
        }
        match &self.provenance {
            MekProvenance::Unsent => false,
            MekProvenance::Labyrinth {
                sender_did,
                sender_epoch_head,
            } => sender_did == my_did && current_heads.contains(sender_epoch_head),
            MekProvenance::Transport { created_here, .. } => *created_here,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_hash_is_order_independent_and_matches_formula() {
        let a = [0xaau8; 32];
        let b = [0x01u8; 32];
        assert_eq!(roster_hash(&[a, b]), roster_hash(&[b, a]));
        let expected = sha256(format!("mek_recipient_list:{}{}", hex(&b), hex(&a)).as_bytes());
        assert_eq!(roster_hash(&[a, b]), expected);
        assert_ne!(roster_hash(&[a]), roster_hash(&[a, b]));
    }

    #[test]
    fn mek_id_binds_secret_and_roster() {
        let m = Mek::generate(&[[1u8; 32]]).unwrap();
        assert_eq!(*m.id(), mek_id(m.secret(), m.roster_hash()));
        assert_ne!(*m.id(), mek_id(m.secret(), &roster_hash(&[[2u8; 32]])));
        assert!(!format!("{m:?}").contains(&hex(m.secret())));
    }

    #[test]
    fn reuse_rule() {
        let heads = [[1u8; 32], [2u8; 32]];
        let mut m = Mek::generate(&heads).unwrap();
        assert!(!m.reusable_for("did:plc:a", &heads), "unsent MEK");
        m.set_provenance(MekProvenance::Labyrinth {
            sender_did: "did:plc:a".into(),
            sender_epoch_head: heads[0],
        });
        assert!(m.reusable_for("did:plc:a", &[heads[1], heads[0]]));
        assert!(
            !m.reusable_for("did:plc:b", &[heads[1], heads[0]]),
            "peer-minted"
        );
        assert!(!m.reusable_for("did:plc:a", &heads[..1]));
        assert!(!m.reusable_for("did:plc:a", &[heads[0], [3u8; 32]]));
        m.set_provenance(MekProvenance::Transport {
            transport_pub: [9; 32],
            created_here: false,
        });
        assert!(!m.reusable_for("did:plc:a", &heads));
        m.set_provenance(MekProvenance::Transport {
            transport_pub: [9; 32],
            created_here: true,
        });
        assert!(m.reusable_for("did:plc:a", &heads));
    }
}

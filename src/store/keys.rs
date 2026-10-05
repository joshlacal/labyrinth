//! Which chat device keys may vouch for a record ([CB-18], [CB-27]).
//!
//! A chat device key signs messages and attests epochs. Once the device is
//! removed, its key must stop vouching for anything written afterwards.
//! *When* a record was written comes from one of two places:
//!
//! - **Server order** ([`ServerOrder`], mls-ds): the receive time on the
//!   server clock and the conversation's chat sequence number at the
//!   write. A key vouches only if the record was received before the key
//!   was revoked account-wide, and, where the backend reports the
//!   conversation's leaves ([`MemberDeviceKey`]), only while the device
//!   had a leaf in that conversation. A removed device cannot backdate
//!   these.
//! - **The sender's timestamp** (the Space backend): the fallback when a
//!   record carries no server order. A removed device can backdate it;
//!   SPEC §10 keeps that as a residual risk for Space-stored threads.

/// The signing key of the DS that sequences a conversation: it signs the
/// redactions the DS applies on its own ([CB-38] account deletion).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequencerKey {
    /// The DS's DID (`defs#redaction.by`).
    pub did: String,
    /// Its Ed25519 redaction signing key.
    pub key: [u8; 32],
}

/// One chat device transport key in the MLS device view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatDeviceKey {
    pub key: [u8; 32],
    /// When the device was revoked account-wide (ms since the Unix epoch).
    /// mls-ds reports its server clock here, the same clock as
    /// [`ServerOrder::received_at_ms`].
    pub removed_at: Option<u64>,
}

impl ChatDeviceKey {
    /// A current device.
    pub fn current(key: [u8; 32]) -> Self {
        Self {
            key,
            removed_at: None,
        }
    }

    pub fn is_current(&self) -> bool {
        self.removed_at.is_none()
    }

    /// Whether this key may vouch for something timestamped `at_ms`:
    /// always while current, otherwise only strictly before removal.
    pub fn valid_at(&self, at_ms: u64) -> bool {
        self.removed_at.is_none_or(|r| at_ms < r)
    }
}

/// One device leaf in a conversation's MLS group, with the chat sequence
/// numbers of the commits that added and removed it (mls-ds
/// `chat.member_devices`). Revoking a device account-wide does not remove
/// its leaves, so this bound is separate from [`ChatDeviceKey::removed_at`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberDeviceKey {
    pub key: [u8; 32],
    pub joined_chat_seq: u64,
    pub removed_chat_seq: Option<u64>,
}

impl MemberDeviceKey {
    /// Whether the leaf existed when the conversation's last entry was
    /// `chat_seq`: joined at or before it, removed strictly after it.
    pub fn active_at(&self, chat_seq: u64) -> bool {
        self.joined_chat_seq <= chat_seq && self.removed_chat_seq.is_none_or(|r| chat_seq < r)
    }
}

/// The order a server assigned to a record when it was written (mls-ds
/// `defs#serverOrder`). The sender cannot choose any of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerOrder {
    /// Per-conversation (or, for owner batches, per-mailbox) write counter.
    pub labyrinth_seq: u64,
    /// The conversation's last chat entry seq at the write, linearized
    /// against MLS commits. `None` outside a conversation.
    pub chat_seq: Option<u64>,
    /// Receive time on the server clock (ms since the Unix epoch).
    pub received_at_ms: u64,
}

/// The point in time a key must have been valid at to vouch for a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VouchAt {
    /// Now: only current keys (addressing a new MEK, [CB-18]).
    Current,
    /// The sender's own timestamp (records without server order).
    SenderClaim(u64),
    /// The server's stamp on the record.
    Server(ServerOrder),
}

impl VouchAt {
    /// The server stamp if there is one, else the sender's claim.
    pub fn of(order: Option<ServerOrder>, sender_claim_ms: u64) -> Self {
        order.map_or(Self::SenderClaim(sender_claim_ms), Self::Server)
    }
}

/// The keys of `keys` that may vouch for a record written at `at`.
///
/// `leaves` is the author's leaves in the record's conversation, when the
/// backend reports them and the key must be a conversation leaf (message
/// signatures and transport MEKs; not epoch attestations, whose device
/// need not be in this conversation). It only applies to a server stamp
/// that carries a `chat_seq`.
pub fn keys_valid_for(
    keys: &[ChatDeviceKey],
    leaves: Option<&[MemberDeviceKey]>,
    at: VouchAt,
) -> Vec<[u8; 32]> {
    keys.iter()
        .filter(|k| match at {
            VouchAt::Current => k.is_current(),
            VouchAt::SenderClaim(t) => k.valid_at(t),
            VouchAt::Server(o) => {
                k.valid_at(o.received_at_ms)
                    && match (leaves, o.chat_seq) {
                        (Some(l), Some(s)) => l.iter().any(|m| m.key == k.key && m.active_at(s)),
                        _ => true,
                    }
            }
        })
        .map(|k| k.key)
        .collect()
}

/// The keys of `keys` that are current (`at_ms = None`) or valid at `at_ms`
/// by the sender's timestamp. Equivalent to [`keys_valid_for`] without
/// server order.
pub fn keys_valid_at(keys: &[ChatDeviceKey], at_ms: Option<u64>) -> Vec<[u8; 32]> {
    keys_valid_for(
        keys,
        None,
        at_ms.map_or(VouchAt::Current, VouchAt::SenderClaim),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(received_at_ms: u64, chat_seq: Option<u64>) -> VouchAt {
        VouchAt::Server(ServerOrder {
            labyrinth_seq: 1,
            chat_seq,
            received_at_ms,
        })
    }

    #[test]
    fn server_order_bounds_account_and_leaf_removal() {
        let keys = [
            ChatDeviceKey::current([1; 32]),
            ChatDeviceKey {
                key: [2; 32],
                removed_at: Some(100),
            },
        ];
        // Account revocation by receive time, not the sender's claim.
        assert_eq!(keys_valid_for(&keys, None, stamp(99, None)).len(), 2);
        assert_eq!(keys_valid_for(&keys, None, stamp(100, None)), [[1; 32]]);
        // Leaf removal by chat seq; a key with no leaf never vouches.
        let leaves = [MemberDeviceKey {
            key: [1; 32],
            joined_chat_seq: 3,
            removed_chat_seq: Some(7),
        }];
        let l = Some(&leaves[..]);
        assert!(keys_valid_for(&keys, l, stamp(1, Some(2))).is_empty());
        assert_eq!(keys_valid_for(&keys, l, stamp(1, Some(3))), [[1; 32]]);
        assert_eq!(keys_valid_for(&keys, l, stamp(1, Some(6))), [[1; 32]]);
        assert!(keys_valid_for(&keys, l, stamp(1, Some(7))).is_empty());
        // Without a chat seq the leaf view is not consulted.
        assert_eq!(keys_valid_for(&keys, l, stamp(1, None)).len(), 2);
        // The fallback keeps the sender-claim rule.
        assert_eq!(keys_valid_at(&keys, Some(99)).len(), 2);
        assert_eq!(keys_valid_at(&keys, None), [[1; 32]]);
    }
}

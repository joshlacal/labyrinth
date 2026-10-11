//! Crate error type.

/// Every fallible operation in the crate returns this error.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("authentication failed")]
    Decrypt,
    #[error("invalid signature")]
    BadSignature,
    #[error("invalid public key")]
    BadPublicKey,
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    #[error("device is not a member of this epoch")]
    NotEpochMember,
    #[error("recovery code is invalid or uncorrectable")]
    BadRecoveryCode,
    #[error("unsupported version or suite: {0}")]
    Unsupported(u8),
    #[error("store conflict: record already exists")]
    Conflict,
    #[error("store refused access")]
    Forbidden,
    #[error("storage backend error: {0}")]
    Backend(String),
    #[error("epoch chain truncated: published epoch {published}, reached {reached}")]
    EpochTruncated { published: u64, reached: u64 },
    #[error("peer epoch rolled back or forked: pinned epoch {pinned}, offered {offered}")]
    EpochRollback { pinned: u64, offered: u64 },
    #[error(
        "directories disagree on the account's epoch chain: PDS epoch {pds}, mls-ds epoch {ds}"
    )]
    DirectoryFork { pds: u64, ds: u64 },
    #[error("epoch is not attested by one of the account's chat devices")]
    Unattested,
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("not a recipient of this MEK")]
    NotRecipient,
    #[error("MEK roster hash does not match its recipients")]
    RosterMismatch,
    #[error("epoch does not match the one the record names")]
    WrongEpoch,
    #[error("MEK id does not match the MEK")]
    MekMismatch,
    #[error("randomness unavailable")]
    Rng,
    /// [CB-40] The store holds epoch `seq` (the create-if-absent race
    /// guard), but it does not chain from this device's epoch: it is not
    /// signed by the previous epoch's mailbox key, its opener is not a
    /// valid member of the previous epoch (or is locally revoked), or its
    /// entropy does not open. No rotation can succeed until the backend
    /// removes it, so the client reports it instead of retrying.
    #[error("epoch {seq} is squatted by an invalid record: {reason}")]
    EpochSquatted { seq: u64, reason: &'static str },
    /// [CB-25] A member this client already verified in the epoch being
    /// rotated now fails verification: the store altered a record it had
    /// served intact. Rotation aborts rather than silently evicting it.
    #[error("a member this device verified in epoch {seq} no longer verifies")]
    MemberTampered { seq: u64 },
    /// The backend does not provide this operation (yet), e.g. an mls-ds
    /// endpoint whose lexicon is not wired into the XRPC stores.
    #[error("operation not supported by this backend: {0}")]
    NotSupported(&'static str),
}

pub type Result<T> = core::result::Result<T, Error>;

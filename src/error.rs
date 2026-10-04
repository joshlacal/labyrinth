//! Crate error type.

/// Every fallible operation in the crate returns this error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
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
}

pub type Result<T> = core::result::Result<T, Error>;

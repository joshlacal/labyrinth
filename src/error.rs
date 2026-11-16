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
    #[error("virtual device record names a non-virtual or active physical device")]
    DeviceTampered,
    #[error("unsupported version or suite: {0}")]
    Unsupported(u8),
    #[error("store conflict: record already exists")]
    Conflict,
    #[error("pending ciphertext must be flushed or discarded before revocation")]
    PendingWrites,
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
    #[error(
        "directory evidence is incomplete: PDS present {pds_present}, mls-ds present {ds_present}"
    )]
    DirectoryIncomplete { pds_present: bool, ds_present: bool },
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
    /// Epoch `seq` was written to the mailbox store, but anchoring its head in
    /// the public directory failed. The client keeps `pending_directory_publication`
    /// set so the caller can retry [`crate::client::Labyrinth::publish_latest_keys`]
    /// or reconcile a lost race via [`crate::client::Labyrinth::recover_unanchored_fork`].
    #[error("epoch {seq} was written to mailbox store but directory publication failed: {reason}")]
    EpochUnanchored { seq: u64, reason: String },
    /// The backend does not provide this operation (yet), e.g. an mls-ds
    /// endpoint whose lexicon is not wired into the XRPC stores.
    #[error("operation not supported by this backend: {0}")]
    NotSupported(&'static str),
    /// [Gate 1 / I13] Archived item `(frame_nonce, payload_bytes)` or sequencer
    /// receipt does not match `receipt.payload.archive_commitment`.
    #[error("archived item commitment does not match sequencer receipt")]
    ReceiptCommitmentMismatch,
    /// Space host offered a writer commit revision older than the highest
    /// revision this client already observed for `(space, author)`.
    #[error(
        "space writer revision rolled back for {author} in {space}: pinned {pinned_rev}, offered {offered_rev}"
    )]
    WriterRollback {
        space: String,
        author: String,
        pinned_rev: String,
        offered_rev: String,
    },
    /// A Space response could not be authenticated: no host KEM key is known
    /// for the Space and the transport does not authenticate responses itself.
    /// The read is refused instead of trusting unauthenticated bytes.
    #[error("space response authentication unavailable: {0}")]
    Unauthenticated(&'static str),
    /// A writer whose repository this client already authenticated in the
    /// Space is no longer served. Its history is reported as withheld rather
    /// than silently dropped.
    #[error("space writer {author} is withheld in {space}")]
    WriterWithheld { space: String, author: String },
}

pub type Result<T> = core::result::Result<T, Error>;

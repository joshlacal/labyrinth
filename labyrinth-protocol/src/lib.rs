//! Shared zero-secrets Labyrinth protocol verification primitives (`I13` receipts,
//! blinded `archive_commitment`, `EpochPublic` chain + `membersHash`, and `L-F01` rollback floors).

pub mod epoch_chain;
pub mod limits;
pub mod receipt;
pub mod transcripts;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("malformed sequencer receipt: {0}")]
    MalformedReceipt(&'static str),
    #[error("sequencer receipt authority mismatch: expected {expected}, got {got}")]
    ReceiptAuthorityMismatch { expected: String, got: String },
    #[error("sequencer receipt key_id mismatch: expected {expected}, got {got}")]
    ReceiptKeyIdMismatch { expected: String, got: String },
    #[error("invalid sequencer receipt ES256 signature")]
    BadReceiptSignature,
    #[error("archived item (frame_nonce, payload) does not match receipt archive_commitment")]
    ReceiptCommitmentMismatch,
    #[error("invalid public key: {0}")]
    BadPublicKey(&'static str),
    #[error("invalid epoch signature: {0}")]
    BadEpochSignature(&'static str),
    #[error("malformed epoch chain: {0}")]
    MalformedEpochChain(&'static str),
    #[error("epoch chain rollback detected: latest seq {latest_seq} < floor seq {floor_seq}")]
    EpochRollback { latest_seq: u64, floor_seq: u64 },
}

pub type Result<T> = core::result::Result<T, ProtocolError>;

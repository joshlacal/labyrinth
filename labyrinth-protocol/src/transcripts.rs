//! Canonical domain-separation labels and transcript prefixes shared across
//! `labyrinth`, `catbird-mls`, and `mls-ds`.

/// Domain label for v2 `I13` ES256 sequencer receipts.
pub const RECEIPT_DOMAIN_V2: &[u8] = b"catbird-mls-sequencer-receipt-v2\0";

/// Required DID verification-method fragment for sequencer receipt signing keys.
pub const RECEIPT_VERIFICATION_FRAGMENT: &str = "#mls-receipt-1";

/// Domain label for the original sender's archive attestation.
pub const ORIGINAL_SENDER_ARCHIVE_DOMAIN: &[u8] = b"catbird.labyrinth.original_sender_archive.v1\0";

/// XEdDSA self-signature prefix over `epochHead`.
pub const EPOCH_SELF_SIG_PREFIX: &[u8] = b"minos.unstructured_signature.epoch_self:";

/// XEdDSA predecessor-link signature prefix over `epochHead`.
pub const EPOCH_PREV_SIG_PREFIX: &[u8] = b"minos.unstructured_signature.epoch_prev:";

/// `[CB-18]` Ed25519 chat-device attestation prefix over `did || ":" || epochHead`.
pub const EPOCH_ATTEST_PREFIX: &str = "catbird.labyrinth.epoch_head_attest:";

/// `[CB-36]` Ed25519 chat-device physical-device enrollment binding prefix.
pub const DEVICE_BINDING_PREFIX: &str = "catbird.labyrinth.device_binding:";

/// `[CB-38]` Ed25519 author message-redaction transcript prefix.
pub const AUTHOR_REDACTION_PREFIX: &str = "catbird.labyrinth.redaction:";

/// Domain label for `EpochPublic.membersHash` (`Gate 2` / `Gate 3`).
pub const MEMBERS_HASH_DOMAIN: &[u8] = b"catbird.labyrinth.members_hash.v2\0";

/// `pk_sign` domain-separation byte for `HawkEncPublic` `epochStorageKeyPubkey` (`I16`).
pub const USE_CASE_EPOCH_STORAGE_KEY_PQ: u8 = 0x32;

/// `pk_sign` domain-separation byte for physical-device `epochStorageAuthKeyPubkey`.
pub const USE_CASE_EPOCH_STORAGE_AUTH_KEY: u8 = 0x31;

/// Append a length-prefixed byte slice (`u32` big-endian length || bytes) to `out`.
pub fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("transcript field fits in u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Canonical original-sender archive transcript.
///
/// The commitment deliberately excludes this signature, avoiding a circular
/// commitment while binding the sender to the exact thread and message id.
pub fn original_sender_archive_transcript(
    thread_id: &str,
    message_id: &str,
    archive_commitment: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        ORIGINAL_SENDER_ARCHIVE_DOMAIN.len()
            + 8
            + thread_id.len()
            + message_id.len()
            + archive_commitment.len(),
    );
    out.extend_from_slice(ORIGINAL_SENDER_ARCHIVE_DOMAIN);
    push_len_prefixed(&mut out, thread_id.as_bytes());
    push_len_prefixed(&mut out, message_id.as_bytes());
    out.extend_from_slice(archive_commitment);
    out
}

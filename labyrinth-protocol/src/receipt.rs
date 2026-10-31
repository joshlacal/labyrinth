//! `I13` blinded `archive_commitment` (`HMAC-SHA256`) and ES256 sequencer receipts
//! (`b"catbird-mls-sequencer-receipt-v2\0"`, `{SERVICE_DID}#mls-receipt-1`).

use hmac::{Hmac, Mac as _};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, Verifier as _},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::{
    ProtocolError, Result,
    limits::{ARCHIVE_COMMITMENT_LEN, ES256_SIG_LEN, FRAME_NONCE_LEN, GROUP_ID_LEN},
    transcripts::{RECEIPT_DOMAIN_V2, RECEIPT_VERIFICATION_FRAGMENT, push_len_prefixed},
};

type HmacSha256 = Hmac<Sha256>;

/// Compute the blinded `I13` archive commitment:
/// `HMAC-SHA256(key = frame_nonce, data = canonical_payload_bytes)`.
///
/// `frame_nonce` MUST live strictly inside the `MEK`-encrypted or owner-encrypted
/// batch payload so `archive_commitment` remains cryptographically hiding against
/// low-entropy message guessing by `mls-ds` or PDS operators.
pub fn compute_archive_commitment(
    frame_nonce: &[u8; FRAME_NONCE_LEN],
    canonical_payload_bytes: &[u8],
) -> [u8; ARCHIVE_COMMITMENT_LEN] {
    let mut mac = HmacSha256::new_from_slice(frame_nonce).expect("HMAC-SHA256 accepts 32-byte key");
    mac.update(canonical_payload_bytes);
    mac.finalize().into_bytes().into()
}

/// Unsigned payload of a v2 sequencer receipt (`I13`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerReceiptPayload {
    pub sequencer_did: String,
    pub conversation_id: String,
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender_device_did_url: String,
    pub entry_id: String,
    pub archive_commitment: [u8; ARCHIVE_COMMITMENT_LEN],
    pub seq: u64,
    pub issued_at_ms: i64,
}

impl SequencerReceiptPayload {
    /// Split `sender_device_did_url` (`"{sender_did}#{sender_device_id}"`) into `(did, device_id)`.
    pub fn split_sender_device(&self) -> Result<(&str, &str)> {
        let (did, device_id) =
            self.sender_device_did_url
                .split_once('#')
                .ok_or(ProtocolError::MalformedReceipt(
                    "sender_device_did_url must contain '#'",
                ))?;
        if did.is_empty() || device_id.is_empty() || device_id.contains('#') {
            return Err(ProtocolError::MalformedReceipt(
                "sender_device_did_url has empty or duplicate fragment",
            ));
        }
        Ok((did, device_id))
    }

    /// Validate structural invariants before signing or verifying.
    pub fn validate_structure(&self) -> Result<()> {
        if !self.sequencer_did.starts_with("did:web:")
            && !self.sequencer_did.starts_with("did:plc:")
        {
            return Err(ProtocolError::MalformedReceipt(
                "sequencer_did must be did:web or did:plc",
            ));
        }
        if self.sequencer_did.contains('#') {
            return Err(ProtocolError::MalformedReceipt(
                "sequencer_did must be a bare DID without fragment",
            ));
        }
        if self.conversation_id.is_empty() || self.entry_id.is_empty() {
            return Err(ProtocolError::MalformedReceipt(
                "conversation_id and entry_id must be non-empty",
            ));
        }
        if self.group_id.len() != GROUP_ID_LEN {
            return Err(ProtocolError::MalformedReceipt("group_id must be 32 bytes"));
        }
        if self.seq == 0 {
            return Err(ProtocolError::MalformedReceipt("seq must be >= 1"));
        }
        if self.issued_at_ms < 0 {
            return Err(ProtocolError::MalformedReceipt("issued_at_ms must be >= 0"));
        }
        let _ = self.split_sender_device()?;
        Ok(())
    }

    /// Canonical length-prefixed v2 signing transcript under `RECEIPT_DOMAIN_V2`.
    pub fn canonical_signing_bytes(&self, key_id: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(RECEIPT_DOMAIN_V2);
        push_len_prefixed(&mut out, self.sequencer_did.as_bytes());
        push_len_prefixed(&mut out, key_id.as_bytes());
        push_len_prefixed(&mut out, self.conversation_id.as_bytes());
        push_len_prefixed(&mut out, &self.group_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        push_len_prefixed(&mut out, self.sender_device_did_url.as_bytes());
        push_len_prefixed(&mut out, self.entry_id.as_bytes());
        out.extend_from_slice(&self.archive_commitment);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out
    }
}

/// Signed v2 ES256 sequencer receipt (`I13`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSequencerReceipt {
    pub payload: SequencerReceiptPayload,
    pub key_id: String,
    #[serde(with = "sig64_serde")]
    pub signature: [u8; ES256_SIG_LEN],
}

mod sig64_serde {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(sig)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(d)?;
        v.try_into()
            .map_err(|_| D::Error::custom("ES256 signature must be 64 bytes"))
    }
}

/// Expected verification method ID `{sequencer_did}#mls-receipt-1`.
pub fn expected_receipt_key_id(sequencer_did: &str) -> String {
    format!("{sequencer_did}{RECEIPT_VERIFICATION_FRAGMENT}")
}

/// Sign a `SequencerReceiptPayload` with ES256 (`sig.normalize_s()` low-S canonical).
pub fn sign_sequencer_receipt(
    sk: &SigningKey,
    key_id: &str,
    payload: &SequencerReceiptPayload,
) -> Result<SignedSequencerReceipt> {
    payload.validate_structure()?;
    let expected_kid = expected_receipt_key_id(&payload.sequencer_did);
    if key_id != expected_kid {
        return Err(ProtocolError::ReceiptKeyIdMismatch {
            expected: expected_kid,
            got: key_id.to_string(),
        });
    }
    let transcript = payload.canonical_signing_bytes(key_id);
    let raw_sig: Signature = sk.sign(&transcript);
    let normalized = raw_sig.normalize_s().unwrap_or(raw_sig);
    let sig_bytes: [u8; ES256_SIG_LEN] = normalized.to_bytes().into();
    Ok(SignedSequencerReceipt {
        payload: payload.clone(),
        key_id: key_id.to_string(),
        signature: sig_bytes,
    })
}

/// Verify a `SignedSequencerReceipt` against `expected_sequencer_did` and its
/// `{expected_sequencer_did}#mls-receipt-1` P-256 verifying key.
pub fn verify_sequencer_receipt(
    pk: &VerifyingKey,
    expected_sequencer_did: &str,
    receipt: &SignedSequencerReceipt,
) -> Result<()> {
    receipt.payload.validate_structure()?;
    if receipt.payload.sequencer_did != expected_sequencer_did {
        return Err(ProtocolError::ReceiptAuthorityMismatch {
            expected: expected_sequencer_did.to_string(),
            got: receipt.payload.sequencer_did.clone(),
        });
    }
    let expected_kid = expected_receipt_key_id(expected_sequencer_did);
    if receipt.key_id != expected_kid {
        return Err(ProtocolError::ReceiptKeyIdMismatch {
            expected: expected_kid,
            got: receipt.key_id.clone(),
        });
    }
    let sig = Signature::from_slice(&receipt.signature)
        .map_err(|_| ProtocolError::BadReceiptSignature)?;
    let normalized = sig.normalize_s().unwrap_or(sig);
    let transcript = receipt.payload.canonical_signing_bytes(&receipt.key_id);
    pk.verify(&transcript, &normalized)
        .map_err(|_| ProtocolError::BadReceiptSignature)
}

/// Verify that a decrypted `(frame_nonce, canonical_payload_bytes)` pair matches
/// `receipt.payload.archive_commitment` in constant time (`Gate 1` / `I13`).
pub fn verify_archived_item_commitment(
    receipt: &SignedSequencerReceipt,
    frame_nonce: &[u8; FRAME_NONCE_LEN],
    canonical_payload_bytes: &[u8],
) -> Result<()> {
    let computed = compute_archive_commitment(frame_nonce, canonical_payload_bytes);
    if bool::from(computed.ct_eq(&receipt.payload.archive_commitment)) {
        Ok(())
    } else {
        Err(ProtocolError::ReceiptCommitmentMismatch)
    }
}

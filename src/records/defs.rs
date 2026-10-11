//! `blue.catbird.labyrinth.defs` object shapes.

use serde::{Deserialize, Serialize};

use super::Bytes;
use crate::deletion::{Redaction, ServerRedaction, StoredRedaction};
use crate::hpke::hawk::HawkEncPublic;
use crate::hpke::labyrinth::X25519Public;
use crate::mailbox::{EpochPublic, MailboxPublicKeys, TransportAttestation};
use crate::mek::MekRecipient;
use crate::message::{OwnerMessage, SealedMessage};
use crate::sign::XVerifyingKey;
use crate::{Error, Result};

/// `defs#transportAttestation` ([CB-18]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportAttestationDef {
    pub transport_pubkey: Bytes,
    pub sig: Bytes,
}

/// `defs#epochPublic` (SPEC §5.2–5.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochPublicDef {
    pub epoch_number: u64,
    pub auth_pubkey: Bytes,
    pub encryption_pubkey: Bytes,
    pub signing_pubkey: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_epoch_head: Option<Bytes>,
    pub epoch_head: Bytes,
    pub self_sig: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_sig: Option<Bytes>,
    pub attestation: TransportAttestationDef,
}

impl EpochPublicDef {
    pub fn from_public(p: &EpochPublic) -> Self {
        Self {
            epoch_number: p.seq,
            auth_pubkey: Bytes::from_slice(&p.keys.auth.0),
            encryption_pubkey: Bytes(p.keys.enc.to_bytes()),
            signing_pubkey: Bytes::from_slice(&p.keys.sig.0),
            previous_epoch_head: p.prev_head.map(|h| Bytes::from_slice(&h)),
            epoch_head: Bytes::from_slice(&p.head),
            self_sig: Bytes::from_slice(&p.self_sig),
            prev_sig: p.prev_sig.map(|s| Bytes::from_slice(&s)),
            attestation: TransportAttestationDef {
                transport_pubkey: Bytes::from_slice(&p.attestation.transport_public_key),
                sig: Bytes::from_slice(&p.attestation.sig),
            },
        }
    }

    /// Parses key encodings and lengths. Does not verify signatures; call
    /// [`EpochPublic::verify`] on the result.
    pub fn to_public(&self) -> Result<EpochPublic> {
        Ok(EpochPublic {
            seq: super::check_epoch_number(self.epoch_number)?,
            keys: MailboxPublicKeys {
                auth: X25519Public(self.auth_pubkey.array("authPubkey length")?),
                enc: HawkEncPublic::from_bytes(&self.encryption_pubkey.0)?,
                sig: XVerifyingKey(self.signing_pubkey.array("signingPubkey length")?),
            },
            prev_head: self
                .previous_epoch_head
                .as_ref()
                .map(|b| b.array("previousEpochHead length"))
                .transpose()?,
            head: self.epoch_head.array("epochHead length")?,
            self_sig: self.self_sig.array("selfSig length")?,
            prev_sig: self
                .prev_sig
                .as_ref()
                .map(|b| b.array("prevSig length"))
                .transpose()?,
            attestation: TransportAttestation {
                transport_public_key: self
                    .attestation
                    .transport_pubkey
                    .array("transportPubkey length")?,
                sig: self.attestation.sig.array("attestation sig length")?,
            },
        })
    }
}

/// `defs#redaction` ([CB-38]): an author's signed unsend request
/// (`transportPubkey` + `sig`), a sequencer DS's account-deletion
/// redaction (`by` + `reason` + `redactedAt`, `sig` when the DS signs), or
/// a bare `{redactedAt}` server removal. See [`StoredRedaction`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionDef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_pubkey: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RedactionDef {
    pub fn from_redaction(r: &Redaction) -> Self {
        Self {
            transport_pubkey: Some(Bytes::from_slice(&r.transport_public_key)),
            sig: Some(Bytes::from_slice(&r.sig)),
            redacted_at: r.redacted_at.clone(),
            by: None,
            reason: None,
        }
    }

    /// A bare server removal: `{redactedAt}` alone, no signature, no `by`.
    pub fn account_deletion(redacted_at: Option<String>) -> Self {
        Self {
            transport_pubkey: None,
            sig: None,
            redacted_at,
            by: None,
            reason: None,
        }
    }

    /// A sequencer DS's redaction ([`ServerRedaction`]).
    pub fn from_server(r: &ServerRedaction) -> Self {
        Self {
            transport_pubkey: None,
            sig: r.sig.as_ref().map(|s| Bytes::from_slice(s)),
            redacted_at: Some(r.redacted_at.clone()),
            by: Some(r.by.clone()),
            reason: Some(r.reason.clone()),
        }
    }

    /// What kind of redaction this is. Any other field combination
    /// (an author key without a signature, `by` with an author key, …)
    /// is malformed.
    pub fn to_stored(&self) -> Result<StoredRedaction> {
        match (&self.transport_pubkey, &self.by) {
            (Some(k), None) if self.reason.is_none() => {
                let s = self
                    .sig
                    .as_ref()
                    .ok_or(Error::Malformed("redaction key and sig must come together"))?;
                Ok(StoredRedaction::Author(Redaction {
                    transport_public_key: k.array("redaction key length")?,
                    sig: s.array("redaction sig length")?,
                    redacted_at: self.redacted_at.clone(),
                }))
            }
            (None, Some(by)) => Ok(StoredRedaction::Server(ServerRedaction {
                by: by.clone(),
                reason: self
                    .reason
                    .clone()
                    .ok_or(Error::Malformed("server redaction without reason"))?,
                redacted_at: self
                    .redacted_at
                    .clone()
                    .ok_or(Error::Malformed("server redaction without redactedAt"))?,
                sig: self
                    .sig
                    .as_ref()
                    .map(|s| s.array("redaction sig length"))
                    .transpose()?,
            })),
            (None, None) if self.sig.is_none() && self.reason.is_none() => {
                Ok(StoredRedaction::Unsigned {
                    redacted_at: self.redacted_at.clone(),
                })
            }
            _ => Err(Error::Malformed("redaction fields do not form one kind")),
        }
    }

    /// The author's signed unsend, or `None` for a server redaction.
    pub fn to_redaction(&self) -> Result<Option<Redaction>> {
        Ok(match self.to_stored()? {
            StoredRedaction::Author(r) => Some(r),
            _ => None,
        })
    }
}

/// `defs#sealedMessage` (SPEC §7.2). A redacted item ([CB-38]) keeps its
/// `messageId`, `timestamp`, `mekId` and sender key, carries `redaction`,
/// and has an empty `signedEncMessage`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMessageDef {
    pub message_id: String,
    pub timestamp: u64,
    pub mek_id: Bytes,
    pub sender_transport_pubkey: Bytes,
    pub signed_enc_message: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionDef>,
}

impl SealedMessageDef {
    pub fn from_message(m: &SealedMessage) -> Self {
        Self {
            message_id: m.message_id.clone(),
            timestamp: m.timestamp,
            mek_id: Bytes::from_slice(&m.mek_id),
            sender_transport_pubkey: Bytes::from_slice(&m.sender_transport_pub),
            signed_enc_message: Bytes(m.signed_enc_message.clone()),
            redaction: None,
        }
    }

    /// `None` if the item is live, else how it was redacted ([CB-38]).
    pub fn redaction(&self) -> Result<Option<StoredRedaction>> {
        self.redaction
            .as_ref()
            .map(RedactionDef::to_stored)
            .transpose()
    }

    pub fn to_message(&self) -> Result<SealedMessage> {
        if self.redaction.is_some() {
            return Err(Error::Malformed("item was redacted"));
        }
        Ok(SealedMessage {
            message_id: self.message_id.clone(),
            timestamp: self.timestamp,
            mek_id: self.mek_id.array("mekId length")?,
            sender_transport_pub: self
                .sender_transport_pubkey
                .array("senderTransportPubkey length")?,
            signed_enc_message: self.signed_enc_message.0.clone(),
        })
    }

    /// Rough size of this item in a JSON record, for [`super::BATCH_BYTE_BUDGET`].
    pub fn approx_json_len(m: &SealedMessage) -> usize {
        m.signed_enc_message.len().div_ceil(3) * 4 + m.message_id.len() + 200
    }
}

/// `defs#ownerMessage` (SPEC §7.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerMessageDef {
    pub thread_id: String,
    pub message_id: String,
    pub timestamp: u64,
    pub epoch_number: u64,
    pub version: u8,
    pub encrypted: Bytes,
}

impl OwnerMessageDef {
    pub fn from_message(m: &OwnerMessage) -> Self {
        Self {
            thread_id: m.thread_id.clone(),
            message_id: m.message_id.clone(),
            timestamp: m.timestamp,
            epoch_number: m.epoch_seq,
            version: m.version,
            encrypted: Bytes(m.encrypted.clone()),
        }
    }

    pub fn to_message(&self) -> OwnerMessage {
        OwnerMessage {
            thread_id: self.thread_id.clone(),
            message_id: self.message_id.clone(),
            timestamp: self.timestamp,
            epoch_seq: self.epoch_number,
            version: self.version,
            encrypted: self.encrypted.0.clone(),
        }
    }
}

/// `defs#mekRecipient` (SPEC §7.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MekRecipientDef {
    pub did: String,
    pub recipient_epoch_head: Bytes,
    pub ciphertext: Bytes,
}

impl MekRecipientDef {
    pub fn from_recipient(r: &MekRecipient) -> Self {
        Self {
            did: r.did.clone(),
            recipient_epoch_head: Bytes::from_slice(&r.recipient_epoch_head),
            ciphertext: Bytes(r.ciphertext.clone()),
        }
    }

    pub fn to_recipient(&self) -> Result<MekRecipient> {
        if self.did.is_empty() {
            return Err(Error::Malformed("empty recipient did"));
        }
        Ok(MekRecipient {
            did: self.did.clone(),
            recipient_epoch_head: self
                .recipient_epoch_head
                .array("recipientEpochHead length")?,
            ciphertext: self.ciphertext.0.clone(),
        })
    }
}

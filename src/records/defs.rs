//! `blue.catbird.labyrinth.defs` object shapes.

use serde::{Deserialize, Serialize};

use super::Bytes;
use crate::deletion::{Redaction, StoredRedaction};
use crate::hpke::X25519Public;
use crate::hpke::hawk::HawkEncPublic;
use crate::mailbox::{EpochPublic, MailboxPublicKeys, TransportAttestation};
use crate::mek::MekRecipient;
use crate::message::{
    ArchivedReceipt, OriginalSenderArchiveAttestation, OwnerMessage, SealedMessage,
};
use crate::sign::XVerifyingKey;
use crate::{Error, Result};

/// CID link wrapper inside an ATProto blob reference (`{"$link": "<cid>"}` in JSON, tag-42 CID in DAG-CBOR).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CidLinkDef {
    pub link: String,
}

impl serde::Serialize for CidLinkDef {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        if !serializer.is_human_readable()
            && let Ok(parsed) = self.link.parse::<cid::Cid>()
        {
            return parsed.serialize(serializer);
        }
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("$link", &self.link)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for CidLinkDef {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        if !deserializer.is_human_readable() {
            let parsed = cid::Cid::deserialize(deserializer)?;
            return Ok(Self {
                link: parsed.to_string(),
            });
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(rename = "$link")]
            link: String,
        }
        let w = Wire::deserialize(deserializer)?;
        Ok(Self { link: w.link })
    }
}

/// Standard ATProto blob reference (`{"$type": "blob", "ref": {"$link": cid}, "mimeType": ..., "size": ...}`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlobRefDef {
    #[serde(rename = "$type")]
    pub type_: String,
    pub r#ref: CidLinkDef,
    pub mime_type: String,
    pub size: u64,
}

impl BlobRefDef {
    pub fn new(cid: impl Into<String>, mime_type: impl Into<String>, size: u64) -> Self {
        Self {
            type_: "blob".into(),
            r#ref: CidLinkDef { link: cid.into() },
            mime_type: mime_type.into(),
            size,
        }
    }

    pub fn cid_link(&self) -> &str {
        &self.r#ref.link
    }

    pub fn check(&self) -> Result<()> {
        if self.type_ != "blob" || self.r#ref.link.is_empty() || self.mime_type.is_empty() {
            return Err(Error::Malformed("invalid blob ref"));
        }
        Ok(())
    }
}

/// `defs#originalSenderArchiveAttestation` (`G1` / `G6`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginalSenderArchiveAttestationDef {
    pub sender_did: String,
    pub sender_device_id: String,
    pub sender_transport_pubkey: Bytes,
    pub signature: Bytes,
}

impl OriginalSenderArchiveAttestationDef {
    fn from_attestation(attestation: &OriginalSenderArchiveAttestation) -> Self {
        Self {
            sender_did: attestation.sender_did.clone(),
            sender_device_id: attestation.sender_device_id.clone(),
            sender_transport_pubkey: Bytes::from_slice(&attestation.sender_transport_public_key),
            signature: Bytes::from_slice(&attestation.signature),
        }
    }

    fn to_attestation(&self) -> Result<OriginalSenderArchiveAttestation> {
        if self.sender_did.is_empty()
            || self.sender_device_id.is_empty()
            || self.sender_did.contains('#')
            || self.sender_device_id.contains('#')
        {
            return Err(Error::Malformed("original sender archive identity"));
        }
        Ok(OriginalSenderArchiveAttestation {
            sender_did: self.sender_did.clone(),
            sender_device_id: self.sender_device_id.clone(),
            sender_transport_public_key: self
                .sender_transport_pubkey
                .array("original sender transport key length")?,
            signature: self
                .signature
                .array("original sender archive signature length")?,
        })
    }
}

/// `defs#sequencerReceipt` (`I13`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SequencerReceiptDef {
    pub conversation_id: String,
    pub generation: u64,
    pub group_id: Bytes,
    pub epoch: u64,
    pub entry_id: String,
    pub seq: u64,
    pub sender_did: String,
    pub sender_device_id: String,
    pub archive_commitment: Bytes,
    pub issued_at_ms: u64,
    pub sequencer_did: String,
    pub kid: String,
    pub signature: Bytes,
    pub original_sender_attestation: OriginalSenderArchiveAttestationDef,
}

impl SequencerReceiptDef {
    pub fn from_archived(r: &ArchivedReceipt) -> Self {
        let p = &r.signed.payload;
        let (sender_did, sender_device_id) = p
            .sender_device_did_url
            .split_once('#')
            .unwrap_or((&p.sender_device_did_url, ""));
        Self {
            conversation_id: p.conversation_id.clone(),
            generation: r.generation,
            group_id: Bytes::from_slice(&p.group_id),
            epoch: p.epoch,
            entry_id: p.entry_id.clone(),
            seq: p.seq,
            sender_did: sender_did.to_owned(),
            sender_device_id: sender_device_id.to_owned(),
            archive_commitment: Bytes::from_slice(&p.archive_commitment),
            issued_at_ms: u64::try_from(p.issued_at_ms).unwrap_or(0),
            sequencer_did: p.sequencer_did.clone(),
            kid: r.signed.key_id.clone(),
            signature: Bytes::from_slice(&r.signed.signature),
            original_sender_attestation: OriginalSenderArchiveAttestationDef::from_attestation(
                &r.original_sender_attestation,
            ),
        }
    }

    pub fn to_archived(&self) -> Result<ArchivedReceipt> {
        let group_id = self
            .group_id
            .array::<32>("receipt groupId length")?
            .to_vec();
        let archive_commitment = self
            .archive_commitment
            .array::<32>("receipt archiveCommitment length")?;
        let signature = self.signature.array::<64>("receipt signature length")?;
        let issued_at_ms = i64::try_from(self.issued_at_ms)
            .map_err(|_| Error::Malformed("receipt issuedAtMs out of range"))?;
        if self.sender_did.is_empty()
            || self.sender_device_id.is_empty()
            || self.sender_did.contains('#')
            || self.sender_device_id.contains('#')
        {
            return Err(Error::Malformed("receipt sender device identity"));
        }
        let payload = labyrinth_protocol::receipt::SequencerReceiptPayload {
            sequencer_did: self.sequencer_did.clone(),
            conversation_id: self.conversation_id.clone(),
            group_id,
            epoch: self.epoch,
            sender_device_did_url: format!("{}#{}", self.sender_did, self.sender_device_id),
            entry_id: self.entry_id.clone(),
            archive_commitment,
            seq: self.seq,
            issued_at_ms,
        };
        payload
            .validate_structure()
            .map_err(|_| Error::Malformed("receipt payload structure"))?;
        let original_sender_attestation = self.original_sender_attestation.to_attestation()?;
        if original_sender_attestation.sender_did != self.sender_did
            || original_sender_attestation.sender_device_id != self.sender_device_id
        {
            return Err(Error::Malformed(
                "receipt and original sender archive identity differ",
            ));
        }
        Ok(ArchivedReceipt {
            signed: labyrinth_protocol::receipt::SignedSequencerReceipt {
                payload,
                key_id: self.kid.clone(),
                signature,
            },
            generation: self.generation,
            original_sender_attestation,
        })
    }
}

/// `defs#transportAttestation` ([CB-18]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportAttestationDef {
    pub transport_pubkey: Bytes,
    pub sig: Bytes,
}

/// `defs#deviceRevocation`: XEdDSA revocation statement signed by a physical device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceRevocationDef {
    pub revoked_by: Bytes,
    pub sig: Bytes,
}

impl DeviceRevocationDef {
    pub fn from_revocation(r: &crate::device::DeviceRevocation) -> Self {
        Self {
            revoked_by: Bytes::from_slice(&r.revoked_by.0),
            sig: Bytes::from_slice(&r.sig),
        }
    }

    pub fn to_revocation(&self) -> Result<crate::device::DeviceRevocation> {
        Ok(crate::device::DeviceRevocation {
            revoked_by: XVerifyingKey(self.revoked_by.array("revokedBy length")?),
            sig: self.sig.array("deviceRevocation sig length")?,
        })
    }
}

/// `defs#epochPublic` (SPEC §5.2–5.3, Gate 2/3 `membersHash`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochPublicDef {
    pub epoch_number: u64,
    pub auth_pubkey: Bytes,
    pub encryption_pubkey: Bytes,
    pub signing_pubkey: Bytes,
    pub members_hash: Bytes,
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
            members_hash: Bytes::from_slice(&p.members_hash),
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
            members_hash: self.members_hash.array("membersHash length")?,
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
/// (`transportPubkey` + `sig`), or a bare `{redactedAt}` server removal.
/// The lexicon's sequencer-DS variant (`by`, `reason`) is retired (G16):
/// a record carrying it does not parse. See [`StoredRedaction`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionDef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_pubkey: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_at: Option<String>,
}

impl RedactionDef {
    pub fn from_redaction(r: &Redaction) -> Self {
        Self {
            transport_pubkey: Some(Bytes::from_slice(&r.transport_public_key)),
            sig: Some(Bytes::from_slice(&r.sig)),
            redacted_at: r.redacted_at.clone(),
        }
    }

    /// What kind of redaction this is. An author key without a signature,
    /// or a signature without an author key, is malformed.
    pub fn to_stored(&self) -> Result<StoredRedaction> {
        match (&self.transport_pubkey, &self.sig) {
            (Some(k), Some(s)) => Ok(StoredRedaction::Author(Redaction {
                transport_public_key: k.array("redaction key length")?,
                sig: s.array("redaction sig length")?,
                redacted_at: self.redacted_at.clone(),
            })),
            (None, None) => Ok(StoredRedaction::Unsigned {
                redacted_at: self.redacted_at.clone(),
            }),
            _ => Err(Error::Malformed("redaction key and sig must come together")),
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

/// `defs#sealedMessage` (SPEC §7.2, `I13`). A redacted item ([CB-38]) keeps its
/// `messageId`, `timestamp`, `mekId` and sender key, carries `redaction`,
/// and has an empty `signedEncMessage`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMessageDef {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub timestamp: u64,
    pub mek_id: Bytes,
    pub sender_transport_pubkey: Bytes,
    pub signed_enc_message: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequencer_receipt: Option<SequencerReceiptDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionDef>,
}

impl SealedMessageDef {
    pub fn from_message(m: &SealedMessage) -> Self {
        Self {
            message_id: m.message_id.clone(),
            seq: m.seq,
            timestamp: m.timestamp,
            mek_id: Bytes::from_slice(&m.mek_id),
            sender_transport_pubkey: Bytes::from_slice(&m.sender_transport_pub),
            signed_enc_message: Bytes(m.signed_enc_message.clone()),
            sequencer_receipt: m
                .sequencer_receipt
                .as_ref()
                .map(SequencerReceiptDef::from_archived),
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
        let sequencer_receipt = self
            .sequencer_receipt
            .as_ref()
            .map(SequencerReceiptDef::to_archived)
            .transpose()?;
        if let (Some(seq), Some(r)) = (self.seq, &sequencer_receipt)
            && seq != r.signed.payload.seq
        {
            return Err(Error::Malformed("sealedMessage seq != receipt.seq"));
        }
        Ok(SealedMessage {
            message_id: self.message_id.clone(),
            seq: self
                .seq
                .or_else(|| sequencer_receipt.as_ref().map(|r| r.signed.payload.seq)),
            timestamp: self.timestamp,
            mek_id: self.mek_id.array("mekId length")?,
            sender_transport_pub: self
                .sender_transport_pubkey
                .array("senderTransportPubkey length")?,
            signed_enc_message: self.signed_enc_message.0.clone(),
            sequencer_receipt,
        })
    }

    /// Rough size of this item in a JSON record, for [`super::BATCH_BYTE_BUDGET`].
    pub fn approx_json_len(m: &SealedMessage) -> usize {
        let receipt_overhead = if m.sequencer_receipt.is_some() {
            550
        } else {
            0
        };
        m.signed_enc_message.len().div_ceil(3) * 4 + m.message_id.len() + 200 + receipt_overhead
    }
}

/// `defs#ownerMessage` (SPEC §7.1, `I13`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerMessageDef {
    pub thread_id: String,
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub timestamp: u64,
    pub epoch_number: u64,
    pub version: u8,
    pub encrypted: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequencer_receipt: Option<SequencerReceiptDef>,
}

impl OwnerMessageDef {
    pub fn from_message(m: &OwnerMessage) -> Self {
        Self {
            thread_id: m.thread_id.clone(),
            message_id: m.message_id.clone(),
            seq: m.seq,
            timestamp: m.timestamp,
            epoch_number: m.epoch_seq,
            version: m.version,
            encrypted: Bytes(m.encrypted.clone()),
            sequencer_receipt: m
                .sequencer_receipt
                .as_ref()
                .map(SequencerReceiptDef::from_archived),
        }
    }

    pub fn to_message(&self) -> Result<OwnerMessage> {
        let sequencer_receipt = self
            .sequencer_receipt
            .as_ref()
            .map(SequencerReceiptDef::to_archived)
            .transpose()?;
        if let (Some(seq), Some(r)) = (self.seq, &sequencer_receipt)
            && seq != r.signed.payload.seq
        {
            return Err(Error::Malformed("ownerMessage seq != receipt.seq"));
        }
        Ok(OwnerMessage {
            thread_id: self.thread_id.clone(),
            message_id: self.message_id.clone(),
            seq: self
                .seq
                .or_else(|| sequencer_receipt.as_ref().map(|r| r.signed.payload.seq)),
            timestamp: self.timestamp,
            epoch_seq: self.epoch_number,
            version: self.version,
            encrypted: self.encrypted.0.clone(),
            sequencer_receipt,
        })
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

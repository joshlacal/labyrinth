//! Records in the conversation space: MEK distributions and sender batches
//! ([CB-15], [CB-21]). Each lives in its author's repo.

use serde::{Deserialize, Serialize};

use super::defs::{EpochPublicDef, MekRecipientDef, RedactionDef, SealedMessageDef};
use super::{Bytes, check_type, nsid};
use crate::mailbox::EpochPublic;
use crate::mek::{MekRecord, MekSender};
use crate::message::SealedMessage;
use crate::{Error, Result};

/// `mek#labyrinthSender`. Carries the sender's full `epochPublic` so a
/// reader can authenticate a MEK from an epoch the sender has since
/// rotated away from (the public `mailboxKeys` record shows only the
/// latest one).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LabyrinthSenderDef {
    pub did: String,
    pub sender_epoch_head: Bytes,
    pub sender_epoch: EpochPublicDef,
}

/// `mek#transportSender`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportSenderDef {
    pub transport_pubkey: Bytes,
    pub ephemeral_auth_pubkey: Bytes,
    pub sig: Bytes,
}

/// The closed `sender` union, tagged by `$type`.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum MekSenderDef {
    #[serde(rename = "blue.catbird.labyrinth.mek#labyrinthSender")]
    Labyrinth(LabyrinthSenderDef),
    #[serde(rename = "blue.catbird.labyrinth.mek#transportSender")]
    Transport(TransportSenderDef),
}

/// `blue.catbird.labyrinth.mek`, rkey = `hex(mekId)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MekDistribution {
    #[serde(rename = "$type")]
    pub type_: String,
    pub thread_id: String,
    pub mek_id: Bytes,
    pub roster_hash: Bytes,
    pub sender: MekSenderDef,
    pub recipients: Vec<MekRecipientDef>,
    pub created_at: String,
}

impl MekDistribution {
    /// `sender_epoch` is required for a Labyrinth sender and must have the
    /// record's `senderEpochHead`; it is ignored for a transport sender.
    pub fn from_record(
        r: &MekRecord,
        sender_epoch: Option<&EpochPublic>,
        created_at: String,
    ) -> Result<Self> {
        let sender = match &r.sender {
            MekSender::Labyrinth {
                did,
                sender_epoch_head,
            } => {
                let e = sender_epoch.ok_or(Error::NotFound("sender epoch"))?;
                if e.head != *sender_epoch_head {
                    return Err(Error::WrongEpoch);
                }
                MekSenderDef::Labyrinth(LabyrinthSenderDef {
                    did: did.clone(),
                    sender_epoch_head: Bytes::from_slice(sender_epoch_head),
                    sender_epoch: EpochPublicDef::from_public(e),
                })
            }
            MekSender::Transport {
                transport_pub,
                ephemeral_auth_pub,
                sig,
            } => MekSenderDef::Transport(TransportSenderDef {
                transport_pubkey: Bytes::from_slice(transport_pub),
                ephemeral_auth_pubkey: Bytes::from_slice(ephemeral_auth_pub),
                sig: Bytes::from_slice(sig),
            }),
        };
        Ok(Self {
            type_: nsid::MEK.into(),
            thread_id: r.thread_id.clone(),
            mek_id: Bytes::from_slice(&r.mek_id),
            roster_hash: Bytes::from_slice(&r.roster_hash),
            sender,
            recipients: r
                .recipients
                .iter()
                .map(MekRecipientDef::from_recipient)
                .collect(),
            created_at,
        })
    }

    /// The protocol record plus, for a Labyrinth sender, the sender's
    /// (unverified) epoch public data.
    pub fn to_record(&self) -> Result<(MekRecord, Option<EpochPublic>)> {
        check_type(&self.type_, nsid::MEK)?;
        let (sender, epoch) = match &self.sender {
            MekSenderDef::Labyrinth(l) => {
                let head = l.sender_epoch_head.array("senderEpochHead length")?;
                let epoch = l.sender_epoch.to_public()?;
                if epoch.head != head {
                    return Err(Error::WrongEpoch);
                }
                let s = MekSender::Labyrinth {
                    did: l.did.clone(),
                    sender_epoch_head: head,
                };
                (s, Some(epoch))
            }
            MekSenderDef::Transport(t) => (
                MekSender::Transport {
                    transport_pub: t.transport_pubkey.array("transportPubkey length")?,
                    ephemeral_auth_pub: t
                        .ephemeral_auth_pubkey
                        .array("ephemeralAuthPubkey length")?,
                    sig: t.sig.array("transport sender sig length")?,
                },
                None,
            ),
        };
        let record = MekRecord {
            thread_id: self.thread_id.clone(),
            mek_id: self.mek_id.array("mekId length")?,
            roster_hash: self.roster_hash.array("rosterHash length")?,
            sender,
            recipients: self
                .recipients
                .iter()
                .map(MekRecipientDef::to_recipient)
                .collect::<Result<_>>()?,
        };
        Ok((record, epoch))
    }

    pub fn rkey(&self) -> String {
        hex::encode(&self.mek_id.0)
    }
}

/// One item of a [`Batch`].
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchEntry {
    Sealed(SealedMessage),
    /// Redacted ([CB-38]); the ciphertext is gone. `redaction` says by
    /// whom; only a verified [`crate::deletion::StoredRedaction::Author`]
    /// is an author unsend.
    Redacted {
        message_id: String,
        timestamp: u64,
        redaction: crate::deletion::StoredRedaction,
    },
}

impl BatchEntry {
    pub fn message_id(&self) -> &str {
        match self {
            Self::Sealed(s) => &s.message_id,
            Self::Redacted { message_id, .. } => message_id,
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Sealed(s) => s.timestamp,
            Self::Redacted { timestamp, .. } => *timestamp,
        }
    }
}

/// Immutable author unsend record. Its deterministic rkey gives each message
/// an independent create-if-absent slot, so concurrent unsends cannot overwrite
/// one another's batch state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorRedaction {
    #[serde(rename = "$type")]
    pub type_: String,
    pub thread_id: String,
    pub message_id: String,
    pub redaction: RedactionDef,
    pub created_at: String,
}

impl AuthorRedaction {
    pub fn new(
        thread_id: &str,
        message_id: &str,
        redaction: &crate::deletion::Redaction,
        created_at: String,
    ) -> Self {
        Self {
            type_: nsid::AUTHOR_REDACTION.into(),
            thread_id: thread_id.to_owned(),
            message_id: message_id.to_owned(),
            redaction: RedactionDef::from_redaction(redaction),
            created_at,
        }
    }

    pub fn rkey(&self) -> String {
        let mut transcript = Vec::with_capacity(
            "catbird.labyrinth.author_redaction_record.v1\0".len()
                + self.thread_id.len()
                + self.message_id.len()
                + 8,
        );
        transcript.extend_from_slice(b"catbird.labyrinth.author_redaction_record.v1\0");
        labyrinth_protocol::transcripts::push_len_prefixed(
            &mut transcript,
            self.thread_id.as_bytes(),
        );
        labyrinth_protocol::transcripts::push_len_prefixed(
            &mut transcript,
            self.message_id.as_bytes(),
        );
        hex::encode(crate::encoding::sha256(&transcript))
    }

    pub fn to_redaction(&self) -> Result<crate::deletion::Redaction> {
        check_type(&self.type_, nsid::AUTHOR_REDACTION)?;
        if self.thread_id.is_empty() || self.message_id.is_empty() {
            return Err(Error::Malformed("author redaction coordinates"));
        }
        self.redaction
            .to_redaction()?
            .ok_or(Error::Malformed("authorRedaction is not author signed"))
    }
}

/// `blue.catbird.labyrinth.batch`, rkey = TID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Batch {
    #[serde(rename = "$type")]
    pub type_: String,
    pub thread_id: String,
    pub items: Vec<SealedMessageDef>,
    pub created_at: String,
}

impl Batch {
    /// Fails if `items` is empty or longer than [`super::MAX_BATCH_ITEMS`].
    pub fn from_messages(
        thread_id: &str,
        items: &[SealedMessage],
        created_at: String,
    ) -> Result<Self> {
        if items.is_empty() || items.len() > super::MAX_BATCH_ITEMS {
            return Err(Error::Malformed("batch size"));
        }
        Ok(Self {
            type_: nsid::BATCH.into(),
            thread_id: thread_id.to_owned(),
            items: items.iter().map(SealedMessageDef::from_message).collect(),
            created_at,
        })
    }

    /// Every item, redacted ones ([CB-38]) included.
    pub fn entries(&self) -> Result<Vec<BatchEntry>> {
        check_type(&self.type_, nsid::BATCH)?;
        if self.items.is_empty() || self.items.len() > super::MAX_BATCH_ITEMS {
            return Err(Error::Malformed("batch size"));
        }
        self.items
            .iter()
            .map(|i| match i.redaction()? {
                Some(redaction) => Ok(BatchEntry::Redacted {
                    message_id: i.message_id.clone(),
                    timestamp: i.timestamp,
                    redaction,
                }),
                None => i.to_message().map(BatchEntry::Sealed),
            })
            .collect()
    }

    /// The sealed items; fails if any was redacted (see [`Self::entries`]).
    pub fn to_messages(&self) -> Result<Vec<SealedMessage>> {
        check_type(&self.type_, nsid::BATCH)?;
        if self.items.is_empty() || self.items.len() > super::MAX_BATCH_ITEMS {
            return Err(Error::Malformed("batch size"));
        }
        self.items
            .iter()
            .map(SealedMessageDef::to_message)
            .collect()
    }
}

/// `blue.catbird.labyrinth.attachmentManifest` (`Gate 5`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachmentManifest {
    #[serde(rename = "$type")]
    pub type_: String,
    pub blob: super::defs::BlobRefDef,
    pub sha256: Bytes,
    pub ciphertext_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type_hint: Option<String>,
    pub created_at: String,
}

impl AttachmentManifest {
    pub fn from_meta(
        cid: &str,
        meta: &crate::attachment::AttachmentCiphertextMeta,
        created_at: String,
    ) -> Self {
        let mime = meta
            .mime_type_hint
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        Self {
            type_: nsid::ATTACHMENT_MANIFEST.into(),
            blob: super::defs::BlobRefDef::new(cid, mime, meta.ciphertext_size),
            sha256: Bytes::from_slice(&meta.sha256),
            ciphertext_size: meta.ciphertext_size,
            mime_type_hint: meta.mime_type_hint.clone(),
            created_at,
        }
    }

    pub fn to_meta(&self) -> Result<(String, crate::attachment::AttachmentCiphertextMeta)> {
        check_type(&self.type_, nsid::ATTACHMENT_MANIFEST)?;
        self.blob.check()?;
        if self.ciphertext_size == 0
            || self.ciphertext_size > crate::attachment::MAX_ATTACHMENT_CIPHERTEXT_SIZE
            || self.blob.size != self.ciphertext_size
        {
            return Err(Error::Malformed("attachmentManifest ciphertextSize"));
        }
        let sha256 = self
            .sha256
            .array::<32>("attachmentManifest sha256 length")?;
        let _ = super::ms_from_datetime(&self.created_at)?;
        Ok((
            self.blob.cid_link().to_owned(),
            crate::attachment::AttachmentCiphertextMeta {
                sha256,
                ciphertext_size: self.ciphertext_size,
                mime_type_hint: self.mime_type_hint.clone(),
            },
        ))
    }
}

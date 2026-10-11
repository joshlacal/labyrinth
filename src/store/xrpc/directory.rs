//! The mls-ds directory (design §1a, §2 "Directory") and ORF server role
//! (§2 "ORF and attachments").

use std::sync::Arc;

use serde::Deserialize;

use super::wire::{
    AttachmentRefOut, ChatDeviceKeyView, DeleteRefIn, DeviceKeyIn, Empty, EpochHeadOut,
    MemberDeviceView, OrfParent, PublishHeadIn, PutRefIn, RegisterOrfIn,
};
use super::{Xrpc, XrpcTransport};
use crate::mailbox::EpochPublic;
use crate::orf::{EvolveToken, ObliviousId};
use crate::records::{Bytes, MailboxKeysRecord, ms_from_datetime};
use crate::sign::XVerifyingKey;
use crate::store::{
    AttachmentFetch, AttachmentPut, ChatDeviceKey, KeyPublisher, MailboxDirectory, MemberDeviceKey,
    OrfServer,
};
use crate::{Error, Result};

/// mls-ds's verified, append-only head chain of every enrolled DID, plus
/// the chat device view. Use it as the `ds` side of a
/// [`crate::client::CompositeDirectory`], and as a [`KeyPublisher`] when
/// the mailbox lives in a Space.
pub struct XrpcDirectory {
    x: Xrpc,
}

/// One participant's `labyrinthHead` in `blue.catbird.chat.getConversationState`
/// (design §1a, Y5): a summary of mls-ds's latest head for that DID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabyrinthHead {
    pub did: String,
    pub epoch_number: u64,
    pub epoch_head: [u8; 32],
    pub attestation_key_id: String,
}

#[derive(Deserialize)]
struct ConversationStateOut {
    state: ConversationState,
}
#[derive(Deserialize)]
struct ConversationState {
    participants: Vec<Participant>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Participant {
    user_did: String,
    #[serde(default)]
    labyrinth_head: Option<HeadView>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeadView {
    epoch_number: u64,
    epoch_head: Bytes,
    attestation_key_id: String,
}

fn key32(b: &Bytes) -> Result<[u8; 32]> {
    b.array::<32>("signingPublicKey length")
}

impl XrpcDirectory {
    pub fn new(transport: Arc<dyn XrpcTransport>) -> Self {
        Self {
            x: Xrpc::new(transport),
        }
    }

    fn head(&self, did: &str, seq: Option<u64>) -> Result<Option<EpochPublic>> {
        let mut p = vec![("did", did.to_owned())];
        if let Some(s) = seq {
            p.push(("epochNumber", s.to_string()));
        }
        self.x
            .get_opt::<EpochHeadOut>("getEpochHead", &p)?
            .map(|h| h.epoch.to_public())
            .transpose()
    }

    /// The `labyrinthHead` of every participant of `conversation_id` that
    /// has one. The full record comes from [`MailboxDirectory::epoch`].
    pub fn conversation_heads(&self, conversation_id: &str) -> Result<Vec<LabyrinthHead>> {
        let out: ConversationStateOut = self.x.get_full(
            "blue.catbird.chat.getConversationState",
            &[("conversationId", conversation_id.to_owned())],
        )?;
        out.state
            .participants
            .into_iter()
            .filter_map(|p| p.labyrinth_head.map(|h| (p.user_did, h)))
            .map(|(did, h)| {
                Ok(LabyrinthHead {
                    did,
                    epoch_number: h.epoch_number,
                    epoch_head: h.epoch_head.array::<32>("labyrinthHead.epochHead length")?,
                    attestation_key_id: h.attestation_key_id,
                })
            })
            .collect()
    }
}

impl MailboxDirectory for XrpcDirectory {
    fn latest(&self, did: &str) -> Result<Option<EpochPublic>> {
        self.head(did, None)
    }

    fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>> {
        let e = self.head(did, Some(seq))?;
        if e.as_ref().is_some_and(|e| e.seq != seq) {
            return Err(Error::Malformed("getEpochHead returned another epoch"));
        }
        Ok(e)
    }

    fn device_transport_keys(&self, did: &str) -> Result<Vec<ChatDeviceKey>> {
        let v: Vec<ChatDeviceKeyView> = self
            .x
            .list_all("getChatDeviceKeys", &[("did", did.to_owned())])?;
        v.iter()
            .map(|k| {
                Ok(ChatDeviceKey {
                    key: key32(&k.signing_public_key)?,
                    removed_at: k.revoked_at.as_deref().map(ms_from_datetime).transpose()?,
                })
            })
            .collect()
    }

    fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> Result<Option<Vec<MemberDeviceKey>>> {
        let p = [("threadId", thread_id.to_owned()), ("did", did.to_owned())];
        let v: Vec<MemberDeviceView> = match self.x.list_all("getMemberDevices", &p) {
            Err(Error::NotFound(_)) => return Ok(None),
            r => r?,
        };
        v.iter()
            .map(|m| {
                Ok(MemberDeviceKey {
                    key: key32(&m.signing_public_key)?,
                    joined_chat_seq: m.joined_seq,
                    removed_chat_seq: m.removed_seq,
                })
            })
            .collect::<Result<_>>()
            .map(Some)
    }
}

impl KeyPublisher for XrpcDirectory {
    fn publish(&self, record: &MailboxKeysRecord) -> Result<()> {
        let input = PublishHeadIn {
            epoch: record.current.clone(),
        };
        let _: Empty = self.x.post("publishEpochHead", &input)?;
        Ok(())
    }

    /// mls-ds drops a DID's head chain only with its whole mailbox
    /// (`purgeMailbox`); there is no head-only retract. Use this publisher
    /// only for an account that is being deleted everywhere.
    fn retract(&self) -> Result<()> {
        let _: Empty = self.x.post("purgeMailbox", &Empty {})?;
        Ok(())
    }
}

/// The ORF server role on mls-ds ([CB-17]).
pub struct XrpcOrf {
    x: Xrpc,
}

impl XrpcOrf {
    pub fn new(transport: Arc<dyn XrpcTransport>) -> Self {
        Self {
            x: Xrpc::new(transport),
        }
    }

    /// `getAttachmentRef`: when the reference at this blinded index was
    /// created (ms), or `None`. mls-ds keeps no readable thread, message
    /// or blob linkage to return (decision J4).
    pub fn attachment_ref_created_at(
        &self,
        device_key: &XVerifyingKey,
        blinded_index: &ObliviousId,
    ) -> Result<Option<u64>> {
        let p = [
            ("deviceKeyPubkey", hex::encode(device_key.0)),
            ("blindedIndex", hex::encode(blinded_index.0)),
        ];
        self.x
            .get_opt::<AttachmentRefOut>("getAttachmentRef", &p)?
            .map(|o| ms_from_datetime(&o.created_at))
            .transpose()
    }
}

impl OrfServer for XrpcOrf {
    fn register(
        &self,
        device_key: &XVerifyingKey,
        parent: Option<(&XVerifyingKey, &EvolveToken)>,
    ) -> Result<()> {
        let input = RegisterOrfIn {
            device_key_pubkey: Bytes::from_slice(&device_key.0),
            parent: parent.map(|(k, t)| OrfParent {
                device_key_pubkey: Bytes::from_slice(&k.0),
                evolve_token: Bytes::from_slice(&t.0),
            }),
        };
        let _: Empty = self.x.post("registerOrfState", &input)?;
        Ok(())
    }

    /// mls-ds exposes no raw `orfMap` oracle (design §2): it maps only
    /// inside `putAttachmentRef` / `getAttachmentRef`.
    fn map(&self, _: &XVerifyingKey, _: &[u8], _: &ObliviousId) -> Result<[u8; 32]> {
        Err(Error::Backend(
            "mls-ds exposes no raw ORF map; use the attachment-reference endpoints".into(),
        ))
    }

    fn delete(&self, device_key: &XVerifyingKey) -> Result<()> {
        let input = DeviceKeyIn {
            device_key_pubkey: Bytes::from_slice(&device_key.0),
        };
        let _: Empty = self.x.post("deleteOrfState", &input)?;
        Ok(())
    }

    fn put_attachment_ref(&self, device_key: &XVerifyingKey, put: &AttachmentPut) -> Result<()> {
        let input = PutRefIn {
            device_key_pubkey: Bytes::from_slice(&device_key.0),
            blinded_index: Bytes::from_slice(&put.blinded_index.0),
            blinded_token_salt: Bytes::from_slice(&put.blinded_token_salt.0),
            blob_id: put.blob_id.clone(),
            thread_id: put.thread_id.clone(),
            message_id: put.message_id.clone(),
        };
        let _: Empty = self.x.post("putAttachmentRef", &input)?;
        Ok(())
    }

    /// `getAttachmentBlob`; every refusal is `NotFound("attachment")`.
    fn fetch_attachment(
        &self,
        device_key: &XVerifyingKey,
        fetch: &AttachmentFetch,
    ) -> Result<Vec<u8>> {
        let p = [
            ("deviceKeyPubkey", hex::encode(device_key.0)),
            ("blindedIndex", hex::encode(fetch.blinded_index.0)),
            ("blindedTokenSalt", hex::encode(fetch.blinded_token_salt.0)),
            ("threadId", fetch.thread_id.clone()),
            ("messageId", fetch.message_id.clone()),
        ];
        self.x.get_raw("getAttachmentBlob", &p)
    }

    fn delete_attachment_ref(
        &self,
        device_key: &XVerifyingKey,
        blinded_index: &ObliviousId,
    ) -> Result<()> {
        let input = DeleteRefIn {
            device_key_pubkey: Bytes::from_slice(&device_key.0),
            blinded_index: Bytes::from_slice(&blinded_index.0),
        };
        let _: Empty = self.x.post("deleteAttachmentRef", &input)?;
        Ok(())
    }
}

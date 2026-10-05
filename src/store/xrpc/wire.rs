//! JSON shapes of the `blue.catbird.labyrinth.*` endpoints, shared by the
//! stores and the reference server. Lexicons:
//! `lexicons/blue/catbird/labyrinth/`. Responses ignore unknown fields so
//! the server can add some; records keep their strict shapes.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::records::{Bytes, EpochPublicDef, RedactionDef, datetime_from_ms, ms_from_datetime};
use crate::store::ServerOrder;

/// `defs#serverOrder`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderDef {
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_seq: Option<u64>,
    pub received_at: String,
}

impl OrderDef {
    pub fn from_order(o: &ServerOrder) -> Self {
        Self {
            seq: o.labyrinth_seq,
            chat_seq: o.chat_seq,
            received_at: datetime_from_ms(o.received_at_ms),
        }
    }

    pub fn to_order(&self) -> Result<ServerOrder> {
        Ok(ServerOrder {
            labyrinth_seq: self.seq,
            chat_seq: self.chat_seq,
            received_at_ms: ms_from_datetime(&self.received_at)?,
        })
    }
}

/// `{items, cursor?}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `{record}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecordBody<T> {
    pub record: T,
}

/// `{}`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Empty {}

/// `{rkey}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RkeyOut {
    pub rkey: String,
}

/// `{rkey, order}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RkeyOrderOut {
    pub rkey: String,
    pub order: OrderDef,
}

/// `markDeviceRevoked` input.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkRevokedIn {
    pub device_key_pubkey: Bytes,
    pub revoked_at: String,
}

/// `createEpoch` input.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateEpochIn<E, M> {
    pub epoch: E,
    pub members: Vec<M>,
}

/// `createEpoch` output.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateEpochOut {
    pub epoch_id: String,
    pub epoch_number: u64,
}

/// `getEpoch` output and `listEpochs` item.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochView<E> {
    pub epoch_id: String,
    pub record: E,
}

/// `listOwnerBatches` item.
#[derive(Debug, Serialize, Deserialize)]
pub struct OwnedView<T> {
    pub rkey: String,
    pub record: T,
    pub order: OrderDef,
}

/// `findMeks` / `listBatches` item.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthoredView<T> {
    pub author: String,
    pub rkey: String,
    pub record: T,
    pub order: OrderDef,
}

/// `publishEpochHead` input.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublishHeadIn {
    pub epoch: EpochPublicDef,
}

/// `getEpochHead` output.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochHeadOut {
    pub epoch: EpochPublicDef,
    pub received_at: String,
}

/// `getChatDeviceKeys` item.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatDeviceKeyView {
    pub key_id: String,
    pub signing_public_key: Bytes,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

/// `getMemberDevices` item.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberDeviceView {
    pub key_id: String,
    pub signing_public_key: Bytes,
    pub joined_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_seq: Option<u64>,
}

/// `registerOrfState` parent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrfParent {
    pub device_key_pubkey: Bytes,
    pub evolve_token: Bytes,
}

/// `registerOrfState` input.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterOrfIn {
    pub device_key_pubkey: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<OrfParent>,
}

/// `deleteOrfState` input.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyIn {
    pub device_key_pubkey: Bytes,
}

/// `redactMessage` input. `redaction` carries the author's
/// `transportPubkey` and `sig`; the server sets `redactedAt`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactIn {
    pub thread_id: String,
    pub message_id: String,
    pub redaction: RedactionDef,
}

/// `redactMessage` output.
#[derive(Debug, Serialize, Deserialize)]
pub struct RedactOut {
    pub redacted: usize,
}

/// `touchVirtualDevice` / `deleteVirtualDevice` input.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VdeviceIn {
    pub vdevice_id: Bytes,
}

/// `putAttachmentRef` input.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutRefIn {
    pub device_key_pubkey: Bytes,
    pub blinded_index: Bytes,
    pub blinded_token_salt: Bytes,
    pub blob_id: String,
    pub thread_id: String,
    pub message_id: String,
}

/// `deleteAttachmentRef` input.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteRefIn {
    pub device_key_pubkey: Bytes,
    pub blinded_index: Bytes,
}

/// `getAttachmentRef` output.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRefOut {
    pub created_at: String,
}

/// `listThreads` / `listOwnerThreads` item (`#threadView`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadView {
    pub thread_id: String,
}

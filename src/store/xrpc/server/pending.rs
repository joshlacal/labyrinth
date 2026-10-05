//! Reference handlers for the gap-closing endpoints ([CB-33], [CB-38],
//! [CB-39]) whose lexicons the mls-ds lane is writing. The XRPC *stores*
//! do not call these yet (their trait methods return
//! [`crate::Error::NotSupported`]); the handlers pin the agreed
//! semantics so the client wrappers can be added once the lexicons land:
//!
//! | NSID | Shape |
//! |---|---|
//! | `redactMessage` | `{threadId, messageId, redaction:{transportPubkey, sig}}` → `{redacted}`; the key must be the calling chat device |
//! | `purgeMailbox` | `{}` → `{}` |
//! | `touchVirtualDevice`, `deleteVirtualDevice` | `{vdeviceId}` → `{}` |
//! | `putAttachmentRef` | `{deviceKeyPubkey, blindedIndex, blindedTokenSalt, blobId, threadId, messageId}` → `{}` |
//! | `getAttachmentBlob` (query) | `deviceKeyPubkey, blindedIndex, blindedTokenSalt` (hex), `threadId, messageId` → blob bytes |
//! | `deleteAttachmentRef` | `{deviceKeyPubkey, blindedIndex}` → `{}` |
//! | `listThreads`, `listOwnerThreads` (crate proposal, not built in mls-ds) | → `{threads: [threadId]}` |
//!
//! Errors as mls-ds returns them: a missing reference, a wrong token and a
//! redacted or missing message are all `NotFound` (no probing);
//! `OrfStateNotFound`; `AttachmentNotEntitled` (403) on put;
//! `AttachmentAlreadyReferenced` (409).

use serde::{Deserialize, Serialize};

use super::{Caller, Input, MemoryXrpcServer, Reply, bad, body, err, hex_param, json, req};
use crate::deletion::Redaction;
use crate::orf::ObliviousId;
use crate::records::Bytes;
use crate::sign::XVerifyingKey;
use crate::store::xrpc::XrpcError;
use crate::store::xrpc::wire::Empty;
use crate::store::{AttachmentFetch, AttachmentPut, MailboxStore, OrfServer, ThreadStore};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RedactionIn {
    pub transport_pubkey: Bytes,
    pub sig: Bytes,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RedactIn {
    pub thread_id: String,
    pub message_id: String,
    pub redaction: RedactionIn,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RedactOut {
    pub redacted: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VdeviceIn {
    pub vdevice_id: Bytes,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PutRefIn {
    pub device_key_pubkey: Bytes,
    pub blinded_index: Bytes,
    pub blinded_token_salt: Bytes,
    pub blob_id: String,
    pub thread_id: String,
    pub message_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeleteRefIn {
    pub device_key_pubkey: Bytes,
    pub blinded_index: Bytes,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ThreadsOut {
    pub threads: Vec<String>,
}

fn arr<const N: usize>(b: &Bytes, what: &str) -> core::result::Result<[u8; N], XrpcError> {
    b.array::<N>("bytes")
        .map_err(|_| bad(&format!("{what} is not {N} bytes")))
}

fn attachment_error(e: crate::Error) -> XrpcError {
    match e {
        crate::Error::Conflict => {
            XrpcError::named(409, "AttachmentAlreadyReferenced", e.to_string())
        }
        crate::Error::NotFound("attachment") => XrpcError::named(404, "NotFound", e.to_string()),
        crate::Error::Forbidden => XrpcError::named(403, "AttachmentNotEntitled", e.to_string()),
        e => err(e),
    }
}

pub(super) fn handle(
    s: &MemoryXrpcServer,
    c: &Caller,
    name: &str,
    input: &Input<'_>,
) -> Option<Reply> {
    let orf = s.net.orf(&c.did);
    let r = match name {
        "redactMessage" => (|| {
            let i: RedactIn = body(input)?;
            let key = arr::<32>(&i.redaction.transport_pubkey, "transportPubkey")?;
            if key != c.device {
                return Err(bad("transportPubkey is not the calling chat device"));
            }
            let r = Redaction {
                transport_public_key: key,
                sig: arr::<64>(&i.redaction.sig, "sig")?,
                redacted_at: None,
            };
            let n = s
                .net
                .threads(&c.did)
                .redact_item(&i.thread_id, &i.message_id, &r)
                .map_err(err)?;
            json(&RedactOut { redacted: n })
        })(),
        "purgeMailbox" => (|| {
            let _: Empty = body(input)?;
            s.net.mailbox(&c.did).purge_mailbox().map_err(err)?;
            json(&Empty {})
        })(),
        "touchVirtualDevice" | "deleteVirtualDevice" => (|| {
            let i: VdeviceIn = body(input)?;
            let id = arr::<16>(&i.vdevice_id, "vdeviceId")?;
            let mb = s.net.mailbox(&c.did);
            let r = if name == "touchVirtualDevice" {
                mb.touch_virtual_device(&id)
            } else {
                mb.delete_virtual_device(&id)
            };
            r.map_err(|e| match e {
                crate::Error::NotFound(_) => {
                    XrpcError::named(404, "VirtualDeviceNotFound", "not found")
                }
                e => err(e),
            })?;
            json(&Empty {})
        })(),
        "putAttachmentRef" => (|| {
            let i: PutRefIn = body(input)?;
            let put = AttachmentPut {
                blinded_index: ObliviousId(arr(&i.blinded_index, "blindedIndex")?),
                blinded_token_salt: ObliviousId(arr(&i.blinded_token_salt, "blindedTokenSalt")?),
                blob_id: i.blob_id,
                thread_id: i.thread_id,
                message_id: i.message_id,
            };
            let k = XVerifyingKey(arr(&i.device_key_pubkey, "deviceKeyPubkey")?);
            orf.put_attachment_ref(&k, &put).map_err(attachment_error)?;
            json(&Empty {})
        })(),
        "getAttachmentBlob" => (|| {
            let f = AttachmentFetch {
                blinded_index: ObliviousId(hex_param(input, "blindedIndex")?),
                blinded_token_salt: ObliviousId(hex_param(input, "blindedTokenSalt")?),
                thread_id: req(input, "threadId")?.to_owned(),
                message_id: req(input, "messageId")?.to_owned(),
            };
            let k = XVerifyingKey(hex_param(input, "deviceKeyPubkey")?);
            orf.fetch_attachment(&k, &f).map_err(attachment_error)
        })(),
        "deleteAttachmentRef" => (|| {
            let i: DeleteRefIn = body(input)?;
            let k = XVerifyingKey(arr(&i.device_key_pubkey, "deviceKeyPubkey")?);
            let idx = ObliviousId(arr(&i.blinded_index, "blindedIndex")?);
            orf.delete_attachment_ref(&k, &idx).map_err(err)?;
            json(&Empty {})
        })(),
        "listThreads" => s
            .net
            .threads(&c.did)
            .list_threads()
            .map_err(err)
            .and_then(|threads| json(&ThreadsOut { threads })),
        "listOwnerThreads" => s
            .net
            .mailbox(&c.did)
            .list_owner_threads()
            .map_err(err)
            .and_then(|threads| json(&ThreadsOut { threads })),
        _ => return None,
    };
    Some(r)
}

//! Attachment-reference endpoints of the reference server ([CB-33], SPEC
//! §8; mls-ds decision J4): `putAttachmentRef`, `getAttachmentRef`,
//! `getAttachmentBlob` (a query whose output is the blob bytes) and
//! `deleteAttachmentRef`.
//!
//! Errors as mls-ds returns them: every refusal of a read is `NotFound`
//! (a missing reference, a wrong token and a redacted or missing message
//! look alike); `OrfStateNotFound`; on put, `AttachmentNotEntitled` (403)
//! when the blob or the message is not one the caller may reference, and
//! `AttachmentAlreadyReferenced` (409) for a second message per blob.
//! Re-putting a reference that already exists answers `RecordAlreadyExists`
//! (409), as mls-ds does, and leaves the one stored reference unchanged. (The
//! memory `OrfServer` itself treats an identical re-put as a no-op; the
//! XRPC layer reports it the way mls-ds does.)

use super::{Caller, Input, MemoryXrpcServer, Reply, bad, body, err, hex_param, json, req};
use crate::Error;
use crate::orf::ObliviousId;
use crate::records::{Bytes, datetime_from_ms};
use crate::sign::XVerifyingKey;
use crate::store::xrpc::XrpcError;
use crate::store::xrpc::wire::{AttachmentRefOut, DeleteRefIn, Empty, PutRefIn};
use crate::store::{AttachmentFetch, AttachmentPut, OrfServer};

fn arr<const N: usize>(b: &Bytes, what: &str) -> core::result::Result<[u8; N], XrpcError> {
    b.array::<N>("bytes")
        .map_err(|_| bad(&format!("{what} is not {N} bytes")))
}

fn attachment_error(e: Error) -> XrpcError {
    match e {
        Error::Conflict => XrpcError::named(409, "AttachmentAlreadyReferenced", e.to_string()),
        Error::NotFound("attachment") => XrpcError::named(404, "NotFound", e.to_string()),
        Error::Forbidden | Error::NotFound("blob") => {
            XrpcError::named(403, "AttachmentNotEntitled", e.to_string())
        }
        e => err(e),
    }
}

fn put(s: &MemoryXrpcServer, c: &Caller, input: &Input<'_>) -> Reply {
    let i: PutRefIn = body(input)?;
    let put = AttachmentPut {
        blinded_index: ObliviousId(arr(&i.blinded_index, "blindedIndex")?),
        blinded_token_salt: ObliviousId(arr(&i.blinded_token_salt, "blindedTokenSalt")?),
        blob_id: i.blob_id,
        thread_id: i.thread_id,
        message_id: i.message_id,
    };
    let k = XVerifyingKey(arr(&i.device_key_pubkey, "deviceKeyPubkey")?);
    let existed = s
        .net
        .attachment_ref_created_at(&c.did, &k.0, &put.blinded_index)
        .is_ok();
    s.net
        .orf(&c.did)
        .put_attachment_ref(&k, &put)
        .map_err(attachment_error)?;
    if existed {
        return Err(XrpcError::named(
            409,
            "RecordAlreadyExists",
            "attachment reference already exists",
        ));
    }
    json(&Empty {})
}

fn fetch(s: &MemoryXrpcServer, c: &Caller, input: &Input<'_>) -> Reply {
    let f = AttachmentFetch {
        blinded_index: ObliviousId(hex_param(input, "blindedIndex")?),
        blinded_token_salt: ObliviousId(hex_param(input, "blindedTokenSalt")?),
        thread_id: req(input, "threadId")?.to_owned(),
        message_id: req(input, "messageId")?.to_owned(),
    };
    let k = XVerifyingKey(hex_param(input, "deviceKeyPubkey")?);
    s.net
        .orf(&c.did)
        .fetch_attachment(&k, &f)
        .map_err(|e| match e {
            // A blob GC'd under a live reference reads like any refusal.
            Error::NotFound(_) if !matches!(e, Error::NotFound("orf state")) => {
                XrpcError::named(404, "NotFound", "not found")
            }
            e => attachment_error(e),
        })
}

pub(super) fn handle(
    s: &MemoryXrpcServer,
    c: &Caller,
    name: &str,
    input: &Input<'_>,
) -> Option<Reply> {
    let r = match name {
        "putAttachmentRef" => put(s, c, input),
        "getAttachmentBlob" => fetch(s, c, input),
        "getAttachmentRef" => (|| {
            let k: [u8; 32] = hex_param(input, "deviceKeyPubkey")?;
            let idx = ObliviousId(hex_param(input, "blindedIndex")?);
            let at = s
                .net
                .attachment_ref_created_at(&c.did, &k, &idx)
                .map_err(attachment_error)?;
            json(&AttachmentRefOut {
                created_at: datetime_from_ms(at),
            })
        })(),
        "deleteAttachmentRef" => (|| {
            let i: DeleteRefIn = body(input)?;
            let k = XVerifyingKey(arr(&i.device_key_pubkey, "deviceKeyPubkey")?);
            let idx = ObliviousId(arr(&i.blinded_index, "blindedIndex")?);
            s.net
                .orf(&c.did)
                .delete_attachment_ref(&k, &idx)
                .map_err(err)?;
            json(&Empty {})
        })(),
        _ => return None,
    };
    Some(r)
}

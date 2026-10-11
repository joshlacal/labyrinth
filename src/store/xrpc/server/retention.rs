//! Retention endpoints of the reference server ([CB-38], [CB-39]; mls-ds
//! decisions J1, J2): `redactMessage`, `purgeMailbox`, `deleteAccountData`,
//! `touchVirtualDevice` and `deleteVirtualDevice`, with mls-ds's errors.
//!
//! `redactMessage` is idempotent: an unknown or already-redacted id counts
//! zero. A redaction whose key is not the calling chat device, or whose
//! signature does not verify, is `InvalidRedaction`.

use super::{Caller, Input, MemoryXrpcServer, Reply, body, err, json};
use crate::Error;
use crate::store::xrpc::XrpcError;
use crate::store::xrpc::wire::{Empty, RedactIn, RedactOut, VdeviceIn};
use crate::store::{MailboxStore, ThreadStore};

fn invalid_redaction(msg: &str) -> XrpcError {
    XrpcError::named(400, "InvalidRedaction", msg)
}

fn redact(s: &MemoryXrpcServer, c: &Caller, input: &Input<'_>) -> Reply {
    let i: RedactIn = body(input)?;
    if i.redaction.redacted_at.is_some() {
        return Err(invalid_redaction("redactedAt is set by the server"));
    }
    let r = i
        .redaction
        .to_redaction()
        .map_err(|_| invalid_redaction("malformed redaction"))?
        .ok_or_else(|| invalid_redaction("an unsend carries transportPubkey and sig"))?;
    if r.transport_public_key != c.device {
        return Err(invalid_redaction(
            "transportPubkey is not the calling chat device's key",
        ));
    }
    let redacted = match s
        .net
        .threads(&c.did)
        .redact_item(&i.thread_id, &i.message_id, &r)
    {
        Ok(n) => n,
        Err(Error::NotFound(_)) => 0,
        Err(Error::BadSignature) => return Err(invalid_redaction("sig does not verify")),
        Err(e) => return Err(err(e)),
    };
    json(&RedactOut { redacted })
}

fn vdevice(s: &MemoryXrpcServer, c: &Caller, name: &str, input: &Input<'_>) -> Reply {
    let i: VdeviceIn = body(input)?;
    let id = i
        .vdevice_id
        .array::<16>("vdeviceId")
        .map_err(|_| super::bad("vdeviceId is not 16 bytes"))?;
    let mb = s.net.mailbox(&c.did);
    let r = if name == "touchVirtualDevice" {
        mb.touch_virtual_device(&id)
    } else {
        mb.delete_virtual_device(&id)
    };
    r.map_err(|e| match e {
        Error::NotFound(_) => XrpcError::named(404, "VirtualDeviceNotFound", "not found"),
        e => err(e),
    })?;
    json(&Empty {})
}

pub(super) fn handle(
    s: &MemoryXrpcServer,
    c: &Caller,
    name: &str,
    input: &Input<'_>,
) -> Option<Reply> {
    let r = match name {
        "redactMessage" => redact(s, c, input),
        "purgeMailbox" | "deleteAccountData" => (|| {
            let _: Empty = body(input)?;
            if name == "purgeMailbox" {
                s.net.mailbox(&c.did).purge_mailbox().map_err(err)?;
            } else {
                s.net.delete_account_data(&c.did);
            }
            json(&Empty {})
        })(),
        "touchVirtualDevice" | "deleteVirtualDevice" => vdevice(s, c, name, input),
        _ => return None,
    };
    Some(r)
}

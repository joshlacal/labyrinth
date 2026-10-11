//! The mls-ds Labyrinth-device ↔ chat-device binding rules ([CB-36];
//! mls-ds `labyrinth/repo/binding.rs`), enforced by the reference server.
//!
//! `createDevice` requires a physical device to carry a `chatBinding` by
//! the *calling* chat device's key (a virtual device carries none). Epoch
//! writes then require the caller to hold a current, non-virtual,
//! Labyrinth device bound to its chat key, and every member they name to
//! be a current device of the account. A chat device can therefore only
//! act as its own Labyrinth device; clients revoke the chat device before
//! rotating its Labyrinth device out.

use super::{Caller, MemoryXrpcServer, err};
use crate::records::Device;
use crate::sign::XVerifyingKey;
use crate::store::MailboxStore;
use crate::store::xrpc::XrpcError;

fn invalid(msg: &str) -> XrpcError {
    XrpcError::named(400, "InvalidChatBinding", msg)
}

/// `createDevice`'s check.
pub(super) fn verify_chat_binding(c: &Caller, d: &Device) -> Result<(), XrpcError> {
    let binding = d
        .chat_binding()
        .map_err(|_| invalid("malformed chatBinding"))?;
    match (binding, d.r#virtual) {
        (None, true) => Ok(()),
        (Some(_), true) => Err(invalid("a virtual device carries no chatBinding")),
        (None, false) => Err(invalid("a physical device needs a chatBinding")),
        (Some(b), false) => {
            if b.transport_public_key != c.device {
                return Err(invalid(
                    "chatBinding.transportPubkey is not the calling chat device's key",
                ));
            }
            let key = d
                .device_key_pubkey
                .array::<32>("deviceKeyPubkey")
                .map_err(|_| invalid("deviceKeyPubkey is not 32 bytes"))?;
            b.verify(&c.did, &XVerifyingKey(key))
                .map_err(|_| invalid("chatBinding.sig does not verify"))
        }
    }
}

/// Whether `did` keeps its mailbox on this server. An account whose mailbox
/// is in its PDS Space has none here; mls-ds then serves only its head
/// directory and ORF state, and the binding rules do not apply to it.
pub(super) fn hosts_mailbox(s: &MemoryXrpcServer, did: &str) -> Result<bool, XrpcError> {
    let mb = s.net.mailbox(did);
    Ok(!mb.list_devices().map_err(err)?.is_empty()
        || !mb.list_epochs().map_err(err)?.is_empty()
        || !mb.list_virtual_devices().map_err(err)?.is_empty())
}

/// The caller holds a current, non-virtual device bound to its chat key
/// (that device exactly, with `key`).
pub(super) fn require_bound(
    s: &MemoryXrpcServer,
    c: &Caller,
    key: Option<&[u8]>,
) -> Result<(), XrpcError> {
    let devices = s.net.mailbox(&c.did).list_devices().map_err(err)?;
    let bound = devices.iter().any(|d| {
        !d.r#virtual
            && d.revoked_at.is_none()
            && key.is_none_or(|k| d.device_key_pubkey.0 == k)
            && d.chat_binding()
                .ok()
                .flatten()
                .is_some_and(|b| b.transport_public_key == c.device)
    });
    if bound {
        Ok(())
    } else {
        Err(XrpcError::named(
            403,
            "LabyrinthDeviceNotBound",
            "the calling chat device holds no current Labyrinth device",
        ))
    }
}

/// Every key is a current (non-revoked) device of the caller's account.
pub(super) fn require_registered(
    s: &MemoryXrpcServer,
    c: &Caller,
    keys: &[&[u8]],
) -> Result<(), XrpcError> {
    let devices = s.net.mailbox(&c.did).list_devices().map_err(err)?;
    let ok = keys.iter().all(|k| {
        devices
            .iter()
            .any(|d| d.revoked_at.is_none() && d.device_key_pubkey.0 == *k)
    });
    if ok {
        Ok(())
    } else {
        Err(XrpcError::named(
            400,
            "MemberDeviceNotRegistered",
            "an epoch member is not a current Labyrinth device of this account",
        ))
    }
}

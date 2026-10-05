//! Thread and directory endpoints of the reference server.

use std::collections::HashMap;

use super::mailbox::range;
use super::{Caller, Input, MemoryXrpcServer, Reply, bad, body, err, hex_param, json, num, req};
use crate::records::{
    Batch, Bytes, EpochPublicDef, MekDistribution, MekSenderDef, datetime_from_ms, ms_from_datetime,
};
use crate::store::xrpc::XrpcError;
use crate::store::xrpc::wire::{
    AuthoredView, ChatDeviceKeyView, Empty, EpochHeadOut, MemberDeviceView, OrderDef,
    PublishHeadIn, RecordBody, RkeyOrderOut,
};
use crate::store::{MailboxDirectory, Stored, ThreadStore, TimeRange};

fn named(status: u16, name: &str, msg: &str) -> XrpcError {
    XrpcError::named(status, name, msg)
}

/// Per-MEK read authorization: the caller wrote the MEK or is addressed.
fn can_read(m: &Stored<MekDistribution>, did: &str) -> bool {
    m.author == did || m.value.recipients.iter().any(|r| r.did == did)
}

fn authored<T>(v: Stored<T>) -> AuthoredView<T> {
    AuthoredView {
        order: OrderDef::from_order(&v.order.unwrap_or_default()),
        author: v.author,
        rkey: v.rkey,
        record: v.value,
    }
}

pub(super) fn handle(
    s: &MemoryXrpcServer,
    c: &Caller,
    name: &str,
    input: &Input<'_>,
) -> Option<Reply> {
    let th = s.net.threads(&c.did);
    let r = match name {
        "createMek" => (|| {
            let m: RecordBody<MekDistribution> = body(input)?;
            let m = m.record;
            match &m.sender {
                MekSenderDef::Labyrinth(l) => {
                    if l.did != c.did {
                        return Err(named(400, "SenderMismatch", "sender DID is not the caller"));
                    }
                    let k = &l.sender_epoch.attestation.transport_pubkey.0;
                    let current = s
                        .net
                        .directory()
                        .device_transport_keys(&c.did)
                        .map_err(err)?
                        .iter()
                        .any(|x| x.is_current() && x.key[..] == k[..]);
                    if !current {
                        return Err(named(400, "AttestationNotCurrent", "attestation key"));
                    }
                }
                MekSenderDef::Transport(t) => {
                    if t.transport_pubkey.0 != c.device {
                        return Err(named(
                            400,
                            "SenderMismatch",
                            "transport key is not the caller's",
                        ));
                    }
                }
            }
            th.create_mek(&m).map_err(err)?;
            let id = m.mek_id.array::<12>("mekId").map_err(err)?;
            let order = th
                .find_meks(&m.thread_id, &id)
                .map_err(err)?
                .into_iter()
                .find(|x| x.author == c.did)
                .and_then(|x| x.order)
                .unwrap_or_default();
            json(&RkeyOrderOut {
                rkey: m.rkey(),
                order: OrderDef::from_order(&order),
            })
        })(),
        "findMeks" => (|| {
            let id = hex_param::<12>(input, "mekId")?;
            let v: Vec<_> = th
                .find_meks(req(input, "threadId")?, &id)
                .map_err(err)?
                .into_iter()
                .filter(|m| can_read(m, &c.did))
                .map(authored)
                .collect();
            s.page(v, input)
        })(),
        "appendBatch" => (|| {
            let b: RecordBody<Batch> = body(input)?;
            let b = b.record;
            let first = b.items.first().ok_or_else(|| bad("empty batch"))?;
            if b.items.iter().any(|i| i.mek_id != first.mek_id) {
                return Err(named(400, "MixedMekBatch", "one MEK per batch"));
            }
            if b.items
                .iter()
                .any(|i| i.sender_transport_pubkey.0 != c.device)
            {
                return Err(named(400, "SenderKeyMismatch", "not the caller's key"));
            }
            let id = first.mek_id.array::<12>("mekId").map_err(err)?;
            let meks = th.find_meks(&b.thread_id, &id).map_err(err)?;
            if meks.is_empty() {
                return Err(named(400, "UnknownMek", "no such MEK in the thread"));
            }
            if !meks.iter().any(|m| can_read(m, &c.did)) {
                return Err(named(403, "NotRecipient", "caller cannot use this MEK"));
            }
            let rkey = th.append_batch(&b).map_err(err)?;
            let order = th
                .list_batches(&b.thread_id, Some(&c.did), TimeRange::ALL)
                .map_err(err)?
                .into_iter()
                .find(|x| x.rkey == rkey)
                .and_then(|x| x.order)
                .unwrap_or_default();
            json(&RkeyOrderOut {
                rkey,
                order: OrderDef::from_order(&order),
            })
        })(),
        "listBatches" => (|| {
            let thread = req(input, "threadId")?;
            let sender = super::param(input, "sender");
            let v = th
                .list_batches(thread, sender, range(input)?)
                .map_err(err)?;
            let v = readable(&th, &c.did, thread, received(input, v)?)?;
            s.page(seq_order(v, flag(input, "reverse")?), input)
        })(),
        "publishEpochHead" => (|| {
            let i: PublishHeadIn = body(input)?;
            let e = i.epoch.to_public().map_err(err)?;
            s.net.record_ds_head(&c.did, &e).map_err(|e| match e {
                crate::Error::Conflict => named(409, "EpochHeadConflict", "different head"),
                e => err(e),
            })?;
            json(&Empty {})
        })(),
        "getEpochHead" => (|| {
            let did = req(input, "did")?;
            let dir = s.net.ds_directory();
            let e = match num(input, "epochNumber")? {
                Some(n) => dir.epoch(did, n),
                None => dir.latest(did),
            }
            .map_err(err)?
            .ok_or_else(|| named(404, "EpochNotFound", "no such head"))?;
            json(&EpochHeadOut {
                epoch: EpochPublicDef::from_public(&e),
                received_at: datetime_from_ms(s.net.server_time()),
            })
        })(),
        "getChatDeviceKeys" => (|| {
            let keys = s
                .net
                .directory()
                .device_transport_keys(req(input, "did")?)
                .map_err(err)?;
            let v: Vec<_> = keys
                .iter()
                .map(|k| ChatDeviceKeyView {
                    key_id: hex::encode(&k.key[..8]),
                    signing_public_key: Bytes::from_slice(&k.key),
                    created_at: datetime_from_ms(0),
                    revoked_at: k.removed_at.map(datetime_from_ms),
                })
                .collect();
            s.page(v, input)
        })(),
        "getMemberDevices" => (|| {
            let keys = s
                .net
                .directory()
                .member_device_keys(req(input, "threadId")?, req(input, "did")?)
                .map_err(err)?
                .ok_or_else(|| named(404, "ConversationNotFound", "no leaf view"))?;
            let v: Vec<_> = keys
                .iter()
                .map(|k| MemberDeviceView {
                    key_id: hex::encode(&k.key[..8]),
                    signing_public_key: Bytes::from_slice(&k.key),
                    joined_seq: k.joined_chat_seq,
                    removed_seq: k.removed_chat_seq,
                })
                .collect();
            s.page(v, input)
        })(),
        _ => return None,
    };
    Some(r)
}

/// Batches the caller may read: its own, or sealed under a MEK it wrote
/// or received ([CB-16], [CB-22]); one MEK lookup per distinct MEK.
pub(super) fn readable(
    th: &impl ThreadStore,
    did: &str,
    thread: &str,
    batches: Vec<Stored<Batch>>,
) -> core::result::Result<Vec<Stored<Batch>>, XrpcError> {
    let mut known: HashMap<Vec<u8>, bool> = HashMap::new();
    let mut keep = Vec::new();
    for b in batches {
        let Some(first) = b.value.items.first() else {
            continue;
        };
        let ok = b.author == did
            || match known.get(&first.mek_id.0) {
                Some(ok) => *ok,
                None => {
                    let id = first.mek_id.array::<12>("mekId").map_err(err)?;
                    let ok = th
                        .find_meks(thread, &id)
                        .map_err(err)?
                        .iter()
                        .any(|m| can_read(m, did));
                    known.insert(first.mek_id.0.clone(), ok);
                    ok
                }
            };
        if ok {
            keep.push(b);
        }
    }
    Ok(keep)
}

/// Keeps records the server received in `[since, until)`.
pub(super) fn received<T>(
    input: &Input<'_>,
    v: Vec<Stored<T>>,
) -> core::result::Result<Vec<Stored<T>>, XrpcError> {
    let at = |k: &str| {
        super::param(input, k)
            .map(|d| ms_from_datetime(d).map_err(|_| bad(&format!("{k} is not a datetime"))))
            .transpose()
    };
    let (since, until) = (at("since")?, at("until")?);
    Ok(v.into_iter()
        .filter(|b| {
            let t = b.order.map_or(0, |o| o.received_at_ms);
            since.is_none_or(|s| t >= s) && until.is_none_or(|u| t < u)
        })
        .collect())
}

/// Server seq order (descending with `reverse`), as authored views.
pub(super) fn seq_order<T>(mut v: Vec<Stored<T>>, reverse: bool) -> Vec<AuthoredView<T>> {
    v.sort_by_key(|b| b.order.map(|o| o.labyrinth_seq));
    if reverse {
        v.reverse();
    }
    v.into_iter().map(authored).collect()
}

/// A boolean query parameter (`true` / `false`, default false).
pub(super) fn flag(input: &Input<'_>, k: &str) -> core::result::Result<bool, XrpcError> {
    match super::param(input, k) {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(bad(&format!("{k} is not a boolean"))),
    }
}

/// The `labyrinthHead` projection of `getConversationState` (design §1a):
/// one participant per DID with a leaf, carrying mls-ds's latest head.
pub(super) fn conversation_state(s: &MemoryXrpcServer, input: &Input<'_>) -> Reply {
    let thread = req(input, "conversationId")?;
    let dir = s.net.ds_directory();
    let mut participants = Vec::new();
    for did in s.net.leaf_dids(thread) {
        let mut p = serde_json::json!({ "userDid": did });
        if let Some(e) = dir.latest(&did).map_err(err)? {
            p["labyrinthHead"] = serde_json::json!({
                "epochNumber": e.seq,
                "epochHead": Bytes::from_slice(&e.head),
                "attestationKeyId": hex::encode(&e.attestation.transport_public_key[..8]),
            });
        }
        participants.push(p);
    }
    json(&serde_json::json!({ "state": { "participants": participants } }))
}

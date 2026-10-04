//! Thread and directory endpoints of the reference server.

use std::collections::HashMap;

use super::mailbox::range;
use super::{Caller, Input, MemoryXrpcServer, Reply, bad, body, err, hex_param, json, num, req};
use crate::records::{
    Batch, Bytes, EpochPublicDef, MekDistribution, MekSenderDef, datetime_from_ms,
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
            let mut v = th
                .list_batches(thread, sender, range(input)?)
                .map_err(err)?;
            let mut readable: HashMap<Vec<u8>, bool> = HashMap::new();
            let mut keep = Vec::new();
            for b in v.drain(..) {
                let Some(first) = b.value.items.first() else {
                    continue;
                };
                let ok = b.author == c.did
                    || match readable.get(&first.mek_id.0) {
                        Some(ok) => *ok,
                        None => {
                            let id = first.mek_id.array::<12>("mekId").map_err(err)?;
                            let ok = th
                                .find_meks(thread, &id)
                                .map_err(err)?
                                .iter()
                                .any(|m| can_read(m, &c.did));
                            readable.insert(first.mek_id.0.clone(), ok);
                            ok
                        }
                    };
                if ok {
                    keep.push(b);
                }
            }
            keep.sort_by_key(|b| b.order.map(|o| o.labyrinth_seq));
            s.page(keep.into_iter().map(authored).collect(), input)
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

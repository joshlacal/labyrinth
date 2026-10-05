//! Mailbox and ORF endpoints of the reference server. Every call reads and
//! writes the caller DID's own mailbox.

use serde::{Deserialize, Serialize};

use super::binding::{require_bound, require_registered, verify_chat_binding};
use super::{Caller, Input, MemoryXrpcServer, Reply, bad, body, err, hex_param, json, num, req};
use crate::orf::EvolveToken;
use crate::records::{Device, Epoch, EpochMember, OwnerBatch, VirtualDevice};
use crate::sign::XVerifyingKey;
use crate::store::xrpc::XrpcError;
use crate::store::xrpc::wire::{
    CreateEpochIn, CreateEpochOut, DeviceKeyIn, Empty, EpochView, MarkRevokedIn, OrderDef,
    OrfParent, OwnedView, RecordBody, RegisterOrfIn, RkeyOrderOut, RkeyOut,
};
use crate::store::{MailboxStore, OrfServer, TimeRange};

/// `createVirtualDevice` input. `member` and `orf` are optional: the
/// client writes them through `createEpochMember` / `registerOrfState`.
#[derive(Serialize, Deserialize)]
struct CreateVirtualDeviceIn {
    record: VirtualDevice,
    #[serde(default)]
    member: Option<EpochMember>,
    #[serde(default)]
    orf: Option<OrfParent>,
}

fn key(b: &crate::records::Bytes) -> core::result::Result<XVerifyingKey, XrpcError> {
    b.array::<32>("key")
        .map(XVerifyingKey)
        .map_err(|_| bad("key is not 32 bytes"))
}

fn not_found(name: &str) -> XrpcError {
    XrpcError::named(404, name, "not found")
}

pub(super) fn range(input: &Input<'_>) -> core::result::Result<TimeRange, XrpcError> {
    Ok(TimeRange {
        from_ms: num(input, "fromMs")?,
        until_ms: num(input, "untilMs")?,
    })
}

pub(super) fn handle(
    s: &MemoryXrpcServer,
    c: &Caller,
    name: &str,
    input: &Input<'_>,
) -> Option<Reply> {
    let mb = s.net.mailbox(&c.did);
    let orf = s.net.orf(&c.did);
    let r = match name {
        "createDevice" => (|| {
            let d: RecordBody<Device> = body(input)?;
            verify_chat_binding(c, &d.record)?;
            mb.create_device(&d.record).map_err(err)?;
            json(&RkeyOut {
                rkey: hex::encode(&d.record.device_key_pubkey.0),
            })
        })(),
        "markDeviceRevoked" => (|| {
            let i: MarkRevokedIn = body(input)?;
            let k = key(&i.device_key_pubkey)?;
            require_bound(s, c, None)?;
            mb.set_device_revoked(&k, &i.revoked_at).map_err(err)?;
            orf.delete(&k).map_err(err)?;
            json(&Empty {})
        })(),
        "getDevice" => (|| {
            let k = XVerifyingKey(hex_param::<32>(input, "deviceKeyPubkey")?);
            let d = mb.get_device(&k).map_err(err)?;
            json(&RecordBody {
                record: d.ok_or_else(|| not_found("DeviceNotFound"))?,
            })
        })(),
        "listDevices" => mb
            .list_devices()
            .map_err(err)
            .and_then(|v| s.page(v, input)),
        "createEpoch" => (|| {
            let i: CreateEpochIn<Epoch, EpochMember> = body(input)?;
            if i.members.len() > 256 {
                return Err(bad("too many members"));
            }
            require_bound(s, c, Some(&i.epoch.opened_by.0))?;
            let keys: Vec<&[u8]> = i
                .members
                .iter()
                .map(|m| m.device_key_pubkey.0.as_slice())
                .collect();
            require_registered(s, c, &keys)?;
            let public = i.epoch.public.to_public().map_err(err)?;
            s.net.record_ds_head(&c.did, &public).map_err(err)?;
            let id = mb.create_epoch(&i.epoch, &i.members).map_err(err)?;
            json(&CreateEpochOut {
                epoch_id: id,
                epoch_number: i.epoch.seq(),
            })
        })(),
        "getEpoch" => (|| {
            let n = num(input, "epochNumber")?.ok_or_else(|| bad("missing epochNumber"))?;
            let e = mb.get_epoch(n).map_err(err)?;
            let e = e.ok_or_else(|| not_found("EpochNotFound"))?;
            json(&EpochView {
                epoch_id: e.rkey,
                record: e.value,
            })
        })(),
        "listEpochs" => (|| {
            let v = mb.list_epochs().map_err(err)?;
            let v: Vec<_> = v
                .into_iter()
                .map(|e| EpochView {
                    epoch_id: e.rkey,
                    record: e.value,
                })
                .collect();
            s.page(v, input)
        })(),
        "createEpochMember" => (|| {
            let m: RecordBody<EpochMember> = body(input)?;
            require_bound(s, c, None)?;
            require_registered(s, c, &[&m.record.device_key_pubkey.0])?;
            mb.create_epoch_member(&m.record).map_err(err)?;
            json(&Empty {})
        })(),
        "listEpochMembers" => (|| {
            let n = num(input, "epochNumber")?.ok_or_else(|| bad("missing epochNumber"))?;
            s.page(mb.list_epoch_members(n).map_err(err)?, input)
        })(),
        "createVirtualDevice" => (|| {
            let i: CreateVirtualDeviceIn = body(input)?;
            mb.create_virtual_device(&i.record).map_err(err)?;
            if let Some(m) = &i.member {
                require_bound(s, c, None)?;
                require_registered(s, c, &[&m.device_key_pubkey.0])?;
                mb.create_epoch_member(m).map_err(err)?;
            }
            if let Some(p) = &i.orf {
                let token = EvolveToken(p.evolve_token.array::<32>("token").map_err(err)?);
                let child = key(&i.record.device_key_pubkey)?;
                orf.register(&child, Some((&key(&p.device_key_pubkey)?, &token)))
                    .map_err(err)?;
            }
            json(&Empty {})
        })(),
        "getVirtualDevice" => (|| {
            let id = hex_param::<16>(input, "vdeviceId")?;
            let v = mb.get_virtual_device(&id).map_err(err)?;
            json(&RecordBody {
                record: v.ok_or_else(|| not_found("VirtualDeviceNotFound"))?,
            })
        })(),
        "listVirtualDevices" => mb
            .list_virtual_devices()
            .map_err(err)
            .and_then(|v| s.page(v, input)),
        "appendOwnerBatch" => (|| {
            let b: RecordBody<OwnerBatch> = body(input)?;
            let rkey = mb.append_owner_batch(&b.record).map_err(err)?;
            let stored = mb
                .list_owner_batches(&b.record.thread_id, TimeRange::ALL)
                .map_err(err)?;
            let order = stored
                .iter()
                .find(|x| x.rkey == rkey)
                .and_then(|x| x.order)
                .ok_or_else(|| bad("owner batch not stamped"))?;
            json(&RkeyOrderOut {
                rkey,
                order: OrderDef::from_order(&order),
            })
        })(),
        "listOwnerBatches" => (|| {
            let v = mb
                .list_owner_batches(req(input, "threadId")?, range(input)?)
                .map_err(err)?;
            let v: Vec<_> = v
                .into_iter()
                .map(|b| OwnedView {
                    order: OrderDef::from_order(&b.order.unwrap_or_default()),
                    rkey: b.rkey,
                    record: b.value,
                })
                .collect();
            s.page(v, input)
        })(),
        "registerOrfState" => (|| {
            let i: RegisterOrfIn = body(input)?;
            let parent = match &i.parent {
                None => None,
                Some(p) => Some((
                    key(&p.device_key_pubkey)?,
                    EvolveToken(p.evolve_token.array::<32>("token").map_err(err)?),
                )),
            };
            orf.register(
                &key(&i.device_key_pubkey)?,
                parent.as_ref().map(|(k, t)| (k, t)),
            )
            .map_err(err)?;
            json(&Empty {})
        })(),
        "deleteOrfState" => (|| {
            let i: DeviceKeyIn = body(input)?;
            orf.delete(&key(&i.device_key_pubkey)?).map_err(err)?;
            json(&Empty {})
        })(),
        _ => return None,
    };
    Some(r)
}

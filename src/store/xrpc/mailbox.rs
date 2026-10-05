//! [`MailboxStore`] over the mls-ds mailbox endpoints (design §2,
//! "Mailbox"). The caller is a chat device of the mailbox owner.

use std::sync::Arc;

use super::wire::{
    CreateEpochIn, CreateEpochOut, Empty, EpochView, MarkRevokedIn, OwnedView, PublishHeadIn,
    RecordBody, RkeyOrderOut, RkeyOut, ThreadView, VdeviceIn,
};
use super::{Xrpc, XrpcTransport};
use crate::records::{
    Bytes, Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use crate::sign::XVerifyingKey;
use crate::store::{MailboxStore, Stored, TimeRange};
use crate::{Error, Result};

/// A personal mailbox stored in mls-ds, bound to its owner's DID.
pub struct XrpcMailboxStore {
    did: String,
    x: Xrpc,
}

impl XrpcMailboxStore {
    pub fn new(did: &str, transport: Arc<dyn XrpcTransport>) -> Self {
        Self {
            did: did.to_owned(),
            x: Xrpc::new(transport),
        }
    }

    fn stored<T>(&self, rkey: String, value: T) -> Stored<T> {
        Stored {
            author: self.did.clone(),
            rkey,
            value,
            order: None,
        }
    }
}

pub(super) fn range_params(range: TimeRange, p: &mut Vec<(&'static str, String)>) {
    if let Some(f) = range.from_ms {
        p.push(("fromMs", f.to_string()));
    }
    if let Some(u) = range.until_ms {
        p.push(("untilMs", u.to_string()));
    }
}

impl MailboxStore for XrpcMailboxStore {
    fn owner(&self) -> &str {
        &self.did
    }

    fn create_device(&self, device: &Device) -> Result<()> {
        let _: RkeyOut = self
            .x
            .post("createDevice", &RecordBody { record: device })?;
        Ok(())
    }

    fn set_device_revoked(&self, device_key: &XVerifyingKey, revoked_at: &str) -> Result<()> {
        let input = MarkRevokedIn {
            device_key_pubkey: Bytes::from_slice(&device_key.0),
            revoked_at: revoked_at.to_owned(),
        };
        let _: Empty = self.x.post("markDeviceRevoked", &input)?;
        Ok(())
    }

    fn get_device(&self, device_key: &XVerifyingKey) -> Result<Option<Device>> {
        let p = [("deviceKeyPubkey", hex::encode(device_key.0))];
        Ok(self
            .x
            .get_opt::<RecordBody<Device>>("getDevice", &p)?
            .map(|r| r.record))
    }

    fn list_devices(&self) -> Result<Vec<Device>> {
        self.x.list_all("listDevices", &[])
    }

    fn create_epoch(&self, epoch: &Epoch, members: &[EpochMember]) -> Result<String> {
        let input = CreateEpochIn {
            epoch,
            members: members.iter().collect(),
        };
        let out: CreateEpochOut = self.x.post("createEpoch", &input)?;
        if out.epoch_number != epoch.seq() {
            return Err(Error::Backend("createEpoch returned another epoch".into()));
        }
        Ok(out.epoch_id)
    }

    fn get_epoch(&self, seq: u64) -> Result<Option<Stored<Epoch>>> {
        let p = [("epochNumber", seq.to_string())];
        Ok(self
            .x
            .get_opt::<EpochView<Epoch>>("getEpoch", &p)?
            .map(|v| self.stored(v.epoch_id, v.record)))
    }

    fn list_epochs(&self) -> Result<Vec<Stored<Epoch>>> {
        let v: Vec<EpochView<Epoch>> = self.x.list_all("listEpochs", &[])?;
        Ok(v.into_iter()
            .map(|v| self.stored(v.epoch_id, v.record))
            .collect())
    }

    fn create_epoch_member(&self, member: &EpochMember) -> Result<()> {
        let _: Empty = self
            .x
            .post("createEpochMember", &RecordBody { record: member })?;
        Ok(())
    }

    fn list_epoch_members(&self, seq: u64) -> Result<Vec<EpochMember>> {
        self.x
            .list_all("listEpochMembers", &[("epochNumber", seq.to_string())])
    }

    fn create_virtual_device(&self, vdevice: &VirtualDevice) -> Result<()> {
        let _: Empty = self
            .x
            .post("createVirtualDevice", &RecordBody { record: vdevice })?;
        Ok(())
    }

    fn get_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<Option<VirtualDevice>> {
        let p = [("vdeviceId", hex::encode(vdevice_id))];
        Ok(self
            .x
            .get_opt::<RecordBody<VirtualDevice>>("getVirtualDevice", &p)?
            .map(|r| r.record))
    }

    fn list_virtual_devices(&self) -> Result<Vec<VirtualDevice>> {
        self.x.list_all("listVirtualDevices", &[])
    }

    fn append_owner_batch(&self, batch: &OwnerBatch) -> Result<String> {
        let out: RkeyOrderOut = self
            .x
            .post("appendOwnerBatch", &RecordBody { record: batch })?;
        Ok(out.rkey)
    }

    fn list_owner_batches(
        &self,
        thread_id: &str,
        range: TimeRange,
    ) -> Result<Vec<Stored<OwnerBatch>>> {
        let mut p = vec![("threadId", thread_id.to_owned())];
        range_params(range, &mut p);
        let v: Vec<OwnedView<OwnerBatch>> = self.x.list_all("listOwnerBatches", &p)?;
        v.into_iter()
            .map(|v| {
                Ok(Stored {
                    order: Some(v.order.to_order()?),
                    ..self.stored(v.rkey, v.record)
                })
            })
            .collect()
    }

    /// mls-ds already recorded the head when `createEpoch` ran; this
    /// re-sends it to `publishEpochHead`, which accepts identical bytes.
    /// The PDS `mailboxKeys` copy ([CB-19]) must still be written, through
    /// a [`crate::store::KeyPublisher`] in `Backends::publishers`.
    fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> Result<()> {
        let input = PublishHeadIn {
            epoch: record.current.clone(),
        };
        let _: Empty = self.x.post("publishEpochHead", &input)?;
        Ok(())
    }

    /// `listOwnerThreads`.
    fn list_owner_threads(&self) -> Result<Vec<String>> {
        let v: Vec<ThreadView> = self.x.list_all("listOwnerThreads", &[])?;
        Ok(v.into_iter().map(|t| t.thread_id).collect())
    }

    /// `listOwnerBatches` newest first (`reverse=true`, `untilMs`), then
    /// sorted by newest item: server seq is not sender time, so `limit`
    /// cannot stop it early.
    fn list_owner_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Stored<OwnerBatch>>> {
        let _ = limit;
        let mut p = vec![
            ("threadId", thread_id.to_owned()),
            ("reverse", "true".to_owned()),
        ];
        if let Some(b) = before_ms {
            p.push(("untilMs", b.to_string()));
        }
        let v: Vec<OwnedView<OwnerBatch>> = self.x.list_all("listOwnerBatches", &p)?;
        let mut v = v
            .into_iter()
            .map(|v| {
                Ok(Stored {
                    order: Some(v.order.to_order()?),
                    ..self.stored(v.rkey, v.record)
                })
            })
            .collect::<Result<Vec<_>>>()?;
        v.sort_by_key(|b| core::cmp::Reverse(b.value.items.iter().map(|i| i.timestamp).max()));
        Ok(v)
    }

    /// `touchVirtualDevice`.
    fn touch_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        let input = VdeviceIn {
            vdevice_id: Bytes::from_slice(vdevice_id),
        };
        let _: Empty = self.x.post("touchVirtualDevice", &input)?;
        Ok(())
    }

    /// `deleteVirtualDevice`.
    fn delete_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        let input = VdeviceIn {
            vdevice_id: Bytes::from_slice(vdevice_id),
        };
        let _: Empty = self.x.post("deleteVirtualDevice", &input)?;
        Ok(())
    }

    /// `purgeMailbox`: the mailbox, every ORF state and attachment
    /// reference, and the head chain. Thread records stay.
    fn purge_mailbox(&self) -> Result<()> {
        let _: Empty = self.x.post("purgeMailbox", &Empty {})?;
        Ok(())
    }

    /// `deleteAccountData`: `purgeMailbox` plus an unsigned redaction of
    /// every thread item the DID authored, across delivery services.
    fn delete_account_data(&self) -> Result<()> {
        let _: Empty = self.x.post("deleteAccountData", &Empty {})?;
        Ok(())
    }
}

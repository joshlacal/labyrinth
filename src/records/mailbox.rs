//! Records in the personal mailbox space (and the public `mailboxKeys`).

use serde::{Deserialize, Serialize};

use super::defs::{EpochPublicDef, OwnerMessageDef, TransportAttestationDef};
use super::{Bytes, check_type, nsid};
use crate::device::{ChatBinding, DevicePublic};
use crate::epoch::{EpochMemberRecord, EpochRecord};
use crate::hpke::labyrinth::X25519Public;
use crate::mailbox::EpochPublic;
use crate::message::OwnerMessage;
use crate::sign::XVerifyingKey;
use crate::virtual_device::{Mechanism, VirtualDeviceRecord};
use crate::{Error, Result};

/// `blue.catbird.labyrinth.device`, rkey = `hex(deviceKeyPubkey)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Device {
    #[serde(rename = "$type")]
    pub type_: String,
    pub device_key_pubkey: Bytes,
    pub epoch_storage_key_pubkey: Bytes,
    pub epoch_storage_key_sig: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_storage_auth_key_pubkey: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_storage_auth_key_sig: Option<Bytes>,
    pub r#virtual: bool,
    /// [CB-36] The enrolling chat device's binding; physical devices only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_binding: Option<TransportAttestationDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    pub created_at: String,
}

impl Device {
    pub fn from_public(p: &DevicePublic, created_at: String) -> Self {
        Self {
            type_: nsid::DEVICE.into(),
            device_key_pubkey: Bytes::from_slice(&p.device_key_pub.0),
            epoch_storage_key_pubkey: Bytes::from_slice(&p.epoch_storage_key_pub.0),
            epoch_storage_key_sig: Bytes::from_slice(&p.sig_0x30),
            epoch_storage_auth_key_pubkey: p
                .epoch_storage_auth_key_pub
                .map(|k| Bytes::from_slice(&k.0)),
            epoch_storage_auth_key_sig: p.sig_0x31.map(|s| Bytes::from_slice(&s)),
            r#virtual: p.is_virtual,
            chat_binding: None,
            revoked_at: None,
            created_at,
        }
    }

    /// A physical device record carrying its [CB-36] chat binding.
    pub fn bound(p: &DevicePublic, binding: &ChatBinding, created_at: String) -> Self {
        let mut d = Self::from_public(p, created_at);
        d.chat_binding = Some(TransportAttestationDef {
            transport_pubkey: Bytes::from_slice(&binding.transport_public_key),
            sig: Bytes::from_slice(&binding.sig),
        });
        d
    }

    /// The [CB-36] chat binding, parsed (not verified).
    pub fn chat_binding(&self) -> Result<Option<ChatBinding>> {
        self.chat_binding
            .as_ref()
            .map(|b| {
                Ok(ChatBinding {
                    transport_public_key: b.transport_pubkey.array("chatBinding key length")?,
                    sig: b.sig.array("chatBinding sig length")?,
                })
            })
            .transpose()
    }

    /// Parses the record; call [`DevicePublic::verify`] on the result.
    pub fn to_public(&self) -> Result<DevicePublic> {
        check_type(&self.type_, nsid::DEVICE)?;
        Ok(DevicePublic {
            device_key_pub: XVerifyingKey(self.device_key_pubkey.array("deviceKeyPubkey")?),
            epoch_storage_key_pub: X25519Public(
                self.epoch_storage_key_pubkey
                    .array("epochStorageKeyPubkey")?,
            ),
            sig_0x30: self.epoch_storage_key_sig.array("epochStorageKeySig")?,
            epoch_storage_auth_key_pub: self
                .epoch_storage_auth_key_pubkey
                .as_ref()
                .map(|b| b.array("epochStorageAuthKeyPubkey").map(X25519Public))
                .transpose()?,
            sig_0x31: self
                .epoch_storage_auth_key_sig
                .as_ref()
                .map(|b| b.array("epochStorageAuthKeySig"))
                .transpose()?,
            is_virtual: self.r#virtual,
        })
    }

    pub fn device_key(&self) -> Result<XVerifyingKey> {
        Ok(XVerifyingKey(
            self.device_key_pubkey.array("deviceKeyPubkey")?,
        ))
    }
}

/// `blue.catbird.labyrinth.epoch`, rkey = the backend's `epochID` ([CB-9]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Epoch {
    #[serde(rename = "$type")]
    pub type_: String,
    pub public: EpochPublicDef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_previous_epoch_number: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_previous_epoch_root_key: Option<Bytes>,
    pub opened_by: Bytes,
    pub created_at: String,
}

impl Epoch {
    pub fn from_record(r: &EpochRecord, created_at: String) -> Self {
        Self {
            type_: nsid::EPOCH.into(),
            public: EpochPublicDef::from_public(&r.public),
            encrypted_previous_epoch_number: r.encrypted_prev_seq.clone().map(Bytes),
            encrypted_previous_epoch_root_key: r.encrypted_prev_root.clone().map(Bytes),
            opened_by: Bytes::from_slice(&r.opened_by.0),
            created_at,
        }
    }

    pub fn to_record(&self) -> Result<EpochRecord> {
        check_type(&self.type_, nsid::EPOCH)?;
        let r = EpochRecord {
            public: self.public.to_public()?,
            encrypted_prev_seq: self.encrypted_previous_epoch_number.clone().map(|b| b.0),
            encrypted_prev_root: self.encrypted_previous_epoch_root_key.clone().map(|b| b.0),
            opened_by: XVerifyingKey(self.opened_by.array("openedBy length")?),
        };
        let genesis = r.public.seq == 0;
        if genesis == r.encrypted_prev_seq.is_some() || genesis == r.encrypted_prev_root.is_some() {
            return Err(Error::Malformed("epoch back-link presence"));
        }
        Ok(r)
    }

    pub fn seq(&self) -> u64 {
        self.public.epoch_number
    }
}

/// `blue.catbird.labyrinth.epochMember`, rkey = [`EpochMember::rkey`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochMember {
    #[serde(rename = "$type")]
    pub type_: String,
    pub epoch_number: u64,
    pub device_key_pubkey: Bytes,
    pub device_mac: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_entropy: Option<Bytes>,
    pub created_at: String,
}

impl EpochMember {
    pub fn from_record(r: &EpochMemberRecord, created_at: String) -> Self {
        Self {
            type_: nsid::EPOCH_MEMBER.into(),
            epoch_number: r.seq,
            device_key_pubkey: Bytes::from_slice(&r.device_key_pub.0),
            device_mac: Bytes::from_slice(&r.device_mac),
            encrypted_entropy: r.encrypted_entropy.clone().map(Bytes),
            created_at,
        }
    }

    pub fn to_record(&self) -> Result<EpochMemberRecord> {
        check_type(&self.type_, nsid::EPOCH_MEMBER)?;
        Ok(EpochMemberRecord {
            seq: super::check_epoch_number(self.epoch_number)?,
            device_key_pub: XVerifyingKey(self.device_key_pubkey.array("deviceKeyPubkey")?),
            device_mac: self.device_mac.array("deviceMac length")?,
            encrypted_entropy: self.encrypted_entropy.clone().map(|b| b.0),
        })
    }

    /// `<12-digit epoch>-<hex deviceKeyPubkey>`.
    pub fn rkey(&self) -> String {
        format!(
            "{:012}-{}",
            self.epoch_number,
            hex::encode(&self.device_key_pubkey.0)
        )
    }
}

/// Passkey PRF wrap stored next to a bundle ([CB-13]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyWrap {
    /// `virtual_device::passkey::wrap_code` output.
    pub wrapped_code: Vec<u8>,
    /// WebAuthn credential id the PRF output came from.
    pub credential_id: Vec<u8>,
}

/// `blue.catbird.labyrinth.virtualDevice`, rkey = `hex(vdeviceId)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VirtualDevice {
    #[serde(rename = "$type")]
    pub type_: String,
    pub vdevice_id: Bytes,
    pub device_key_pubkey: Bytes,
    pub epoch_storage_key_pubkey: Bytes,
    pub epoch_storage_key_sig: Bytes,
    pub encrypted_device_key_priv: Bytes,
    pub encrypted_epoch_storage_key_priv: Bytes,
    pub encrypted_orf_client_state: Bytes,
    pub encrypted_mailbox_root_salt: Bytes,
    pub encrypted_epoch_root_key: Bytes,
    pub encrypted_epoch_number: Bytes,
    pub mechanism: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_wrapped_code: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_credential_id: Option<Bytes>,
    pub created_at: String,
    /// Last successful restore or keep-alive ([CB-39]); stamped by the
    /// server (clients never write it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

impl VirtualDevice {
    pub fn from_bundle(
        r: &VirtualDeviceRecord,
        passkey: Option<&PasskeyWrap>,
        created_at: String,
    ) -> Self {
        Self {
            type_: nsid::VIRTUAL_DEVICE.into(),
            vdevice_id: Bytes::from_slice(&r.vdevice_id),
            device_key_pubkey: Bytes::from_slice(&r.public.device_key_pub.0),
            epoch_storage_key_pubkey: Bytes::from_slice(&r.public.epoch_storage_key_pub.0),
            epoch_storage_key_sig: Bytes::from_slice(&r.public.sig_0x30),
            encrypted_device_key_priv: Bytes(r.encrypted_device_key_priv.clone()),
            encrypted_epoch_storage_key_priv: Bytes(r.encrypted_epoch_storage_key_priv.clone()),
            encrypted_orf_client_state: Bytes(r.encrypted_orf_client_state.clone()),
            encrypted_mailbox_root_salt: Bytes(r.encrypted_mailbox_root_salt.clone()),
            encrypted_epoch_root_key: Bytes(r.encrypted_epoch_root_key.clone()),
            encrypted_epoch_number: Bytes(r.encrypted_epoch_number.clone()),
            mechanism: r.mechanism.as_str().into(),
            passkey_wrapped_code: passkey.map(|p| Bytes(p.wrapped_code.clone())),
            passkey_credential_id: passkey.map(|p| Bytes(p.credential_id.clone())),
            created_at,
            last_used_at: None,
        }
    }

    pub fn to_bundle(&self) -> Result<(VirtualDeviceRecord, Option<PasskeyWrap>)> {
        check_type(&self.type_, nsid::VIRTUAL_DEVICE)?;
        let public = DevicePublic {
            device_key_pub: XVerifyingKey(self.device_key_pubkey.array("deviceKeyPubkey")?),
            epoch_storage_key_pub: X25519Public(
                self.epoch_storage_key_pubkey
                    .array("epochStorageKeyPubkey")?,
            ),
            sig_0x30: self.epoch_storage_key_sig.array("epochStorageKeySig")?,
            epoch_storage_auth_key_pub: None,
            sig_0x31: None,
            is_virtual: true,
        };
        let passkey = match (&self.passkey_wrapped_code, &self.passkey_credential_id) {
            (Some(w), Some(c)) => Some(PasskeyWrap {
                wrapped_code: w.0.clone(),
                credential_id: c.0.clone(),
            }),
            (None, None) => None,
            _ => return Err(Error::Malformed("passkey fields must come together")),
        };
        let record = VirtualDeviceRecord {
            vdevice_id: self.vdevice_id.array("vdeviceId length")?,
            public,
            encrypted_device_key_priv: self.encrypted_device_key_priv.0.clone(),
            encrypted_epoch_storage_key_priv: self.encrypted_epoch_storage_key_priv.0.clone(),
            encrypted_orf_client_state: self.encrypted_orf_client_state.0.clone(),
            encrypted_mailbox_root_salt: self.encrypted_mailbox_root_salt.0.clone(),
            encrypted_epoch_root_key: self.encrypted_epoch_root_key.0.clone(),
            encrypted_epoch_number: self.encrypted_epoch_number.0.clone(),
            mechanism: Mechanism::parse(&self.mechanism)?,
        };
        Ok((record, passkey))
    }

    pub fn rkey(&self) -> String {
        hex::encode(&self.vdevice_id.0)
    }
}

/// `blue.catbird.labyrinth.ownerBatch`, rkey = TID. One thread per batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerBatch {
    #[serde(rename = "$type")]
    pub type_: String,
    pub thread_id: String,
    pub items: Vec<OwnerMessageDef>,
    pub created_at: String,
}

impl OwnerBatch {
    /// Fails if `items` is empty, longer than [`super::MAX_BATCH_ITEMS`], or
    /// mixes threads.
    pub fn from_messages(items: &[OwnerMessage], created_at: String) -> Result<Self> {
        let thread_id = items
            .first()
            .ok_or(Error::Malformed("empty owner batch"))?
            .thread_id
            .clone();
        let b = Self {
            type_: nsid::OWNER_BATCH.into(),
            thread_id,
            items: items.iter().map(OwnerMessageDef::from_message).collect(),
            created_at,
        };
        b.check()?;
        Ok(b)
    }

    pub fn to_messages(&self) -> Result<Vec<OwnerMessage>> {
        check_type(&self.type_, nsid::OWNER_BATCH)?;
        self.check()?;
        Ok(self.items.iter().map(OwnerMessageDef::to_message).collect())
    }

    fn check(&self) -> Result<()> {
        if self.items.is_empty() || self.items.len() > super::MAX_BATCH_ITEMS {
            return Err(Error::Malformed("owner batch size"));
        }
        if self.items.iter().any(|i| i.thread_id != self.thread_id) {
            return Err(Error::Malformed("owner batch mixes threads"));
        }
        for i in &self.items {
            super::check_epoch_number(i.epoch_number)?;
        }
        Ok(())
    }
}

/// `blue.catbird.labyrinth.mailboxKeys/self` in the PUBLIC repo ([CB-19]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailboxKeysRecord {
    #[serde(rename = "$type")]
    pub type_: String,
    pub current: EpochPublicDef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    pub updated_at: String,
}

impl MailboxKeysRecord {
    pub fn from_public(p: &EpochPublic, backend: Option<&str>, updated_at: String) -> Self {
        Self {
            type_: nsid::MAILBOX_KEYS.into(),
            current: EpochPublicDef::from_public(p),
            backend: backend.map(str::to_owned),
            updated_at,
        }
    }

    pub fn to_public(&self) -> Result<EpochPublic> {
        check_type(&self.type_, nsid::MAILBOX_KEYS)?;
        self.current.to_public()
    }
}

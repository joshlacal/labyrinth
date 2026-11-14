//! Opening an epoch (SPEC §5.1–5.5, Gate 2, `I16`).

use zeroize::Zeroizing;

use super::{
    EpochKeys, EpochMemberRecord, EpochRecord, EpochSecret, METADATA_AAD, PendingEpoch,
    entropy_aad, member_record, root_from_entropy, verify_member, verify_public,
};
use crate::aead;
use crate::device::{DevicePublic, DeviceSecrets};
use crate::encoding::random;
use crate::hpke::X25519Secret;
use crate::hpke::hawk::hawk_encrypt_with_psk;
use crate::mailbox::{EpochPublic, members_hash_for_devices};
use crate::sign::TransportSigner;
use crate::{Error, Result};

/// Everything the opener publishes for a new epoch: the epoch record and
/// one membership record per device (the opener included).
#[derive(Clone, Debug)]
pub struct NewEpoch {
    pub record: EpochRecord,
    pub members: Vec<EpochMemberRecord>,
}

impl NewEpoch {
    /// The membership record for `device_key_pub`, if any.
    pub fn member(&self, device: &DevicePublic) -> Option<&EpochMemberRecord> {
        self.members
            .iter()
            .find(|m| m.device_key_pub == device.device_key_pub)
    }
}

fn require_physical(me: &DeviceSecrets) -> Result<&X25519Secret> {
    me.storage_auth
        .as_ref()
        .ok_or(Error::Malformed("virtual devices cannot open epochs"))
}

/// Open epoch 0 with a uniformly random root. The opener is the only member.
pub fn open_genesis(
    did: &str,
    me: &DeviceSecrets,
    transport: &dyn TransportSigner,
) -> Result<(PendingEpoch, NewEpoch)> {
    require_physical(me)?;
    let mut root = Zeroizing::new([0u8; 32]);
    random(root.as_mut())?;
    let epoch = PendingEpoch::new(0, *root);
    let members_hash = members_hash_for_devices(std::slice::from_ref(me.public()))?;
    let public = EpochPublic::sign(
        did,
        0,
        &epoch.mailbox_keys(),
        members_hash,
        None,
        None,
        transport,
    )?;
    let members = vec![member_record(
        &epoch,
        &me.public().device_key_pub,
        false,
        None,
    )];
    let record = EpochRecord {
        public,
        encrypted_prev_seq: None,
        encrypted_prev_root: None,
        opened_by: me.public().device_key_pub,
        revocations: Vec::new(),
        revocations_sig: None,
    };
    Ok((epoch, NewEpoch { record, members }))
}

/// Open the epoch after `prev` using `Hawk + PSK` entropy distribution (`I16`)
/// and binding `members_hash` (`Gate 2`).
pub fn open_next(
    did: &str,
    prev: &EpochSecret,
    prev_public: &EpochPublic,
    prev_members: &[EpochMemberRecord],
    continuing: &[DevicePublic],
    me: &DeviceSecrets,
    transport: &dyn TransportSigner,
) -> Result<(PendingEpoch, NewEpoch)> {
    open_next_with_additions(
        did,
        prev,
        prev_public,
        prev_members,
        continuing,
        &[],
        me,
        transport,
    )
}

/// Open the epoch after `prev`, carrying `continuing` members from `prev` and
/// atomically admitting `added_virtual` recovery devices into `E+1`.
#[allow(clippy::too_many_arguments)]
pub fn open_next_with_additions(
    did: &str,
    prev: &EpochSecret,
    prev_public: &EpochPublic,
    prev_members: &[EpochMemberRecord],
    continuing: &[DevicePublic],
    added_virtual: &[DevicePublic],
    me: &DeviceSecrets,
    transport: &dyn TransportSigner,
) -> Result<(PendingEpoch, NewEpoch)> {
    let auth = require_physical(me)?;
    verify_public(prev, prev_public)?;
    let seq = prev
        .seq
        .checked_add(1)
        .ok_or(Error::Malformed("epoch sequence overflow"))?;

    let mut recipients: Vec<DevicePublic> =
        Vec::with_capacity(continuing.len() + added_virtual.len() + 1);
    for d in continuing.iter().chain(core::iter::once(me.public())) {
        if !recipients
            .iter()
            .any(|r| r.device_key_pub == d.device_key_pub)
        {
            recipients.push(d.clone());
        }
    }
    for d in &recipients {
        let rec = prev_members
            .iter()
            .find(|m| m.device_key_pub == d.device_key_pub)
            .ok_or(Error::NotEpochMember)?;
        verify_member(prev, rec, d.is_virtual)?;
        d.verify()?;
    }
    for v in added_virtual {
        if !v.is_virtual {
            return Err(Error::DeviceTampered);
        }
        v.verify()?;
        if recipients
            .iter()
            .any(|r| r.device_key_pub == v.device_key_pub)
        {
            return Err(Error::Conflict);
        }
        recipients.push(v.clone());
    }

    let mut entropy = Zeroizing::new([0u8; 32]);
    random(entropy.as_mut())?;
    let (chain_key, psk) = prev.chaining_keys();
    let epoch = PendingEpoch::new(seq, root_from_entropy(&entropy, &chain_key));
    let members_hash = members_hash_for_devices(&recipients)?;

    let prev_keys = prev.mailbox_keys();
    let public = EpochPublic::sign(
        did,
        seq,
        &epoch.mailbox_keys(),
        members_hash,
        Some(prev_public.head),
        Some(&prev_keys.sig_secret),
        transport,
    )?;
    let data_key = epoch.data_key();
    let record = EpochRecord {
        public,
        encrypted_prev_seq: Some(aead::seal(
            &data_key,
            METADATA_AAD,
            prev.seq.to_string().as_bytes(),
        )?),
        encrypted_prev_root: Some(aead::seal(&data_key, METADATA_AAD, prev.root())?),
        opened_by: me.public().device_key_pub,
        revocations: Vec::new(),
        revocations_sig: None,
    };

    let auth_pub = auth.public();
    let aad = entropy_aad(seq);
    let members = recipients
        .iter()
        .map(|d| {
            let ct = hawk_encrypt_with_psk(
                &d.epoch_storage_key_pub,
                auth,
                &auth_pub,
                psk.as_slice(),
                &aad,
                entropy.as_slice(),
            )?;
            Ok(member_record(
                &epoch,
                &d.device_key_pub,
                d.is_virtual,
                Some(ct),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((epoch, NewEpoch { record, members }))
}

/// Open the epoch after `prev` during atomic recovery / `OTC` enrollment (`Gate 3`),
/// admitting `new_device` directly into `E+1` alongside `continuing` members of `prev`
/// while sealing `E+1` entropy under `new_device`'s own `storage_auth` key.
#[allow(clippy::too_many_arguments)]
pub fn open_next_enrolling(
    did: &str,
    prev: &EpochSecret,
    prev_public: &EpochPublic,
    prev_members: &[EpochMemberRecord],
    continuing: &[DevicePublic],
    new_device: &DeviceSecrets,
    transport: &dyn TransportSigner,
) -> Result<(PendingEpoch, NewEpoch)> {
    let auth = require_physical(new_device)?;
    verify_public(prev, prev_public)?;
    let seq = prev
        .seq
        .checked_add(1)
        .ok_or(Error::Malformed("epoch sequence overflow"))?;

    let mut verified_continuing: Vec<DevicePublic> = Vec::with_capacity(continuing.len());
    for d in continuing {
        if d.device_key_pub == new_device.public().device_key_pub {
            return Err(Error::Conflict);
        }
        if !verified_continuing
            .iter()
            .any(|r| r.device_key_pub == d.device_key_pub)
        {
            let rec = prev_members
                .iter()
                .find(|m| m.device_key_pub == d.device_key_pub)
                .ok_or(Error::NotEpochMember)?;
            verify_member(prev, rec, d.is_virtual)?;
            d.verify()?;
            verified_continuing.push(d.clone());
        }
    }

    let mut recipients = verified_continuing;
    recipients.push(new_device.public().clone());

    let mut entropy = Zeroizing::new([0u8; 32]);
    random(entropy.as_mut())?;
    let (chain_key, psk) = prev.chaining_keys();
    let epoch = PendingEpoch::new(seq, root_from_entropy(&entropy, &chain_key));
    let members_hash = members_hash_for_devices(&recipients)?;

    let prev_keys = prev.mailbox_keys();
    let public = EpochPublic::sign(
        did,
        seq,
        &epoch.mailbox_keys(),
        members_hash,
        Some(prev_public.head),
        Some(&prev_keys.sig_secret),
        transport,
    )?;
    let data_key = epoch.data_key();
    let record = EpochRecord {
        public,
        encrypted_prev_seq: Some(aead::seal(
            &data_key,
            METADATA_AAD,
            prev.seq.to_string().as_bytes(),
        )?),
        encrypted_prev_root: Some(aead::seal(&data_key, METADATA_AAD, prev.root())?),
        opened_by: new_device.public().device_key_pub,
        revocations: Vec::new(),
        revocations_sig: None,
    };

    let auth_pub = auth.public();
    let aad = entropy_aad(seq);
    let members = recipients
        .iter()
        .map(|d| {
            let ct = hawk_encrypt_with_psk(
                &d.epoch_storage_key_pub,
                auth,
                &auth_pub,
                psk.as_slice(),
                &aad,
                entropy.as_slice(),
            )?;
            Ok(member_record(
                &epoch,
                &d.device_key_pub,
                d.is_virtual,
                Some(ct),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((epoch, NewEpoch { record, members }))
}

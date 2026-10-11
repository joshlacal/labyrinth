//! Opening an epoch (SPEC §5.1–5.5, paper p.25–29).

use zeroize::Zeroizing;

use super::{
    EpochKeys, EpochMemberRecord, EpochRecord, EpochSecret, METADATA_AAD, PendingEpoch,
    entropy_aad, member_record, root_from_entropy, verify_member, verify_public,
};
use crate::aead;
use crate::device::{DevicePublic, DeviceSecrets};
use crate::encoding::random;
use crate::hpke::labyrinth as lhpke;
use crate::mailbox::EpochPublic;
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

fn require_physical(me: &DeviceSecrets) -> Result<&crate::hpke::labyrinth::X25519Secret> {
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
    let public = EpochPublic::sign(did, 0, &epoch.mailbox_keys(), None, None, transport)?;
    let members = vec![member_record(&epoch, &me.public().device_key_pub, None)];
    let record = EpochRecord {
        public,
        encrypted_prev_seq: None,
        encrypted_prev_root: None,
        opened_by: me.public().device_key_pub,
    };
    Ok((epoch, NewEpoch { record, members }))
}

/// Open the epoch after `prev`.
///
/// `continuing` lists the devices to carry over; a device that is left out is
/// revoked ([CB-11]). Each one must hold a valid MAC in `prev_members` and
/// valid signatures, or the call fails rather than silently dropping it. The
/// opener (`me`, a physical member of `prev`) is always carried over, and
/// also receives its own entropy so that any of its installs can
/// forward-chain.
pub fn open_next(
    did: &str,
    prev: &EpochSecret,
    prev_public: &EpochPublic,
    prev_members: &[EpochMemberRecord],
    continuing: &[DevicePublic],
    me: &DeviceSecrets,
    transport: &dyn TransportSigner,
) -> Result<(PendingEpoch, NewEpoch)> {
    let auth = require_physical(me)?;
    verify_public(prev, prev_public)?;
    let seq = prev
        .seq
        .checked_add(1)
        .ok_or(Error::Malformed("epoch sequence overflow"))?;

    // The recipient list: `continuing` plus the opener, without duplicates.
    let mut recipients: Vec<&DevicePublic> = Vec::with_capacity(continuing.len() + 1);
    for d in continuing.iter().chain(core::iter::once(me.public())) {
        if !recipients
            .iter()
            .any(|r| r.device_key_pub == d.device_key_pub)
        {
            recipients.push(d);
        }
    }
    for d in &recipients {
        let rec = prev_members
            .iter()
            .find(|m| m.device_key_pub == d.device_key_pub)
            .ok_or(Error::NotEpochMember)?;
        verify_member(prev, rec)?;
        d.verify()?;
    }

    let mut entropy = Zeroizing::new([0u8; 32]);
    random(entropy.as_mut())?;
    let (chain_key, psk) = prev.chaining_keys();
    let epoch = PendingEpoch::new(seq, root_from_entropy(&entropy, &chain_key));

    let prev_keys = prev.mailbox_keys();
    let public = EpochPublic::sign(
        did,
        seq,
        &epoch.mailbox_keys(),
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
    };

    let auth_pub = auth.public();
    let aad = entropy_aad(seq);
    let members = recipients
        .iter()
        .map(|d| {
            let ct = lhpke::encrypt(
                &d.epoch_storage_key_pub,
                &auth_pub,
                auth,
                psk.as_slice(),
                &aad,
                entropy.as_slice(),
            )?;
            Ok(member_record(&epoch, &d.device_key_pub, Some(ct)))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((epoch, NewEpoch { record, members }))
}

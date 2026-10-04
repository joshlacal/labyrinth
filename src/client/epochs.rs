//! Mailbox lifecycle: genesis, forward/backward chaining, revocation and
//! the epoch-integrity check (SPEC §5, §10).

use super::{Backends, Labyrinth};
use crate::device::{DevicePublic, DeviceSecrets};
use crate::encoding::random;
use crate::epoch::{
    EpochMemberRecord, EpochRecord, EpochSecret, OpenedEpoch, backward_chain, forward_chain,
    open_genesis, open_next, verify_member, verify_public,
};
use crate::hpke::labyrinth::X25519Secret;
use crate::records::{Device, Epoch, EpochMember, MailboxKeysRecord};
use crate::sign::{TransportSigner, XVerifyingKey};
use crate::store::{MailboxDirectory, MailboxStore};
use crate::{Error, Result};

/// Result of [`Labyrinth::sync_epochs`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub from: u64,
    pub to: u64,
}

/// Result of [`Labyrinth::revoke_device`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationReport {
    /// The epoch opened without the revoked device.
    pub new_epoch: u64,
    /// The caller must now ask the ORF server (mls-ds, [CB-17]) to delete
    /// this device's ORF server state (SPEC §5.6).
    pub revoked: XVerifyingKey,
}

/// How many times a rotation retries after losing the create race.
const ROTATE_ATTEMPTS: usize = 3;

pub(super) fn epoch_record(mb: &dyn MailboxStore, seq: u64) -> Result<(String, EpochRecord)> {
    let s = mb.get_epoch(seq)?.ok_or(Error::NotFound("epoch"))?;
    if s.value.seq() != seq {
        return Err(Error::Malformed("epoch record under the wrong key"));
    }
    Ok((s.rkey, s.value.to_record()?))
}

fn device_public(mb: &dyn MailboxStore, key: &XVerifyingKey) -> Result<DevicePublic> {
    mb.get_device(key)?
        .ok_or(Error::NotFound("device"))?
        .to_public()
}

fn member(
    mb: &dyn MailboxStore,
    seq: u64,
    key: &XVerifyingKey,
) -> Result<Option<EpochMemberRecord>> {
    mb.get_epoch_member(seq, key)?
        .map(|m| m.to_record())
        .transpose()
}

/// Forward-chains from `start` as long as the store has a next epoch.
/// Returns every epoch reached, `start` first. A next epoch that holds no
/// membership for `me` fails with [`Error::NotEpochMember`]: the device
/// was revoked.
pub(super) fn chain_forward(
    mb: &dyn MailboxStore,
    did: &str,
    start: EpochSecret,
    me: &DevicePublic,
    storage: &X25519Secret,
) -> Result<Vec<EpochSecret>> {
    let mut out = vec![start];
    loop {
        let prev = out.last().expect("non-empty");
        let seq = prev.seq + 1;
        let Some(next) = mb.get_epoch(seq)? else {
            return Ok(out);
        };
        let record = next.value.to_record()?;
        let mine = member(mb, seq, &me.device_key_pub)?.ok_or(Error::NotEpochMember)?;
        let opener = device_public(mb, &record.opened_by)?;
        let opener_prev =
            member(mb, prev.seq, &opener.device_key_pub)?.ok_or(Error::NotEpochMember)?;
        let prev_public = epoch_record(mb, prev.seq)?.1.public;
        let opened = OpenedEpoch {
            epoch_id: &next.rkey,
            record: &record,
            my_member: &mine,
            opener: &opener,
            opener_prev_member: &opener_prev,
        };
        let e = forward_chain(did, prev, &prev_public, &opened, storage)?;
        out.push(e);
    }
}

/// SPEC §10 epoch-integrity check ([CB-28]): the account's published latest epoch
/// (from the directory, i.e. the public `mailboxKeys` / mls-ds roster view)
/// must not be ahead of what this device reached, nor fork from it.
pub(super) fn check_integrity(
    dir: &dyn MailboxDirectory,
    did: &str,
    reached: u64,
    reached_head: &[u8; 32],
) -> Result<()> {
    let Some(published) = dir.latest(did)? else {
        return Ok(());
    };
    published.verify(did, None)?;
    if published.seq > reached {
        return Err(Error::EpochTruncated {
            published: published.seq,
            reached,
        });
    }
    if published.seq == reached && published.head != *reached_head {
        return Err(Error::Malformed("published epoch head forks from mailbox"));
    }
    Ok(())
}

impl Labyrinth {
    /// Create a new mailbox for `did`: a genesis device, epoch 0, and the
    /// public `mailboxKeys` record. Fails with [`Error::Conflict`] if the
    /// mailbox already has an epoch 0.
    pub fn initialize(
        did: &str,
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<Self> {
        let device = DeviceSecrets::generate()?;
        let (pending, new) = open_genesis(did, &device, transport.as_ref())?;
        let now = crate::records::datetime_from_ms(b.clock.now_ms());
        let members: Vec<_> = new
            .members
            .iter()
            .map(|m| EpochMember::from_record(m, now.clone()))
            .collect();
        // The epoch create is the guard; the device record follows it.
        let id = b
            .mailbox
            .create_epoch(&Epoch::from_record(&new.record, now.clone()), &members)?;
        b.mailbox
            .create_device(&Device::from_public(device.public(), now))?;
        let mut salt = [0u8; 32];
        random(&mut salt)?;
        let me = Self::assemble(did, device, transport, b, salt, [pending.assign_id(id)])?;
        me.publish_keys(&new.record.public)?;
        Ok(me)
    }

    pub(super) fn epoch_record(&self, seq: u64) -> Result<(String, EpochRecord)> {
        epoch_record(self.b.mailbox.as_ref(), seq)
    }

    pub(super) fn publish_keys(&self, public: &crate::mailbox::EpochPublic) -> Result<()> {
        self.b
            .mailbox
            .publish_mailbox_keys(&MailboxKeysRecord::from_public(public, None, self.now()))
    }

    /// Forward-chain into every epoch opened since this device last synced
    /// (e.g. by a sibling device's revocation), then run
    /// [`check_epoch_integrity`](Self::check_epoch_integrity).
    ///
    /// [`Error::NotEpochMember`] means this device has been revoked.
    pub fn sync_epochs(&mut self) -> Result<SyncReport> {
        let from = self.latest;
        let start = self.epoch_secret(from)?;
        let reached = chain_forward(
            self.b.mailbox.as_ref(),
            &self.did,
            start,
            self.device.public(),
            &self.device.storage,
        )?;
        for e in reached {
            self.latest = self.latest.max(e.seq);
            self.epochs.insert(e.seq, e);
        }
        self.check_epoch_integrity()?;
        Ok(SyncReport {
            from,
            to: self.latest,
        })
    }

    /// SPEC §10 mitigation for a backend that hides newer epochs: fails with
    /// [`Error::EpochTruncated`] if the directory's published latest epoch
    /// for this account is ahead of the newest epoch this device reached.
    pub fn check_epoch_integrity(&self) -> Result<()> {
        let head = self.epoch_record(self.latest)?.1.public.head;
        check_integrity(self.b.directory.as_ref(), &self.did, self.latest, &head)
    }

    /// The secret of my epoch `seq`, backward-chaining lazily from the
    /// nearest newer epoch I hold (SPEC §5.4, p.36). Each recovered epoch
    /// is authenticated against its published record.
    pub(super) fn epoch_secret(&mut self, seq: u64) -> Result<EpochSecret> {
        if let Some(e) = self.epochs.get(&seq) {
            return Ok(e.clone());
        }
        let mut cur = self
            .epochs
            .range(seq + 1..)
            .next()
            .map(|(_, e)| e.clone())
            .ok_or(Error::NotFound("epoch"))?;
        while cur.seq > seq {
            let (_, record) = self.epoch_record(cur.seq)?;
            let (prev_id, prev_record) = self.epoch_record(cur.seq - 1)?;
            let prev = backward_chain(&cur, &record, &prev_id)?;
            verify_public(&prev, &prev_record.public)?;
            self.epochs.insert(prev.seq, prev.clone());
            cur = prev;
        }
        Ok(cur)
    }

    /// Revoke a device: mark it revoked, then open a new epoch that carries
    /// over every other unrevoked member ([CB-11], [CB-25]) and publish its
    /// keys. Retries if a sibling device opens the same epoch first.
    pub fn revoke_device(&mut self, target: &XVerifyingKey) -> Result<RotationReport> {
        if *target == self.device.public().device_key_pub {
            return Err(Error::Malformed("a device cannot revoke itself"));
        }
        self.sync_epochs()?;
        self.b.mailbox.set_device_revoked(target, &self.now())?;
        for _ in 0..ROTATE_ATTEMPTS {
            match self.rotate() {
                Err(Error::Conflict) => {
                    self.sync_epochs()?;
                }
                Ok(new_epoch) => {
                    return Ok(RotationReport {
                        new_epoch,
                        revoked: *target,
                    });
                }
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict)
    }

    /// Open the epoch after `self.latest`, carrying over every unrevoked
    /// device with a valid MAC in it.
    fn rotate(&mut self) -> Result<u64> {
        let prev = self.epoch_secret(self.latest)?;
        let mb = self.b.mailbox.as_ref();
        let (_, prev_record) = epoch_record(mb, prev.seq)?;
        let prev_members: Vec<EpochMemberRecord> = mb
            .list_epoch_members(prev.seq)?
            .iter()
            .map(EpochMember::to_record)
            .collect::<Result<_>>()?;
        let me = self.device.public().device_key_pub;
        let mut continuing = Vec::new();
        for m in &prev_members {
            if m.device_key_pub == me || verify_member(&prev, m).is_err() {
                continue;
            }
            let rec = mb
                .get_device(&m.device_key_pub)?
                .ok_or(Error::NotFound("device"))?;
            if rec.revoked_at.is_none() {
                continuing.push(rec.to_public()?);
            }
        }
        let (pending, new) = open_next(
            &self.did,
            &prev,
            &prev_record.public,
            &prev_members,
            &continuing,
            &self.device,
            self.transport.as_ref(),
        )?;
        let now = self.now();
        let members: Vec<_> = new
            .members
            .iter()
            .map(|m| EpochMember::from_record(m, now.clone()))
            .collect();
        let id = mb.create_epoch(&Epoch::from_record(&new.record, now), &members)?;
        let e = pending.assign_id(id);
        self.latest = e.seq;
        self.epochs.insert(e.seq, e);
        self.publish_keys(&new.record.public)?;
        Ok(self.latest)
    }
}

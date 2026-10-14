//! Mailbox lifecycle: genesis, forward/backward chaining, revocation and
//! the epoch-integrity check (SPEC §5, §10).

use std::collections::BTreeSet;

use super::members::ExcludedMember;
use super::{Backends, Labyrinth};
use crate::device::{ChatBinding, DevicePublic, DeviceSecrets};
use crate::encoding::random;
use crate::epoch::{
    EpochMemberRecord, EpochRecord, EpochSecret, OpenedEpoch, backward_chain, forward_chain,
    open_genesis, open_next, verify_member, verify_public,
};
use crate::hpke::labyrinth::X25519Secret;
use crate::mailbox::EpochPublic;
use crate::records::{Device, Epoch, EpochMember, MailboxKeysRecord};
use crate::sign::{TransportSigner, XVerifyingKey};
use crate::store::{MailboxDirectory, MailboxStore};
use crate::{Error, Result};

/// Result of [`Labyrinth::sync_epochs`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub from: u64,
    pub to: u64,
    /// Devices this client revoked that are nevertheless members of the
    /// epoch it reached (a sibling re-admitted them, or a revocation's
    /// rotation never completed). Call [`Labyrinth::revoke_device`] again
    /// for each.
    pub readmitted: Vec<XVerifyingKey>,
    /// Members of the reached epoch that fail verification or are not
    /// bound to a current chat device ([CB-25], [CB-36]). The next
    /// rotation drops them; surface them to the user (a planted row, or a
    /// removed chat device whose Labyrinth device is still a member).
    pub invalid_members: Vec<ExcludedMember>,
}

/// Result of [`Labyrinth::revoke_device`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationReport {
    /// The epoch opened without the revoked device.
    pub new_epoch: u64,
    /// The revoked device. Its ORF server state ([CB-17]) has already
    /// been deleted through [`super::Backends::orf`] (SPEC §5.6).
    pub revoked: XVerifyingKey,
    /// Members of the previous epoch the rotation dropped because they
    /// failed verification or are not bound to a current chat device
    /// ([CB-25] as amended, [CB-36]). Never silent: show these.
    pub excluded: Vec<ExcludedMember>,
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

/// Reads my own epoch `secret.seq` from the mailbox and authenticates the
/// whole record before it is adopted ([CB-43]): [`verified_own_signatures`]
/// and [`check_own_attester`].
pub(super) fn verified_own(
    mb: &dyn MailboxStore,
    dir: &dyn MailboxDirectory,
    did: &str,
    secret: &EpochSecret,
) -> Result<EpochPublic> {
    let public = verified_own_signatures(mb, did, secret)?;
    check_own_attester(dir, did, &public)?;
    Ok(public)
}

/// The part of [`verified_own`] that needs only the mailbox: the record's
/// id and keys match the secret, its self signature and attestation
/// verify, and above epoch 0 its `prev_sig` verifies under the previous
/// epoch's mailbox key (recovered by backward-chaining, so a substituted
/// predecessor fails too).
pub(super) fn verified_own_signatures(
    mb: &dyn MailboxStore,
    did: &str,
    secret: &EpochSecret,
) -> Result<EpochPublic> {
    let (id, record) = epoch_record(mb, secret.seq)?;
    if id != secret.epoch_id {
        return Err(Error::Malformed("epoch id does not match store"));
    }
    verify_public(secret, &record.public)?;
    let prev = match secret.seq.checked_sub(1) {
        None => None,
        Some(prev_seq) => {
            let (prev_id, prev_record) = epoch_record(mb, prev_seq)?;
            let prev = backward_chain(secret, &record, &prev_id)?;
            verify_public(&prev, &prev_record.public)?;
            Some(prev_record.public)
        }
    };
    record.public.verify(did, prev.as_ref())?;
    Ok(record.public)
}

/// [`Error::Unattested`] unless my epoch's attestation key is one of the
/// account's chat devices in `dir`. A removed device still counts: it may
/// have opened the epoch before it was removed, and peers apply their own,
/// stricter [CB-18] check.
pub(super) fn check_own_attester(
    dir: &dyn MailboxDirectory,
    did: &str,
    public: &EpochPublic,
) -> Result<()> {
    let attester = public.attestation.transport_public_key;
    if dir
        .device_transport_keys(did)?
        .iter()
        .any(|k| k.key == attester)
    {
        Ok(())
    } else {
        Err(Error::Unattested)
    }
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
/// Returns every epoch reached, `start` first.
///
/// A next epoch that chains validly (signed with the previous epoch's
/// mailbox key, opened by a valid member of the previous epoch) but holds
/// no valid membership for `me` fails with [`Error::NotEpochMember`]: the
/// device was revoked. A next epoch that does not chain, or whose opener
/// is in `revoked`, fails with [`Error::EpochSquatted`] ([CB-40]): it
/// occupies the sequence number every rotation needs, so retrying cannot
/// help and the caller must surface it.
pub(super) fn chain_forward(
    mb: &dyn MailboxStore,
    did: &str,
    start: EpochSecret,
    me: &DevicePublic,
    storage: &X25519Secret,
    revoked: &BTreeSet<[u8; 32]>,
) -> Result<Vec<EpochSecret>> {
    let mut out = vec![start];
    loop {
        let prev = out.last().expect("non-empty");
        let seq = prev
            .seq
            .checked_add(1)
            .ok_or(Error::Malformed("epoch sequence overflow"))?;
        let Some(next) = mb.get_epoch(seq)? else {
            return Ok(out);
        };
        let squat = |reason| Error::EpochSquatted { seq, reason };
        let record = next
            .value
            .to_record()
            .ok()
            .filter(|r| r.public.seq == seq)
            .ok_or(squat("the epoch record does not parse"))?;
        let prev_public = epoch_record(mb, prev.seq)?.1.public;
        record
            .public
            .verify(did, Some(&prev_public))
            .map_err(|_| squat("it is not signed by the previous epoch's mailbox key"))?;
        let opener = mb
            .get_device(&record.opened_by)?
            .and_then(|d| d.to_public().ok())
            .filter(|p| p.verify().is_ok() && !p.is_virtual && p.device_key_pub == record.opened_by)
            .ok_or(squat("its opener has no valid physical device record"))?;
        if revoked.contains(&record.opened_by.0) {
            return Err(squat("it was opened by a device this client revoked"));
        }
        let opener_prev = member(mb, prev.seq, &opener.device_key_pub)
            .ok()
            .flatten()
            .filter(|m| verify_member(prev, m).is_ok())
            .ok_or(squat("its opener was not a member of the previous epoch"))?;
        let mine = member(mb, seq, &me.device_key_pub)
            .ok()
            .flatten()
            .ok_or(Error::NotEpochMember)?;
        let opened = OpenedEpoch {
            epoch_id: &next.rkey,
            record: &record,
            my_member: &mine,
            opener: &opener,
            opener_prev_member: &opener_prev,
        };
        let e = forward_chain(did, prev, &prev_public, &opened, storage).map_err(|e| match e {
            Error::NotEpochMember => Error::NotEpochMember,
            _ => squat("the entropy addressed to this device does not open"),
        })?;
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
    ///
    /// Creating epoch 0 is the point of no return: after it, only this
    /// client holds the keys that open the mailbox. So the steps after it,
    /// the ORF registration and publishing, do not fail the call (that
    /// would discard the only copy of the genesis keys and leave epoch 0
    /// squatted). Use [`initialize_with_report`](Self::initialize_with_report)
    /// to see such a failure, and retry with
    /// [`finish_initialize`](Self::finish_initialize).
    pub fn initialize(
        did: &str,
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<Self> {
        Self::initialize_with_report(did, transport, b).map(|(me, _)| me)
    }

    /// [`initialize`](Self::initialize), also returning the first error of
    /// the steps after epoch 0 was created (`None` when the ORF state was
    /// registered and every destination took the new `mailboxKeys`).
    pub fn initialize_with_report(
        did: &str,
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<(Self, Option<Error>)> {
        if b.mailbox.owner() != did || b.threads.author() != did {
            return Err(Error::Malformed("store handles belong to another DID"));
        }
        let device = DeviceSecrets::generate()?;
        let (pending, new) = open_genesis(did, &device, transport.as_ref())?;
        let mut salt = [0u8; 32];
        random(&mut salt)?;
        let now = crate::records::datetime_from_ms(b.clock.now_ms());
        let members: Vec<_> = new
            .members
            .iter()
            .map(|m| EpochMember::from_record(m, now.clone()))
            .collect();
        // mls-ds admits only registered devices as epoch members, so the
        // device record comes first; the epoch create stays the race guard
        // (a loser leaves an orphan device record that is never a member).
        let key = device.public().device_key_pub;
        let binding = ChatBinding::sign(did, &key, transport.as_ref());
        b.mailbox
            .create_device(&Device::bound(device.public(), &binding, now.clone()))?;
        let id = b
            .mailbox
            .create_epoch(&Epoch::from_record(&new.record, now), &members)?;
        let mut me = Self::assemble(did, device, transport, b, salt, [pending.assign_id(id)])?;
        // Made here, so it needs no checking.
        me.adopted(new.record.public.clone());
        me.remember_verified(0, [key.0]);
        let unfinished = me.finish_initialize().err();
        Ok((me, unfinished))
    }

    /// The steps of [`initialize`](Self::initialize) after epoch 0: register
    /// this genesis device's ORF state (an existing state is kept) and
    /// publish every epoch from 0 up, in order. Safe to repeat until it
    /// succeeds.
    ///
    /// Publishing from epoch 0 matters when a rotation ran before this
    /// retry: the mls-ds head chain refuses a newer epoch until it has
    /// epoch 0, and the PDS needs every per-epoch copy for [CB-29]. Each
    /// destination accepts an epoch it already has. While older epochs
    /// are replayed, a PDS's `mailboxKeys/self` briefly names an older
    /// epoch; the last write restores the newest.
    pub fn finish_initialize(&self) -> Result<()> {
        let key = self.device.public().device_key_pub;
        let orf = match self.b.orf.register(&key, None) {
            Ok(()) | Err(Error::Conflict) => Ok(()),
            Err(e) => Err(e),
        };
        // Publish even when the ORF is down: the directories don't need it.
        let published = (0..=self.latest)
            .try_for_each(|seq| self.publish_keys(&self.epoch_record(seq)?.1.public));
        orf.and(published)
    }

    pub(super) fn epoch_record(&self, seq: u64) -> Result<(String, EpochRecord)> {
        epoch_record(self.b.mailbox.as_ref(), seq)
    }

    /// Publishes a new epoch to the mailbox and every extra publisher.
    /// Every destination is tried; the first failure is returned.
    pub(super) fn publish_keys(&self, public: &crate::mailbox::EpochPublic) -> Result<()> {
        let record = MailboxKeysRecord::from_public(public, None, self.now());
        let mut result = self.b.mailbox.publish_mailbox_keys(&record);
        for p in &self.b.publishers {
            let r = p.publish(&record);
            if result.is_ok() {
                result = r;
            }
        }
        result
    }

    /// Publish the newest epoch again, to the mailbox and every extra
    /// publisher: the retry after a rotation whose epoch was created but
    /// whose publish failed. The [CB-28] check depends on the other
    /// directory staying current.
    pub fn publish_latest_keys(&self) -> Result<()> {
        self.publish_keys(&self.latest_public()?)
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
            &self.revoked,
        )?;
        for e in reached {
            self.latest = self.latest.max(e.seq);
            self.epochs.insert(e.seq, e);
        }
        self.adopt_latest()?;
        self.check_epoch_integrity()?;
        let latest = self.epoch_secret(self.latest)?;
        let audit = self.audit_epoch(&latest)?;
        let readmitted = audit
            .valid
            .iter()
            .map(|v| v.record.device_key_pub)
            .chain(audit.excluded.iter().filter_map(|x| x.device_key))
            .filter(|k| self.revoked.contains(&k.0))
            .collect();
        self.remember_verified(
            latest.seq,
            audit.valid.iter().map(|v| v.record.device_key_pub.0),
        );
        Ok(SyncReport {
            from,
            to: self.latest,
            readmitted,
            invalid_members: audit.excluded,
        })
    }

    /// SPEC §10 mitigation for a backend that hides newer epochs: fails with
    /// [`Error::EpochTruncated`] if the directory's published latest epoch
    /// for this account is ahead of the newest epoch this device reached.
    pub fn check_epoch_integrity(&self) -> Result<()> {
        let head = self.latest_public()?.head;
        check_integrity(self.b.directory.as_ref(), &self.did, self.latest, &head)
    }

    /// The secret of my epoch `seq`, backward-chaining lazily from the
    /// nearest newer epoch I hold (SPEC §5.4, p.36). Each recovered epoch
    /// is authenticated against its published record.
    pub(super) fn epoch_secret(&mut self, seq: u64) -> Result<EpochSecret> {
        if let Some(e) = self.epochs.get(&seq) {
            return Ok(e.clone());
        }
        let next = seq
            .checked_add(1)
            .ok_or(Error::Malformed("epoch sequence overflow"))?;
        let mut cur = self
            .epochs
            .range(next..)
            .next()
            .map(|(_, e)| e.clone())
            .ok_or(Error::NotFound("epoch"))?;
        while cur.seq > seq {
            let (_, record) = self.epoch_record(cur.seq)?;
            let prev_seq = cur
                .seq
                .checked_sub(1)
                .ok_or(Error::Malformed("epoch 0 has no predecessor"))?;
            let (prev_id, prev_record) = self.epoch_record(prev_seq)?;
            let prev = backward_chain(&cur, &record, &prev_id)?;
            verify_public(&prev, &prev_record.public)?;
            self.epochs.insert(prev.seq, prev.clone());
            cur = prev;
        }
        Ok(cur)
    }

    /// Revoke a device: record it in this client's local revoked set,
    /// mark it revoked in the store, delete its ORF server state, then open
    /// a new epoch that carries
    /// over every other unrevoked member ([CB-11], [CB-25]) and publish its
    /// keys. Retries if a sibling device opens the same epoch first.
    ///
    /// The exclusion comes from the local revoked set, not from the
    /// store's `revokedAt` (which a malicious or buggy store can drop), and
    /// every later rotation by this client excludes the whole set. Success
    /// is reported only after checking that the new epoch neither lists
    /// the target as a member nor encrypts entropy to it.
    pub fn revoke_device(&mut self, target: &XVerifyingKey) -> Result<RotationReport> {
        if *target == self.device.public().device_key_pub {
            return Err(Error::Malformed("a device cannot revoke itself"));
        }
        self.revoked.insert(target.0);
        self.sync_epochs()?;
        self.b.mailbox.set_device_revoked(target, &self.now())?;
        self.b.orf.delete(target)?;
        for _ in 0..ROTATE_ATTEMPTS {
            let exclude = self.revoked.clone();
            match self.rotate(&exclude) {
                Err(Error::Conflict) => {
                    self.sync_epochs()?;
                }
                Ok((new_epoch, excluded)) => {
                    return Ok(RotationReport {
                        new_epoch,
                        revoked: *target,
                        excluded,
                    });
                }
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict)
    }

    /// Devices this client has revoked. Part of the persisted client state
    /// ([`Labyrinth::export_state`]).
    pub fn revoked_devices(&self) -> impl Iterator<Item = XVerifyingKey> + '_ {
        self.revoked.iter().map(|k| XVerifyingKey(*k))
    }

    /// Open the epoch after `self.latest`, carrying over every member of
    /// the previous epoch except this device (the opener is added by
    /// [`open_next`]), the devices in `exclude`, and devices the store
    /// reports as revoked.
    ///
    /// [CB-25] as amended: a member that fails verification or is not
    /// bound to a current chat device ([CB-36]) is dropped and returned,
    /// so one planted row cannot block revocation; a member this client
    /// already verified in that epoch failing now aborts with
    /// [`Error::MemberTampered`].
    fn rotate(&mut self, exclude: &BTreeSet<[u8; 32]>) -> Result<(u64, Vec<ExcludedMember>)> {
        let prev = self.epoch_secret(self.latest)?;
        let mine = self.transport.transport_public_key();
        let current = self.b.directory.device_transport_keys(&self.did)?;
        if !current.iter().any(|k| k.is_current() && k.key == mine) {
            // Without our own chat device the directory view is wrong (or
            // we were removed); a rotation would drop every sibling.
            return Err(Error::Unattested);
        }
        let audit = self.audit_epoch(&prev)?;
        self.check_not_tampered(prev.seq, &audit.excluded)?;
        let mb = self.b.mailbox.as_ref();
        let (_, prev_record) = epoch_record(mb, prev.seq)?;
        let me = self.device.public().device_key_pub;
        let continuing: Vec<DevicePublic> = audit
            .valid
            .iter()
            .filter(|v| {
                let k = v.record.device_key_pub;
                k != me && !exclude.contains(&k.0) && !v.revoked
            })
            .map(|v| v.public.clone())
            .collect();
        let prev_members: Vec<EpochMemberRecord> =
            audit.valid.iter().map(|v| v.record.clone()).collect();
        let (pending, new) = open_next(
            &self.did,
            &prev,
            &prev_record.public,
            &prev_members,
            &continuing,
            &self.device,
            self.transport.as_ref(),
        )?;
        if new
            .members
            .iter()
            .any(|m| exclude.contains(&m.device_key_pub.0))
        {
            return Err(Error::Malformed("rotation would re-admit a revoked device"));
        }
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
        // Made here, so it needs no checking.
        self.adopted(new.record.public.clone());
        self.remember_verified(self.latest, new.members.iter().map(|m| m.device_key_pub.0));
        self.publish_keys(&new.record.public)?;
        let excluded = audit
            .excluded
            .into_iter()
            .filter(|x| x.device_key.is_none_or(|k| !exclude.contains(&k.0)))
            .collect();
        Ok((self.latest, excluded))
    }
}

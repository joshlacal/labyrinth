//! Mailbox lifecycle: genesis, forward/backward chaining, revocation and
//! the epoch-integrity check (SPEC §5, §10).

use std::collections::BTreeSet;

use super::members::{Audit, ExcludedMember, ExclusionReason};
use super::{Backends, Labyrinth};
use crate::device::{ChatBinding, DevicePublic, DeviceSecrets};
use crate::encoding::random;
use crate::epoch::{
    EpochMemberRecord, EpochRecord, EpochSecret, OpenedEpoch, backward_chain, forward_chain,
    open_genesis, open_next, verify_member, verify_public,
};
use crate::hpke::hawk::HawkEncSecret;
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
    /// The revoked device.
    pub revoked: XVerifyingKey,
    /// Members of the previous epoch the rotation dropped because they
    /// failed verification or are not bound to a current chat device
    /// ([CB-25] as amended, [CB-36]). Never silent: show these.
    pub excluded: Vec<ExcludedMember>,
}

/// How many times a rotation retries after losing the create race.
const ROTATE_ATTEMPTS: usize = 3;

/// Keys with a cryptographically valid membership in `audit`. Physical
/// devices whose member MAC is valid but whose chat binding is absent or no
/// longer current still know this epoch's entropy, so revocation safety must
/// count them even though rotation excludes them for [CB-36]. Malformed rows,
/// missing/invalid device records and invalid MACs remain non-blocking.
fn confirmed_epoch_member_keys(audit: &Audit) -> impl Iterator<Item = XVerifyingKey> + '_ {
    audit
        .valid
        .iter()
        .map(|v| v.record.device_key_pub)
        .chain(audit.excluded.iter().filter_map(|x| {
            matches!(
                x.reason,
                ExclusionReason::Unbound | ExclusionReason::ChatDeviceNotCurrent
            )
            .then_some(x.device_key)
            .flatten()
        }))
}

pub(super) fn epoch_record(mb: &dyn MailboxStore, seq: u64) -> Result<(String, EpochRecord)> {
    let s = mb.get_epoch(seq)?.ok_or(Error::NotFound("epoch"))?;
    if s.value.seq() != seq {
        return Err(Error::Malformed("epoch record under the wrong key"));
    }
    Ok((s.rkey, s.value.to_record()?))
}

/// Create an immutable epoch, reconciling an ambiguous response by reading
/// back the exact signed record and every initial member. This keeps the
/// pending epoch secrets alive when a backend committed the write but its
/// acknowledgement was lost. A process crash still requires a durable
/// operation journal outside this in-memory call.
fn create_epoch_reconciled(
    mb: &dyn MailboxStore,
    epoch: &Epoch,
    members: &[EpochMember],
) -> Result<String> {
    let failure = match mb.create_epoch(epoch, members) {
        Ok(id) => return Ok(id),
        Err(error) => error,
    };
    if !matches!(&failure, Error::Backend(_) | Error::Conflict) {
        return Err(failure);
    }
    let seq = epoch.public.epoch_number;
    let Some(stored) = mb.get_epoch(seq)? else {
        return Err(failure);
    };
    if stored.author != mb.owner() || stored.value != *epoch {
        return Err(failure);
    }
    let actual = mb.list_epoch_members(seq)?;
    if !members.iter().all(|expected| actual.contains(expected)) {
        return Err(failure);
    }
    Ok(stored.rkey)
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
pub(super) fn chain_forward(
    mb: &dyn MailboxStore,
    did: &str,
    start: EpochSecret,
    me: &DevicePublic,
    storage: &HawkEncSecret,
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
        // In Gate 3 atomic enrollment (`open_next_enrolling`), a newly enrolled
        // physical device opens `E+1` directly using `E`'s mailbox signing key;
        // it was not yet a member of `E`, whereas normal rotations have `opener_prev`.
        let opener_prev = member(mb, prev.seq, &opener.device_key_pub)?;
        if let Some(ref op_prev) = opener_prev {
            verify_member(prev, op_prev, opener.is_virtual)
                .map_err(|_| squat("its opener's previous epoch membership failed MAC"))?;
        }
        let mine = member(mb, seq, &me.device_key_pub)?.ok_or(Error::NotEpochMember)?;
        let opened = OpenedEpoch {
            epoch_id: &next.rkey,
            record: &record,
            my_member: &mine,
            opener: &opener,
            opener_prev_member: opener_prev.as_ref(),
        };
        let e = forward_chain(did, prev, &prev_public, &opened, storage, me.is_virtual)
            .map_err(|_| squat("the entropy addressed to this device does not open"))?;
        out.push(e);
    }
}

/// SPEC §10 epoch-integrity check ([CB-28]): the account's published latest epoch
/// (from the directory, i.e. the public `mailboxKeys` / mls-ds roster view)
/// must not be ahead of what this device reached, nor fork from it.
fn checked_published(
    dir: &dyn MailboxDirectory,
    did: &str,
    reached: u64,
    reached_head: &[u8; 32],
) -> Result<Option<EpochPublic>> {
    let Some(published) = dir.latest(did)? else {
        return Ok(None);
    };
    published.verify(did, None)?;
    if published.seq > reached {
        // A self-consistent ahead row can carry attacker-generated epoch
        // and transport keys. It has no authenticated chain path yet, so a
        // historically associated but removed key must not be allowed to
        // invent it and block sync/recovery. Only a current account device
        // may supply this fail-closed truncation anchor.
        let attester = published.attestation.transport_public_key;
        if !dir
            .device_transport_keys(did)?
            .iter()
            .any(|key| key.is_current() && key.key == attester)
        {
            return Err(Error::Unattested);
        }
        return Err(Error::EpochTruncated {
            published: published.seq,
            reached,
        });
    }
    // Equal or historical heads are accepted from a removed device because
    // they may genuinely predate its removal; their ancestry is checked by
    // the caller below.
    check_own_attester(dir, did, &published)?;
    if published.seq == reached && published.head != *reached_head {
        return Err(Error::Malformed("published epoch head forks from mailbox"));
    }
    Ok(Some(published))
}

/// Checks the published epoch and proves that a lagging published head is
/// an ancestor of the candidate reached through the mailbox. Every link is
/// authenticated with the previous epoch's mailbox signing key; removed
/// historical attesters remain valid while the candidate's own attester is
/// checked separately by [`verified_own`].
pub(super) fn check_candidate_integrity(
    mb: &dyn MailboxStore,
    dir: &dyn MailboxDirectory,
    did: &str,
    reached: u64,
    reached_head: &[u8; 32],
) -> Result<()> {
    let Some(published) = checked_published(dir, did, reached, reached_head)? else {
        return Ok(());
    };
    if published.seq == reached {
        return Ok(());
    }

    let mut seq = reached;
    let mut child = epoch_record(mb, seq)?.1.public;
    if child.head != *reached_head {
        return Err(Error::Malformed("published epoch head forks from mailbox"));
    }
    while seq > published.seq {
        let prev_seq = seq
            .checked_sub(1)
            .ok_or(Error::Malformed("epoch chain broken"))?;
        let prev = epoch_record(mb, prev_seq)?.1.public;
        child.verify(did, Some(&prev))?;
        child = prev;
        seq = prev_seq;
    }
    if child.head != published.head {
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
        let epoch = Epoch::from_record(&new.record, now);
        let id = create_epoch_reconciled(b.mailbox.as_ref(), &epoch, &members)?;
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
        self.ensure_latest_revocation_safe()?;
        (0..=self.latest).try_for_each(|seq| {
            match self.publish_keys(&self.epoch_record(seq)?.1.public) {
                Ok(()) => Ok(()),
                Err(Error::EpochRollback { pinned, .. })
                    if seq < self.latest && pinned <= self.latest =>
                {
                    Ok(())
                }
                Err(e) => Err(e),
            }
        })
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
        self.ensure_latest_revocation_safe()?;
        self.publish_keys(&self.latest_public()?)
    }

    /// Publishing an inclusive head after a locally decided revocation
    /// would advertise unsafe keys even though new encryption is blocked.
    /// Re-audit the cached latest epoch and include invalid/omitted rows for
    /// keys this client already knows were members.
    fn ensure_latest_revocation_safe(&self) -> Result<()> {
        if self.revoked.is_empty() {
            return Ok(());
        }
        let epoch = self
            .epochs
            .get(&self.latest)
            .ok_or(Error::NotFound("epoch"))?;
        let audit = self.audit_epoch(epoch)?;
        let served_revoked = confirmed_epoch_member_keys(&audit)
            .map(|member| member.0)
            .chain(
                audit
                    .excluded
                    .iter()
                    .filter_map(|member| member.device_key.map(|key| key.0)),
            )
            .any(|key| self.revoked.contains(&key));
        let omitted_verified_revoked = self.verified.0 == epoch.seq
            && self.verified.1.iter().any(|key| self.revoked.contains(key));
        if served_revoked || omitted_verified_revoked {
            return Err(Error::EpochSquatted {
                seq: epoch.seq,
                reason: "it re-admits a device this client revoked",
            });
        }
        Ok(())
    }

    /// Forward-chain into every epoch opened since this device last synced
    /// (e.g. by a sibling device's revocation), then run
    /// [`check_epoch_integrity`](Self::check_epoch_integrity).
    ///
    /// [`Error::NotEpochMember`] means this device has been revoked.
    pub fn sync_epochs(&mut self) -> Result<SyncReport> {
        self.sync_epochs_allowing(&BTreeSet::new())
    }

    /// Sync while permitting `pending_revocations` to remain members of the
    /// reached chain. This is used only between the local decision to revoke
    /// a target and the rotation that removes it; no ordinary operation gets
    /// access to an epoch containing a previously revoked device.
    fn sync_epochs_allowing(
        &mut self,
        pending_revocations: &BTreeSet<[u8; 32]>,
    ) -> Result<SyncReport> {
        let from = self.latest;
        let start = self.epoch_secret(from)?;
        // A target may legitimately have opened an unseen epoch before this
        // device decided to revoke it. During the private preparatory catch-up
        // only, let that target's existing opener signature through so this
        // client can reach the head and immediately rotate it out. Ordinary
        // sync still rejects every locally revoked opener, and addressing is
        // blocked until the safe rotation succeeds.
        let enforced_revoked: BTreeSet<[u8; 32]> = self
            .revoked
            .difference(pending_revocations)
            .copied()
            .collect();
        let reached = chain_forward(
            self.b.mailbox.as_ref(),
            &self.did,
            start,
            self.device.public(),
            &self.device.storage,
            &enforced_revoked,
        )?;
        let latest = reached.last().expect("chain contains its start");
        let latest_public = if latest.seq == self.latest {
            let public = self.latest_public()?;
            if !self.own_attester_checked {
                check_own_attester(self.b.directory.as_ref(), &self.did, &public)?;
            }
            public
        } else {
            verified_own(
                self.b.mailbox.as_ref(),
                self.b.directory.as_ref(),
                &self.did,
                latest,
            )?
        };
        check_candidate_integrity(
            self.b.mailbox.as_ref(),
            self.b.directory.as_ref(),
            &self.did,
            latest.seq,
            &latest_public.head,
        )?;
        let mut latest_audit = None;
        for epoch in &reached {
            let audit = self.audit_epoch(epoch)?;
            let is_enforced_revoked =
                |key: &[u8; 32]| self.revoked.contains(key) && !pending_revocations.contains(key);
            // Once this client has decided a key is revoked, a store cannot
            // make its possession of the epoch root disappear by corrupting
            // or omitting the served member row. Named invalid rows count,
            // and the persisted verified set covers same-epoch omissions.
            // An unseen epoch's complete roster still needs a committed
            // membership root at the protocol layer; this closes the local
            // evidence the client already possesses.
            let served_revoked = confirmed_epoch_member_keys(&audit)
                .map(|member| member.0)
                .chain(
                    audit
                        .excluded
                        .iter()
                        .filter_map(|member| member.device_key.map(|key| key.0)),
                )
                .any(|key| is_enforced_revoked(&key));
            let omitted_verified_revoked =
                self.verified.0 == epoch.seq && self.verified.1.iter().any(is_enforced_revoked);
            if served_revoked || omitted_verified_revoked {
                return Err(Error::EpochSquatted {
                    seq: epoch.seq,
                    reason: "it re-admits a device this client revoked",
                });
            }
            self.check_not_tampered(epoch.seq, &audit)?;
            latest_audit = Some(audit);
        }
        let audit = latest_audit.expect("chain contains its start");
        let readmitted = confirmed_epoch_member_keys(&audit)
            .filter(|k| self.revoked.contains(&k.0))
            .collect::<Vec<_>>();

        let to = latest.seq;
        for e in reached {
            self.epochs.insert(e.seq, e);
        }
        self.latest = to;
        self.adopted(latest_public);
        self.remember_verified(to, audit.valid.iter().map(|v| v.record.device_key_pub.0));
        Ok(SyncReport {
            from,
            to,
            readmitted,
            invalid_members: audit.excluded,
        })
    }

    /// SPEC §10 mitigation for a backend that hides newer epochs: fails with
    /// [`Error::EpochTruncated`] if the directory's published latest epoch
    /// for this account is ahead of the newest epoch this device reached.
    pub fn check_epoch_integrity(&self) -> Result<()> {
        let head = self.latest_public()?.head;
        check_candidate_integrity(
            self.b.mailbox.as_ref(),
            self.b.directory.as_ref(),
            &self.did,
            self.latest,
            &head,
        )
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
        // A queued sender/owner ciphertext was sealed under the pre-decision
        // epoch or recipient roster. Crossing the revocation boundary would
        // let a removed device receive old-key ciphertext after the cutoff.
        // The caller must deliberately flush it first or discard and
        // re-archive under the post-rotation keys.
        if self.outbox.values().any(|items| !items.is_empty())
            || self.owner_outbox.values().any(|items| !items.is_empty())
        {
            return Err(Error::PendingWrites);
        }
        self.revoked.insert(target.0);
        self.sync_epochs_allowing(&BTreeSet::from([target.0]))?;
        self.b.mailbox.set_device_revoked(target, &self.now())?;
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
        self.check_not_tampered(prev.seq, &audit)?;
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
        let epoch = Epoch::from_record(&new.record, now);
        let id = create_epoch_reconciled(mb, &epoch, &members)?;
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

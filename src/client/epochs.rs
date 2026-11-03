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

pub(super) async fn epoch_record(mb: &dyn MailboxStore, seq: u64) -> Result<(String, EpochRecord)> {
    let s = mb.get_epoch(seq).await?.ok_or(Error::NotFound("epoch"))?;
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
async fn create_epoch_reconciled(
    mb: &dyn MailboxStore,
    epoch: &Epoch,
    members: &[EpochMember],
) -> Result<String> {
    let failure = match mb.create_epoch(epoch, members).await {
        Ok(id) => return Ok(id),
        Err(error) => error,
    };
    if !matches!(&failure, Error::Backend(_) | Error::Conflict) {
        return Err(failure);
    }
    let seq = epoch.public.epoch_number;
    let Some(stored) = mb.get_epoch(seq).await? else {
        return Err(failure);
    };
    if stored.author != mb.owner() || stored.value != *epoch {
        return Err(failure);
    }
    let actual = mb.list_epoch_members(seq).await?;
    if !members.iter().all(|expected| actual.contains(expected)) {
        return Err(failure);
    }
    Ok(stored.rkey)
}

/// Reads my own epoch `secret.seq` from the mailbox and authenticates the
/// whole record before it is adopted ([CB-43]): [`verified_own_signatures`]
/// and [`check_own_attester`].
pub(super) async fn verified_own(
    mb: &dyn MailboxStore,
    dir: &dyn MailboxDirectory,
    did: &str,
    secret: &EpochSecret,
) -> Result<EpochPublic> {
    let public = verified_own_signatures(mb, did, secret).await?;
    check_own_attester(dir, did, &public).await?;
    Ok(public)
}

/// The part of [`verified_own`] that needs only the mailbox: the record's
/// id and keys match the secret, its self signature and attestation
/// verify, and above epoch 0 its `prev_sig` verifies under the previous
/// epoch's mailbox key (recovered by backward-chaining, so a substituted
/// predecessor fails too).
pub(super) async fn verified_own_signatures(
    mb: &dyn MailboxStore,
    did: &str,
    secret: &EpochSecret,
) -> Result<EpochPublic> {
    let (id, record) = epoch_record(mb, secret.seq).await?;
    if id != secret.epoch_id {
        return Err(Error::Malformed("epoch id does not match store"));
    }
    verify_public(secret, &record.public)?;
    let prev = match secret.seq.checked_sub(1) {
        None => None,
        Some(prev_seq) => {
            let (prev_id, prev_record) = epoch_record(mb, prev_seq).await?;
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
pub(super) async fn check_own_attester(
    dir: &dyn MailboxDirectory,
    did: &str,
    public: &EpochPublic,
) -> Result<()> {
    let attester = public.attestation.transport_public_key;
    if dir
        .device_transport_keys(did)
        .await?
        .iter()
        .any(|k| k.key == attester)
    {
        Ok(())
    } else {
        Err(Error::Unattested)
    }
}

async fn member(
    mb: &dyn MailboxStore,
    seq: u64,
    key: &XVerifyingKey,
) -> Result<Option<EpochMemberRecord>> {
    mb.get_epoch_member(seq, key)
        .await?
        .map(|m| m.to_record())
        .transpose()
}

enum StepOutcome {
    Absent,
    Valid(Box<EpochSecret>),
    Squatted { seq: u64, reason: &'static str },
}

async fn step_forward(
    mb: &dyn MailboxStore,
    did: &str,
    prev: &EpochSecret,
    me: &DevicePublic,
    storage: &HawkEncSecret,
    revoked: &BTreeSet<[u8; 32]>,
) -> Result<StepOutcome> {
    let seq = prev
        .seq
        .checked_add(1)
        .ok_or(Error::Malformed("epoch sequence overflow"))?;
    let squat = |reason| StepOutcome::Squatted { seq, reason };
    let next = match mb.get_epoch(seq).await {
        Ok(Some(next)) => next,
        Ok(None) => return Ok(StepOutcome::Absent),
        Err(Error::Malformed("space record")) => {
            return Ok(squat("the epoch record does not parse"));
        }
        Err(e) => return Err(e),
    };
    let Some(record) = next.value.to_record().ok().filter(|r| r.public.seq == seq) else {
        return Ok(squat("the epoch record does not parse"));
    };
    let prev_public = epoch_record(mb, prev.seq).await?.1.public;
    if record.public.verify(did, Some(&prev_public)).is_err() {
        return Ok(squat(
            "it is not signed by the previous epoch's mailbox key",
        ));
    }
    let opener_raw = match mb.get_device(&record.opened_by).await {
        Ok(opt) => opt,
        Err(Error::Malformed("space record")) => None,
        Err(e) => return Err(e),
    };
    let Some(opener) = opener_raw
        .and_then(|d| d.to_public().ok())
        .filter(|p| p.verify().is_ok() && !p.is_virtual && p.device_key_pub == record.opened_by)
    else {
        return Ok(squat("its opener has no valid physical device record"));
    };
    if revoked.contains(&record.opened_by.0) {
        return Ok(squat("it was opened by a device this client revoked"));
    }
    // In Gate 3 atomic enrollment (`open_next_enrolling`), a newly enrolled
    // physical device opens `E+1` directly using `E`'s mailbox signing key;
    // it was not yet a member of `E`, whereas normal rotations have `opener_prev`.
    let opener_prev = member(mb, prev.seq, &opener.device_key_pub).await?;
    if let Some(ref op_prev) = opener_prev
        && verify_member(prev, op_prev, opener.is_virtual).is_err()
    {
        return Ok(squat("its opener's previous epoch membership failed MAC"));
    }
    let mine = member(mb, seq, &me.device_key_pub)
        .await?
        .ok_or(Error::NotEpochMember)?;
    let opened = OpenedEpoch {
        epoch_id: &next.rkey,
        record: &record,
        my_member: &mine,
        opener: &opener,
        opener_prev_member: opener_prev.as_ref(),
    };
    match forward_chain(did, prev, &prev_public, &opened, storage, me.is_virtual) {
        Ok(e) => Ok(StepOutcome::Valid(Box::new(e))),
        Err(_) => Ok(squat("the entropy addressed to this device does not open")),
    }
}

/// Forward-chains from `start` as long as the store has a next epoch.
/// Returns every epoch reached, `start` first.
pub(super) async fn chain_forward(
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
        match step_forward(mb, did, prev, me, storage, revoked).await? {
            StepOutcome::Absent => return Ok(out),
            StepOutcome::Valid(e) => out.push(*e),
            StepOutcome::Squatted { seq, reason } => {
                return Err(Error::EpochSquatted { seq, reason });
            }
        }
    }
}

async fn ensure_seq_unanchored_in_directory(
    dir: &dyn MailboxDirectory,
    did: &str,
    seq: u64,
    reached: u64,
) -> Result<()> {
    if let Some(published) = dir.latest(did).await?
        && published.seq >= seq
    {
        published.verify(did, None)?;
        let attester = published.attestation.transport_public_key;
        if !dir
            .device_transport_keys(did)
            .await?
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
    if let Some(anchored) = dir.epoch(did, seq).await? {
        anchored.verify(did, None)?;
        return Err(Error::EpochTruncated {
            published: seq,
            reached,
        });
    }
    Ok(())
}

async fn is_epoch_header_or_opener_invalid(
    mb: &dyn MailboxStore,
    did: &str,
    prev_public: &EpochPublic,
    next_seq: u64,
) -> Result<Option<bool>> {
    let existing = match mb.get_epoch(next_seq).await {
        Ok(None) => return Ok(None),
        Ok(Some(existing)) => existing,
        Err(Error::Malformed("space record")) => return Ok(Some(true)),
        Err(e) => return Err(e),
    };
    let Some(record) = existing
        .value
        .to_record()
        .ok()
        .filter(|r| r.public.seq == next_seq)
    else {
        return Ok(Some(true));
    };
    if record.public.verify(did, Some(prev_public)).is_err() {
        return Ok(Some(true));
    }
    let opener_raw = match mb.get_device(&record.opened_by).await {
        Ok(opt) => opt,
        Err(Error::Malformed("space record")) => None,
        Err(e) => return Err(e),
    };
    let valid_physical_opener = opener_raw
        .and_then(|d| d.to_public().ok())
        .is_some_and(|p| {
            p.verify().is_ok() && !p.is_virtual && p.device_key_pub == record.opened_by
        });
    Ok(Some(!valid_physical_opener))
}

/// Forward-chains from `start` during recovery enrollment, healing at most 8
/// unanchored `[CB-40]` squatted successor records while refusing to touch any
/// directory-anchored epoch or valid sibling rotation.
pub(super) async fn chain_forward_healing_squats(
    mb: &dyn MailboxStore,
    dir: &dyn MailboxDirectory,
    did: &str,
    start: EpochSecret,
    me: &DevicePublic,
    storage: &HawkEncSecret,
    revoked: &BTreeSet<[u8; 32]>,
) -> Result<Vec<EpochSecret>> {
    let mut out = vec![start];
    let mut heals = 0usize;
    loop {
        let prev = out.last().expect("non-empty").clone();
        match step_forward(mb, did, &prev, me, storage, revoked).await? {
            StepOutcome::Absent => return Ok(out),
            StepOutcome::Valid(e) => out.push(*e),
            StepOutcome::Squatted { seq, reason } => {
                if heals >= 8 {
                    return Err(Error::EpochSquatted { seq, reason });
                }
                ensure_seq_unanchored_in_directory(dir, did, seq, prev.seq).await?;
                match step_forward(mb, did, &prev, me, storage, revoked).await? {
                    StepOutcome::Absent => return Ok(out),
                    StepOutcome::Valid(e) => out.push(*e),
                    StepOutcome::Squatted { .. } => {
                        mb.delete_squatted_epoch(seq).await?;
                        heals += 1;
                    }
                }
            }
        }
    }
}

/// Clears an unanchored, cryptographically invalid successor record at
/// `prev_public.seq + 1` before OTC `atomic_enroll` opens `E + 1`.
pub(super) async fn clear_unanchored_invalid_successor(
    mb: &dyn MailboxStore,
    dir: &dyn MailboxDirectory,
    did: &str,
    prev_public: &EpochPublic,
) -> Result<()> {
    let next_seq = prev_public
        .seq
        .checked_add(1)
        .ok_or(Error::Malformed("epoch sequence overflow"))?;
    match is_epoch_header_or_opener_invalid(mb, did, prev_public, next_seq).await? {
        None | Some(false) => return Ok(()),
        Some(true) => {}
    }
    ensure_seq_unanchored_in_directory(dir, did, next_seq, prev_public.seq).await?;
    if matches!(
        is_epoch_header_or_opener_invalid(mb, did, prev_public, next_seq).await?,
        Some(true)
    ) {
        mb.delete_squatted_epoch(next_seq).await?;
    }
    Ok(())
}

/// SPEC §10 epoch-integrity check ([CB-28]): the account's published latest epoch
/// (from the directory, i.e. the public `mailboxKeys` / mls-ds roster view)
/// must not be ahead of what this device reached, nor fork from it.
async fn checked_published(
    dir: &dyn MailboxDirectory,
    did: &str,
    reached: u64,
    reached_head: &[u8; 32],
) -> Result<Option<EpochPublic>> {
    let Some(published) = dir.latest(did).await? else {
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
            .device_transport_keys(did)
            .await?
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
    check_own_attester(dir, did, &published).await?;
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
pub(super) async fn check_candidate_integrity(
    mb: &dyn MailboxStore,
    dir: &dyn MailboxDirectory,
    did: &str,
    reached: u64,
    reached_head: &[u8; 32],
) -> Result<()> {
    let Some(published) = checked_published(dir, did, reached, reached_head).await? else {
        return Ok(());
    };
    if published.seq == reached {
        return Ok(());
    }

    let mut seq = reached;
    let mut child = epoch_record(mb, seq).await?.1.public;
    if child.head != *reached_head {
        return Err(Error::Malformed("published epoch head forks from mailbox"));
    }
    while seq > published.seq {
        let prev_seq = seq
            .checked_sub(1)
            .ok_or(Error::Malformed("epoch chain broken"))?;
        let prev = epoch_record(mb, prev_seq).await?.1.public;
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
    /// client holds the keys that open the mailbox. So publishing after it
    /// does not fail the call (that would discard the only copy of the
    /// genesis keys and leave epoch 0 squatted). Use
    /// [`initialize_with_report`](Self::initialize_with_report) to see such
    /// a failure, and retry with [`finish_initialize`](Self::finish_initialize).
    pub async fn initialize(
        did: &str,
        transport: Box<dyn TransportSigner>,
        b: Backends,
    ) -> Result<Self> {
        Self::initialize_with_report(did, transport, b)
            .await
            .map(|(me, _)| me)
    }

    /// [`initialize`](Self::initialize), also returning the first error of
    /// the steps after epoch 0 was created (`None` when every destination
    /// took the new `mailboxKeys`).
    pub async fn initialize_with_report(
        did: &str,
        transport: Box<dyn TransportSigner>,
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
        let key = device.public().device_key_pub;
        let binding = ChatBinding::sign(did, &key, transport.as_ref());
        b.mailbox
            .create_device(&Device::bound(device.public(), &binding, now.clone()))
            .await?;
        let epoch = Epoch::from_record(&new.record, now);
        let id = create_epoch_reconciled(b.mailbox.as_ref(), &epoch, &members).await?;
        let mut me = Self::assemble(did, device, transport, b, salt, [pending.assign_id(id)])?;
        // Made here, so it needs no checking.
        me.adopted(new.record.public.clone());
        me.remember_verified(0, [key.0]);
        let unfinished = me.finish_initialize().await.err();
        Ok((me, unfinished))
    }

    /// The steps of [`initialize`](Self::initialize) after epoch 0: publish
    /// every epoch from 0 up, in order. Safe to repeat until it succeeds.
    ///
    /// Publishing from epoch 0 matters when a rotation ran before this
    /// retry: the mls-ds head chain refuses a newer epoch until it has
    /// epoch 0, and the PDS needs every per-epoch copy for [CB-29].
    pub async fn finish_initialize(&self) -> Result<()> {
        self.ensure_latest_revocation_safe().await?;
        for seq in 0..=self.latest {
            let public = self.epoch_record(seq).await?.1.public;
            match self.publish_keys(&public).await {
                Ok(()) => {}
                Err(Error::EpochRollback { pinned, .. })
                    if seq < self.latest && pinned <= self.latest => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub(super) async fn epoch_record(&self, seq: u64) -> Result<(String, EpochRecord)> {
        epoch_record(self.b.mailbox.as_ref(), seq).await
    }

    /// Publishes a new epoch to the mailbox and every extra publisher.
    /// Every destination is tried; the first failure is returned.
    pub(super) async fn publish_keys(&self, public: &crate::mailbox::EpochPublic) -> Result<()> {
        let record = MailboxKeysRecord::from_public(public, None, self.now());
        let mut result = self.b.mailbox.publish_mailbox_keys(&record).await;
        for p in &self.b.publishers {
            let r = p.publish(&record).await;
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
    pub async fn publish_latest_keys(&self) -> Result<()> {
        self.ensure_latest_revocation_safe().await?;
        let public = self.latest_public()?;
        self.publish_keys(&public).await
    }

    /// Publishing an inclusive head after a locally decided revocation
    /// would advertise unsafe keys even though new encryption is blocked.
    /// Re-audit the cached latest epoch and include invalid/omitted rows for
    /// keys this client already knows were members.
    async fn ensure_latest_revocation_safe(&self) -> Result<()> {
        if self.revoked.is_empty() {
            return Ok(());
        }
        let epoch = self
            .epochs
            .get(&self.latest)
            .ok_or(Error::NotFound("epoch"))?;
        let audit = self.audit_epoch(epoch).await?;
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
    /// (e.g. by a sibling device's revocation or enrollment), then run
    /// [`check_epoch_integrity`](Self::check_epoch_integrity).
    ///
    /// [`Error::NotEpochMember`] means this device has been revoked.
    pub async fn sync_epochs(&mut self) -> Result<SyncReport> {
        self.sync_epochs_allowing(&BTreeSet::new()).await
    }

    /// Sync while permitting `pending_revocations` to remain members of the
    /// reached chain. This is used only between the local decision to revoke
    /// a target and the rotation that removes it; no ordinary operation gets
    /// access to an epoch containing a previously revoked device.
    async fn sync_epochs_allowing(
        &mut self,
        pending_revocations: &BTreeSet<[u8; 32]>,
    ) -> Result<SyncReport> {
        let from = self.latest;
        let start = self
            .epochs
            .get(&from)
            .cloned()
            .ok_or(Error::NotFound("epoch"))?;
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
        )
        .await?;
        let latest = reached.last().expect("chain contains its start");
        let latest_public = if latest.seq == self.latest {
            let public = self.latest_public()?;
            if !self.own_attester_checked {
                check_own_attester(self.b.directory.as_ref(), &self.did, &public).await?;
            }
            public
        } else {
            verified_own(
                self.b.mailbox.as_ref(),
                self.b.directory.as_ref(),
                &self.did,
                latest,
            )
            .await?
        };
        check_candidate_integrity(
            self.b.mailbox.as_ref(),
            self.b.directory.as_ref(),
            &self.did,
            latest.seq,
            &latest_public.head,
        )
        .await?;
        let mut latest_audit = None;
        for epoch in &reached {
            let audit = self.audit_epoch(epoch).await?;
            let is_enforced_revoked =
                |key: &[u8; 32]| self.revoked.contains(key) && !pending_revocations.contains(key);
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
        if to != from {
            self.checkpoint_state()?;
        }
        Ok(SyncReport {
            from,
            to,
            readmitted,
            invalid_members: audit.excluded,
        })
    }

    /// Safely clear an unanchored, unverified squatted epoch record at
    /// `seq == self.latest + 1` from the personal mailbox Space (`[CB-40]`).
    ///
    /// Returns `Ok(true)` if the squatted `epoch/<seq>` (and any planted
    /// `epochMember/<seq>-*` records) were deleted from the mailbox store,
    /// `Ok(false)` if `epoch/<seq>` was already absent or is now a valid
    /// sibling rotation (so no deletion was performed), or `Err(...)` if:
    /// - `seq <= self.latest` (local-revocation quarantine on an already-reached
    ///   epoch is never cleared),
    /// - this device's chat transport key is not currently active in the
    ///   directory (`Error::Unattested`),
    /// - `epoch/<seq>` validly chains from `self.latest` and omits this device
    ///   (`Error::NotEpochMember` — either this device was revoked or a
    ///   multi-chunk rotation is in flight), or
    /// - `self.b.directory` (`CompositeDirectory` over PDS `mailboxKeys` and
    ///   `mls-ds` `epoch_chain`) already anchors an epoch at or above `seq`
    ///   (deleting from the Space would fork against the directory).
    pub async fn clear_squatted_epoch(&mut self, seq: u64) -> Result<bool> {
        if seq <= self.latest {
            return Err(Error::EpochSquatted {
                seq,
                reason: "cannot clear an epoch at or below the locally reached head",
            });
        }

        // Caller must hold a currently active chat device key in the directory.
        let mine = self.transport.transport_public_key();
        let current_keys = self.b.directory.device_transport_keys(&self.did).await?;
        if !current_keys.iter().any(|k| k.is_current() && k.key == mine) {
            return Err(Error::Unattested);
        }

        // Step through any valid, clean intermediate epochs `self.latest + 1 .. seq`
        // so an offline device that missed a valid sibling rotation before a squat
        // can catch up to `seq - 1` without failing all-or-nothing in `sync_epochs`.
        while self.latest.saturating_add(1) < seq {
            let prev = self
                .epochs
                .get(&self.latest)
                .cloned()
                .ok_or(Error::NotFound("epoch"))?;
            match step_forward(
                self.b.mailbox.as_ref(),
                &self.did,
                &prev,
                self.device.public(),
                &self.device.storage,
                &self.revoked,
            )
            .await?
            {
                StepOutcome::Absent => return Ok(false),
                StepOutcome::Squatted {
                    seq: first_squat,
                    reason,
                } => {
                    return Err(Error::EpochSquatted {
                        seq: first_squat,
                        reason,
                    });
                }
                StepOutcome::Valid(next_epoch) => {
                    let audit = self.audit_epoch(&next_epoch).await?;
                    let served_revoked = confirmed_epoch_member_keys(&audit)
                        .map(|m| m.0)
                        .chain(
                            audit
                                .excluded
                                .iter()
                                .filter_map(|m| m.device_key.map(|k| k.0)),
                        )
                        .any(|k| self.revoked.contains(&k));
                    if served_revoked {
                        return Err(Error::EpochSquatted {
                            seq: next_epoch.seq,
                            reason: "it re-admits a device this client revoked",
                        });
                    }
                    self.check_not_tampered(next_epoch.seq, &audit)?;
                    let (_, rec) = epoch_record(self.b.mailbox.as_ref(), next_epoch.seq).await?;
                    let reached_seq = next_epoch.seq;
                    self.epochs.insert(reached_seq, *next_epoch);
                    self.latest = reached_seq;
                    self.adopted(rec.public);
                    self.remember_verified(
                        reached_seq,
                        audit.valid.iter().map(|v| v.record.device_key_pub.0),
                    );
                    self.checkpoint_state()?;
                }
            }
        }

        let expected_next = self
            .latest
            .checked_add(1)
            .ok_or(Error::Malformed("epoch sequence overflow"))?;
        if seq != expected_next {
            return Err(Error::EpochSquatted {
                seq,
                reason: "squatted epoch is not the immediate successor of latest",
            });
        }

        let prev = self
            .epochs
            .get(&self.latest)
            .cloned()
            .ok_or(Error::NotFound("epoch"))?;
        match step_forward(
            self.b.mailbox.as_ref(),
            &self.did,
            &prev,
            self.device.public(),
            &self.device.storage,
            &self.revoked,
        )
        .await?
        {
            StepOutcome::Absent => return Ok(false),
            StepOutcome::Valid(next_epoch) => {
                let audit = self.audit_epoch(&next_epoch).await?;
                let served_revoked = confirmed_epoch_member_keys(&audit)
                    .map(|m| m.0)
                    .chain(
                        audit
                            .excluded
                            .iter()
                            .filter_map(|m| m.device_key.map(|k| k.0)),
                    )
                    .any(|k| self.revoked.contains(&k));
                if !served_revoked {
                    self.sync_epochs().await?;
                    return Ok(false);
                }
                // `next_epoch` re-admits a locally-revoked device -> treat as squatted
                // and fall through to the directory anchoring check!
            }
            StepOutcome::Squatted { .. } => {}
        }

        // Refuse deletion if this device's own record is already marked revoked in the mailbox.
        if let Ok(Some(my_dev)) = self
            .b
            .mailbox
            .get_device(&self.device.public().device_key_pub)
            .await
            && my_dev.revoked_at.is_some()
        {
            return Err(Error::NotEpochMember);
        }

        // Cross-check the directory (`CompositeDirectory` = PDS + `mls-ds`) BEFORE
        // deleting from the mailbox Space: if either directory source already anchors
        // `seq` (or is incomplete/divergent), never delete `epoch/<seq>`.
        ensure_seq_unanchored_in_directory(self.b.directory.as_ref(), &self.did, seq, self.latest)
            .await?;

        // Re-verify one final time right before deletion so a sibling rotation
        // that landed while querying the directory is never clobbered.
        match step_forward(
            self.b.mailbox.as_ref(),
            &self.did,
            &prev,
            self.device.public(),
            &self.device.storage,
            &self.revoked,
        )
        .await?
        {
            StepOutcome::Absent => return Ok(false),
            StepOutcome::Valid(next_epoch) => {
                let audit = self.audit_epoch(&next_epoch).await?;
                let served_revoked = confirmed_epoch_member_keys(&audit)
                    .map(|m| m.0)
                    .chain(
                        audit
                            .excluded
                            .iter()
                            .filter_map(|m| m.device_key.map(|k| k.0)),
                    )
                    .any(|k| self.revoked.contains(&k));
                if !served_revoked {
                    self.sync_epochs().await?;
                    return Ok(false);
                }
            }
            StepOutcome::Squatted { .. } => {}
        }

        self.b.mailbox.delete_squatted_epoch(seq).await?;
        Ok(true)
    }

    /// SPEC §10 mitigation for a backend that hides newer epochs: fails with
    /// [`Error::EpochTruncated`] if the directory's published latest epoch
    /// for this account is ahead of the newest epoch this device reached.
    pub async fn check_epoch_integrity(&self) -> Result<()> {
        let head = self.latest_public()?.head;
        check_candidate_integrity(
            self.b.mailbox.as_ref(),
            self.b.directory.as_ref(),
            &self.did,
            self.latest,
            &head,
        )
        .await
    }

    /// The secret of my epoch `seq`, backward-chaining lazily from the
    /// nearest newer epoch I hold (SPEC §5.4, p.36). Each recovered epoch
    /// is authenticated against its published record.
    pub(super) async fn epoch_secret(&mut self, seq: u64) -> Result<EpochSecret> {
        if let Some(e) = self.epochs.get(&seq) {
            return Ok(e.clone());
        }
        if seq > self.latest {
            self.sync_epochs().await?;
            if let Some(e) = self.epochs.get(&seq) {
                return Ok(e.clone());
            }
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
        let mut inserted = false;
        while cur.seq > seq {
            let (_, record) = self.epoch_record(cur.seq).await?;
            let prev_seq = cur
                .seq
                .checked_sub(1)
                .ok_or(Error::Malformed("epoch 0 has no predecessor"))?;
            let (prev_id, prev_record) = self.epoch_record(prev_seq).await?;
            let prev = backward_chain(&cur, &record, &prev_id)?;
            verify_public(&prev, &prev_record.public)?;
            self.epochs.insert(prev.seq, prev.clone());
            inserted = true;
            cur = prev;
        }
        if inserted {
            self.checkpoint_state()?;
        }
        Ok(cur)
    }

    /// Revoke a device: record it in this client's local revoked set,
    /// mark it revoked in the store, then open a new epoch that carries
    /// over every other unrevoked member ([CB-11], [CB-25]) and publish its
    /// keys. Retries if a sibling device opens the same epoch first.
    pub async fn revoke_device(&mut self, target: &XVerifyingKey) -> Result<RotationReport> {
        if *target == self.device.public().device_key_pub {
            return Err(Error::Malformed("a device cannot revoke itself"));
        }
        if self.outbox.values().any(|items| !items.is_empty())
            || self.owner_outbox.values().any(|items| !items.is_empty())
        {
            return Err(Error::PendingWrites);
        }
        if self.revoked.insert(target.0) {
            self.checkpoint_state()?;
        }
        self.sync_epochs_allowing(&BTreeSet::from([target.0]))
            .await?;
        self.b
            .mailbox
            .set_device_revoked(target, &self.now())
            .await?;
        for _ in 0..ROTATE_ATTEMPTS {
            let exclude = self.revoked.clone();
            match self.rotate(&exclude).await {
                Err(Error::Conflict) => {
                    self.sync_epochs().await?;
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

    /// Rotate the mailbox to the next epoch while carrying over unrevoked members.
    pub async fn rotate_epoch(&mut self) -> Result<u64> {
        if self.outbox.values().any(|items| !items.is_empty())
            || self.owner_outbox.values().any(|items| !items.is_empty())
        {
            return Err(Error::PendingWrites);
        }
        self.sync_epochs().await?;
        for _ in 0..ROTATE_ATTEMPTS {
            let exclude = self.revoked.clone();
            match self.rotate(&exclude).await {
                Err(Error::Conflict) => {
                    self.sync_epochs().await?;
                }
                Ok((epoch, _)) => return Ok(epoch),
                Err(error) => return Err(error),
            }
        }
        Err(Error::Conflict)
    }

    /// Open the epoch after `self.latest`, carrying over every member of
    /// the previous epoch except this device (the opener is added by
    /// [`open_next`]), the devices in `exclude`, and devices the store
    /// reports as revoked.
    async fn rotate(&mut self, exclude: &BTreeSet<[u8; 32]>) -> Result<(u64, Vec<ExcludedMember>)> {
        let prev = self.epoch_secret(self.latest).await?;
        let mine = self.transport.transport_public_key();
        let current = self.b.directory.device_transport_keys(&self.did).await?;
        if !current.iter().any(|k| k.is_current() && k.key == mine) {
            // Without our own chat device the directory view is wrong (or
            // we were removed); a rotation would drop every sibling.
            return Err(Error::Unattested);
        }
        let audit = self.audit_epoch(&prev).await?;
        self.check_not_tampered(prev.seq, &audit)?;
        let mb = self.b.mailbox.as_ref();
        let (_, prev_record) = epoch_record(mb, prev.seq).await?;
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
        let id = create_epoch_reconciled(mb, &epoch, &members).await?;
        let e = pending.assign_id(id);
        self.latest = e.seq;
        self.epochs.insert(e.seq, e);
        // Made here, so it needs no checking.
        self.adopted(new.record.public.clone());
        self.remember_verified(self.latest, new.members.iter().map(|m| m.device_key_pub.0));
        self.checkpoint_state()?;
        self.publish_keys(&new.record.public).await?;
        let excluded = audit
            .excluded
            .into_iter()
            .filter(|x| x.device_key.is_none_or(|k| !exclude.contains(&k.0)))
            .collect();
        Ok((self.latest, excluded))
    }
}

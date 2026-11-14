//! Mailbox lifecycle: genesis, forward/backward chaining, revocation and
//! the epoch-integrity check (SPEC §5, §10).

use std::collections::{BTreeMap, BTreeSet};

use super::enroll::RecoverySetup;
use super::members::{Audit, ExcludedMember, ExclusionReason, verify_epoch_members_hash};
use super::{Backends, Labyrinth};
use crate::device::{ChatBinding, DevicePublic, DeviceRevocation, DeviceSecrets};
use crate::epoch::{
    EpochMemberRecord, EpochRecord, EpochSecret, OpenedEpoch, backward_chain, forward_chain,
    open_genesis, open_next_with_additions, verify_member, verify_public,
};
use crate::hpke::hawk::HawkEncSecret;
use crate::mailbox::EpochPublic;
use crate::records::{Device, Epoch, EpochMember, MailboxKeysRecord, VirtualDevice};
use crate::recovery_code::RecoveryCode;
use crate::sign::{TransportSigner, XVerifyingKey};
use crate::store::{MailboxDirectory, MailboxStore};
use crate::virtual_device::{self, Mechanism};
use crate::{Error, Result};

/// A recovery method invalidated and rotated out when revoking a physical device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidatedRecoveryMethod {
    pub vdevice_id: [u8; 16],
    pub mechanism: Mechanism,
    pub device_key: XVerifyingKey,
}

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

/// Result of a rotation ([`Labyrinth::revoke_device`],
/// [`Labyrinth::rotate_epoch`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationReport {
    /// The epoch the rotation opened.
    pub new_epoch: u64,
    /// The revoked device; `None` for an ordinary rotation.
    pub revoked: Option<XVerifyingKey>,
    /// Other revoked members evicted in this rotation (pending revocations,
    /// signed store revocations, or invalidated virtual recovery devices).
    pub evicted_revoked: Vec<XVerifyingKey>,
    /// Members of the previous epoch the rotation dropped because they
    /// failed verification, are not bound to a current chat device
    /// ([CB-25] as amended, [CB-36]), or are recovery bundles past their
    /// TTL ([CB-39]). Never silent: show these.
    pub excluded: Vec<ExcludedMember>,
    /// Recovery methods invalidated and excluded because a physical device
    /// was revoked.
    pub invalidated_recovery_methods: Vec<InvalidatedRecoveryMethod>,
    /// Fresh recovery code minted in `new_epoch` when one or more active
    /// recovery methods were invalidated by a physical device revocation.
    pub rekeyed_recovery: Option<RecoverySetup>,
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
    record.verify_revocations(did)?;
    verify_epoch_members_hash(mb, secret, &record.public).await?;
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
    if record.verify_revocations(did).is_err() {
        return Ok(squat("its revocation list signature is invalid"));
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
    if record.verify_revocations(did).is_err() {
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
        let mut me = Self::assemble(did, device, transport, b, [pending.assign_id(id)])?;
        // Made here, so it needs no checking.
        me.adopted(new.record.public.clone());
        me.remember_verified(0, [key.0]);
        let unfinished = me.finish_initialize().await.err();
        Ok((me, unfinished))
    }

    /// The steps of [`initialize`](Self::initialize) after epoch 0: durably
    /// mark the latest head pending, then publish every epoch from 0 up in
    /// order. Safe to repeat until every configured destination succeeds.
    ///
    /// Publishing from epoch 0 matters when a rotation ran before this
    /// retry: the mls-ds head chain refuses a newer epoch until it has
    /// epoch 0, and the PDS needs every per-epoch copy for [CB-29].
    pub async fn finish_initialize(&mut self) -> Result<()> {
        self.mark_directory_publication_pending()?;
        self.retry_pending_directory_publication().await.map(|_| ())
    }

    fn mark_directory_publication_pending(&mut self) -> Result<()> {
        if self.pending_directory_publication == Some(self.latest) {
            return Ok(());
        }
        let previous = self.pending_directory_publication;
        self.pending_directory_publication = Some(self.latest);
        if let Err(error) = self.checkpoint_state() {
            self.pending_directory_publication = previous;
            return Err(error);
        }
        Ok(())
    }

    async fn clear_pending_if_two_source_superseded(&mut self, pending: u64) -> Result<bool> {
        let Some(anchored) = self.b.directory.latest_two_source(&self.did).await? else {
            return Ok(false);
        };
        if anchored.seq <= pending {
            return Ok(false);
        }

        let mut previous = self.latest_public()?;
        if previous.seq != pending {
            return Err(Error::Malformed("pending publication is not latest epoch"));
        }
        for seq in pending + 1..=anchored.seq {
            let next = self.epoch_record(seq).await?.1.public;
            next.verify(&self.did, Some(&previous))?;
            previous = next;
        }
        if previous.head != anchored.head {
            return Err(Error::Malformed(
                "superseding directory head forks from mailbox",
            ));
        }

        self.pending_directory_publication = None;
        if let Err(error) = self.checkpoint_state() {
            self.pending_directory_publication = Some(pending);
            return Err(error);
        }
        Ok(true)
    }

    /// Retry a durably pending epoch-head publication. All epochs are
    /// replayed so a destination that missed genesis can accept the head.
    ///
    /// A failed stale publication is cleared only when the strict directory
    /// independently proves that PDS and `mls-ds` share a newer head and the
    /// mailbox contains its valid chain from the pending local head.
    pub async fn retry_pending_directory_publication(&mut self) -> Result<bool> {
        let Some(pending) = self.pending_directory_publication else {
            return Ok(false);
        };
        if pending != self.latest {
            return Err(Error::Malformed("pending publication is not latest epoch"));
        }
        self.ensure_latest_revocation_safe().await?;
        let mine = self.transport.transport_public_key();
        for seq in 0..=pending {
            let public = self.epoch_record(seq).await?.1.public;
            if public.attestation.transport_public_key != mine {
                if seq == pending {
                    return Err(Error::Unattested);
                }
                continue;
            }
            match self.publish_keys(&public).await {
                Ok(()) => {}
                Err(Error::EpochRollback { pinned, .. }) if seq < pending && pinned <= pending => {}
                Err(error) => {
                    return match self.clear_pending_if_two_source_superseded(pending).await {
                        Ok(true) => Ok(true),
                        Ok(false) => Err(error),
                        Err(verification_error) => Err(verification_error),
                    };
                }
            }
        }
        self.pending_directory_publication = None;
        if let Err(error) = self.checkpoint_state() {
            self.pending_directory_publication = Some(pending);
            return Err(error);
        }
        Ok(true)
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

    /// Durably mark and publish the newest epoch again. This is the retry
    /// after a partial PDS/DS publication; it never clears the marker until
    /// every configured destination succeeds.
    pub async fn publish_latest_keys(&mut self) -> Result<()> {
        self.mark_directory_publication_pending()?;
        self.retry_pending_directory_publication().await.map(|_| ())
    }

    /// Publishing an inclusive head after a locally decided revocation
    /// would advertise unsafe keys even though new encryption is blocked.
    /// Re-audit the cached latest epoch and include invalid/omitted rows for
    /// keys this client already knows were members.
    async fn ensure_latest_revocation_safe(&self) -> Result<()> {
        let all_revoked = self.all_revoked_keys();
        if all_revoked.is_empty() {
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
            .any(|key| all_revoked.contains(&key));
        let omitted_verified_revoked = self.verified.0 == epoch.seq
            && self.verified.1.iter().any(|key| all_revoked.contains(key));
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
        self.flush_cache.clear();
        // Publication failure is separately durable; callers with a status
        // surface retry it explicitly, while core sync may still reach a
        // safely verifiable mailbox chain.
        let _ = self.retry_pending_directory_publication().await;
        let opener_revoked = self.all_revoked_keys();
        self.sync_epochs_inner(&BTreeMap::new(), &opener_revoked)
            .await
    }

    /// Sync for archiving and roster resolution: permits uncommitted pending
    /// revocations only up to the epoch at which each pending revocation was
    /// decided locally, while refusing any epoch opened by a revoked/pending
    /// device and any newer epoch that re-admits a pending or revoked device.
    pub(super) async fn sync_epochs_for_archive(&mut self) -> Result<SyncReport> {
        let _ = self.retry_pending_directory_publication().await;
        let allowed_pending = self.pending_revocations.clone();
        let opener_revoked = self.all_revoked_keys();
        self.sync_epochs_inner(&allowed_pending, &opener_revoked)
            .await
    }

    async fn sync_epochs_inner(
        &mut self,
        allowed_pending_until: &BTreeMap<[u8; 32], u64>,
        opener_revoked: &BTreeSet<[u8; 32]>,
    ) -> Result<SyncReport> {
        let from = self.latest;
        let start = self
            .epochs
            .get(&from)
            .cloned()
            .ok_or(Error::NotFound("epoch"))?;
        let reached = chain_forward(
            self.b.mailbox.as_ref(),
            &self.did,
            start,
            self.device.public(),
            &self.device.storage,
            opener_revoked,
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
        let all_revoked = self.all_revoked_keys();
        let mut discovered_revocations = BTreeSet::new();
        let mut latest_audit = None;
        for epoch in &reached {
            let (_, rec) = epoch_record(self.b.mailbox.as_ref(), epoch.seq).await?;
            rec.verify_revocations(&self.did)?;
            discovered_revocations.extend(rec.revocations.iter().map(|k| k.0));
            let audit = self.audit_epoch(epoch).await?;
            let is_disallowed_revoked = |key: &[u8; 32]| {
                if self.revoked.contains(key) {
                    return true;
                }
                if self.pending_revocations.contains_key(key) {
                    return allowed_pending_until
                        .get(key)
                        .is_none_or(|&max_seq| epoch.seq > max_seq);
                }
                false
            };
            let served_revoked = confirmed_epoch_member_keys(&audit)
                .map(|member| member.0)
                .chain(
                    audit
                        .excluded
                        .iter()
                        .filter_map(|member| member.device_key.map(|key| key.0)),
                )
                .any(|key| is_disallowed_revoked(&key));
            let omitted_verified_revoked =
                self.verified.0 == epoch.seq && self.verified.1.iter().any(is_disallowed_revoked);
            if served_revoked || omitted_verified_revoked {
                return Err(Error::EpochSquatted {
                    seq: epoch.seq,
                    reason: "it re-admits a device this client revoked",
                });
            }
            self.check_not_tampered(epoch.seq, &audit)?;
            audit.verify_members_hash(epoch.seq, &rec.public)?;
            latest_audit = Some(audit);
        }
        let audit = latest_audit.expect("chain contains its start");
        let active_in_latest: BTreeSet<[u8; 32]> =
            confirmed_epoch_member_keys(&audit).map(|k| k.0).collect();
        let readmitted = active_in_latest
            .iter()
            .filter(|k| all_revoked.contains(*k))
            .copied()
            .map(XVerifyingKey)
            .collect::<Vec<_>>();

        let to = latest.seq;
        let mut state_mutated = to != from;
        for k in discovered_revocations {
            self.pending_revocations.remove(&k);
            if self.revoked.insert(k) {
                state_mutated = true;
            }
        }
        if to > from {
            let promoted: Vec<[u8; 32]> = self
                .pending_revocations
                .keys()
                .filter(|k| !active_in_latest.contains(*k))
                .copied()
                .collect();
            for k in promoted {
                self.pending_revocations.remove(&k);
                self.revoked.insert(k);
                state_mutated = true;
            }
        }
        for e in reached {
            self.epochs.insert(e.seq, e);
        }
        self.latest = to;
        self.adopted(latest_public);
        self.remember_verified(to, audit.valid.iter().map(|v| v.record.device_key_pub.0));
        if state_mutated {
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

        let all_revoked = self.all_revoked_keys();
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
                &all_revoked,
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
                    let (_, rec) = epoch_record(self.b.mailbox.as_ref(), next_epoch.seq).await?;
                    rec.verify_revocations(&self.did)?;
                    let audit = self.audit_epoch(&next_epoch).await?;
                    let served_revoked = confirmed_epoch_member_keys(&audit)
                        .map(|m| m.0)
                        .chain(
                            audit
                                .excluded
                                .iter()
                                .filter_map(|m| m.device_key.map(|k| k.0)),
                        )
                        .any(|k| all_revoked.contains(&k));
                    if served_revoked {
                        return Err(Error::EpochSquatted {
                            seq: next_epoch.seq,
                            reason: "it re-admits a device this client revoked",
                        });
                    }
                    self.check_not_tampered(next_epoch.seq, &audit)?;
                    audit.verify_members_hash(next_epoch.seq, &rec.public)?;
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
            &all_revoked,
        )
        .await?
        {
            StepOutcome::Absent => return Ok(false),
            StepOutcome::Valid(next_epoch) => {
                let (_, rec) = epoch_record(self.b.mailbox.as_ref(), next_epoch.seq).await?;
                rec.verify_revocations(&self.did)?;
                let audit = self.audit_epoch(&next_epoch).await?;
                audit.verify_members_hash(next_epoch.seq, &rec.public)?;
                let served_revoked = confirmed_epoch_member_keys(&audit)
                    .map(|m| m.0)
                    .chain(
                        audit
                            .excluded
                            .iter()
                            .filter_map(|m| m.device_key.map(|k| k.0)),
                    )
                    .any(|k| all_revoked.contains(&k));
                if !served_revoked {
                    self.sync_epochs().await?;
                    return Ok(false);
                }
                ensure_seq_unanchored_in_directory(
                    self.b.directory.as_ref(),
                    &self.did,
                    seq,
                    self.latest,
                )
                .await?;
                return Err(Error::EpochSquatted {
                    seq,
                    reason: "it re-admits a device this client revoked",
                });
            }
            StepOutcome::Squatted { .. } => {}
        }

        // Refuse deletion only if this device's own record carries a valid
        // signed revocation from an attested physical device of the account.
        if let Ok(Some(my_dev)) = self
            .b
            .mailbox
            .get_device(&self.device.public().device_key_pub)
            .await
            && my_dev.revoked_at.is_some()
        {
            let all_devices = self.b.mailbox.list_devices().await?;
            let known_transport: BTreeSet<[u8; 32]> = self
                .b
                .directory
                .device_transport_keys(&self.did)
                .await?
                .into_iter()
                .map(|k| k.key)
                .collect();
            let valid_revokers =
                super::members::valid_revoker_keys(&self.did, &all_devices, &known_transport);
            if matches!(
                super::members::check_signed_revocation(
                    &self.did,
                    &my_dev,
                    &self.device.public().device_key_pub,
                    &valid_revokers,
                ),
                Ok(true)
            ) {
                return Err(Error::NotEpochMember);
            }
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
            &all_revoked,
        )
        .await?
        {
            StepOutcome::Absent => return Ok(false),
            StepOutcome::Valid(next_epoch) => {
                let (_, rec) = epoch_record(self.b.mailbox.as_ref(), next_epoch.seq).await?;
                rec.verify_revocations(&self.did)?;
                let audit = self.audit_epoch(&next_epoch).await?;
                audit.verify_members_hash(next_epoch.seq, &rec.public)?;
                let served_revoked = confirmed_epoch_member_keys(&audit)
                    .map(|m| m.0)
                    .chain(
                        audit
                            .excluded
                            .iter()
                            .filter_map(|m| m.device_key.map(|k| k.0)),
                    )
                    .any(|k| all_revoked.contains(&k));
                if !served_revoked {
                    self.sync_epochs().await?;
                    return Ok(false);
                }
                return Err(Error::EpochSquatted {
                    seq,
                    reason: "it re-admits a device this client revoked",
                });
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
    /// mark it revoked in the store with a signed [`DeviceRevocation`], then
    /// open a new epoch that carries over every other unrevoked member
    /// ([CB-11], [CB-25]), re-keys recovery methods on physical revocation,
    /// and publishes its keys.
    ///
    /// If the new epoch is written to the mailbox store but directory
    /// publication fails, returns [`Error::EpochUnanchored`] while retaining
    /// the completed [`RotationReport`] via
    /// [`last_unanchored_rotation`](Self::last_unanchored_rotation).
    pub async fn revoke_device(&mut self, target: &XVerifyingKey) -> Result<RotationReport> {
        match self.revoke_device_with_report(target).await? {
            (report, None) => {
                self.last_unanchored_rotation = None;
                Ok(report)
            }
            (report, Some(err)) => {
                let seq = report.new_epoch;
                self.last_unanchored_rotation = Some(report);
                Err(Error::EpochUnanchored {
                    seq,
                    reason: err.to_string(),
                })
            }
        }
    }

    /// [`revoke_device`](Self::revoke_device), returning `(report, Some(err))`
    /// instead of [`Error::EpochUnanchored`] when the mailbox rotation succeeded
    /// and only directory publication remained pending.
    pub async fn revoke_device_with_report(
        &mut self,
        target: &XVerifyingKey,
    ) -> Result<(RotationReport, Option<Error>)> {
        if *target == self.device.public().device_key_pub {
            return Err(Error::Malformed("a device cannot revoke itself"));
        }
        if self.outbox.values().any(|items| !items.is_empty())
            || self.owner_outbox.values().any(|items| !items.is_empty())
        {
            return Err(Error::PendingWrites);
        }
        self.flush_cache.clear();
        let already_known =
            self.pending_revocations.contains_key(&target.0) || self.revoked.contains(&target.0);
        if !already_known {
            // Allow catching up through epochs already anchored in the directory
            // before this local revocation decision, while refusing any
            // unanchored Space-only race opened by `target` or any previously
            // revoked/pending key.
            let pre_existing_revoked = self.all_revoked_keys();
            let published_seq = match self.b.directory.latest(&self.did).await {
                Ok(Some(pub_e)) if pub_e.verify(&self.did, None).is_ok() => pub_e.seq,
                _ => self.latest,
            };
            let max_decision_seq = self.latest.max(published_seq);
            self.pending_revocations.insert(target.0, max_decision_seq);
            self.checkpoint_state()?;
            let mut allowed_pending = self.pending_revocations.clone();
            allowed_pending.insert(target.0, max_decision_seq);
            // Check that no epoch above `published_seq` in the mailbox was opened by `target`.
            if let Ok(Some(unanchored_next)) = self
                .b
                .mailbox
                .get_epoch(max_decision_seq.saturating_add(1))
                .await
                && let Ok(rec) = unanchored_next.value.to_record()
                && rec.opened_by == *target
            {
                return Err(Error::EpochSquatted {
                    seq: max_decision_seq.saturating_add(1),
                    reason: "it was opened by a device this client revoked",
                });
            }
            self.sync_epochs_inner(&allowed_pending, &pre_existing_revoked)
                .await?;
            if self.pending_revocations.contains_key(&target.0) {
                self.pending_revocations.insert(target.0, self.latest);
                self.checkpoint_state()?;
            }
        } else {
            let allowed_pending = self.pending_revocations.clone();
            let opener_revoked = self.all_revoked_keys();
            self.sync_epochs_inner(&allowed_pending, &opener_revoked)
                .await?;
        }

        let now = self.now();
        let mut to_stamp: BTreeSet<[u8; 32]> = self.pending_revocations.keys().copied().collect();
        to_stamp.insert(target.0);
        let mut rekey_virtual_methods = false;
        for key_bytes in &to_stamp {
            let key = XVerifyingKey(*key_bytes);
            let is_virtual = self
                .b
                .mailbox
                .get_device(&key)
                .await?
                .and_then(|d| d.to_public().ok())
                .is_some_and(|p| p.is_virtual);
            if !is_virtual {
                rekey_virtual_methods = true;
            }
            let rev = DeviceRevocation::sign(&self.did, &key, &now, &self.device.device_key)?;
            let rev_def = crate::records::DeviceRevocationDef::from_revocation(&rev);
            self.b
                .mailbox
                .set_device_revocation(&key, &now, &rev_def)
                .await?;
        }

        for _ in 0..ROTATE_ATTEMPTS {
            let exclude = self.all_revoked_keys();
            match self
                .rotate_inner(&exclude, Some(*target), rekey_virtual_methods)
                .await
            {
                Err(Error::Conflict) => {
                    let opener_revoked = self.all_revoked_keys();
                    let published_seq = match self.b.directory.latest(&self.did).await {
                        Ok(Some(pub_e)) if pub_e.verify(&self.did, None).is_ok() => pub_e.seq,
                        _ => self.latest,
                    };
                    let max_allowed_seq = self.latest.max(published_seq);
                    let mut allowed_pending = self.pending_revocations.clone();
                    for val in allowed_pending.values_mut() {
                        *val = (*val).max(max_allowed_seq);
                    }
                    self.sync_epochs_inner(&allowed_pending, &opener_revoked)
                        .await?;
                    let cur = self.latest;
                    for val in self.pending_revocations.values_mut() {
                        *val = cur;
                    }
                    self.checkpoint_state()?;
                }
                Ok(outcome) => return Ok(outcome),
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict)
    }

    /// Report from the most recent rotation whose mailbox write committed while
    /// directory publication remained pending.
    pub fn last_unanchored_rotation(&self) -> Option<&RotationReport> {
        self.last_unanchored_rotation.as_ref()
    }

    /// Cancel an uncommitted local revocation decision before its rotation
    /// completes. Returns `Ok(true)` if `target` was pending and removed, or
    /// `Ok(false)` if `target` was not pending (including if already rotated out).
    pub fn cancel_pending_revocation(&mut self, target: &XVerifyingKey) -> Result<bool> {
        let Some(prev_seq) = self.pending_revocations.remove(&target.0) else {
            return Ok(false);
        };
        if let Err(err) = self.checkpoint_state() {
            self.pending_revocations.insert(target.0, prev_seq);
            return Err(err);
        }
        Ok(true)
    }

    /// Devices whose revocation rotation has not yet committed.
    pub fn pending_revocation_devices(&self) -> impl Iterator<Item = XVerifyingKey> + '_ {
        self.pending_revocations.keys().copied().map(XVerifyingKey)
    }

    /// Devices this client has revoked (committed or pending). Part of the
    /// persisted client state ([`Labyrinth::export_state`]).
    pub fn revoked_devices(&self) -> impl Iterator<Item = XVerifyingKey> + '_ {
        self.all_revoked_keys().into_iter().map(XVerifyingKey)
    }

    /// Recover from losing an unanchored directory publication race: if this
    /// client holds an unanchored local tip `self.latest` (`pending_directory_publication == Some(self.latest)`)
    /// and the directory independently anchors a competing chain from `self.latest - 1`,
    /// roll back the unanchored local tip, adopt the anchored chain, and
    /// immediately rotate to evict any locally revoked device still present on
    /// the anchored chain.
    pub async fn recover_unanchored_fork(&mut self) -> Result<Option<RotationReport>> {
        let Some(pending) = self.pending_directory_publication else {
            return Ok(None);
        };
        if pending != self.latest || pending == 0 {
            return Ok(None);
        }
        let anchored = match self.b.directory.latest_two_source(&self.did).await? {
            Some(a) => Some(a),
            None => self.b.directory.latest(&self.did).await?,
        };
        let Some(anchored) = anchored else {
            return Ok(None);
        };
        anchored.verify(&self.did, None)?;
        check_own_attester(self.b.directory.as_ref(), &self.did, &anchored).await?;
        if anchored.seq < pending {
            return Ok(None);
        }
        let my_pending_head = self.latest_public().ok().map(|p| p.head);
        if anchored.seq == pending && my_pending_head == Some(anchored.head) {
            let _ = self.retry_pending_directory_publication().await?;
            return Ok(None);
        }

        let base_seq = pending - 1;
        let base_secret = self.epoch_secret(base_seq).await?;
        let (_, base_rec) = epoch_record(self.b.mailbox.as_ref(), base_seq).await?;
        verify_public(&base_secret, &base_rec.public)?;

        // Verify the mailbox holds a continuous chain from `base_seq` to `anchored.head`.
        let mut cursor_pub = base_rec.public.clone();
        for seq in pending..=anchored.seq {
            let (_, next_rec) = epoch_record(self.b.mailbox.as_ref(), seq).await?;
            next_rec.public.verify(&self.did, Some(&cursor_pub))?;
            next_rec.verify_revocations(&self.did)?;
            cursor_pub = next_rec.public;
        }
        if cursor_pub.head != anchored.head {
            return Err(Error::Malformed(
                "anchored directory head does not match mailbox chain",
            ));
        }

        let must_evict = self.all_revoked_keys();
        let saved_epochs = self.epochs.clone();
        let saved_latest = self.latest;
        let saved_own = self.own_latest.clone();
        let saved_attester = self.own_attester_checked;
        let saved_pending_pub = self.pending_directory_publication;
        let saved_verified = self.verified.clone();
        let saved_revoked = self.revoked.clone();
        let saved_pending_rev = self.pending_revocations.clone();

        let adopt_res: Result<(Audit, BTreeSet<[u8; 32]>)> = async {
            self.epochs.retain(|&seq, _| seq <= base_seq);
            self.latest = base_seq;
            self.own_latest = Some(base_rec.public.clone());
            self.own_attester_checked = true;
            self.pending_directory_publication = None;
            self.verified = (base_seq, BTreeSet::new());

            let reached = chain_forward(
                self.b.mailbox.as_ref(),
                &self.did,
                base_secret,
                self.device.public(),
                &self.device.storage,
                &BTreeSet::new(),
            )
            .await?;
            let tip = reached.last().expect("non-empty");
            if tip.seq < anchored.seq {
                return Err(Error::EpochTruncated {
                    published: anchored.seq,
                    reached: tip.seq,
                });
            }
            let mut chain_revoked = BTreeSet::new();
            let mut latest_audit = None;
            for ep in &reached {
                let (_, rec) = epoch_record(self.b.mailbox.as_ref(), ep.seq).await?;
                rec.verify_revocations(&self.did)?;
                chain_revoked.extend(rec.revocations.iter().map(|k| k.0));
                let audit = self.audit_epoch(ep).await?;
                audit.verify_members_hash(ep.seq, &rec.public)?;
                latest_audit = Some(audit);
            }
            let tip_pub = verified_own(
                self.b.mailbox.as_ref(),
                self.b.directory.as_ref(),
                &self.did,
                tip,
            )
            .await?;
            check_candidate_integrity(
                self.b.mailbox.as_ref(),
                self.b.directory.as_ref(),
                &self.did,
                tip.seq,
                &tip_pub.head,
            )
            .await?;
            let audit = latest_audit.expect("non-empty");
            let to = tip.seq;
            for e in reached {
                self.epochs.insert(e.seq, e);
            }
            self.latest = to;
            self.adopted(tip_pub);
            self.remember_verified(to, audit.valid.iter().map(|v| v.record.device_key_pub.0));
            Ok((audit, chain_revoked))
        }
        .await;

        let (audit, chain_revoked) = match adopt_res {
            Ok(v) => v,
            Err(err) => {
                self.epochs = saved_epochs;
                self.latest = saved_latest;
                self.own_latest = saved_own;
                self.own_attester_checked = saved_attester;
                self.pending_directory_publication = saved_pending_pub;
                self.verified = saved_verified;
                self.revoked = saved_revoked;
                self.pending_revocations = saved_pending_rev;
                return Err(err);
            }
        };

        for k in chain_revoked {
            self.pending_revocations.remove(&k);
            self.revoked.insert(k);
        }

        let active_in_tip: BTreeSet<[u8; 32]> =
            confirmed_epoch_member_keys(&audit).map(|k| k.0).collect();
        let still_present: Vec<XVerifyingKey> = must_evict
            .iter()
            .filter(|k| active_in_tip.contains(*k))
            .copied()
            .map(XVerifyingKey)
            .collect();
        if still_present.is_empty() {
            for k in must_evict {
                self.pending_revocations.remove(&k);
                self.revoked.insert(k);
            }
            self.flush_cache.clear();
            self.checkpoint_state()?;
            return Ok(None);
        }

        // At least one locally revoked device is still active on the winning
        // anchored fork: stamp signed revocations and rotate immediately!
        for k in &still_present {
            self.revoked.remove(&k.0);
            self.pending_revocations.insert(k.0, self.latest);
        }
        let now = self.now();
        let mut rekey_virtual_methods = false;
        for k in &still_present {
            let is_virtual = self
                .b
                .mailbox
                .get_device(k)
                .await?
                .and_then(|d| d.to_public().ok())
                .is_some_and(|p| p.is_virtual);
            if !is_virtual {
                rekey_virtual_methods = true;
            }
            let rev = DeviceRevocation::sign(&self.did, k, &now, &self.device.device_key)?;
            let rev_def = crate::records::DeviceRevocationDef::from_revocation(&rev);
            self.b
                .mailbox
                .set_device_revocation(k, &now, &rev_def)
                .await?;
        }
        let exclude = self.all_revoked_keys();
        let primary = still_present.first().copied();
        let (report, unfinished) = self
            .rotate_inner(&exclude, primary, rekey_virtual_methods)
            .await?;
        if let Some(err) = unfinished {
            let seq = report.new_epoch;
            self.last_unanchored_rotation = Some(report);
            return Err(Error::EpochUnanchored {
                seq,
                reason: err.to_string(),
            });
        }
        self.last_unanchored_rotation = None;
        Ok(Some(report))
    }

    /// Rotate the mailbox to the next epoch while carrying over unrevoked
    /// members, and report every member the rotation dropped.
    pub async fn rotate_epoch(&mut self) -> Result<RotationReport> {
        if self.outbox.values().any(|items| !items.is_empty())
            || self.owner_outbox.values().any(|items| !items.is_empty())
        {
            return Err(Error::PendingWrites);
        }
        self.flush_cache.clear();
        self.sync_epochs().await?;
        for _ in 0..ROTATE_ATTEMPTS {
            let exclude = self.all_revoked_keys();
            match self.rotate_inner(&exclude, None, false).await {
                Err(Error::Conflict) => {
                    let opener_revoked = self.all_revoked_keys();
                    let published_seq = match self.b.directory.latest(&self.did).await {
                        Ok(Some(pub_e)) if pub_e.verify(&self.did, None).is_ok() => pub_e.seq,
                        _ => self.latest,
                    };
                    let max_allowed_seq = self.latest.max(published_seq);
                    let mut allowed_pending = self.pending_revocations.clone();
                    for val in allowed_pending.values_mut() {
                        *val = (*val).max(max_allowed_seq);
                    }
                    self.sync_epochs_inner(&allowed_pending, &opener_revoked)
                        .await?;
                    let cur = self.latest;
                    for val in self.pending_revocations.values_mut() {
                        *val = cur;
                    }
                    self.checkpoint_state()?;
                }
                Ok((report, None)) => return Ok(report),
                Ok((report, Some(err))) => {
                    self.last_unanchored_rotation = Some(report);
                    return Err(err);
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::Conflict)
    }

    /// [CB-39] Virtual devices of automatically stored recovery bundles
    /// (keychain, passkey) unused past their TTL. A bundle that does not
    /// parse opens nothing and never blocks a rotation.
    async fn expired_recovery_devices(&self) -> Result<BTreeSet<[u8; 32]>> {
        let now = self.b.clock.now_ms();
        let mut expired = BTreeSet::new();
        for entry in self.b.mailbox.list_virtual_device_records().await? {
            let Ok(vdev) = entry else { continue };
            let Ok((record, _)) = vdev.to_bundle_for_did(&self.did) else {
                continue;
            };
            if super::enroll::vdevice_stale_at_ms(record.mechanism, &vdev, now)
                .ok()
                .flatten()
                .is_some_and(|stale_at| now >= stale_at)
            {
                expired.insert(record.public.device_key_pub.0);
            }
        }
        Ok(expired)
    }

    /// Open the epoch after `self.latest`, carrying over every member of
    /// the previous epoch except this device (the opener is added by
    /// [`open_next_with_additions`]), the devices in `exclude`, devices the
    /// store reports as validly revoked, and expired recovery bundles ([CB-39]).
    async fn rotate_inner(
        &mut self,
        exclude: &BTreeSet<[u8; 32]>,
        primary_revoked: Option<XVerifyingKey>,
        rekey_virtual_methods: bool,
    ) -> Result<(RotationReport, Option<Error>)> {
        let prev = self.epoch_secret(self.latest).await?;
        let mine = self.transport.transport_public_key();
        let current = self.b.directory.device_transport_keys(&self.did).await?;
        if !current.iter().any(|k| k.is_current() && k.key == mine) {
            // Without our own chat device the directory view is wrong (or
            // we were removed); a rotation would drop every sibling.
            return Err(Error::Unattested);
        }
        let mb = self.b.mailbox.as_ref();
        let (_, prev_record) = epoch_record(mb, prev.seq).await?;
        prev_record.verify_revocations(&self.did)?;
        let audit = self.audit_epoch(&prev).await?;
        self.check_not_tampered(prev.seq, &audit)?;
        audit.verify_members_hash(prev.seq, &prev_record.public)?;
        if audit.excluded.iter().any(|x| {
            x.reason == ExclusionReason::UnsignedRevocation
                && x.device_key.is_none_or(|k| !exclude.contains(&k.0))
        }) {
            return Err(Error::DeviceTampered);
        }
        let expired = self.expired_recovery_devices().await?;
        let me = self.device.public().device_key_pub;
        let now = self.now();

        let mut invalidated_recovery_methods = Vec::new();
        let mut invalidated_vkeys = BTreeSet::new();
        if rekey_virtual_methods {
            for v in &audit.valid {
                let k = v.record.device_key_pub;
                if v.public.is_virtual
                    && k != me
                    && !exclude.contains(&k.0)
                    && !v.revoked
                    && !expired.contains(&k.0)
                {
                    let (vdevice_id, mechanism) = v
                        .vdevice_meta
                        .ok_or(Error::Malformed("virtual member missing bundle metadata"))?;
                    invalidated_vkeys.insert(k.0);
                    invalidated_recovery_methods.push(InvalidatedRecoveryMethod {
                        vdevice_id,
                        mechanism,
                        device_key: k,
                    });
                }
            }
        }

        let mut replacement_vdev: Option<(RecoveryCode, DeviceSecrets)> = None;
        let mut added_virtual_pubs = Vec::new();
        if !invalidated_recovery_methods.is_empty() {
            let new_code = RecoveryCode::generate()?;
            let new_vsecrets = DeviceSecrets::generate_virtual()?;
            added_virtual_pubs.push(new_vsecrets.public().clone());
            replacement_vdev = Some((new_code, new_vsecrets));
        }

        let mut cumulative_revoked: BTreeSet<[u8; 32]> =
            prev_record.revocations.iter().map(|k| k.0).collect();
        cumulative_revoked.extend(exclude.iter().copied());
        cumulative_revoked.extend(invalidated_vkeys.iter().copied());

        let mut evicted_set = BTreeSet::new();
        for v in &audit.valid {
            let k = v.record.device_key_pub;
            if k != me
                && (exclude.contains(&k.0)
                    || v.revoked
                    || cumulative_revoked.contains(&k.0)
                    || invalidated_vkeys.contains(&k.0))
            {
                cumulative_revoked.insert(k.0);
                if Some(k) != primary_revoked {
                    evicted_set.insert(k.0);
                }
            }
        }
        for &k in exclude {
            if Some(XVerifyingKey(k)) != primary_revoked {
                evicted_set.insert(k);
            }
        }

        let carried = |v: &&super::members::ValidMember| {
            let k = v.record.device_key_pub;
            k != me
                && !exclude.contains(&k.0)
                && !v.revoked
                && !cumulative_revoked.contains(&k.0)
                && !invalidated_vkeys.contains(&k.0)
        };
        let continuing: Vec<DevicePublic> = audit
            .valid
            .iter()
            .filter(carried)
            .filter(|v| !expired.contains(&v.record.device_key_pub.0))
            .map(|v| v.public.clone())
            .collect();
        let expired_members: Vec<ExcludedMember> = audit
            .valid
            .iter()
            .filter(carried)
            .filter(|v| expired.contains(&v.record.device_key_pub.0))
            .map(|v| ExcludedMember {
                device_key: Some(v.record.device_key_pub),
                reason: ExclusionReason::RecoveryExpired,
            })
            .collect();
        let prev_members: Vec<EpochMemberRecord> =
            audit.valid.iter().map(|v| v.record.clone()).collect();
        let (pending, mut new) = open_next_with_additions(
            &self.did,
            &prev,
            &prev_record.public,
            &prev_members,
            &continuing,
            &added_virtual_pubs,
            &self.device,
            self.transport.as_ref(),
        )?;
        if !cumulative_revoked.is_empty() {
            new.record.sign_revocations(
                &self.did,
                &self.device.device_key,
                cumulative_revoked.iter().copied().map(XVerifyingKey),
            )?;
        }
        if new.members.iter().any(|m| {
            exclude.contains(&m.device_key_pub.0) || invalidated_vkeys.contains(&m.device_key_pub.0)
        }) {
            return Err(Error::Malformed("rotation would re-admit a revoked device"));
        }

        let prepared_replacement = if let Some((new_code, new_vsecrets)) = replacement_vdev {
            let vrec = virtual_device::seal_virtual_device(
                &self.did,
                &new_code,
                &new_vsecrets,
                &pending,
                Mechanism::Code,
                Some(now.as_str()),
            )?;
            let bundle = VirtualDevice::from_bundle(&vrec, None, now.clone());
            mb.create_device(&Device::from_public(new_vsecrets.public(), now.clone()))
                .await?;
            mb.create_virtual_device(&bundle).await?;
            Some((vrec.vdevice_id, new_code))
        } else {
            None
        };
        let members: Vec<_> = new
            .members
            .iter()
            .map(|m| EpochMember::from_record(m, now.clone()))
            .collect();
        let epoch = Epoch::from_record(&new.record, now.clone());
        let id = match create_epoch_reconciled(mb, &epoch, &members).await {
            Ok(id) => id,
            Err(err) => {
                if let Some((ref vdevice_id, _)) = prepared_replacement {
                    let _ = mb.delete_virtual_device(vdevice_id).await;
                }
                return Err(err);
            }
        };
        let e = pending.assign_id(id);

        for k in cumulative_revoked {
            self.pending_revocations.remove(&k);
            self.revoked.insert(k);
        }
        self.latest = e.seq;
        self.epochs.insert(e.seq, e);
        // Made here, so it needs no checking.
        self.adopted(new.record.public.clone());
        self.remember_verified(self.latest, new.members.iter().map(|m| m.device_key_pub.0));
        self.pending_directory_publication = Some(self.latest);
        self.flush_cache.clear();
        self.checkpoint_state()?;

        for inv in &invalidated_recovery_methods {
            if let Ok(rev) =
                DeviceRevocation::sign(&self.did, &inv.device_key, &now, &self.device.device_key)
            {
                let rev_def = crate::records::DeviceRevocationDef::from_revocation(&rev);
                let _ = self
                    .b
                    .mailbox
                    .set_device_revocation(&inv.device_key, &now, &rev_def)
                    .await;
            }
            let _ = self.b.mailbox.delete_virtual_device(&inv.vdevice_id).await;
        }

        let rekeyed_recovery =
            prepared_replacement.map(|(vdevice_id, code)| RecoverySetup { vdevice_id, code });
        let unfinished = self.retry_pending_directory_publication().await.err();
        let excluded = audit
            .excluded
            .into_iter()
            .filter(|x| x.device_key.is_none_or(|k| !exclude.contains(&k.0)))
            .chain(expired_members)
            .collect();
        let evicted_revoked = evicted_set.into_iter().map(XVerifyingKey).collect();
        Ok((
            RotationReport {
                new_epoch: self.latest,
                revoked: primary_revoked,
                evicted_revoked,
                excluded,
                invalidated_recovery_methods,
                rekeyed_recovery,
            },
            unfinished,
        ))
    }
}

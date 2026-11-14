//! Membership audit ([CB-25] as amended, [CB-36]): which members of an
//! epoch a rotation may carry over, and which it must drop and report.
//!
//! The attack this answers (gap audit G-P0-2): any chat device of the DID
//! can write a bogus `epochMember` (or `device`) row. If an invalid row
//! aborted rotation, one planted row would block every revocation
//! forever; if it were dropped silently, a store could evict a real
//! device unannounced. So an invalid member is **excluded and reported**
//! ([`ExcludedMember`] in [`super::RotationReport`] and
//! [`super::SyncReport`]), never silent, with one exception: a member this
//! client already verified in the same epoch that now fails verification
//! means the store rewrote a record it had served intact, and rotation
//! aborts with [`Error::MemberTampered`].
//!
//! A physical member must also carry a [`ChatBinding`] by a *current*
//! chat device of the DID ([CB-36]), so revoking a chat device drops its
//! Labyrinth device at the next rotation.

use std::collections::{BTreeMap, BTreeSet};

use super::Labyrinth;
use crate::device::DevicePublic;
use crate::epoch::{EpochMemberRecord, EpochSecret, verify_member};
use crate::mailbox::EpochPublic;
use crate::records::{Device, VirtualDevice, ms_from_datetime};
use crate::sign::XVerifyingKey;
use crate::store::{MailboxDirectory, MailboxStore};
use crate::virtual_device::{Mechanism, VirtualDeviceRecord};
use crate::{Error, Result};

/// Why a member was left out of a rotation or flagged by an audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExclusionReason {
    /// The `epochMember` record does not parse.
    MalformedMember,
    /// The member names a device with no `device` record.
    MissingDeviceRecord,
    /// The `device` record does not parse or its `0x30`/`0x31`
    /// signatures fail.
    InvalidDeviceRecord,
    /// The member's MAC does not verify under the epoch's MAC key.
    InvalidMac,
    /// A physical device with no [CB-36] chat binding, or one whose
    /// signature fails.
    Unbound,
    /// The binding names a chat device that is no longer current.
    ChatDeviceNotCurrent,
    /// A virtual member has no matching `virtualDevice` recovery bundle.
    MissingRecoveryBundle,
    /// A virtual member's `virtualDevice` recovery bundle is malformed,
    /// has an invalid signature/shape, or disagrees with its `device` record.
    InvalidRecoveryBundle,
    /// A `device` record carries `revokedAt` without a valid revocation
    /// signature from a bound physical device of the account.
    UnsignedRevocation,
    /// An automatically stored recovery bundle (keychain, passkey) unused
    /// past its TTL ([CB-39]); rotation drops its virtual device.
    RecoveryExpired,
}

/// A member left out of a rotation (or flagged by an audit), loudly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExcludedMember {
    /// `None` when the member record is too malformed to name a key.
    pub device_key: Option<XVerifyingKey>,
    pub reason: ExclusionReason,
}

/// A member that passed every check.
pub(super) struct ValidMember {
    pub record: EpochMemberRecord,
    pub public: DevicePublic,
    pub revoked: bool,
    pub vdevice_meta: Option<([u8; 16], Mechanism)>,
}

/// Result of auditing one epoch's member list.
pub(super) struct Audit {
    pub valid: Vec<ValidMember>,
    pub excluded: Vec<ExcludedMember>,
    pub initial_publics: Vec<DevicePublic>,
}

impl Audit {
    /// Verifies that the cryptographically valid initial members of `seq`
    /// match `public.members_hash`.
    pub(super) fn verify_members_hash(&self, seq: u64, public: &EpochPublic) -> Result<()> {
        public
            .verify_members(&self.initial_publics)
            .map_err(|_| Error::MemberTampered { seq })
    }
}

pub(super) fn valid_revoker_keys(
    did: &str,
    devices: &[Device],
    known_transport_keys: &BTreeSet<[u8; 32]>,
) -> BTreeSet<[u8; 32]> {
    let mut out = BTreeSet::new();
    for d in devices {
        if d.r#virtual {
            continue;
        }
        let Ok(public) = d.to_public() else { continue };
        if public.is_virtual || public.verify().is_err() {
            continue;
        }
        let bound = d
            .chat_binding()
            .ok()
            .flatten()
            .filter(|b| known_transport_keys.contains(&b.transport_public_key))
            .is_some_and(|b| b.verify(did, &public.device_key_pub).is_ok());
        if bound {
            out.insert(public.device_key_pub.0);
        }
    }
    out
}

pub(super) fn check_signed_revocation(
    did: &str,
    device: &Device,
    target_key: &XVerifyingKey,
    valid_revokers: &BTreeSet<[u8; 32]>,
) -> core::result::Result<bool, ExclusionReason> {
    match device.revoked_at.as_deref() {
        None => {
            if device.revocation.is_some() {
                Err(ExclusionReason::UnsignedRevocation)
            } else {
                Ok(false)
            }
        }
        Some(revoked_at) => {
            if ms_from_datetime(revoked_at).is_err() {
                return Err(ExclusionReason::UnsignedRevocation);
            }
            let rev = device
                .revocation()
                .ok()
                .flatten()
                .ok_or(ExclusionReason::UnsignedRevocation)?;
            if !valid_revokers.contains(&rev.revoked_by.0) {
                return Err(ExclusionReason::UnsignedRevocation);
            }
            rev.verify(did, target_key, revoked_at)
                .map(|()| true)
                .map_err(|_| ExclusionReason::UnsignedRevocation)
        }
    }
}

type BundleIndex = (
    BTreeMap<[u8; 32], core::result::Result<VirtualDeviceRecord, ExclusionReason>>,
    bool,
);

type VirtualBundleMeta = Option<([u8; 16], Mechanism)>;
type CheckedMember = (DevicePublic, bool, VirtualBundleMeta);

fn index_virtual_bundles(did: &str, records: Vec<Result<VirtualDevice>>) -> BundleIndex {
    let mut map: BTreeMap<[u8; 32], core::result::Result<VirtualDeviceRecord, ExclusionReason>> =
        BTreeMap::new();
    let mut saw_unkeyed_malformed = false;
    for entry in records {
        let Ok(v) = entry else {
            saw_unkeyed_malformed = true;
            continue;
        };
        let key_opt = v.device_key_pubkey.array::<32>("key").ok();
        match v.to_bundle_for_did(did) {
            Ok((rec, _)) if ms_from_datetime(&v.created_at).is_ok() => {
                let key = rec.public.device_key_pub.0;
                match map.entry(key) {
                    std::collections::btree_map::Entry::Occupied(mut e) => {
                        let _ = e.insert(Err(ExclusionReason::InvalidRecoveryBundle));
                    }
                    std::collections::btree_map::Entry::Vacant(e) => {
                        e.insert(Ok(rec));
                    }
                }
            }
            _ => {
                if let Some(key) = key_opt {
                    map.insert(key, Err(ExclusionReason::InvalidRecoveryBundle));
                } else {
                    saw_unkeyed_malformed = true;
                }
            }
        }
    }
    (map, saw_unkeyed_malformed)
}

#[allow(clippy::too_many_arguments)]
fn check_member_for_did(
    did: &str,
    epoch: &EpochSecret,
    record: &EpochMemberRecord,
    device: Option<&Device>,
    current: &BTreeSet<[u8; 32]>,
    valid_revokers: &BTreeSet<[u8; 32]>,
    bundles: &BTreeMap<[u8; 32], core::result::Result<VirtualDeviceRecord, ExclusionReason>>,
    saw_unkeyed_malformed_bundle: bool,
) -> core::result::Result<CheckedMember, ExclusionReason> {
    let device = device.ok_or(ExclusionReason::MissingDeviceRecord)?;
    let public = device
        .to_public()
        .ok()
        .filter(|p| p.verify().is_ok() && p.device_key_pub == record.device_key_pub)
        .ok_or(ExclusionReason::InvalidDeviceRecord)?;
    verify_member(epoch, record, public.is_virtual).map_err(|_| ExclusionReason::InvalidMac)?;
    let vdevice_meta = if !public.is_virtual {
        let binding = device
            .chat_binding()
            .ok()
            .flatten()
            .filter(|b| b.verify(did, &public.device_key_pub).is_ok())
            .ok_or(ExclusionReason::Unbound)?;
        if !current.contains(&binding.transport_public_key) {
            return Err(ExclusionReason::ChatDeviceNotCurrent);
        }
        None
    } else {
        if device.chat_binding.is_some() {
            return Err(ExclusionReason::InvalidRecoveryBundle);
        }
        match bundles.get(&public.device_key_pub.0) {
            Some(Ok(vrec)) if vrec.public == public => Some((vrec.vdevice_id, vrec.mechanism)),
            Some(Ok(_)) => return Err(ExclusionReason::InvalidRecoveryBundle),
            Some(Err(reason)) => return Err(*reason),
            None if saw_unkeyed_malformed_bundle => {
                return Err(ExclusionReason::InvalidRecoveryBundle);
            }
            None => return Err(ExclusionReason::MissingRecoveryBundle),
        }
    };
    let revoked = check_signed_revocation(did, device, &public.device_key_pub, valid_revokers)?;
    Ok((public, revoked, vdevice_meta))
}

/// Verifies `public.members_hash` directly against the mailbox's initial
/// members of `epoch`.
pub(super) async fn verify_epoch_members_hash(
    mb: &dyn MailboxStore,
    epoch: &EpochSecret,
    public: &EpochPublic,
) -> Result<()> {
    let mut initial_publics = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in mb.list_epoch_members(epoch.seq).await? {
        let Ok(record) = raw.to_record() else {
            continue;
        };
        if !seen.insert(record.device_key_pub.0) {
            continue;
        }
        let Some(dev) = mb.get_device(&record.device_key_pub).await? else {
            continue;
        };
        let Ok(dev_pub) = dev.to_public() else {
            continue;
        };
        if dev_pub.device_key_pub != record.device_key_pub || dev_pub.verify().is_err() {
            continue;
        }
        if verify_member(epoch, &record, dev_pub.is_virtual).is_err() {
            continue;
        }
        let is_initial = if epoch.seq == 0 {
            !dev_pub.is_virtual && record.encrypted_entropy.is_none()
        } else {
            record.encrypted_entropy.is_some()
        };
        if is_initial {
            initial_publics.push(dev_pub);
        }
    }
    public
        .verify_members(&initial_publics)
        .map_err(|_| Error::MemberTampered { seq: epoch.seq })
}

/// Audit the members of `epoch` directly against `mb` and `dir`.
pub(super) async fn audit_epoch_stores(
    mb: &dyn MailboxStore,
    dir: &dyn MailboxDirectory,
    did: &str,
    epoch: &EpochSecret,
) -> Result<Audit> {
    let all_transport = dir.device_transport_keys(did).await?;
    let current: BTreeSet<[u8; 32]> = all_transport
        .iter()
        .filter(|k| k.is_current())
        .map(|k| k.key)
        .collect();
    let known_transport: BTreeSet<[u8; 32]> = all_transport.into_iter().map(|k| k.key).collect();
    let all_devices = mb.list_devices().await?;
    let valid_revokers = valid_revoker_keys(did, &all_devices, &known_transport);
    let (bundles, saw_unkeyed_malformed_bundle) =
        index_virtual_bundles(did, mb.list_virtual_device_records().await?);
    let mut out = Audit {
        valid: Vec::new(),
        excluded: Vec::new(),
        initial_publics: Vec::new(),
    };
    let mut seen = BTreeSet::new();
    for raw in mb.list_epoch_members(epoch.seq).await? {
        let Ok(record) = raw.to_record() else {
            let device_key = raw.device_key_pubkey.array("key").ok().map(XVerifyingKey);
            out.excluded.push(ExcludedMember {
                device_key,
                reason: ExclusionReason::MalformedMember,
            });
            continue;
        };
        if !seen.insert(record.device_key_pub.0) {
            continue;
        }
        let key = record.device_key_pub;
        let device = mb.get_device(&key).await?;
        if let Some(ref dev) = device
            && let Ok(dev_pub) = dev.to_public()
            && dev_pub.device_key_pub == key
            && dev_pub.verify().is_ok()
            && verify_member(epoch, &record, dev_pub.is_virtual).is_ok()
        {
            let is_initial = if epoch.seq == 0 {
                !dev_pub.is_virtual && record.encrypted_entropy.is_none()
            } else {
                record.encrypted_entropy.is_some()
            };
            if is_initial {
                out.initial_publics.push(dev_pub);
            }
        }
        match check_member_for_did(
            did,
            epoch,
            &record,
            device.as_ref(),
            &current,
            &valid_revokers,
            &bundles,
            saw_unkeyed_malformed_bundle,
        ) {
            Ok((public, revoked, vdevice_meta)) => out.valid.push(ValidMember {
                record,
                public,
                revoked,
                vdevice_meta,
            }),
            Err(reason) => out.excluded.push(ExcludedMember {
                device_key: Some(key),
                reason,
            }),
        }
    }
    Ok(out)
}

impl Labyrinth {
    /// Audit the members of epoch `epoch` (held by this device).
    pub(super) async fn audit_epoch(&self, epoch: &EpochSecret) -> Result<Audit> {
        audit_epoch_stores(
            self.b.mailbox.as_ref(),
            self.b.directory.as_ref(),
            &self.did,
            epoch,
        )
        .await
    }

    /// Fails with [`Error::MemberTampered`] if a member this client already
    /// verified in epoch `seq` is among `audit.excluded` for a reason the
    /// store alone could cause (record or MAC failures), or if a non-revoked
    /// verified member vanished from both `audit.valid` and `audit.excluded`
    /// in the same epoch without a rotation. A dropped chat binding is a
    /// legitimate exclusion and passes.
    pub(super) fn check_not_tampered(&self, seq: u64, audit: &Audit) -> Result<()> {
        if self.verified.0 != seq {
            return Ok(());
        }
        let tampered = audit.excluded.iter().any(|x| {
            !matches!(x.reason, ExclusionReason::ChatDeviceNotCurrent)
                && x.device_key.is_some_and(|k| self.verified.1.contains(&k.0))
        });
        let all_revoked = self.all_revoked_keys();
        let omitted = self
            .verified
            .1
            .iter()
            .filter(|k| !all_revoked.contains(*k))
            .any(|k| {
                let in_valid = audit.valid.iter().any(|v| v.record.device_key_pub.0 == *k);
                let in_excluded = audit
                    .excluded
                    .iter()
                    .any(|x| x.device_key.is_some_and(|dk| dk.0 == *k));
                !in_valid && !in_excluded
            });
        if tampered || omitted {
            Err(Error::MemberTampered { seq })
        } else {
            Ok(())
        }
    }

    /// Records the members of epoch `seq` this client has verified.
    pub(super) fn remember_verified(&mut self, seq: u64, keys: impl IntoIterator<Item = [u8; 32]>) {
        if self.verified.0 != seq {
            self.verified = (seq, BTreeSet::new());
        }
        self.verified.1.extend(keys);
    }

    /// Audit the newest epoch this device reached ([CB-25], [CB-36]):
    /// members the next rotation would drop, with the reason. Valid
    /// members are remembered as verified for that epoch.
    pub async fn audit_members(&mut self) -> Result<Vec<ExcludedMember>> {
        let e = self.epoch_secret(self.latest).await?;
        let public = self.latest_public()?;
        let audit = self.audit_epoch(&e).await?;
        audit.verify_members_hash(e.seq, &public)?;
        self.remember_verified(e.seq, audit.valid.iter().map(|v| v.record.device_key_pub.0));
        Ok(audit.excluded)
    }
}

impl Labyrinth {
    /// [CB-36] This account's unrevoked physical Labyrinth devices whose
    /// verified chat binding names `chat_key`: the Labyrinth device(s) a
    /// chat device enrolled. A binding that does not verify is ignored.
    ///
    /// A `revokedAt` stamp skips a device only after a signed revocation has
    /// rotated it out of `self.latest`, preventing a pre-marked `device`
    /// record from bypassing epoch rotation.
    pub async fn devices_bound_to(&self, chat_key: &[u8; 32]) -> Result<Vec<XVerifyingKey>> {
        let all_devices = self.b.mailbox.list_devices().await?;
        let known_transport: BTreeSet<[u8; 32]> = self
            .b
            .directory
            .device_transport_keys(&self.did)
            .await?
            .into_iter()
            .map(|k| k.key)
            .collect();
        let valid_revokers = valid_revoker_keys(&self.did, &all_devices, &known_transport);
        let active_in_latest: BTreeSet<[u8; 32]> = self
            .b
            .mailbox
            .list_epoch_members(self.latest)
            .await?
            .into_iter()
            .filter_map(|m| m.device_key_pubkey.array::<32>("key").ok())
            .collect();
        let mut out = Vec::new();
        for d in all_devices {
            if d.r#virtual {
                continue;
            }
            let Ok(public) = d.to_public() else { continue };
            if public.is_virtual || public.verify().is_err() {
                continue;
            }
            let already_rotated_out = !active_in_latest.contains(&public.device_key_pub.0)
                && (self.revoked.contains(&public.device_key_pub.0)
                    || matches!(
                        check_signed_revocation(
                            &self.did,
                            &d,
                            &public.device_key_pub,
                            &valid_revokers,
                        ),
                        Ok(true)
                    ));
            if already_rotated_out {
                continue;
            }
            let bound = d
                .chat_binding()
                .ok()
                .flatten()
                .filter(|b| b.transport_public_key == *chat_key)
                .is_some_and(|b| b.verify(&self.did, &public.device_key_pub).is_ok());
            if bound {
                out.push(public.device_key_pub);
            }
        }
        Ok(out)
    }

    /// Revoke the Labyrinth device(s) chat device `chat_key` enrolled,
    /// after the chat device itself was revoked (mls-ds requires that
    /// order). One rotation per device; this device is never revoked by
    /// its own call. Returns the rotations (empty if none was bound).
    pub async fn revoke_chat_device(
        &mut self,
        chat_key: &[u8; 32],
    ) -> Result<Vec<super::RotationReport>> {
        let me = self.device.public().device_key_pub;
        let targets: Vec<XVerifyingKey> = self
            .devices_bound_to(chat_key)
            .await?
            .into_iter()
            .filter(|k| *k != me)
            .collect();
        let mut out = Vec::with_capacity(targets.len());
        for k in &targets {
            out.push(self.revoke_device(k).await?);
        }
        Ok(out)
    }
}

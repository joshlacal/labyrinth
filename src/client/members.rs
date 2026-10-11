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

use std::collections::BTreeSet;

use super::Labyrinth;
use crate::device::DevicePublic;
use crate::epoch::{EpochMemberRecord, EpochSecret, verify_member};
use crate::records::Device;
use crate::sign::XVerifyingKey;
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
}

/// Result of auditing one epoch's member list.
pub(super) struct Audit {
    pub valid: Vec<ValidMember>,
    pub excluded: Vec<ExcludedMember>,
}

impl Labyrinth {
    /// Audit the members of epoch `epoch` (held by this device).
    pub(super) fn audit_epoch(&self, epoch: &EpochSecret) -> Result<Audit> {
        let mb = self.b.mailbox.as_ref();
        let current: BTreeSet<[u8; 32]> = self
            .b
            .directory
            .device_transport_keys(&self.did)?
            .into_iter()
            .filter(|k| k.is_current())
            .map(|k| k.key)
            .collect();
        let mut out = Audit {
            valid: Vec::new(),
            excluded: Vec::new(),
        };
        let mut seen = BTreeSet::new();
        for raw in mb.list_epoch_members(epoch.seq)? {
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
            let device = mb.get_device(&key)?;
            match self.check_member(epoch, &record, device.as_ref(), &current) {
                Ok((public, revoked)) => out.valid.push(ValidMember {
                    record,
                    public,
                    revoked,
                }),
                Err(reason) => out.excluded.push(ExcludedMember {
                    device_key: Some(key),
                    reason,
                }),
            }
        }
        Ok(out)
    }

    fn check_member(
        &self,
        epoch: &EpochSecret,
        record: &EpochMemberRecord,
        device: Option<&Device>,
        current: &BTreeSet<[u8; 32]>,
    ) -> core::result::Result<(DevicePublic, bool), ExclusionReason> {
        let device = device.ok_or(ExclusionReason::MissingDeviceRecord)?;
        let public = device
            .to_public()
            .ok()
            .filter(|p| p.verify().is_ok() && p.device_key_pub == record.device_key_pub)
            .ok_or(ExclusionReason::InvalidDeviceRecord)?;
        verify_member(epoch, record).map_err(|_| ExclusionReason::InvalidMac)?;
        if !public.is_virtual {
            let binding = device
                .chat_binding()
                .ok()
                .flatten()
                .filter(|b| b.verify(&self.did, &public.device_key_pub).is_ok())
                .ok_or(ExclusionReason::Unbound)?;
            if !current.contains(&binding.transport_public_key) {
                return Err(ExclusionReason::ChatDeviceNotCurrent);
            }
        }
        Ok((public, device.revoked_at.is_some()))
    }

    /// Fails with [`Error::MemberTampered`] if a member this client already
    /// verified in epoch `seq` is among `excluded` for a reason the
    /// store alone could cause (record or MAC failures). A dropped chat
    /// binding is a legitimate exclusion and passes.
    pub(super) fn check_not_tampered(&self, seq: u64, excluded: &[ExcludedMember]) -> Result<()> {
        if self.verified.0 != seq {
            return Ok(());
        }
        let tampered = excluded.iter().any(|x| {
            !matches!(x.reason, ExclusionReason::ChatDeviceNotCurrent)
                && x.device_key.is_some_and(|k| self.verified.1.contains(&k.0))
        });
        if tampered {
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
    pub fn audit_members(&mut self) -> Result<Vec<ExcludedMember>> {
        let e = self.epoch_secret(self.latest)?;
        let audit = self.audit_epoch(&e)?;
        self.remember_verified(e.seq, audit.valid.iter().map(|v| v.record.device_key_pub.0));
        Ok(audit.excluded)
    }
}

impl Labyrinth {
    /// [CB-36] This account's unrevoked physical Labyrinth devices whose
    /// verified chat binding names `chat_key`: the Labyrinth device(s) a
    /// chat device enrolled. A binding that does not verify is ignored.
    pub fn devices_bound_to(&self, chat_key: &[u8; 32]) -> Result<Vec<XVerifyingKey>> {
        let mut out = Vec::new();
        for d in self.b.mailbox.list_devices()? {
            if d.r#virtual || d.revoked_at.is_some() {
                continue;
            }
            let Ok(public) = d.to_public() else { continue };
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
    pub fn revoke_chat_device(
        &mut self,
        chat_key: &[u8; 32],
    ) -> Result<Vec<super::RotationReport>> {
        let me = self.device.public().device_key_pub;
        let targets: Vec<XVerifyingKey> = self
            .devices_bound_to(chat_key)?
            .into_iter()
            .filter(|k| *k != me)
            .collect();
        targets.iter().map(|k| self.revoke_device(k)).collect()
    }
}

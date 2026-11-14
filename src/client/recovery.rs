//! Managing recovery methods (paper p.43–46, gap audit 8.1/8.7, decision
//! J2 defaults; [CB-39]).
//!
//! Each recovery method is one virtual device. Bundles stored by the
//! platform on the user's behalf (iCloud Keychain / Android Auto Backup,
//! and passkey-wrapped codes) become stale after [`AUTO_RECOVERY_TTL_MS`]
//! without use (paper p.46). Staleness is advisory; only a rotation that
//! excludes the virtual device makes the method unusable. Codes the user
//! holds (`code`, `otc`) never become stale.
//! Removing a method revokes its virtual device (a rotation that excludes
//! it, [CB-11]) and then deletes the bundle.

use std::collections::{BTreeMap, BTreeSet};

use super::members::{check_signed_revocation, valid_revoker_keys};
use super::{Labyrinth, RotationReport};
use crate::epoch::verify_member;
use crate::records::ms_from_datetime;
use crate::sign::XVerifyingKey;
use crate::virtual_device::Mechanism;
use crate::{Error, Result};

/// Inactivity after which an automatically stored bundle becomes stale:
/// 180 days.
pub const AUTO_RECOVERY_TTL_MS: u64 = 180 * 24 * 60 * 60 * 1000;

/// When a bundle of `mechanism`, created at `created_ms` and last used at
/// `last_used_ms`, becomes stale; `None` if it never does.
pub fn recovery_stale_at(
    mechanism: Mechanism,
    created_ms: u64,
    last_used_ms: Option<u64>,
) -> Option<u64> {
    match mechanism {
        Mechanism::Keychain | Mechanism::Passkey => Some(
            created_ms
                .max(last_used_ms.unwrap_or(0))
                .saturating_add(AUTO_RECOVERY_TTL_MS),
        ),
        Mechanism::Code | Mechanism::Otc => None,
    }
}

/// One recovery method of the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryMethod {
    pub vdevice_id: [u8; 16],
    pub mechanism: Mechanism,
    /// The virtual device's key, as it appears in epoch membership.
    pub device_key: XVerifyingKey,
    pub created_at_ms: u64,
    pub last_used_at_ms: Option<u64>,
    /// [`recovery_stale_at`]; `None` for codes the user holds.
    pub stale_at_ms: Option<u64>,
    /// The virtual device is marked revoked (a removal did not finish).
    pub revoked: bool,
}

impl RecoveryMethod {
    pub fn stale_at(&self, now_ms: u64) -> bool {
        self.stale_at_ms.is_some_and(|t| now_ms >= t)
    }
}

impl Labyrinth {
    /// Every active recovery method (virtual device) in the current epoch,
    /// cross-checked against its `epochMember`, `device`, and `virtualDevice`
    /// records so forged or orphaned bundles are never listed as active.
    pub async fn list_recovery_methods(&self) -> Result<Vec<RecoveryMethod>> {
        let mb = self.b.mailbox.as_ref();
        let epoch = self
            .epochs
            .get(&self.latest)
            .ok_or(Error::NotFound("epoch"))?;
        let now_ms = self.b.clock.now_ms();
        let all_devices = mb.list_devices().await?;
        let known_transport: BTreeSet<[u8; 32]> = self
            .b
            .directory
            .device_transport_keys(&self.did)
            .await
            .map(|keys| keys.into_iter().map(|k| k.key).collect())
            .unwrap_or_default();
        let valid_revokers = valid_revoker_keys(&self.did, &all_devices, &known_transport);
        let all_revoked = self.all_revoked_keys();

        let mut bundles = BTreeMap::new();
        for entry in mb.list_virtual_device_records().await? {
            let Ok(v) = entry else { continue };
            let Ok((rec, _)) = v.to_bundle_for_did(&self.did) else {
                continue;
            };
            let Ok(created_at_ms) = ms_from_datetime(&v.created_at) else {
                continue;
            };
            let key = rec.public.device_key_pub.0;
            match bundles.entry(key) {
                std::collections::btree_map::Entry::Occupied(mut e) => {
                    e.insert(None);
                }
                std::collections::btree_map::Entry::Vacant(e) => {
                    e.insert(Some((rec, v, created_at_ms)));
                }
            }
        }

        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for raw_member in mb.list_epoch_members(self.latest).await? {
            let Ok(member) = raw_member.to_record() else {
                continue;
            };
            if !seen.insert(member.device_key_pub.0) {
                continue;
            }
            let Some(Some((rec, v, created_at_ms))) = bundles.get(&member.device_key_pub.0) else {
                continue;
            };
            if verify_member(epoch, &member, true).is_err() {
                continue;
            }
            let Some(dev) = mb.get_device(&rec.public.device_key_pub).await? else {
                continue;
            };
            let Ok(dev_pub) = dev.to_public() else {
                continue;
            };
            if !dev_pub.is_virtual
                || dev.chat_binding.is_some()
                || dev_pub != rec.public
                || dev_pub.verify().is_err()
            {
                continue;
            }
            // `lastUsedAt` is an unsigned hint: malformed, pre-creation, or
            // future-dated values are ignored so a store cannot stretch TTL
            // past `created_at_ms + AUTO_RECOVERY_TTL_MS`.
            let last_used_at_ms = v
                .last_used_at
                .as_deref()
                .and_then(|ts| ms_from_datetime(ts).ok())
                .filter(|&ts| ts >= *created_at_ms && ts <= now_ms);
            let signed_revoked = matches!(
                check_signed_revocation(
                    &self.did,
                    &dev,
                    &rec.public.device_key_pub,
                    &valid_revokers,
                ),
                Ok(true)
            );
            let revoked = signed_revoked || all_revoked.contains(&rec.public.device_key_pub.0);
            out.push(RecoveryMethod {
                vdevice_id: rec.vdevice_id,
                mechanism: rec.mechanism,
                device_key: rec.public.device_key_pub,
                created_at_ms: *created_at_ms,
                last_used_at_ms,
                stale_at_ms: recovery_stale_at(rec.mechanism, *created_at_ms, last_used_at_ms),
                revoked,
            });
        }
        out.sort_by_key(|m| m.vdevice_id);
        Ok(out)
    }

    /// Keep a platform-stored method alive, e.g. after the app confirmed
    /// its keychain copy is still present ([CB-39]).
    pub async fn touch_recovery_method(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        self.b.mailbox.touch_virtual_device(vdevice_id).await
    }

    /// Remove a recovery method: revoke its virtual device (a new epoch
    /// without it) and delete its bundle, so the code no longer opens
    /// anything new and the bundle is gone. History up to the rotation
    /// stays readable to anyone who already copied the bundle and code,
    /// as with any revoked device.
    pub async fn remove_recovery_method(
        &mut self,
        vdevice_id: &[u8; 16],
    ) -> Result<RotationReport> {
        let v = self
            .b
            .mailbox
            .get_virtual_device(vdevice_id)
            .await?
            .ok_or(Error::NotFound("virtual device"))?;
        let (rec, _) = v.to_bundle()?;
        if rec.public.device_key_pub == self.device.public().device_key_pub {
            return Err(Error::DeviceTampered);
        }
        let dev = self
            .b
            .mailbox
            .get_device(&rec.public.device_key_pub)
            .await?
            .ok_or(Error::DeviceTampered)?;
        let dev_pub = dev.to_public()?;
        dev_pub.verify()?;
        if !dev_pub.is_virtual || dev.chat_binding.is_some() || dev_pub != rec.public {
            return Err(Error::DeviceTampered);
        }
        let _ = v.to_bundle_for_did(&self.did)?;
        let report = self.revoke_device(&rec.public.device_key_pub).await?;
        self.b.mailbox.delete_virtual_device(vdevice_id).await?;
        Ok(report)
    }
}

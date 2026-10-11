//! Managing recovery methods (paper p.43–46, gap audit 8.1/8.7, decision
//! J2 defaults; [CB-39]).
//!
//! Each recovery method is one virtual device. Bundles stored by the
//! platform on the user's behalf (iCloud Keychain / Android Auto Backup,
//! and passkey-wrapped codes) expire after [`AUTO_RECOVERY_TTL_MS`]
//! without use, so no forgotten cloud account keeps a working key forever
//! (paper p.46). Codes the user holds (`code`, `otc`) never expire.
//! Removing a method revokes its virtual device (a rotation that excludes
//! it, [CB-11]) and then deletes the bundle.

use super::{Labyrinth, RotationReport};
use crate::records::ms_from_datetime;
use crate::sign::XVerifyingKey;
use crate::virtual_device::Mechanism;
use crate::{Error, Result};

/// Inactivity after which an automatically stored bundle expires: 180
/// days.
pub const AUTO_RECOVERY_TTL_MS: u64 = 180 * 24 * 60 * 60 * 1000;

/// When a bundle of `mechanism`, created at `created_ms` and last used at
/// `last_used_ms`, expires; `None` if it never does.
pub fn recovery_expiry(
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
    /// [`recovery_expiry`]; `None` for codes the user holds.
    pub expires_at_ms: Option<u64>,
    /// The virtual device is marked revoked (a removal did not finish).
    pub revoked: bool,
}

impl RecoveryMethod {
    pub fn expired_at(&self, now_ms: u64) -> bool {
        self.expires_at_ms.is_some_and(|t| now_ms >= t)
    }
}

impl Labyrinth {
    /// Every recovery method (virtual device) of the account.
    pub fn list_recovery_methods(&self) -> Result<Vec<RecoveryMethod>> {
        let mb = self.b.mailbox.as_ref();
        mb.list_virtual_devices()?
            .into_iter()
            .map(|v| {
                let (rec, _) = v.to_bundle()?;
                let created_at_ms = ms_from_datetime(&v.created_at)?;
                let last_used_at_ms = v
                    .last_used_at
                    .as_deref()
                    .map(ms_from_datetime)
                    .transpose()?;
                let revoked = mb
                    .get_device(&rec.public.device_key_pub)?
                    .is_some_and(|d| d.revoked_at.is_some());
                Ok(RecoveryMethod {
                    vdevice_id: rec.vdevice_id,
                    mechanism: rec.mechanism,
                    device_key: rec.public.device_key_pub,
                    created_at_ms,
                    last_used_at_ms,
                    expires_at_ms: recovery_expiry(rec.mechanism, created_at_ms, last_used_at_ms),
                    revoked,
                })
            })
            .collect()
    }

    /// Keep a platform-stored method alive, e.g. after the app confirmed
    /// its keychain copy is still present ([CB-39]).
    pub fn touch_recovery_method(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        self.b.mailbox.touch_virtual_device(vdevice_id)
    }

    /// Remove a recovery method: revoke its virtual device (a new epoch
    /// without it, its ORF state deleted) and delete its bundle, so the
    /// code no longer opens anything new and the bundle is gone. History
    /// up to the rotation stays readable to anyone who already copied the
    /// bundle and code, as with any revoked device.
    pub fn remove_recovery_method(&mut self, vdevice_id: &[u8; 16]) -> Result<RotationReport> {
        let method = self
            .list_recovery_methods()?
            .into_iter()
            .find(|m| m.vdevice_id == *vdevice_id)
            .ok_or(Error::NotFound("virtual device"))?;
        let report = self.revoke_device(&method.device_key)?;
        self.b.mailbox.delete_virtual_device(vdevice_id)?;
        Ok(report)
    }

    /// Remove every method that expired by the client clock; returns the
    /// removed ids. One rotation per method (rare, and each is reported).
    pub fn remove_expired_recovery_methods(&mut self) -> Result<Vec<[u8; 16]>> {
        let now = self.b.clock.now_ms();
        let expired: Vec<[u8; 16]> = self
            .list_recovery_methods()?
            .into_iter()
            .filter(|m| m.expired_at(now))
            .map(|m| m.vdevice_id)
            .collect();
        for id in &expired {
            self.remove_recovery_method(id)?;
        }
        Ok(expired)
    }
}

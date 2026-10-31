//! Adding devices: recovery codes, passkey-wrapped codes and one-time
//! codes (SPEC §6).

use std::collections::BTreeSet;

use super::epochs::{chain_forward, check_candidate_integrity, epoch_record, verified_own};
use super::members::audit_epoch_stores;
use super::{Backends, Labyrinth};
use crate::device::{ChatBinding, DevicePublic};
use crate::epoch::{
    EpochKeys as _, EpochMemberRecord, EpochSecret, PendingEpoch, open_next_enrolling,
    verify_public,
};
use crate::mailbox::EpochPublic;
use crate::otc::{Initiator, InitiatorMessage, OneTimeCode, Responder, ResponderMessage};
use crate::records::mailbox::PasskeyWrap;
use crate::records::{Device, Epoch, EpochMember, VirtualDevice, datetime_from_ms};
use crate::recovery_code::RecoveryCode;
use crate::sign::{TransportSigner, XVerifyingKey};
use crate::store::{AtomicEnrollBundle, EnrollCleanup};
use crate::virtual_device::{self, Mechanism, OtcPayload, RestoredState, passkey};
use crate::{Error, Result};

/// A new recovery bundle. Show `code` to the user (or store it in the
/// keychain), then drop it.
pub struct RecoverySetup {
    pub code: RecoveryCode,
    pub vdevice_id: [u8; 16],
}

/// A device enrolled by restore or one-time code.
pub struct Enrollment {
    pub device_key: XVerifyingKey,
}

/// What the enrolled device sends back in a one-time-code transfer.
pub struct OtcResponse {
    pub message: ResponderMessage,
    /// [`OtcPayload`] sealed under the hybrid PQ `OtcSessionKey`.
    pub sealed_payload: Vec<u8>,
}

impl core::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Enrollment")
            .field("device_key", &self.device_key)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for RecoverySetup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoverySetup")
            .field("vdevice_id", &hex::encode(self.vdevice_id))
            .finish_non_exhaustive()
    }
}

fn prefer_passkey_error(current: &mut Option<Error>, candidate: Error) {
    // A legitimate bundle opened with the wrong 32-byte PRF reports
    // `Decrypt`. Keep that result stable even when an attacker prepends a
    // malformed or unsupported matching record to the listing.
    let rank = |error: &Error| match error {
        Error::Backend(_) | Error::Forbidden => 6,
        Error::Decrypt => 5,
        Error::BadRecoveryCode => 4,
        Error::Expired => 3,
        Error::Unsupported(_) => 2,
        _ => 1,
    };
    if current
        .as_ref()
        .is_none_or(|error| rank(&candidate) > rank(error))
    {
        *current = Some(candidate);
    }
}

fn vdevice_expiry_ms(mechanism: Mechanism, vdev: &VirtualDevice) -> Result<Option<u64>> {
    let created_ms = crate::records::ms_from_datetime(&vdev.created_at)?;
    let last_used_ms = vdev
        .last_used_at
        .as_deref()
        .map(crate::records::ms_from_datetime)
        .transpose()?;
    Ok(super::recovery::recovery_expiry(
        mechanism,
        created_ms,
        last_used_ms,
    ))
}

fn select_passkey_bundles<'a>(
    did: &str,
    prf_output: &[u8],
    credential_id: &[u8],
    bundles: &'a [VirtualDevice],
) -> Result<Vec<(&'a VirtualDevice, RecoveryCode)>> {
    let mut first_error = None;
    let mut selected: Vec<(&VirtualDevice, RecoveryCode)> = Vec::new();
    for candidate in bundles {
        if candidate
            .passkey_credential_id
            .as_ref()
            .is_none_or(|id| id.0 != credential_id)
        {
            continue;
        }
        let resolved = (|| {
            let wrapped = candidate
                .passkey_wrapped_code
                .as_ref()
                .ok_or(Error::Malformed("passkey fields must come together"))?;
            let code = passkey::unwrap_code(prf_output, &wrapped.0)?;
            let (vdevice_id, _) = code.derive(did);
            let mut canonical_matches = bundles
                .iter()
                .filter(|bundle| bundle.vdevice_id.0.as_slice() == vdevice_id);
            let canonical = canonical_matches.next().ok_or(Error::BadRecoveryCode)?;
            if canonical_matches.next().is_some() {
                return Err(Error::Conflict);
            }
            let canonical_wrap = canonical
                .to_bundle()?
                .1
                .ok_or(Error::Malformed("passkey fields must come together"))?;
            if canonical_wrap.credential_id != credential_id {
                return Err(Error::BadRecoveryCode);
            }
            Ok((canonical, code))
        })();
        match resolved {
            Ok((canonical, code)) => {
                if !selected
                    .iter()
                    .any(|(known, _)| known.vdevice_id == canonical.vdevice_id)
                {
                    selected.push((canonical, code));
                }
            }
            Err(Error::Conflict) => return Err(Error::Conflict),
            Err(error) => {
                prefer_passkey_error(&mut first_error, error);
            }
        }
    }
    if selected.is_empty() {
        Err(first_error.unwrap_or(Error::NotFound("passkey bundle")))
    } else {
        Ok(selected)
    }
}

struct PreparedRestore {
    vdev: VirtualDevice,
    restored: RestoredState,
    reached: Vec<EpochSecret>,
    latest_public: EpochPublic,
}

impl Labyrinth {
    /// Create a recovery bundle in the current epoch (SPEC §6.2). The
    /// bundle's virtual device is carried over by later rotations.
    pub async fn create_recovery_code(&mut self, mechanism: Mechanism) -> Result<RecoverySetup> {
        self.create_bundle(mechanism, None).await
    }

    /// Create a recovery bundle whose code is also stored wrapped under a
    /// WebAuthn PRF output ([CB-13]), so [`Labyrinth::restore_with_passkey`]
    /// can recover without the user typing it.
    pub async fn create_passkey_recovery(
        &mut self,
        prf_output: &[u8],
        credential_id: &[u8],
    ) -> Result<RecoverySetup> {
        self.create_bundle(Mechanism::Passkey, Some((prf_output, credential_id)))
            .await
    }

    async fn create_bundle(
        &mut self,
        mechanism: Mechanism,
        passkey: Option<(&[u8], &[u8])>,
    ) -> Result<RecoverySetup> {
        self.sync_epochs().await?;
        let current = self.epoch_secret(self.latest).await?;
        let code = RecoveryCode::generate()?;
        let (rec, member) = virtual_device::create(
            &self.did,
            &code,
            &self.device,
            &current,
            &self.mailbox_root_salt,
            mechanism,
        )?;
        let wrap = passkey
            .map(|(prf, cred)| {
                Ok::<_, Error>(PasskeyWrap {
                    wrapped_code: passkey::wrap_code(prf, &code)?,
                    credential_id: cred.to_vec(),
                })
            })
            .transpose()?;
        let now = self.now();
        let mb = self.b.mailbox.as_ref();
        mb.create_device(&Device::from_public(&rec.public, now.clone()))
            .await?;
        mb.create_virtual_device(&VirtualDevice::from_bundle(
            &rec,
            wrap.as_ref(),
            now.clone(),
        ))
        .await?;
        mb.create_epoch_member(&EpochMember::from_record(&member, now))
            .await?;
        Ok(RecoverySetup {
            code,
            vdevice_id: rec.vdevice_id,
        })
    }

    /// Enroll a new device from a recovery code, correcting up to three
    /// typos (SPEC §6.1, §6.3). Forward-chains with the bundle's virtual
    /// device to the newest epoch `E` it can reach, checks `E` against the
    /// published latest epoch (SPEC §10), then atomically rotates `E -> E+1`
    /// (`Gate 3`).
    pub async fn restore_with_recovery_code(
        did: &str,
        code_input: &str,
        transport: Box<dyn TransportSigner>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        let known_ids: BTreeSet<[u8; 16]> = b
            .mailbox
            .list_virtual_devices()
            .await?
            .into_iter()
            .filter_map(|v| <[u8; 16]>::try_from(v.vdevice_id.0.as_slice()).ok())
            .collect();
        let code = virtual_device::find_code(code_input, did, |id| known_ids.contains(id))?;
        let bundle = b
            .mailbox
            .get_virtual_device(&code.derive(did).0)
            .await?
            .ok_or(Error::BadRecoveryCode)?;
        Self::restore_from_bundle(did, &bundle, &code, transport, b).await
    }

    /// Enroll a new device from the passkey-wrapped code stored with the
    /// bundle for `credential_id`.
    pub async fn restore_with_passkey(
        did: &str,
        prf_output: &[u8],
        credential_id: &[u8],
        transport: Box<dyn TransportSigner>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        passkey::validate_prf_output(prf_output)?;
        let bundles = b.mailbox.list_virtual_devices().await?;
        let candidates = select_passkey_bundles(did, prf_output, credential_id, &bundles)?;
        let mut prepared = None;
        let mut first_error = None;
        let now = b.clock.now_ms();
        for (bundle, code) in candidates {
            if vdevice_expiry_ms(Mechanism::Passkey, bundle)?.is_some_and(|exp| now >= exp) {
                prefer_passkey_error(&mut first_error, Error::Expired);
                continue;
            }
            match Self::prepare_restore_from_bundle(did, bundle, &code, &b).await {
                Ok(_) if prepared.is_some() => return Err(Error::Conflict),
                Ok(candidate) => prepared = Some(candidate),
                Err(Error::NotEpochMember) => {
                    prefer_passkey_error(&mut first_error, Error::NotEpochMember)
                }
                Err(Error::Expired) => {
                    prefer_passkey_error(&mut first_error, Error::Expired);
                }
                Err(error) => return Err(error),
            }
        }
        let prepared = prepared
            .ok_or_else(|| first_error.unwrap_or(Error::NotFound("active passkey bundle")))?;
        Self::finish_prepared_restore(did, prepared, transport, b).await
    }

    async fn restore_from_bundle(
        did: &str,
        bundle: &VirtualDevice,
        code: &RecoveryCode,
        transport: Box<dyn TransportSigner>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        let prepared = Self::prepare_restore_from_bundle(did, bundle, code, &b).await?;
        Self::finish_prepared_restore(did, prepared, transport, b).await
    }

    async fn prepare_restore_from_bundle(
        did: &str,
        bundle: &VirtualDevice,
        code: &RecoveryCode,
        b: &Backends,
    ) -> Result<PreparedRestore> {
        let (record, _) = bundle.to_bundle()?;
        let vdev = b
            .mailbox
            .get_virtual_device(&record.vdevice_id)
            .await?
            .ok_or(Error::NotFound("virtual device"))?;
        let now = b.clock.now_ms();
        if vdevice_expiry_ms(record.mechanism, bundle)?.is_some_and(|exp| now >= exp)
            || vdevice_expiry_ms(record.mechanism, &vdev)?.is_some_and(|exp| now >= exp)
        {
            return Err(Error::Expired);
        }
        let (fresh_record, _) = vdev.to_bundle()?;
        if fresh_record != record {
            return Err(Error::Conflict);
        }
        let restored = virtual_device::open(&record, code, did)?;
        let seq = restored.epoch.seq();
        let (id, start_record) = epoch_record(b.mailbox.as_ref(), seq).await?;
        let start = PendingEpoch::new(seq, *restored.epoch.root()).assign_id(id);
        verify_public(&start, &start_record.public)?;
        start_record.public.verify(did, None)?;
        let reached = chain_forward(
            b.mailbox.as_ref(),
            did,
            start,
            restored.device.public(),
            &restored.device.storage,
            &Default::default(),
        )
        .await?;
        let latest = reached.last().expect("non-empty");
        let latest_public =
            verified_own(b.mailbox.as_ref(), b.directory.as_ref(), did, latest).await?;
        check_candidate_integrity(
            b.mailbox.as_ref(),
            b.directory.as_ref(),
            did,
            latest.seq,
            &latest_public.head,
        )
        .await?;
        Ok(PreparedRestore {
            vdev,
            restored,
            reached,
            latest_public,
        })
    }

    async fn finish_prepared_restore(
        did: &str,
        prepared: PreparedRestore,
        transport: Box<dyn TransportSigner>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        let PreparedRestore {
            mut vdev,
            restored,
            mut reached,
            latest_public,
        } = prepared;
        let mine = transport.transport_public_key();
        let current = b.directory.device_transport_keys(did).await?;
        if !current.iter().any(|k| k.is_current() && k.key == mine) {
            return Err(Error::Unattested);
        }
        let latest = reached.last().expect("non-empty");
        let (device, public, _) = virtual_device::enroll_from_virtual(&restored, latest)?;
        let audit =
            audit_epoch_stores(b.mailbox.as_ref(), b.directory.as_ref(), did, latest).await?;
        let continuing: Vec<DevicePublic> = audit
            .valid
            .iter()
            .filter(|v| !v.revoked)
            .map(|v| v.public.clone())
            .collect();
        let prev_members: Vec<EpochMemberRecord> =
            audit.valid.iter().map(|v| v.record.clone()).collect();
        let (pending_next, new_next) = open_next_enrolling(
            did,
            latest,
            &latest_public,
            &prev_members,
            &continuing,
            &device,
            transport.as_ref(),
        )?;
        let now = datetime_from_ms(b.clock.now_ms());
        vdev.last_used_at = Some(now.clone());
        let binding = ChatBinding::sign(did, &public.device_key_pub, transport.as_ref());
        let bundle = AtomicEnrollBundle {
            cleanup: Some(EnrollCleanup::TouchVirtualDevice { updated: vdev }),
            device: Device::bound(&public, &binding, now.clone()),
            epoch: Epoch::from_record(&new_next.record, now.clone()),
            members: new_next
                .members
                .iter()
                .map(|m| EpochMember::from_record(m, now.clone()))
                .collect(),
        };
        let next_id = b.mailbox.atomic_enroll(&bundle).await?;
        let next_secret = pending_next.assign_id(next_id);
        let next_seq = next_secret.seq;
        reached.push(next_secret);
        let mut me = Self::assemble(
            did,
            device,
            transport,
            b,
            restored.mailbox_root_salt,
            reached,
        )?;
        me.adopted(new_next.record.public.clone());
        me.remember_verified(
            next_seq,
            new_next.members.iter().map(|m| m.device_key_pub.0),
        );
        me.publish_keys(&new_next.record.public).await?;
        Ok((
            me,
            Enrollment {
                device_key: public.device_key_pub,
            },
        ))
    }

    /// Existing device: start offering a one-time code (show
    /// `responder.code()` to the user).
    pub fn otc_offer(&self) -> Result<Responder> {
        Responder::generate(&self.did)
    }

    /// Existing device: answer the new device's hybrid PQ CPace + ML-KEM-768 message
    /// and send it the sealed enrollment payload for the current epoch (SPEC §6.5).
    pub async fn otc_respond(
        &mut self,
        responder: &mut Responder,
        msg: &InitiatorMessage,
    ) -> Result<OtcResponse> {
        self.sync_epochs().await?;
        let (message, session_key) = responder.respond(msg)?;
        let epoch = self.epoch_secret(self.latest).await?;
        let payload = OtcPayload::create(&epoch, &self.mailbox_root_salt);
        Ok(OtcResponse {
            message,
            sealed_payload: payload.seal(&session_key)?,
        })
    }

    /// New device: start a hybrid PQ one-time-code session with the code the user typed.
    pub fn otc_start(did: &str, code_input: &str) -> Result<(Initiator, InitiatorMessage)> {
        Initiator::start(&OneTimeCode::parse(code_input)?, did)
    }

    /// New device: finish the session, open the payload, verify the transferred
    /// epoch `E` against the store, and atomically rotate `E -> E+1` (`Gate 3`).
    pub async fn enroll_via_otc(
        did: &str,
        initiator: Initiator,
        response: &ResponderMessage,
        sealed_payload: &[u8],
        transport: Box<dyn TransportSigner>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        Self::enroll_via_otc_session(did, initiator, response, sealed_payload, None, transport, b)
            .await
    }

    /// [`enroll_via_otc`](Self::enroll_via_otc) with an optional `otcSession`
    /// `rkey` consumed atomically in the same `space.applyWrites` transaction (`Gate 3`).
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_via_otc_session(
        did: &str,
        initiator: Initiator,
        response: &ResponderMessage,
        sealed_payload: &[u8],
        otc_session_rkey: Option<String>,
        transport: Box<dyn TransportSigner>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        let mine = transport.transport_public_key();
        let current = b.directory.device_transport_keys(did).await?;
        if !current.iter().any(|k| k.is_current() && k.key == mine) {
            return Err(Error::Unattested);
        }
        let session_key = initiator.finish(response)?;
        let payload = OtcPayload::open(&session_key, sealed_payload)?;
        let epoch: &EpochSecret = &payload.epoch;
        let epoch_public =
            verified_own(b.mailbox.as_ref(), b.directory.as_ref(), did, epoch).await?;
        check_candidate_integrity(
            b.mailbox.as_ref(),
            b.directory.as_ref(),
            did,
            epoch.seq,
            &epoch_public.head,
        )
        .await?;
        let (device, public, _) = payload.enroll()?;
        let audit =
            audit_epoch_stores(b.mailbox.as_ref(), b.directory.as_ref(), did, epoch).await?;
        let continuing: Vec<DevicePublic> = audit
            .valid
            .iter()
            .filter(|v| !v.revoked)
            .map(|v| v.public.clone())
            .collect();
        let prev_members: Vec<EpochMemberRecord> =
            audit.valid.iter().map(|v| v.record.clone()).collect();
        let (pending_next, new_next) = open_next_enrolling(
            did,
            epoch,
            &epoch_public,
            &prev_members,
            &continuing,
            &device,
            transport.as_ref(),
        )?;
        let now = datetime_from_ms(b.clock.now_ms());
        let binding = ChatBinding::sign(did, &public.device_key_pub, transport.as_ref());
        let bundle = AtomicEnrollBundle {
            cleanup: otc_session_rkey.map(|rkey| EnrollCleanup::ConsumeOtcSession { rkey }),
            device: Device::bound(&public, &binding, now.clone()),
            epoch: Epoch::from_record(&new_next.record, now.clone()),
            members: new_next
                .members
                .iter()
                .map(|m| EpochMember::from_record(m, now.clone()))
                .collect(),
        };
        let next_id = b.mailbox.atomic_enroll(&bundle).await?;
        let next_secret = pending_next.assign_id(next_id);
        let next_seq = next_secret.seq;
        let mut me = Self::assemble(
            did,
            device,
            transport,
            b,
            payload.mailbox_root_salt,
            [payload.epoch.clone(), next_secret],
        )?;
        me.adopted(new_next.record.public.clone());
        me.remember_verified(
            next_seq,
            new_next.members.iter().map(|m| m.device_key_pub.0),
        );
        me.publish_keys(&new_next.record.public).await?;
        Ok((
            me,
            Enrollment {
                device_key: public.device_key_pub,
            },
        ))
    }
}

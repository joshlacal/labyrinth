//! Adding devices: recovery codes, passkey-wrapped codes and one-time
//! codes (SPEC §6).

use std::collections::BTreeSet;

use super::epochs::{
    chain_forward_healing_squats, check_candidate_integrity, clear_unanchored_invalid_successor,
    epoch_record, verified_own,
};
use super::members::{
    ExcludedMember, ExclusionReason, audit_epoch_stores, verify_epoch_members_hash,
};
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
use crate::recovery_code::{CodeVersion, RecoveryCode};
use crate::recovery_share::{RecoveryShare, RecoveryShares};
use crate::sign::{TransportSigner, XVerifyingKey};
use crate::store::{AtomicEnrollBundle, EnrollCleanup};
use crate::virtual_device::{self, Mechanism, OtcPayload, RestoredState, passkey};
use crate::{Error, Result};

/// A new recovery bundle. Show `code` to the user (or store it in the
/// keychain), then drop it.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoverySetup {
    pub code: RecoveryCode,
    pub vdevice_id: [u8; 16],
}

/// A device enrolled by restore or one-time code.
pub struct Enrollment {
    pub device_key: XVerifyingKey,
    /// The restoring device's local clock considers this automatically
    /// stored recovery method stale. Advisory only; rotation is authoritative.
    pub stale_recovery_method: bool,
    /// Revoked members of the previous epoch dropped by this enrollment rotation.
    pub evicted_revoked: Vec<XVerifyingKey>,
    /// Invalid, unbound, or expired members of the previous epoch dropped by
    /// this enrollment rotation.
    pub excluded: Vec<ExcludedMember>,
    /// The first error publishing the enrolled epoch head. The head then
    /// stays durably pending ([`Labyrinth::pending_directory_epoch`]): save
    /// the returned state, and opening it retries the publication.
    pub unfinished: Option<Error>,
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
            .field("stale_recovery_method", &self.stale_recovery_method)
            .field("evicted_revoked", &self.evicted_revoked)
            .field("excluded", &self.excluded)
            .field("unfinished", &self.unfinished)
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

pub(super) fn vdevice_stale_at_ms(
    mechanism: Mechanism,
    vdev: &VirtualDevice,
    now_ms: u64,
) -> Result<Option<u64>> {
    let created_ms = crate::records::ms_from_datetime(&vdev.created_at)?;
    let last_used_ms = vdev
        .last_used_at
        .as_deref()
        .and_then(|ts| crate::records::ms_from_datetime(ts).ok())
        .filter(|&ts| ts >= created_ms && ts <= now_ms);
    Ok(super::recovery::recovery_stale_at(
        mechanism,
        created_ms,
        last_used_ms,
    ))
}

fn select_recovery_code(
    did: &str,
    code_input: &str,
    bundles: &[VirtualDevice],
) -> Result<RecoveryCode> {
    virtual_device::find_code(code_input, did, |id| {
        bundles
            .iter()
            .any(|bundle| bundle.vdevice_id.0.as_slice() == id)
    })
}

/// Whether the typo-corrected recovery code matching `bundles` is version 3.
///
/// This is only a preflight for choosing whether to prove the recovery-share
/// service. The share store independently checks that proof immediately before
/// it serializes a version-3 fetch token.
pub fn recovery_code_requires_share(
    did: &str,
    code_input: &str,
    bundles: &[VirtualDevice],
) -> Result<bool> {
    Ok(select_recovery_code(did, code_input, bundles)?.version() == CodeVersion::V3)
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
            let vdevice_id = code.vdevice_id(did);
            let mut canonical_matches = bundles
                .iter()
                .filter(|bundle| bundle.vdevice_id.0.as_slice() == vdevice_id);
            let canonical = canonical_matches.next().ok_or(Error::BadRecoveryCode)?;
            if canonical_matches.next().is_some() {
                return Err(Error::Conflict);
            }
            let canonical_wrap = canonical
                .to_bundle_for_did(did)?
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

/// Whether any passkey bundle selected by the unwrapped code needs a
/// version-3 recovery share. No unwrapped code escapes this call.
pub fn passkey_recovery_requires_share(
    did: &str,
    prf_output: &[u8],
    credential_id: &[u8],
    bundles: &[VirtualDevice],
) -> Result<bool> {
    passkey::validate_prf_output(prf_output)?;
    Ok(select_passkey_bundles(did, prf_output, credential_id, bundles)?
        .iter()
        .any(|(_, code)| code.version() == CodeVersion::V3))
}


struct PreparedRestore {
    vdev: VirtualDevice,
    restored: RestoredState,
    reached: Vec<EpochSecret>,
    latest_public: EpochPublic,
    cumulative_revoked: BTreeSet<[u8; 32]>,
    stale_recovery_method: bool,
}

/// The erasable share a version-3 code needs; `None` for a version-2 code.
async fn fetch_share(
    shares: Option<&RecoveryShares>,
    did: &str,
    code: &RecoveryCode,
) -> Result<Option<RecoveryShare>> {
    if code.version() == CodeVersion::V2 {
        return Ok(None);
    }
    let shares = shares.ok_or(Error::RecoveryShareUnavailable)?;
    let d = code.derive_v3(did)?;
    shares
        .store
        .get_share(&d.vdevice_id, &d.fetch_token)
        .await?
        .ok_or(Error::RecoveryShareUnavailable)
        .map(Some)
}

impl Labyrinth {
    /// Install (or remove) the recovery-share configuration. With a store,
    /// version-3 codes restore and removing or re-keying a method deletes its
    /// share; `None` keeps version-2-only behaviour.
    pub fn set_recovery_shares(&mut self, shares: Option<RecoveryShares>) {
        self.shares = shares;
    }

    /// Create a recovery bundle in the current epoch (SPEC §6.2). The
    /// bundle's virtual device is carried over by later rotations.
    pub async fn create_recovery_code(&mut self, mechanism: Mechanism) -> Result<RecoverySetup> {
        self.create_bundle(mechanism, None).await
    }

    /// Create a recovery bundle whose code is also stored wrapped under a
    /// WebAuthn PRF output ([CB-13]), so [`Labyrinth::restore_with_passkey`]
    /// can recover without the user typing it.
    ///
    /// Immediately rotates the personal `OwnerMailbox` epoch (`E -> E + 1`) so
    /// the newly registered virtual device is carried over as an initial member
    /// committed into `EpochPublic.members_hash` across PDS `mailboxKeys` and
    /// `mls-ds` `publishEpochHead`.
    pub async fn create_passkey_recovery(
        &mut self,
        prf_output: &[u8],
        credential_id: &[u8],
    ) -> Result<RecoverySetup> {
        let setup = self
            .create_bundle(Mechanism::Passkey, Some((prf_output, credential_id)))
            .await?;
        self.rotate_epoch().await?;
        Ok(setup)
    }

    async fn create_bundle(
        &mut self,
        mechanism: Mechanism,
        passkey: Option<(&[u8], &[u8])>,
    ) -> Result<RecoverySetup> {
        self.sync_epochs().await?;
        let current = self.epoch_secret(self.latest).await?;
        let code = RecoveryCode::generate()?;
        let now = self.now();
        let (rec, member) =
            virtual_device::create_at(&self.did, &code, &self.device, &current, mechanism, &now)?;
        let wrap = passkey
            .map(|(prf, cred)| {
                Ok::<_, Error>(PasskeyWrap {
                    wrapped_code: passkey::wrap_code(prf, &code)?,
                    credential_id: cred.to_vec(),
                })
            })
            .transpose()?;
        let mb = self.b.mailbox.as_ref();
        let device = Device::from_public(&rec.public, now.clone());
        let bundle = VirtualDevice::from_bundle(&rec, wrap.as_ref(), now.clone());
        let epoch_member = EpochMember::from_record(&member, now);
        mb.create_device(&device).await?;
        mb.create_virtual_device(&bundle).await?;
        mb.create_epoch_member(&epoch_member).await?;

        // Registration succeeds only after the complete passkey/recovery
        // bundle can be read back and cryptographically verified.
        let persisted_device = mb
            .get_device(&rec.public.device_key_pub)
            .await?
            .ok_or(Error::NotFound("persisted recovery device"))?;
        let persisted_public = persisted_device.to_public()?;
        persisted_public.verify()?;
        let persisted_bundle = mb
            .get_virtual_device(&rec.vdevice_id)
            .await?
            .ok_or(Error::NotFound("persisted recovery bundle"))?;
        let (persisted_record, persisted_wrap) = persisted_bundle.to_bundle_for_did(&self.did)?;
        let persisted_member = mb
            .get_epoch_member(current.seq(), &rec.public.device_key_pub)
            .await?
            .ok_or(Error::NotFound("persisted recovery member"))?
            .to_record()?;
        crate::epoch::verify_member(&current, &persisted_member, true)?;
        if persisted_public != rec.public
            || persisted_record != rec
            || persisted_wrap.as_ref() != wrap.as_ref()
            || persisted_member != member
        {
            return Err(Error::Conflict);
        }
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
        Self::restore_with_recovery_code_shared(did, code_input, transport, b, None).await
    }

    /// [`restore_with_recovery_code`](Self::restore_with_recovery_code) with
    /// a recovery-share configuration: a version-3 code fetches its share
    /// from `shares` (and fails with [`Error::RecoveryShareUnavailable`]
    /// without one). The restored client keeps `shares`.
    pub async fn restore_with_recovery_code_shared(
        did: &str,
        code_input: &str,
        transport: Box<dyn TransportSigner>,
        b: Backends,
        shares: Option<RecoveryShares>,
    ) -> Result<(Self, Enrollment)> {
        let bundles = b.mailbox.list_virtual_devices().await?;
        let code = select_recovery_code(did, code_input, &bundles)?;
        let bundle = b
            .mailbox
            .get_virtual_device(&code.vdevice_id(did))
            .await?
            .ok_or(Error::BadRecoveryCode)?;
        let share = fetch_share(shares.as_ref(), did, &code).await?;
        let prepared =
            Self::prepare_restore_from_bundle(did, &bundle, &code, share.as_ref(), &b).await?;
        drop(share);
        let (mut me, enrollment) =
            Self::finish_prepared_restore(did, prepared, transport, b).await?;
        me.shares = shares;
        Ok((me, enrollment))
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
        Self::restore_with_passkey_shared(did, prf_output, credential_id, transport, b, None).await
    }

    /// [`restore_with_passkey`](Self::restore_with_passkey) with a
    /// recovery-share configuration for a passkey-wrapped version-3 code.
    pub async fn restore_with_passkey_shared(
        did: &str,
        prf_output: &[u8],
        credential_id: &[u8],
        transport: Box<dyn TransportSigner>,
        b: Backends,
        shares: Option<RecoveryShares>,
    ) -> Result<(Self, Enrollment)> {
        passkey::validate_prf_output(prf_output)?;
        let bundles = b.mailbox.list_virtual_devices().await?;
        let candidates = select_passkey_bundles(did, prf_output, credential_id, &bundles)?;
        let mut prepared = None;
        let mut first_error = None;
        for (bundle, code) in candidates {
            let share = match fetch_share(shares.as_ref(), did, &code).await {
                Ok(share) => share,
                Err(error @ Error::RecoveryShareUnavailable) => {
                    prefer_passkey_error(&mut first_error, error);
                    continue;
                }
                Err(error) => return Err(error),
            };
            match Self::prepare_restore_from_bundle(did, bundle, &code, share.as_ref(), &b).await {
                Ok(_) if prepared.is_some() => return Err(Error::Conflict),
                Ok(candidate) => prepared = Some(candidate),
                Err(Error::NotEpochMember) => {
                    prefer_passkey_error(&mut first_error, Error::NotEpochMember)
                }
                Err(error) => return Err(error),
            }
        }
        let prepared = prepared
            .ok_or_else(|| first_error.unwrap_or(Error::NotFound("active passkey bundle")))?;
        let (mut me, enrollment) =
            Self::finish_prepared_restore(did, prepared, transport, b).await?;
        me.shares = shares;
        Ok((me, enrollment))
    }

    async fn prepare_restore_from_bundle(
        did: &str,
        bundle: &VirtualDevice,
        code: &RecoveryCode,
        share: Option<&RecoveryShare>,
        b: &Backends,
    ) -> Result<PreparedRestore> {
        let (record, _) = bundle.to_bundle_for_did(did)?;
        let vdev = b
            .mailbox
            .get_virtual_device(&record.vdevice_id)
            .await?
            .ok_or(Error::NotFound("virtual device"))?;
        let now = b.clock.now_ms();
        let stale_recovery_method = vdevice_stale_at_ms(record.mechanism, bundle, now)?
            .is_some_and(|stale_at| now >= stale_at)
            || vdevice_stale_at_ms(record.mechanism, &vdev, now)?
                .is_some_and(|stale_at| now >= stale_at);
        let (fresh_record, _) = vdev.to_bundle_for_did(did)?;
        if fresh_record != record {
            return Err(Error::Conflict);
        }
        let restored = virtual_device::open_with_share(&record, code, share, did)?;
        let seq = restored.epoch.seq();
        let (id, start_record) = epoch_record(b.mailbox.as_ref(), seq).await?;
        let start = PendingEpoch::new(seq, *restored.epoch.root()).assign_id(id);
        verify_public(&start, &start_record.public)?;
        start_record.public.verify(did, None)?;
        start_record.verify_revocations(did)?;
        verify_epoch_members_hash(b.mailbox.as_ref(), &start, &start_record.public).await?;
        let reached = chain_forward_healing_squats(
            b.mailbox.as_ref(),
            b.directory.as_ref(),
            did,
            start,
            restored.device.public(),
            &restored.device.storage,
            &Default::default(),
        )
        .await?;
        let mut cumulative_revoked = BTreeSet::new();
        for s in &reached {
            let (_, rec) = epoch_record(b.mailbox.as_ref(), s.seq).await?;
            rec.verify_revocations(did)?;
            verify_epoch_members_hash(b.mailbox.as_ref(), s, &rec.public).await?;
            cumulative_revoked.extend(rec.revocations.iter().map(|k| k.0));
        }
        if cumulative_revoked.contains(&restored.device.public().device_key_pub.0) {
            return Err(Error::NotEpochMember);
        }
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
            cumulative_revoked,
            stale_recovery_method,
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
            mut cumulative_revoked,
            stale_recovery_method,
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
        audit.verify_members_hash(latest.seq, &latest_public)?;
        if audit
            .excluded
            .iter()
            .any(|x| x.reason == ExclusionReason::UnsignedRevocation)
        {
            return Err(Error::DeviceTampered);
        }
        let mut evicted_revoked = Vec::new();
        for v in &audit.valid {
            if v.revoked || cumulative_revoked.contains(&v.record.device_key_pub.0) {
                evicted_revoked.push(v.record.device_key_pub);
                cumulative_revoked.insert(v.record.device_key_pub.0);
            }
        }
        let continuing: Vec<DevicePublic> = audit
            .valid
            .iter()
            .filter(|v| !v.revoked && !cumulative_revoked.contains(&v.record.device_key_pub.0))
            .map(|v| v.public.clone())
            .collect();
        let prev_members: Vec<EpochMemberRecord> =
            audit.valid.iter().map(|v| v.record.clone()).collect();
        let (pending_next, mut new_next) = open_next_enrolling(
            did,
            latest,
            &latest_public,
            &prev_members,
            &continuing,
            &device,
            transport.as_ref(),
        )?;
        if !cumulative_revoked.is_empty() {
            new_next.record.sign_revocations(
                did,
                &device.device_key,
                cumulative_revoked.iter().copied().map(XVerifyingKey),
            )?;
        }
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
        let mut me = Self::assemble(did, device, transport, b, reached)?;
        me.revoked = cumulative_revoked;
        me.adopted(new_next.record.public.clone());
        me.remember_verified(
            next_seq,
            new_next.members.iter().map(|m| m.device_key_pub.0),
        );
        // The new epoch exists and only `me` holds its keys: a refused
        // publication stays durably pending for retry, never discards them.
        let unfinished = me.publish_latest_keys().await.err();
        Ok((
            me,
            Enrollment {
                device_key: public.device_key_pub,
                stale_recovery_method,
                evicted_revoked,
                excluded: audit.excluded,
                unfinished,
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
        let payload = OtcPayload::create(&epoch);
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
        let (_, current_epoch_rec) = epoch_record(b.mailbox.as_ref(), epoch.seq).await?;
        current_epoch_rec.verify_revocations(did)?;
        let mut cumulative_revoked: BTreeSet<[u8; 32]> =
            current_epoch_rec.revocations.iter().map(|k| k.0).collect();
        let (device, public, _) = payload.enroll()?;
        let audit =
            audit_epoch_stores(b.mailbox.as_ref(), b.directory.as_ref(), did, epoch).await?;
        audit.verify_members_hash(epoch.seq, &epoch_public)?;
        if audit
            .excluded
            .iter()
            .any(|x| x.reason == ExclusionReason::UnsignedRevocation)
        {
            return Err(Error::DeviceTampered);
        }
        let mut evicted_revoked = Vec::new();
        for v in &audit.valid {
            if v.revoked || cumulative_revoked.contains(&v.record.device_key_pub.0) {
                evicted_revoked.push(v.record.device_key_pub);
                cumulative_revoked.insert(v.record.device_key_pub.0);
            }
        }
        let continuing: Vec<DevicePublic> = audit
            .valid
            .iter()
            .filter(|v| !v.revoked && !cumulative_revoked.contains(&v.record.device_key_pub.0))
            .map(|v| v.public.clone())
            .collect();
        let prev_members: Vec<EpochMemberRecord> =
            audit.valid.iter().map(|v| v.record.clone()).collect();
        let (pending_next, mut new_next) = open_next_enrolling(
            did,
            epoch,
            &epoch_public,
            &prev_members,
            &continuing,
            &device,
            transport.as_ref(),
        )?;
        if !cumulative_revoked.is_empty() {
            new_next.record.sign_revocations(
                did,
                &device.device_key,
                cumulative_revoked.iter().copied().map(XVerifyingKey),
            )?;
        }
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
        clear_unanchored_invalid_successor(
            b.mailbox.as_ref(),
            b.directory.as_ref(),
            did,
            &epoch_public,
        )
        .await?;
        let next_id = b.mailbox.atomic_enroll(&bundle).await?;
        let next_secret = pending_next.assign_id(next_id);
        let next_seq = next_secret.seq;
        let mut me = Self::assemble(
            did,
            device,
            transport,
            b,
            [payload.epoch.clone(), next_secret],
        )?;
        me.revoked = cumulative_revoked;
        me.adopted(new_next.record.public.clone());
        me.remember_verified(
            next_seq,
            new_next.members.iter().map(|m| m.device_key_pub.0),
        );
        // As for a restore: a refused publication stays durably pending.
        let unfinished = me.publish_latest_keys().await.err();
        Ok((
            me,
            Enrollment {
                device_key: public.device_key_pub,
                stale_recovery_method: false,
                evicted_revoked,
                excluded: audit.excluded,
                unfinished,
            },
        ))
    }
}

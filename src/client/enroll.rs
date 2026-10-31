//! Adding devices: recovery codes, passkey-wrapped codes and one-time
//! codes (SPEC §6).

use std::cell::RefCell;

use super::epochs::{chain_forward, check_candidate_integrity, epoch_record, verified_own};
use super::{Backends, Labyrinth};
use crate::device::ChatBinding;
use crate::epoch::{EpochKeys as _, EpochSecret, PendingEpoch, verify_public};
use crate::mailbox::EpochPublic;
use crate::orf::EvolveToken;
use crate::otc::{Initiator, InitiatorMessage, OneTimeCode, Responder, ResponderMessage};
use crate::records::mailbox::PasskeyWrap;
use crate::records::{Device, EpochMember, VirtualDevice, datetime_from_ms};
use crate::recovery_code::RecoveryCode;
use crate::sign::{TransportSigner, XVerifyingKey};
use crate::virtual_device::{
    self, Mechanism, OtcPayload, RestoredState, VirtualDeviceRecord, passkey,
};
use crate::{Error, Result};

/// A new recovery bundle. Show `code` to the user (or store it in the
/// keychain), then drop it. The client has already registered the bundle's
/// ORF state with [`Backends::orf`]
/// (`vdeviceServerState = orf_server_evolve(token, parent state)`);
/// `evolve_token` is returned only for callers that mirror ORF state.
pub struct RecoverySetup {
    pub code: RecoveryCode,
    pub vdevice_id: [u8; 16],
    pub evolve_token: EvolveToken,
}

/// A device enrolled by restore or one-time code. The client has already
/// registered `device_key`'s ORF state with [`Backends::orf`];
/// `evolve_token` is returned only for callers that mirror ORF state.
pub struct Enrollment {
    pub device_key: XVerifyingKey,
    pub evolve_token: EvolveToken,
}

/// The id under which a one-time-code transfer's temporary ORF server
/// state is registered: both devices derive it from the CPace session
/// key, so only they can name it. The responder registers the temporary
/// state under it; the new device evolves its own state from it and then
/// deletes it.
fn otc_temp_orf_id(isk: &crate::otc::Isk) -> XVerifyingKey {
    let mut input = b"catbird.labyrinth.otc_temp_orf:".to_vec();
    input.extend_from_slice(isk.as_bytes());
    XVerifyingKey(crate::encoding::sha256(&input))
}

/// What the enrolled device sends back in a one-time-code transfer.
pub struct OtcResponse {
    pub message: ResponderMessage,
    /// [`OtcPayload`] sealed under the CPace session key.
    pub sealed_payload: Vec<u8>,
    /// Evolve token for the temporary ORF state handed to the new device,
    /// already registered with [`Backends::orf`].
    pub evolve_token: EvolveToken,
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
    record: VirtualDeviceRecord,
    restored: RestoredState,
    reached: Vec<EpochSecret>,
    latest_public: EpochPublic,
}

impl Labyrinth {
    /// Create a recovery bundle in the current epoch (SPEC §6.2). The
    /// bundle's virtual device is carried over by later rotations.
    pub fn create_recovery_code(&mut self, mechanism: Mechanism) -> Result<RecoverySetup> {
        self.create_bundle(mechanism, None)
    }

    /// Create a recovery bundle whose code is also stored wrapped under a
    /// WebAuthn PRF output ([CB-13]), so [`Labyrinth::restore_with_passkey`]
    /// can recover without the user typing it.
    pub fn create_passkey_recovery(
        &mut self,
        prf_output: &[u8],
        credential_id: &[u8],
    ) -> Result<RecoverySetup> {
        self.create_bundle(Mechanism::Passkey, Some((prf_output, credential_id)))
    }

    fn create_bundle(
        &mut self,
        mechanism: Mechanism,
        passkey: Option<(&[u8], &[u8])>,
    ) -> Result<RecoverySetup> {
        self.sync_epochs()?;
        let current = self.epoch_secret(self.latest)?;
        let code = RecoveryCode::generate()?;
        let (rec, evolve_token, member) = virtual_device::create(
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
        // Device record first: mls-ds admits only registered devices as
        // members (createVirtualDevice may carry the membership).
        mb.create_device(&Device::from_public(&rec.public, now.clone()))?;
        mb.create_virtual_device(&VirtualDevice::from_bundle(
            &rec,
            wrap.as_ref(),
            now.clone(),
        ))?;
        mb.create_epoch_member(&EpochMember::from_record(&member, now))?;
        self.b.orf.register(
            &rec.public.device_key_pub,
            Some((&self.device.public().device_key_pub, &evolve_token)),
        )?;
        Ok(RecoverySetup {
            code,
            vdevice_id: rec.vdevice_id,
            evolve_token,
        })
    }

    /// Enroll a new device from a recovery code, correcting up to three
    /// typos (SPEC §6.1, §6.3). Forward-chains with the bundle's virtual
    /// device to the newest epoch it can reach, checks that against the
    /// published latest epoch (SPEC §10), then enrolls there.
    pub fn restore_with_recovery_code(
        did: &str,
        code_input: &str,
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        let lookup_err = RefCell::new(None);
        let found = virtual_device::find_code(code_input, did, |id| {
            match b.mailbox.get_virtual_device(id) {
                Ok(v) => v.is_some(),
                Err(e) => {
                    lookup_err.borrow_mut().get_or_insert(e);
                    false
                }
            }
        });
        if let Some(e) = lookup_err.into_inner() {
            return Err(e);
        }
        let code = found?;
        let bundle = b
            .mailbox
            .get_virtual_device(&code.derive(did).0)?
            .ok_or(Error::BadRecoveryCode)?;
        Self::restore_from_bundle(did, &bundle, &code, transport, b)
    }

    /// Enroll a new device from the passkey-wrapped code stored with the
    /// bundle for `credential_id`.
    pub fn restore_with_passkey(
        did: &str,
        prf_output: &[u8],
        credential_id: &[u8],
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        // Validate before listing records so an unknown credential cannot
        // turn a malformed PRF input into a credential-existence oracle.
        passkey::validate_prf_output(prf_output)?;
        let bundles = b.mailbox.list_virtual_devices()?;
        let candidates = select_passkey_bundles(did, prf_output, credential_id, &bundles)?;
        let mut prepared = None;
        let mut first_error = None;
        let now = b.clock.now_ms();
        for (bundle, code) in candidates {
            if vdevice_expiry_ms(Mechanism::Passkey, bundle)?.is_some_and(|exp| now >= exp) {
                prefer_passkey_error(&mut first_error, Error::Expired);
                continue;
            }
            match Self::prepare_restore_from_bundle(did, bundle, &code, &b) {
                Ok(_) if prepared.is_some() => return Err(Error::Conflict),
                Ok(candidate) => prepared = Some(candidate),
                // A bundle conclusively absent from the newest epoch or
                // expired by its recovery TTL may be skipped in favor of a
                // fresh active bundle. Any other preflight failure is
                // uncertainty about a potentially active matching bundle; do
                // not let another candidate hide a backend, attestation, or
                // chain-integrity failure.
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
        Self::finish_prepared_restore(did, prepared, transport, b)
    }

    fn restore_from_bundle(
        did: &str,
        bundle: &VirtualDevice,
        code: &RecoveryCode,
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        let prepared = Self::prepare_restore_from_bundle(did, bundle, code, &b)?;
        Self::finish_prepared_restore(did, prepared, transport, b)
    }

    /// Validate and open a bundle without touching it or creating device,
    /// membership, or ORF state. Passkey recovery uses this to ignore a
    /// retained revoked bundle while detecting multiple active matches
    /// before any candidate can cause a write.
    fn prepare_restore_from_bundle(
        did: &str,
        bundle: &VirtualDevice,
        code: &RecoveryCode,
        b: &Backends,
    ) -> Result<PreparedRestore> {
        let (record, _) = bundle.to_bundle()?;
        let vdev = b
            .mailbox
            .get_virtual_device(&record.vdevice_id)?
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
        let (id, start_record) = epoch_record(b.mailbox.as_ref(), seq)?;
        let start = PendingEpoch::new(seq, *restored.epoch.root()).assign_id(id);
        verify_public(&start, &start_record.public)?;
        // The forward walk verifies every later record against its
        // predecessor; the starting one needs its own signatures checked.
        start_record.public.verify(did, None)?;
        let reached = chain_forward(
            b.mailbox.as_ref(),
            did,
            start,
            restored.device.public(),
            &restored.device.storage,
            &Default::default(),
        )?;
        let latest = reached.last().expect("non-empty");
        let latest_public = verified_own(b.mailbox.as_ref(), b.directory.as_ref(), did, latest)?;
        check_candidate_integrity(
            b.mailbox.as_ref(),
            b.directory.as_ref(),
            did,
            latest.seq,
            &latest_public.head,
        )?;
        Ok(PreparedRestore {
            record,
            restored,
            reached,
            latest_public,
        })
    }

    fn finish_prepared_restore(
        did: &str,
        prepared: PreparedRestore,
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        let PreparedRestore {
            record,
            restored,
            reached,
            latest_public,
        } = prepared;
        let latest = reached.last().expect("non-empty");
        let (device, public, evolve_token, member) =
            virtual_device::enroll_from_virtual(&restored, latest)?;
        let now = datetime_from_ms(b.clock.now_ms());
        let binding = ChatBinding::sign(did, &public.device_key_pub, transport.as_ref());
        b.mailbox
            .create_device(&Device::bound(&public, &binding, now.clone()))?;
        b.mailbox
            .create_epoch_member(&EpochMember::from_record(&member, now))?;
        // [CB-39] The bundle was used: keep it from expiring. Run after
        // `create_device` + `create_epoch_member` so the recovering chat device
        // is already bound (`touchVirtualDevice` requires a bound device).
        match b.mailbox.touch_virtual_device(&record.vdevice_id) {
            Ok(()) | Err(Error::NotSupported(_)) => {}
            Err(e) => return Err(e),
        }
        b.orf.register(
            &public.device_key_pub,
            Some((&restored.device.public().device_key_pub, &evolve_token)),
        )?;
        let mut me = Self::assemble(
            did,
            device,
            transport,
            b,
            restored.mailbox_root_salt,
            reached,
        )?;
        me.adopted(latest_public);
        Ok((
            me,
            Enrollment {
                device_key: public.device_key_pub,
                evolve_token,
            },
        ))
    }

    /// Existing device: start offering a one-time code (show
    /// `responder.code()` to the user).
    pub fn otc_offer(&self) -> Result<Responder> {
        Responder::generate(&self.did)
    }

    /// Existing device: answer the new device's CPace message and send it
    /// the sealed enrollment payload for the current epoch (SPEC §6.5).
    pub fn otc_respond(
        &mut self,
        responder: &mut Responder,
        msg: &InitiatorMessage,
    ) -> Result<OtcResponse> {
        self.sync_epochs()?;
        let (message, isk) = responder.respond(msg, b"")?;
        let epoch = self.epoch_secret(self.latest)?;
        let (payload, evolve_token) =
            OtcPayload::create(&self.device, &epoch, &self.mailbox_root_salt)?;
        self.b.orf.register(
            &otc_temp_orf_id(&isk),
            Some((&self.device.public().device_key_pub, &evolve_token)),
        )?;
        Ok(OtcResponse {
            message,
            sealed_payload: payload.seal(&isk)?,
            evolve_token,
        })
    }

    /// New device: start a one-time-code session with the code the user
    /// typed.
    pub fn otc_start(did: &str, code_input: &str) -> Result<(Initiator, InitiatorMessage)> {
        Initiator::start(&OneTimeCode::parse(code_input)?, did, b"")
    }

    /// New device: finish the session, open the payload and enroll into
    /// the transferred epoch (after checking it against the store).
    pub fn enroll_via_otc(
        did: &str,
        initiator: Initiator,
        response: &ResponderMessage,
        sealed_payload: &[u8],
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        let isk = initiator.finish(response)?;
        let payload = OtcPayload::open(&isk, sealed_payload)?;
        let epoch: &EpochSecret = &payload.epoch;
        let epoch_public = verified_own(b.mailbox.as_ref(), b.directory.as_ref(), did, epoch)?;
        check_candidate_integrity(
            b.mailbox.as_ref(),
            b.directory.as_ref(),
            did,
            epoch.seq,
            &epoch_public.head,
        )?;
        let (device, public, evolve_token, member) = payload.enroll()?;
        let now = datetime_from_ms(b.clock.now_ms());
        let binding = ChatBinding::sign(did, &public.device_key_pub, transport.as_ref());
        b.mailbox
            .create_device(&Device::bound(&public, &binding, now.clone()))?;
        b.mailbox
            .create_epoch_member(&EpochMember::from_record(&member, now))?;
        let temp = otc_temp_orf_id(&isk);
        b.orf
            .register(&public.device_key_pub, Some((&temp, &evolve_token)))?;
        b.orf.delete(&temp)?;
        let mut me = Self::assemble(
            did,
            device,
            transport,
            b,
            payload.mailbox_root_salt,
            [payload.epoch.clone()],
        )?;
        me.adopted(epoch_public);
        Ok((
            me,
            Enrollment {
                device_key: public.device_key_pub,
                evolve_token,
            },
        ))
    }
}

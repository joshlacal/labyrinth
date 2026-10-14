//! Adding devices: recovery codes, passkey-wrapped codes and one-time
//! codes (SPEC §6).

use std::cell::RefCell;

use super::epochs::{chain_forward, check_integrity, epoch_record, verified_own};
use super::{Backends, Labyrinth};
use crate::device::ChatBinding;
use crate::epoch::{EpochKeys as _, EpochSecret, PendingEpoch, verify_public};
use crate::orf::EvolveToken;
use crate::otc::{Initiator, InitiatorMessage, OneTimeCode, Responder, ResponderMessage};
use crate::records::mailbox::PasskeyWrap;
use crate::records::{Device, EpochMember, VirtualDevice, datetime_from_ms};
use crate::recovery_code::RecoveryCode;
use crate::sign::{TransportSigner, XVerifyingKey};
use crate::virtual_device::{self, Mechanism, OtcPayload, passkey};
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
        for bundle in b.mailbox.list_virtual_devices()? {
            let Some(wrap) = bundle.to_bundle()?.1 else {
                continue;
            };
            if wrap.credential_id == credential_id {
                let code = passkey::unwrap_code(prf_output, &wrap.wrapped_code)?;
                return Self::restore_from_bundle(did, &bundle, &code, transport, b);
            }
        }
        Err(Error::NotFound("passkey bundle"))
    }

    fn restore_from_bundle(
        did: &str,
        bundle: &VirtualDevice,
        code: &RecoveryCode,
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<(Self, Enrollment)> {
        let (record, _) = bundle.to_bundle()?;
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
        check_integrity(b.directory.as_ref(), did, latest.seq, &latest_public.head)?;
        // [CB-39] The bundle was used: keep it from expiring. Before any
        // write, so a failure leaves nothing half-enrolled.
        match b.mailbox.touch_virtual_device(&record.vdevice_id) {
            Ok(()) | Err(Error::NotSupported(_)) => {}
            Err(e) => return Err(e),
        }

        let (device, public, evolve_token, member) =
            virtual_device::enroll_from_virtual(&restored, latest)?;
        let now = datetime_from_ms(b.clock.now_ms());
        let binding = ChatBinding::sign(did, &public.device_key_pub, transport.as_ref());
        b.mailbox
            .create_device(&Device::bound(&public, &binding, now.clone()))?;
        b.mailbox
            .create_epoch_member(&EpochMember::from_record(&member, now))?;
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
        check_integrity(b.directory.as_ref(), did, epoch.seq, &epoch_public.head)?;
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

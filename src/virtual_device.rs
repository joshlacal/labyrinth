//! Virtual devices: recovery bundles unlocked by a recovery code
//! (SPEC §6.2–6.5, paper p.32–36, p.43–45).
//!
//! - [`create`] builds a bundle from an enrolled physical device.
//! - [`find_code`] corrects typos using [`RecoveryCode::candidates`].
//! - [`open`] decrypts a bundle; [`enroll_from_virtual`] makes the new
//!   physical device.
//! - [`passkey`] wraps the code under a WebAuthn PRF output ([CB-13]).
//! - [`otc_payload`] carries the same secrets over a one-time-code session.

pub mod otc_payload;
pub mod passkey;

pub use otc_payload::OtcPayload;

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::aead::{self, Suite};
use crate::device::{DevicePublic, DeviceSecrets};
use crate::encoding::b64_decimal;
use crate::epoch::{
    EpochKeys, EpochMemberRecord, EpochSecret, PendingEpoch, member_record, parse_seq,
};
use crate::hpke::labyrinth::X25519Secret;
use crate::orf::{EvolveToken, OrfClientState, orf_client_evolve};
use crate::recovery_code::RecoveryCode;
use crate::sign::XSigningKey;
use crate::{Error, Result};

/// AAD strings from paper p.33 (SPEC §6.2).
pub mod aad {
    pub const DEVICE_KEY: &[u8] = b"virtual_device:virtual_device_private_key";
    pub const STORAGE_KEY: &[u8] = b"virtual_device:epoch_storage_private_key";
    pub const ORF_STATE: &[u8] = b"virtual_device:ocmf_client_state";
    pub const MAILBOX_ROOT_SALT: &[u8] = b"virtual_device:mailbox_root_key";
    pub const EPOCH_ROOT: &[u8] = b"virtual_device:epoch_root_key";
    pub const EPOCH_SEQ: &[u8] = b"virtual_device:epoch_anon_id";
}

/// Which recovery mechanism a bundle backs (lexicon `mechanism`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    Code,
    Passkey,
    Keychain,
    Otc,
}

impl Mechanism {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Passkey => "passkey",
            Self::Keychain => "keychain",
            Self::Otc => "otc",
        }
    }

    /// Inverse of [`as_str`](Self::as_str).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "code" => Ok(Self::Code),
            "passkey" => Ok(Self::Passkey),
            "keychain" => Ok(Self::Keychain),
            "otc" => Ok(Self::Otc),
            _ => Err(Error::Malformed("unknown recovery mechanism")),
        }
    }
}

/// The published bundle (`blue.catbird.labyrinth.virtualDevice`, rkey =
/// `hex(vdevice_id)`). Every `encrypted_*` field is sealed under
/// `vdeviceDecryptionKey` with the matching [`aad`] string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualDeviceRecord {
    pub vdevice_id: [u8; 16],
    pub public: DevicePublic,
    pub encrypted_device_key_priv: Vec<u8>,
    pub encrypted_epoch_storage_key_priv: Vec<u8>,
    pub encrypted_orf_client_state: Vec<u8>,
    pub encrypted_mailbox_root_salt: Vec<u8>,
    pub encrypted_epoch_root_key: Vec<u8>,
    /// Sealed `base64(decimal(seq))`.
    pub encrypted_epoch_number: Vec<u8>,
    pub mechanism: Mechanism,
}

/// What a recovery code unlocks.
pub struct RestoredState {
    /// The virtual device (its ORF client state is `device.orf`).
    pub device: DeviceSecrets,
    pub mailbox_root_salt: [u8; 32],
    /// The epoch the bundle was made in; the caller looks up its `epochID`
    /// on the backend by sequence number and calls `assign_id`.
    pub epoch: PendingEpoch,
}

/// Create a virtual device from the enrolled physical device `me` in
/// epoch `current` (p.32–34).
///
/// Returns the record to publish, the evolve token for the ORF server
/// (`vdeviceServerState = orf_server_evolve(token, me's server state)`),
/// and the virtual device's membership of `current`. The caller must then
/// delete `code` and every virtual-device secret ([`RecoveryCode`] zeroizes
/// on drop).
pub fn create(
    did: &str,
    code: &RecoveryCode,
    me: &DeviceSecrets,
    current: &EpochSecret,
    mailbox_root_salt: &[u8; 32],
    mechanism: Mechanism,
) -> Result<(VirtualDeviceRecord, EvolveToken, EpochMemberRecord)> {
    if me.is_virtual() {
        return Err(Error::Malformed("virtual devices cannot create bundles"));
    }
    let (vorf, token) = orf_client_evolve(&me.orf)?;
    let v = DeviceSecrets::generate_virtual(vorf)?;
    let (vdevice_id, key) = code.derive(did);
    let seal = |aad: &[u8], pt: &[u8]| aead::seal(&key, aad, pt);
    let record = VirtualDeviceRecord {
        vdevice_id,
        public: v.public().clone(),
        encrypted_device_key_priv: seal(
            aad::DEVICE_KEY,
            Zeroizing::new(v.device_key.to_bytes()).as_slice(),
        )?,
        encrypted_epoch_storage_key_priv: seal(
            aad::STORAGE_KEY,
            Zeroizing::new(v.storage.to_bytes()).as_slice(),
        )?,
        encrypted_orf_client_state: seal(
            aad::ORF_STATE,
            Zeroizing::new(v.orf.to_bytes()).as_slice(),
        )?,
        encrypted_mailbox_root_salt: seal(aad::MAILBOX_ROOT_SALT, mailbox_root_salt)?,
        encrypted_epoch_root_key: seal(aad::EPOCH_ROOT, current.root())?,
        encrypted_epoch_number: seal(aad::EPOCH_SEQ, b64_decimal(current.seq).as_bytes())?,
        mechanism,
    };
    let member = member_record(current, &v.public().device_key_pub, None);
    Ok((record, token, member))
}

/// Find the typo-corrected code whose `vdeviceId` the backend knows
/// (paper p.31). `exists` is the backend lookup.
pub fn find_code(
    input: &str,
    did: &str,
    mut exists: impl FnMut(&[u8; 16]) -> bool,
) -> Result<RecoveryCode> {
    RecoveryCode::candidates(input)?
        .find(|c| exists(&c.derive(did).0))
        .ok_or(Error::BadRecoveryCode)
}

fn open32(key: &[u8; 32], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let pt = Zeroizing::new(aead::decrypt_suite(Suite::DndkGcm, key, aad, ct)?);
    let mut out = Zeroizing::new([0u8; 32]);
    if pt.len() != 32 {
        return Err(Error::Malformed("virtual device field length"));
    }
    out.copy_from_slice(&pt);
    Ok(out)
}

/// Decrypt a bundle with a recovery code (p.35 step a).
pub fn open(record: &VirtualDeviceRecord, code: &RecoveryCode, did: &str) -> Result<RestoredState> {
    let (vdevice_id, key) = code.derive(did);
    if vdevice_id != record.vdevice_id {
        return Err(Error::BadRecoveryCode);
    }
    if !record.public.is_virtual {
        return Err(Error::Malformed("bundle device is not virtual"));
    }
    let device_key = XSigningKey::from_bytes(*open32(
        &key,
        aad::DEVICE_KEY,
        &record.encrypted_device_key_priv,
    )?);
    let storage = X25519Secret::from_bytes(*open32(
        &key,
        aad::STORAGE_KEY,
        &record.encrypted_epoch_storage_key_priv,
    )?);
    let orf = OrfClientState::from_bytes(*open32(
        &key,
        aad::ORF_STATE,
        &record.encrypted_orf_client_state,
    )?)?;
    let salt = open32(
        &key,
        aad::MAILBOX_ROOT_SALT,
        &record.encrypted_mailbox_root_salt,
    )?;
    let root = open32(&key, aad::EPOCH_ROOT, &record.encrypted_epoch_root_key)?;
    let seq_b64 = Zeroizing::new(aead::decrypt_suite(
        Suite::DndkGcm,
        &key,
        aad::EPOCH_SEQ,
        &record.encrypted_epoch_number,
    )?);
    let seq_dec = base64::engine::general_purpose::STANDARD
        .decode(seq_b64.as_slice())
        .map_err(|_| Error::Malformed("epoch number is not base64"))?;
    let seq = parse_seq(&seq_dec)?;
    let device = DeviceSecrets::from_parts(device_key, storage, None, orf, record.public.clone())?;
    Ok(RestoredState {
        device,
        mailbox_root_salt: *salt,
        epoch: PendingEpoch::new(seq, *root),
    })
}

/// Enroll a new physical device from a restored virtual device (p.35
/// step b): fresh keys, the ORF state evolved from the virtual device's,
/// and a MAC in `latest` (the newest epoch the caller reached by forward
/// chaining with the virtual device, or the bundle's own epoch).
///
/// The caller publishes the device record, member record and evolve token
/// (`orf_server_evolve(token, vdevice server state)`), then deletes the
/// code and `restored`.
pub fn enroll_from_virtual(
    restored: &RestoredState,
    latest: &impl EpochKeys,
) -> Result<(DeviceSecrets, DevicePublic, EvolveToken, EpochMemberRecord)> {
    enroll_from_orf(&restored.device.orf, latest)
}

pub(crate) fn enroll_from_orf(
    orf: &OrfClientState,
    latest: &impl EpochKeys,
) -> Result<(DeviceSecrets, DevicePublic, EvolveToken, EpochMemberRecord)> {
    let (state, token) = orf_client_evolve(orf)?;
    let me = DeviceSecrets::generate_physical(state)?;
    let public = me.public().clone();
    let member = member_record(latest, &public.device_key_pub, None);
    Ok((me, public, token, member))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::verify_member;

    fn setup() -> (DeviceSecrets, EpochSecret, RecoveryCode) {
        (
            DeviceSecrets::generate().unwrap(),
            EpochSecret::from_parts(2, "e2", [4u8; 32]),
            RecoveryCode::generate().unwrap(),
        )
    }

    #[test]
    fn create_open_round_trip() {
        let did = "did:plc:vdev";
        let (me, epoch, code) = setup();
        let (rec, _t, member) =
            create(did, &code, &me, &epoch, &[6u8; 32], Mechanism::Code).unwrap();
        verify_member(&epoch, &member).unwrap();
        let r = open(&rec, &code, did).unwrap();
        assert_eq!(r.mailbox_root_salt, [6u8; 32]);
        assert_eq!(r.epoch.seq(), 2);
        assert_eq!(r.epoch.root(), &[4u8; 32]);
        assert_eq!(r.device.public(), &rec.public);
        assert!(open(&rec, &code, "did:plc:other").is_err());
        assert!(open(&rec, &RecoveryCode::generate().unwrap(), did).is_err());
    }

    #[test]
    fn every_encrypted_field_is_bound_to_its_aad() {
        let did = "did:plc:vdev";
        let (me, epoch, code) = setup();
        let (rec, _, _) = create(did, &code, &me, &epoch, &[6u8; 32], Mechanism::Code).unwrap();
        // Swapping any two sealed fields fails (AADs differ), as does a flipped byte.
        fn field(r: &mut VirtualDeviceRecord, i: usize) -> &mut Vec<u8> {
            match i {
                0 => &mut r.encrypted_device_key_priv,
                1 => &mut r.encrypted_epoch_storage_key_priv,
                2 => &mut r.encrypted_orf_client_state,
                3 => &mut r.encrypted_mailbox_root_salt,
                4 => &mut r.encrypted_epoch_root_key,
                _ => &mut r.encrypted_epoch_number,
            }
        }
        for i in 0..6 {
            let mut bad = rec.clone();
            field(&mut bad, i)[10] ^= 1;
            assert!(open(&bad, &code, did).is_err(), "flip {i}");
            for j in (0..6).filter(|&j| j != i) {
                let mut bad = rec.clone();
                let a = field(&mut bad, i).clone();
                let b = core::mem::replace(field(&mut bad, j), a);
                *field(&mut bad, i) = b;
                assert!(open(&bad, &code, did).is_err(), "swap {i} {j}");
            }
        }
        let mut bad = rec.clone();
        bad.public.sig_0x30[0] ^= 1;
        assert!(open(&bad, &code, did).is_err());
    }

    #[test]
    fn enroll_evolves_orf() {
        let did = "did:plc:vdev";
        let (me, epoch, code) = setup();
        let (rec, _, _) = create(did, &code, &me, &epoch, &[6u8; 32], Mechanism::Code).unwrap();
        let r = open(&rec, &code, did).unwrap();
        let (dev, public, _t, member) = enroll_from_virtual(&r, &r.epoch).unwrap();
        assert!(!dev.is_virtual());
        public.verify().unwrap();
        verify_member(&r.epoch, &member).unwrap();
        assert_ne!(dev.orf.to_bytes(), r.device.orf.to_bytes());
    }

    #[test]
    fn bundle_fields_refuse_the_v10_suite() {
        let did = "did:plc:vdev";
        let (me, epoch, code) = setup();
        let (rec, _, _) = create(did, &code, &me, &epoch, &[6u8; 32], Mechanism::Code).unwrap();
        let (_, key) = code.derive(did);
        let mut bad = rec.clone();
        bad.encrypted_device_key_priv = aead::encrypt(
            Suite::GcmExtended,
            &key,
            aad::DEVICE_KEY,
            &me.device_key.to_bytes(),
        )
        .unwrap();
        assert_eq!(open(&bad, &code, did).err(), Some(Error::Unsupported(0x01)));
        let mut bad = rec.clone();
        bad.encrypted_epoch_number =
            aead::encrypt(Suite::GcmExtended, &key, aad::EPOCH_SEQ, b"Mg==").unwrap();
        assert_eq!(open(&bad, &code, did).err(), Some(Error::Unsupported(0x01)));
    }
}

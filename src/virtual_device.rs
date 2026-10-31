//! Virtual devices: recovery bundles unlocked by a recovery code
//! (SPEC §6.2–6.5, Gate 2, `I16`, `2A` ORF retired).

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
use crate::hpke::hawk::{HAWK_ENC_SECRET_LEN, HawkEncSecret};
use crate::recovery_code::RecoveryCode;
use crate::sign::XSigningKey;
use crate::{Error, Result};

/// AAD strings from paper p.33 (SPEC §6.2).
pub mod aad {
    pub const DEVICE_KEY: &[u8] = b"virtual_device:virtual_device_private_key";
    pub const STORAGE_KEY: &[u8] = b"virtual_device:epoch_storage_private_key";
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
/// `hex(vdevice_id)`). `encrypted_epoch_storage_key_priv` seals the 96-byte
/// [`HawkEncSecret`] (`I16`); `ORF` is retired (`2A`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualDeviceRecord {
    pub vdevice_id: [u8; 16],
    pub public: DevicePublic,
    pub encrypted_device_key_priv: Vec<u8>,
    pub encrypted_epoch_storage_key_priv: Vec<u8>,
    pub encrypted_mailbox_root_salt: Vec<u8>,
    pub encrypted_epoch_root_key: Vec<u8>,
    /// Sealed `base64(decimal(seq))`.
    pub encrypted_epoch_number: Vec<u8>,
    pub mechanism: Mechanism,
}

/// What a recovery code unlocks.
pub struct RestoredState {
    pub device: DeviceSecrets,
    pub mailbox_root_salt: [u8; 32],
    /// The epoch the bundle was made in.
    pub epoch: PendingEpoch,
}

/// Create a virtual device from the enrolled physical device `me` in
/// epoch `current` (`I16` 96-byte `HawkEncSecret`, `0x32` virtual tag).
pub fn create(
    did: &str,
    code: &RecoveryCode,
    me: &DeviceSecrets,
    current: &EpochSecret,
    mailbox_root_salt: &[u8; 32],
    mechanism: Mechanism,
) -> Result<(VirtualDeviceRecord, EpochMemberRecord)> {
    if me.is_virtual() {
        return Err(Error::Malformed("virtual devices cannot create bundles"));
    }
    let v = DeviceSecrets::generate_virtual()?;
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
        encrypted_mailbox_root_salt: seal(aad::MAILBOX_ROOT_SALT, mailbox_root_salt)?,
        encrypted_epoch_root_key: seal(aad::EPOCH_ROOT, current.root())?,
        encrypted_epoch_number: seal(aad::EPOCH_SEQ, b64_decimal(current.seq).as_bytes())?,
        mechanism,
    };
    let member = member_record(current, &v.public().device_key_pub, true, None);
    Ok((record, member))
}

/// Find the typo-corrected code whose `vdeviceId` the backend knows.
pub fn find_code(
    input: &str,
    did: &str,
    mut exists: impl FnMut(&[u8; 16]) -> bool,
) -> Result<RecoveryCode> {
    RecoveryCode::candidates(input)?
        .find(|c| exists(&c.derive(did).0))
        .ok_or(Error::BadRecoveryCode)
}

fn open_fixed<const N: usize>(key: &[u8; 32], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<[u8; N]>> {
    let pt = Zeroizing::new(aead::decrypt_suite(Suite::DndkGcm, key, aad, ct)?);
    let mut out = Zeroizing::new([0u8; N]);
    if pt.len() != N {
        return Err(Error::Malformed("virtual device field length"));
    }
    out.copy_from_slice(&pt);
    Ok(out)
}

/// Decrypt a bundle with a recovery code.
pub fn open(record: &VirtualDeviceRecord, code: &RecoveryCode, did: &str) -> Result<RestoredState> {
    let (vdevice_id, key) = code.derive(did);
    if vdevice_id != record.vdevice_id {
        return Err(Error::BadRecoveryCode);
    }
    if !record.public.is_virtual {
        return Err(Error::DeviceTampered);
    }
    let device_key = XSigningKey::from_bytes(*open_fixed::<32>(
        &key,
        aad::DEVICE_KEY,
        &record.encrypted_device_key_priv,
    )?);
    let storage = HawkEncSecret::from_bytes(*open_fixed::<HAWK_ENC_SECRET_LEN>(
        &key,
        aad::STORAGE_KEY,
        &record.encrypted_epoch_storage_key_priv,
    )?);
    let salt = open_fixed::<32>(
        &key,
        aad::MAILBOX_ROOT_SALT,
        &record.encrypted_mailbox_root_salt,
    )?;
    let root = open_fixed::<32>(&key, aad::EPOCH_ROOT, &record.encrypted_epoch_root_key)?;
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
    let device = DeviceSecrets::from_parts(device_key, storage, None, record.public.clone())?;
    Ok(RestoredState {
        device,
        mailbox_root_salt: *salt,
        epoch: PendingEpoch::new(seq, *root),
    })
}

/// Generate a fresh physical device and membership record for `latest`.
/// Note: in Clean-Slate Gate 3, recovery enrollment uses atomic `E -> E+1`
/// rotation via [`crate::epoch::open::open_next_enrolling`].
pub fn enroll_from_virtual(
    _restored: &RestoredState,
    latest: &impl EpochKeys,
) -> Result<(DeviceSecrets, DevicePublic, EpochMemberRecord)> {
    let me = DeviceSecrets::generate_physical()?;
    let public = me.public().clone();
    let member = member_record(latest, &public.device_key_pub, false, None);
    Ok((me, public, member))
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
        let (rec, member) = create(did, &code, &me, &epoch, &[6u8; 32], Mechanism::Code).unwrap();
        verify_member(&epoch, &member, true).unwrap();
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
        let (rec, _) = create(did, &code, &me, &epoch, &[6u8; 32], Mechanism::Code).unwrap();
        fn field(r: &mut VirtualDeviceRecord, i: usize) -> &mut Vec<u8> {
            match i {
                0 => &mut r.encrypted_device_key_priv,
                1 => &mut r.encrypted_epoch_storage_key_priv,
                2 => &mut r.encrypted_mailbox_root_salt,
                3 => &mut r.encrypted_epoch_root_key,
                _ => &mut r.encrypted_epoch_number,
            }
        }
        for i in 0..5 {
            let mut bad = rec.clone();
            field(&mut bad, i)[10] ^= 1;
            assert!(open(&bad, &code, did).is_err(), "flip {i}");
            for j in (0..5).filter(|&j| j != i) {
                let mut bad = rec.clone();
                let a = field(&mut bad, i).clone();
                let b = core::mem::replace(field(&mut bad, j), a);
                *field(&mut bad, i) = b;
                assert!(open(&bad, &code, did).is_err(), "swap {i} {j}");
            }
        }
        let mut bad = rec;
        bad.public.sig_storage[0] ^= 1;
        assert!(open(&bad, &code, did).is_err());
    }
}

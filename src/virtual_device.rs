//! Virtual devices: recovery bundles unlocked by a recovery code
//! (SPEC §6.2–6.5, Gate 2, `I16`, `2A` ORF retired).

pub mod otc_payload;
pub mod passkey;

pub use otc_payload::OtcPayload;

/// Serialized `virtualDevice` record format after the clean-slate salt removal.
pub const RECORD_FORMAT_VERSION: u8 = 0x02;

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::aead::{self, Suite};
use crate::device::{DevicePublic, DeviceSecrets};
use crate::encoding::b64_decimal;
use crate::epoch::{
    EpochKeys, EpochMemberRecord, EpochSecret, PendingEpoch, member_record, parse_seq,
};
use crate::hpke::hawk::{HAWK_ENC_SECRET_LEN, HawkEncSecret};
use crate::recovery_code::{CodeVersion, RecoveryCode};
use crate::recovery_share::RecoveryShare;
use crate::sign::XSigningKey;
use crate::{Error, Result};

/// AAD strings from paper p.33 (SPEC §6.2).
pub mod aad {
    pub const DEVICE_KEY: &[u8] = b"virtual_device:virtual_device_private_key";
    pub const STORAGE_KEY: &[u8] = b"virtual_device:epoch_storage_private_key";
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
    pub encrypted_epoch_root_key: Vec<u8>,
    /// Sealed `base64(decimal(seq))`.
    pub encrypted_epoch_number: Vec<u8>,
    pub mechanism: Mechanism,
    /// When `Some`, `(did, vdevice_id, mechanism, created_at)` is bound into
    /// all four field AADs and signed in `metadata_sig` by `public.device_key_pub`.
    pub bound_created_at: Option<String>,
    /// XEdDSA signature by `public.device_key_pub` over the bundle metadata.
    pub metadata_sig: Option<[u8; 64]>,
}

const METADATA_SIG_PREFIX: &str = "catbird.labyrinth.virtual_device_meta_v2:";
const DNDK_OVERHEAD: usize = 1 + 24 + 16 + 32;

fn bundle_aad(
    base: &[u8],
    did: &str,
    vdevice_id: &[u8; 16],
    mechanism: Mechanism,
    created_at: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(base.len() + did.len() + 96);
    out.extend_from_slice(base);
    out.extend_from_slice(b"|v2|did=");
    out.extend_from_slice(did.as_bytes());
    out.extend_from_slice(b"|vid=");
    out.extend_from_slice(hex::encode(vdevice_id).as_bytes());
    out.extend_from_slice(b"|mech=");
    out.extend_from_slice(mechanism.as_str().as_bytes());
    if let Some(ts) = created_at {
        out.extend_from_slice(b"|created=");
        out.extend_from_slice(ts.as_bytes());
    }
    out
}

fn bundle_metadata_message(
    did: &str,
    vdevice_id: &[u8; 16],
    mechanism: Mechanism,
    created_at: &str,
) -> Vec<u8> {
    format!(
        "{METADATA_SIG_PREFIX}{did}:{}:{}:{created_at}",
        hex::encode(vdevice_id),
        mechanism.as_str()
    )
    .into_bytes()
}

impl VirtualDeviceRecord {
    /// Verifies public keys, AEAD suite tags, ciphertext field lengths, and
    /// `metadata_sig` (when `did` is provided and `metadata_sig` is present)
    /// without needing the recovery code.
    pub fn validate_shape(&self, did: Option<&str>) -> Result<()> {
        if !self.public.is_virtual {
            return Err(Error::DeviceTampered);
        }
        self.public.verify()?;
        let check_ct = |ct: &[u8], min_pt: usize, max_pt: usize| -> Result<()> {
            if ct.first() != Some(&(Suite::DndkGcm as u8)) {
                return Err(Error::Malformed("virtual device ciphertext suite"));
            }
            let min_len = DNDK_OVERHEAD + min_pt;
            let max_len = DNDK_OVERHEAD + max_pt;
            if ct.len() < min_len || ct.len() > max_len {
                return Err(Error::Malformed("virtual device ciphertext length"));
            }
            Ok(())
        };
        check_ct(&self.encrypted_device_key_priv, 32, 32)?;
        check_ct(
            &self.encrypted_epoch_storage_key_priv,
            HAWK_ENC_SECRET_LEN,
            HAWK_ENC_SECRET_LEN,
        )?;
        check_ct(&self.encrypted_epoch_root_key, 32, 32)?;
        // `b64_decimal(0)` is 4 bytes ("MA=="); 11 decimal digits base64-encode to 16 bytes.
        check_ct(&self.encrypted_epoch_number, 4, 24)?;
        match (&self.bound_created_at, &self.metadata_sig) {
            (Some(ts), Some(sig)) => {
                let _ = crate::records::ms_from_datetime(ts)?;
                if let Some(did) = did {
                    self.public.device_key_pub.verify(
                        &bundle_metadata_message(did, &self.vdevice_id, self.mechanism, ts),
                        sig,
                    )?;
                }
            }
            (None, None) => {}
            _ => {
                return Err(Error::Malformed(
                    "virtual device metadata signature presence",
                ));
            }
        }
        Ok(())
    }
}

/// What a recovery code unlocks.
pub struct RestoredState {
    pub device: DeviceSecrets,
    /// The epoch the bundle was made in.
    pub epoch: PendingEpoch,
}

/// Seal a pre-generated virtual device `v` into a [`VirtualDeviceRecord`] for
/// `epoch`, binding `(did, vdevice_id, mechanism, created_at)` into every field
/// AAD and signing metadata when `created_at` is `Some`.
pub fn seal_virtual_device(
    did: &str,
    code: &RecoveryCode,
    v: &DeviceSecrets,
    epoch: &impl EpochKeys,
    mechanism: Mechanism,
    created_at: Option<&str>,
) -> Result<VirtualDeviceRecord> {
    seal_virtual_device_with_share(did, code, None, v, epoch, mechanism, created_at)
}

/// [`seal_virtual_device`] for a code of either version: a version-3 code
/// needs its erasable `share`, a version-2 code takes none. The record
/// format is the same for both.
pub fn seal_virtual_device_with_share(
    did: &str,
    code: &RecoveryCode,
    share: Option<&RecoveryShare>,
    v: &DeviceSecrets,
    epoch: &impl EpochKeys,
    mechanism: Mechanism,
    created_at: Option<&str>,
) -> Result<VirtualDeviceRecord> {
    if !v.is_virtual() {
        return Err(Error::DeviceTampered);
    }
    if let Some(ts) = created_at {
        let _ = crate::records::ms_from_datetime(ts)?;
    }
    let (vdevice_id, key) = code.bundle_key(did, share)?;
    let seal = |base: &[u8], pt: &[u8]| {
        let aad = bundle_aad(base, did, &vdevice_id, mechanism, created_at);
        aead::seal(&key, &aad, pt)
    };
    let metadata_sig = match created_at {
        Some(ts) => {
            Some(
                v.device_key
                    .sign(&bundle_metadata_message(did, &vdevice_id, mechanism, ts))?,
            )
        }
        None => None,
    };
    Ok(VirtualDeviceRecord {
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
        encrypted_epoch_root_key: seal(aad::EPOCH_ROOT, epoch.root())?,
        encrypted_epoch_number: seal(aad::EPOCH_SEQ, b64_decimal(epoch.seq()).as_bytes())?,
        mechanism,
        bound_created_at: created_at.map(str::to_owned),
        metadata_sig,
    })
}

/// Create a virtual device from the enrolled physical device `me` in
/// epoch `current` (`I16` 96-byte `HawkEncSecret`, `0x32` virtual tag).
pub fn create(
    did: &str,
    code: &RecoveryCode,
    me: &DeviceSecrets,
    current: &EpochSecret,
    mechanism: Mechanism,
) -> Result<(VirtualDeviceRecord, EpochMemberRecord)> {
    create_inner(did, code, me, current, mechanism, None)
}

/// Create a virtual device from `me` in `current`, binding `created_at` into
/// every field AAD and signing `(did, vdevice_id, mechanism, created_at)`.
pub fn create_at(
    did: &str,
    code: &RecoveryCode,
    me: &DeviceSecrets,
    current: &EpochSecret,
    mechanism: Mechanism,
    created_at: &str,
) -> Result<(VirtualDeviceRecord, EpochMemberRecord)> {
    create_inner(did, code, me, current, mechanism, Some(created_at))
}

fn create_inner(
    did: &str,
    code: &RecoveryCode,
    me: &DeviceSecrets,
    current: &EpochSecret,
    mechanism: Mechanism,
    created_at: Option<&str>,
) -> Result<(VirtualDeviceRecord, EpochMemberRecord)> {
    if me.is_virtual() {
        return Err(Error::Malformed("virtual devices cannot create bundles"));
    }
    let v = DeviceSecrets::generate_virtual()?;
    let record = seal_virtual_device(did, code, &v, current, mechanism, created_at)?;
    let member = member_record(current, &v.public().device_key_pub, true, None);
    Ok((record, member))
}

/// Find the typo-corrected code whose `vdeviceId` the backend knows.
///
/// The version character sits outside the ECC word, so when the code as
/// typed matches nothing, every supported version is tried as well. A
/// well-formed code with an unsupported version that matches nothing fails
/// with [`Error::UnsupportedCodeVersion`].
pub fn find_code(
    input: &str,
    did: &str,
    mut exists: impl FnMut(&[u8; 16]) -> bool,
) -> Result<RecoveryCode> {
    let first_error = match RecoveryCode::candidates(input) {
        Ok(mut c) => {
            if let Some(code) = c.find(|c| exists(&c.vdevice_id(did))) {
                return Ok(code);
            }
            Error::BadRecoveryCode
        }
        Err(e @ (Error::UnsupportedCodeVersion | Error::BadRecoveryCode)) => e,
        Err(e) => return Err(e),
    };
    for version in [CodeVersion::V2, CodeVersion::V3] {
        if let Ok(mut c) = RecoveryCode::candidates_as(input, version)
            && let Some(code) = c.find(|c| exists(&c.vdevice_id(did)))
        {
            return Ok(code);
        }
    }
    Err(first_error)
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

/// Decrypt a bundle with a version-2 recovery code.
pub fn open(record: &VirtualDeviceRecord, code: &RecoveryCode, did: &str) -> Result<RestoredState> {
    open_with_share(record, code, None, did)
}

/// Decrypt a bundle with a recovery code of either version; a version-3 code
/// needs its erasable `share`.
pub fn open_with_share(
    record: &VirtualDeviceRecord,
    code: &RecoveryCode,
    share: Option<&RecoveryShare>,
    did: &str,
) -> Result<RestoredState> {
    if code.vdevice_id(did) != record.vdevice_id {
        return Err(Error::BadRecoveryCode);
    }
    let (_, key) = code.bundle_key(did, share)?;
    if !record.public.is_virtual {
        return Err(Error::DeviceTampered);
    }
    record.validate_shape(Some(did))?;
    let created_at = record.bound_created_at.as_deref();
    let aad_of =
        |base: &[u8]| bundle_aad(base, did, &record.vdevice_id, record.mechanism, created_at);
    let device_key = XSigningKey::from_bytes(*open_fixed::<32>(
        &key,
        &aad_of(aad::DEVICE_KEY),
        &record.encrypted_device_key_priv,
    )?);
    let storage = HawkEncSecret::from_bytes(*open_fixed::<HAWK_ENC_SECRET_LEN>(
        &key,
        &aad_of(aad::STORAGE_KEY),
        &record.encrypted_epoch_storage_key_priv,
    )?);
    let root = open_fixed::<32>(
        &key,
        &aad_of(aad::EPOCH_ROOT),
        &record.encrypted_epoch_root_key,
    )?;
    let seq_b64 = Zeroizing::new(aead::decrypt_suite(
        Suite::DndkGcm,
        &key,
        &aad_of(aad::EPOCH_SEQ),
        &record.encrypted_epoch_number,
    )?);
    let seq_dec = base64::engine::general_purpose::STANDARD
        .decode(seq_b64.as_slice())
        .map_err(|_| Error::Malformed("epoch number is not base64"))?;
    let seq = parse_seq(&seq_dec)?;
    let device = DeviceSecrets::from_parts(device_key, storage, None, record.public.clone())?;
    Ok(RestoredState {
        device,
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
        let (rec, member) = create(did, &code, &me, &epoch, Mechanism::Code).unwrap();
        verify_member(&epoch, &member, true).unwrap();
        let r = open(&rec, &code, did).unwrap();
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
        let (rec, _) = create(did, &code, &me, &epoch, Mechanism::Code).unwrap();
        fn field(r: &mut VirtualDeviceRecord, i: usize) -> &mut Vec<u8> {
            match i {
                0 => &mut r.encrypted_device_key_priv,
                1 => &mut r.encrypted_epoch_storage_key_priv,
                2 => &mut r.encrypted_epoch_root_key,
                _ => &mut r.encrypted_epoch_number,
            }
        }
        for i in 0..4 {
            let mut bad = rec.clone();
            field(&mut bad, i)[10] ^= 1;
            assert!(open(&bad, &code, did).is_err(), "flip {i}");
            for j in (0..4).filter(|&j| j != i) {
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

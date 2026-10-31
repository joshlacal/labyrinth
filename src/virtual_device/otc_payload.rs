//! Hybrid PQ One-Time-Code enrollment payload (SPEC §6.5, `I16`, `2A`).
//!
//! Fixed binary layout (all integers big-endian):
//! ```text
//! 0x02                      format version (ORF-free PQ clean-slate)
//! mailboxRootSalt     (32)
//! epochRootKey        (32)
//! epochSequenceID     (u64, 8)
//! len(epochID)        (u16, 2)   at most 512
//! epochID             (len bytes, UTF-8)
//! ```

use zeroize::Zeroizing;

use crate::aead;
use crate::device::{DevicePublic, DeviceSecrets};
use crate::epoch::{EpochKeys, EpochMemberRecord, EpochSecret, member_record};
use crate::otc::{OtcSessionKey, PAYLOAD_AAD};
use crate::{Error, Result};

/// Payload format version byte (`0x02` = ORF-free PQ clean-slate).
pub const FORMAT_VERSION: u8 = 0x02;
/// Maximum `epochID` length in bytes.
pub const MAX_EPOCH_ID_LEN: usize = 512;
const FIXED_LEN: usize = 1 + 32 * 2 + 8 + 2;

/// `{mailboxRootSalt, epochRootKey, epochID, epochSequenceID}`.
pub struct OtcPayload {
    pub mailbox_root_salt: [u8; 32],
    /// Carries the root, `epochID`, and sequence number.
    pub epoch: EpochSecret,
}

impl OtcPayload {
    pub fn new(mailbox_root_salt: [u8; 32], epoch: EpochSecret) -> Self {
        Self {
            mailbox_root_salt,
            epoch,
        }
    }

    pub fn create(epoch: &EpochSecret, mailbox_root_salt: &[u8; 32]) -> Self {
        Self::new(*mailbox_root_salt, epoch.clone())
    }

    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let id = self.epoch.epoch_id.as_bytes();
        if id.len() > MAX_EPOCH_ID_LEN {
            return Err(Error::Malformed("epoch id too long"));
        }
        let mut out = Zeroizing::new(Vec::with_capacity(FIXED_LEN + id.len()));
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.mailbox_root_salt);
        out.extend_from_slice(self.epoch.root());
        out.extend_from_slice(&self.epoch.seq.to_be_bytes());
        out.extend_from_slice(&(id.len() as u16).to_be_bytes());
        out.extend_from_slice(id);
        Ok(out)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < FIXED_LEN {
            return Err(Error::Malformed("otc payload too short"));
        }
        if b[0] != FORMAT_VERSION {
            return Err(Error::Unsupported(b[0]));
        }
        let arr = |at: usize| -> [u8; 32] { b[at..at + 32].try_into().expect("in bounds") };
        let mailbox_root_salt = arr(1);
        let root = Zeroizing::new(arr(33));
        let seq = u64::from_be_bytes(b[65..73].try_into().expect("in bounds"));
        let id_len = u16::from_be_bytes([b[73], b[74]]) as usize;
        if id_len > MAX_EPOCH_ID_LEN || b.len() != FIXED_LEN + id_len {
            return Err(Error::Malformed("otc payload epoch id length"));
        }
        let epoch_id = core::str::from_utf8(&b[FIXED_LEN..])
            .map_err(|_| Error::Malformed("otc payload epoch id utf-8"))?;
        Ok(Self {
            mailbox_root_salt,
            epoch: EpochSecret::from_parts(seq, epoch_id, *root),
        })
    }

    /// Seal for the new device under the hybrid PQ [`OtcSessionKey`].
    pub fn seal(&self, key: &OtcSessionKey) -> Result<Vec<u8>> {
        aead::seal(key.as_bytes(), PAYLOAD_AAD, &self.to_bytes()?)
    }

    /// Open on the new device under the hybrid PQ [`OtcSessionKey`].
    pub fn open(key: &OtcSessionKey, ct: &[u8]) -> Result<Self> {
        let pt = Zeroizing::new(aead::decrypt_suite(
            aead::Suite::DndkGcm,
            key.as_bytes(),
            PAYLOAD_AAD,
            ct,
        )?);
        Self::from_bytes(&pt)
    }

    /// Generate fresh physical device keys for enrollment.
    pub fn enroll(&self) -> Result<(DeviceSecrets, DevicePublic, EpochMemberRecord)> {
        let me = DeviceSecrets::generate_physical()?;
        let public = me.public().clone();
        let member = member_record(&self.epoch, &public.device_key_pub, false, None);
        Ok((me, public, member))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trip_and_strictness() {
        let epoch = EpochSecret::from_parts(7, "000000000007", [3u8; 32]);
        let p = OtcPayload::create(&epoch, &[9u8; 32]);
        let b = p.to_bytes().unwrap();
        assert_eq!(b.len(), FIXED_LEN + 12);
        let q = OtcPayload::from_bytes(&b).unwrap();
        assert_eq!(q.to_bytes().unwrap(), b);
        let mut long = b.to_vec();
        long.push(0);
        assert!(OtcPayload::from_bytes(&long).is_err());
        assert!(OtcPayload::from_bytes(&b[..b.len() - 1]).is_err());
        let mut v = b.to_vec();
        v[0] = 1;
        assert_eq!(
            OtcPayload::from_bytes(&v).err(),
            Some(Error::Unsupported(1))
        );
    }

    #[test]
    fn payload_refuses_the_v10_suite() {
        use crate::otc::{Initiator, Responder};
        let did = "did:plc:otc";
        let mut r = Responder::generate(did).unwrap();
        let (init, hello) = Initiator::start(r.code(), did).unwrap();
        let (reply, key_b) = r.respond(&hello).unwrap();
        let key_a = init.finish(&reply).unwrap();
        let epoch = EpochSecret::from_parts(7, "000000000007", [3u8; 32]);
        let p = OtcPayload::create(&epoch, &[9u8; 32]);
        assert!(OtcPayload::open(&key_a, &p.seal(&key_b).unwrap()).is_ok());
        let ct = aead::encrypt(
            aead::Suite::GcmExtended,
            key_b.as_bytes(),
            PAYLOAD_AAD,
            &p.to_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(
            OtcPayload::open(&key_a, &ct).err(),
            Some(Error::Unsupported(0x01))
        );
    }
}

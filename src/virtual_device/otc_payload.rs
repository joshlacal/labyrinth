//! One-time-code enrollment payload (SPEC §6.5, paper p.45).
//!
//! The existing device evolves a temporary ORF client state, then sends it
//! with the mailbox root salt and its current epoch to the new device,
//! sealed under the CPace session key:
//!
//! ```text
//! ct = encrypt(otc::payload_key(ISK), "otc_payload", encode(payload))
//! ```
//!
//! `encode` is a fixed binary layout (all integers big-endian):
//!
//! ```text
//! 0x01                      format version
//! tempOrfClientState  (32)
//! mailboxRootSalt     (32)
//! epochRootKey        (32)
//! epochSequenceID     (u64, 8)
//! len(epochID)        (u16, 2)   at most 512
//! epochID             (len bytes, UTF-8)
//! ```

use zeroize::Zeroizing;

use crate::aead;
use crate::device::{DevicePublic, DeviceSecrets};
use crate::epoch::{EpochKeys, EpochMemberRecord, EpochSecret};
use crate::orf::{EvolveToken, OrfClientState, orf_client_evolve};
use crate::otc::{Isk, PAYLOAD_AAD, payload_key};
use crate::{Error, Result};

/// Payload format version byte.
pub const FORMAT_VERSION: u8 = 0x01;
/// Maximum `epochID` length in bytes.
pub const MAX_EPOCH_ID_LEN: usize = 512;
const FIXED_LEN: usize = 1 + 32 * 3 + 8 + 2;

/// `{tempOrfClientState, mailboxRootSalt, epochRootKey, epochID, epochSequenceID}`.
pub struct OtcPayload {
    pub temp_orf_state: OrfClientState,
    pub mailbox_root_salt: [u8; 32],
    /// Carries the root, `epochID` and sequence number.
    pub epoch: EpochSecret,
}

impl OtcPayload {
    /// Build the payload on the existing device. The returned token goes
    /// to the ORF server (`tempServerState = orf_server_evolve(token, s)`).
    pub fn create(
        me: &DeviceSecrets,
        epoch: &EpochSecret,
        mailbox_root_salt: &[u8; 32],
    ) -> Result<(Self, EvolveToken)> {
        let (temp_orf_state, token) = orf_client_evolve(&me.orf)?;
        Ok((
            Self {
                temp_orf_state,
                mailbox_root_salt: *mailbox_root_salt,
                epoch: epoch.clone(),
            },
            token,
        ))
    }

    /// The binary encoding documented in the module header.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let id = self.epoch.epoch_id.as_bytes();
        if id.len() > MAX_EPOCH_ID_LEN {
            return Err(Error::Malformed("epoch id too long"));
        }
        let mut out = Zeroizing::new(Vec::with_capacity(FIXED_LEN + id.len()));
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.temp_orf_state.to_bytes());
        out.extend_from_slice(&self.mailbox_root_salt);
        out.extend_from_slice(self.epoch.root());
        out.extend_from_slice(&self.epoch.seq.to_be_bytes());
        out.extend_from_slice(&(id.len() as u16).to_be_bytes());
        out.extend_from_slice(id);
        Ok(out)
    }

    /// Strict inverse of [`to_bytes`](Self::to_bytes): rejects trailing bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < FIXED_LEN {
            return Err(Error::Malformed("otc payload too short"));
        }
        if b[0] != FORMAT_VERSION {
            return Err(Error::Unsupported(b[0]));
        }
        let arr = |at: usize| -> [u8; 32] { b[at..at + 32].try_into().expect("in bounds") };
        let temp_orf_state = OrfClientState::from_bytes(arr(1))?;
        let mailbox_root_salt = arr(33);
        let root = Zeroizing::new(arr(65));
        let seq = u64::from_be_bytes(b[97..105].try_into().expect("in bounds"));
        let id_len = u16::from_be_bytes([b[105], b[106]]) as usize;
        if id_len > MAX_EPOCH_ID_LEN || b.len() != FIXED_LEN + id_len {
            return Err(Error::Malformed("otc payload epoch id length"));
        }
        let epoch_id = core::str::from_utf8(&b[FIXED_LEN..])
            .map_err(|_| Error::Malformed("otc payload epoch id utf-8"))?;
        Ok(Self {
            temp_orf_state,
            mailbox_root_salt,
            epoch: EpochSecret::from_parts(seq, epoch_id, *root),
        })
    }

    /// Seal for the new device under the CPace session key.
    pub fn seal(&self, isk: &Isk) -> Result<Vec<u8>> {
        aead::seal(&payload_key(isk), PAYLOAD_AAD, &self.to_bytes()?)
    }

    /// Open on the new device.
    pub fn open(isk: &Isk, ct: &[u8]) -> Result<Self> {
        let pt = Zeroizing::new(aead::decrypt_suite(
            aead::Suite::DndkGcm,
            &payload_key(isk),
            PAYLOAD_AAD,
            ct,
        )?);
        Self::from_bytes(&pt)
    }

    /// Enroll the new physical device into `self.epoch`, evolving the
    /// temporary ORF state again (as with a recovery code).
    pub fn enroll(&self) -> Result<(DeviceSecrets, DevicePublic, EvolveToken, EpochMemberRecord)> {
        super::enroll_from_orf(&self.temp_orf_state, &self.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trip_and_strictness() {
        let me = DeviceSecrets::generate().unwrap();
        let epoch = EpochSecret::from_parts(7, "000000000007", [3u8; 32]);
        let (p, _) = OtcPayload::create(&me, &epoch, &[9u8; 32]).unwrap();
        let b = p.to_bytes().unwrap();
        assert_eq!(b.len(), FIXED_LEN + 12);
        let q = OtcPayload::from_bytes(&b).unwrap();
        assert_eq!(q.to_bytes().unwrap(), b);
        let mut long = b.to_vec();
        long.push(0);
        assert!(OtcPayload::from_bytes(&long).is_err());
        assert!(OtcPayload::from_bytes(&b[..b.len() - 1]).is_err());
        let mut v = b.to_vec();
        v[0] = 2;
        assert_eq!(
            OtcPayload::from_bytes(&v).err(),
            Some(Error::Unsupported(2))
        );
    }

    #[test]
    fn payload_refuses_the_v10_suite() {
        use crate::otc::{Initiator, Responder};
        let did = "did:plc:otc";
        let mut r = Responder::generate(did).unwrap();
        let (_init, hello) = Initiator::start(r.code(), did, b"").unwrap();
        let (_, isk) = r.respond(&hello, b"").unwrap();
        let me = DeviceSecrets::generate().unwrap();
        let epoch = EpochSecret::from_parts(7, "000000000007", [3u8; 32]);
        let (p, _) = OtcPayload::create(&me, &epoch, &[9u8; 32]).unwrap();
        assert!(OtcPayload::open(&isk, &p.seal(&isk).unwrap()).is_ok());
        let ct = aead::encrypt(
            aead::Suite::GcmExtended,
            &payload_key(&isk),
            PAYLOAD_AAD,
            &p.to_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(
            OtcPayload::open(&isk, &ct).err(),
            Some(Error::Unsupported(0x01))
        );
    }
}

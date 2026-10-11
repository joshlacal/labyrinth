//! Epochs (SPEC §5, paper p.25–30, p.35–36).
//!
//! An epoch is a root key plus its sequence number and the backend-assigned
//! `epochID` ([CB-9]). From the root we derive the mailbox keys
//! ([`crate::mailbox`]), the data-storage key that seals the link to the
//! previous epoch, and the device-MAC key that authenticates membership.
//!
//! - [`open_genesis`] / [`open_next`] create an epoch ([`open`]).
//! - [`forward_chain`] / [`backward_chain`] walk the chain ([`chain`]).
//! - [`add_device_mac`] / [`verify_member`] manage membership.
//!
//! The `epochID` is only an input to the *next* epoch's chaining KDF, so an
//! epoch the caller has opened but not yet stored is a [`PendingEpoch`]; it
//! becomes an [`EpochSecret`] once the backend assigns the id.

pub mod chain;
pub mod open;

pub use chain::{OpenedEpoch, backward_chain, forward_chain};
pub use open::{NewEpoch, open_genesis, open_next};

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::device::DevicePublic;
use crate::encoding::{b64_decimal, kdf, kdf32, mac};
use crate::mailbox::{EpochPublic, MailboxKeys};
use crate::sign::XVerifyingKey;
use crate::{Error, Result};

/// AAD for the encrypted previous-epoch fields (p.28).
pub(crate) const METADATA_AAD: &[u8] = b"epoch_data_metadata";
/// Maximum decimal length of a decrypted sequence number (p.28).
pub const MAX_SEQ_DIGITS: usize = 11;

/// Keys every epoch derives from `(root, seq)`; implemented by
/// [`EpochSecret`] and [`PendingEpoch`].
pub trait EpochKeys {
    fn seq(&self) -> u64;
    fn root(&self) -> &[u8; 32];

    /// `kdf(root, null, "epoch_data_storage_" || base64(seq))`.
    fn data_key(&self) -> Zeroizing<[u8; 32]> {
        let info = format!("epoch_data_storage_{}", b64_decimal(self.seq()));
        Zeroizing::new(kdf32(self.root(), None, info.as_bytes()))
    }

    /// `kdf(root, null, "epoch_devices_" || base64(seq))`.
    fn mac_key(&self) -> Zeroizing<[u8; 32]> {
        let info = format!("epoch_devices_{}", b64_decimal(self.seq()));
        Zeroizing::new(kdf32(self.root(), None, info.as_bytes()))
    }

    /// The v1.1 mailbox keypairs (SPEC §5.2).
    fn mailbox_keys(&self) -> MailboxKeys {
        MailboxKeys::derive(self.root(), self.seq())
    }

    /// `mac(deviceKeyPub, macKey)`.
    fn device_mac(&self, device_key_pub: &XVerifyingKey) -> [u8; 32] {
        mac(&device_key_pub.0, self.mac_key().as_slice())
    }
}

/// An epoch whose root is known but whose `epochID` the backend has not yet
/// assigned (just opened, or restored from a virtual device bundle).
pub struct PendingEpoch {
    seq: u64,
    root: Zeroizing<[u8; 32]>,
}

impl PendingEpoch {
    pub fn new(seq: u64, root: [u8; 32]) -> Self {
        Self {
            seq,
            root: Zeroizing::new(root),
        }
    }

    /// Attach the backend-assigned `epochID`.
    pub fn assign_id(self, epoch_id: impl Into<String>) -> EpochSecret {
        EpochSecret {
            seq: self.seq,
            epoch_id: epoch_id.into(),
            root: self.root,
        }
    }
}

impl EpochKeys for PendingEpoch {
    fn seq(&self) -> u64 {
        self.seq
    }
    fn root(&self) -> &[u8; 32] {
        &self.root
    }
}

/// A fully identified epoch: what a device caches per epoch.
#[derive(Clone)]
pub struct EpochSecret {
    pub seq: u64,
    /// Opaque backend-assigned id ([CB-9]).
    pub epoch_id: String,
    root: Zeroizing<[u8; 32]>,
}

impl EpochSecret {
    pub fn from_parts(seq: u64, epoch_id: impl Into<String>, root: [u8; 32]) -> Self {
        Self {
            seq,
            epoch_id: epoch_id.into(),
            root: Zeroizing::new(root),
        }
    }

    /// `(epochChainingKey, epochDistributionPreSharedKey) = kdf(root, null,
    /// "epoch_chaining_" || seq || "_" || epochID, 64)` — the inputs to the
    /// *next* epoch (p.25, [CB-4]).
    pub(crate) fn chaining_keys(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        let info = format!("epoch_chaining_{}_{}", self.seq, self.epoch_id);
        let mut okm = Zeroizing::new([0u8; 64]);
        kdf(self.root.as_slice(), None, info.as_bytes(), okm.as_mut());
        let mut chain = Zeroizing::new([0u8; 32]);
        let mut psk = Zeroizing::new([0u8; 32]);
        chain.copy_from_slice(&okm[..32]);
        psk.copy_from_slice(&okm[32..]);
        (chain, psk)
    }
}

impl EpochKeys for EpochSecret {
    fn seq(&self) -> u64 {
        self.seq
    }
    fn root(&self) -> &[u8; 32] {
        &self.root
    }
}

impl core::fmt::Debug for EpochSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpochSecret")
            .field("seq", &self.seq)
            .field("epoch_id", &self.epoch_id)
            .finish_non_exhaustive()
    }
}

/// `root = kdf(entropy, chainKey, "epoch_root_key")`.
pub(crate) fn root_from_entropy(entropy: &[u8; 32], chain_key: &[u8; 32]) -> [u8; 32] {
    kdf32(entropy, Some(chain_key), b"epoch_root_key")
}

/// HPKE AAD for entropy distribution: `"epoch__" || seq` (p.29).
pub(crate) fn entropy_aad(seq: u64) -> Vec<u8> {
    format!("epoch__{seq}").into_bytes()
}

/// The Space backend's `epochID` convention: the decimal sequence number
/// zero-padded to 12 digits, which is also the epoch record's rkey ([CB-9]).
/// Everywhere else ids are opaque strings.
pub fn space_epoch_id(seq: u64) -> String {
    format!("{seq:012}")
}

/// The published part of an epoch (`blue.catbird.labyrinth.epoch`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRecord {
    pub public: EpochPublic,
    /// `encrypt(dataKey, "epoch_data_metadata", decimal(prevSeq))`; `None` for epoch 0.
    pub encrypted_prev_seq: Option<Vec<u8>>,
    /// `encrypt(dataKey, "epoch_data_metadata", prevRoot)`; `None` for epoch 0.
    pub encrypted_prev_root: Option<Vec<u8>>,
    /// `deviceKeyPub` of the opening device.
    pub opened_by: XVerifyingKey,
}

/// One device's membership of one epoch (`blue.catbird.labyrinth.epochMember`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochMemberRecord {
    pub seq: u64,
    pub device_key_pub: XVerifyingKey,
    pub device_mac: [u8; 32],
    /// Labyrinth-HPKE-sealed entropy; present for devices carried over when
    /// the epoch opened, absent for devices added mid-epoch.
    pub encrypted_entropy: Option<Vec<u8>>,
}

/// Admit a device to an epoch mid-epoch (no entropy). Verifies the
/// device's signatures first.
pub fn add_device_mac(epoch: &impl EpochKeys, device: &DevicePublic) -> Result<EpochMemberRecord> {
    device.verify()?;
    Ok(member_record(epoch, &device.device_key_pub, None))
}

pub(crate) fn member_record(
    epoch: &impl EpochKeys,
    device_key_pub: &XVerifyingKey,
    encrypted_entropy: Option<Vec<u8>>,
) -> EpochMemberRecord {
    EpochMemberRecord {
        seq: epoch.seq(),
        device_key_pub: *device_key_pub,
        device_mac: epoch.device_mac(device_key_pub),
        encrypted_entropy,
    }
}

/// Check a membership record's sequence number and MAC (constant time).
pub fn verify_member(epoch: &impl EpochKeys, record: &EpochMemberRecord) -> Result<()> {
    if record.seq != epoch.seq() {
        return Err(Error::NotEpochMember);
    }
    let expected = epoch.device_mac(&record.device_key_pub);
    if bool::from(expected.ct_eq(&record.device_mac)) {
        Ok(())
    } else {
        Err(Error::NotEpochMember)
    }
}

/// Check that a published `EpochPublic` carries the mailbox keys derived
/// from this epoch's root. Combine with [`EpochPublic::verify`] for the
/// signatures and chain.
pub fn verify_public(epoch: &impl EpochKeys, public: &EpochPublic) -> Result<()> {
    if public.seq != epoch.seq() {
        return Err(Error::Malformed("epoch public seq mismatch"));
    }
    if public.keys != epoch.mailbox_keys().public() {
        return Err(Error::Malformed("epoch public keys do not match root"));
    }
    Ok(())
}

/// Parse a canonical decimal sequence number of at most
/// [`MAX_SEQ_DIGITS`] characters (no sign, no leading zeros).
pub(crate) fn parse_seq(bytes: &[u8]) -> Result<u64> {
    let ok = !bytes.is_empty()
        && bytes.len() <= MAX_SEQ_DIGITS
        && bytes.iter().all(u8::is_ascii_digit)
        && (bytes[0] != b'0' || bytes.len() == 1);
    if !ok {
        return Err(Error::Malformed("sequence number is not a short decimal"));
    }
    core::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(Error::Malformed("sequence number is not a short decimal"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_ids_are_padded() {
        assert_eq!(space_epoch_id(0), "000000000000");
        assert_eq!(space_epoch_id(42), "000000000042");
    }

    #[test]
    fn parse_seq_rules() {
        assert_eq!(parse_seq(b"0").unwrap(), 0);
        assert_eq!(parse_seq(b"17").unwrap(), 17);
        assert_eq!(parse_seq(b"99999999999").unwrap(), 99_999_999_999);
        for bad in [
            &b""[..],
            b"012",
            b"-1",
            b"+1",
            b"1a",
            b"999999999999",
            b" 1",
        ] {
            assert!(parse_seq(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn derived_key_labels() {
        // SPEC §5.4: the labels use base64 of the decimal seq.
        let e = PendingEpoch::new(3, [5u8; 32]);
        assert_eq!(
            *e.data_key(),
            kdf32(&[5u8; 32], None, b"epoch_data_storage_Mw==")
        );
        assert_eq!(*e.mac_key(), kdf32(&[5u8; 32], None, b"epoch_devices_Mw=="));
        let s = e.assign_id("abc");
        let (chain, psk) = s.chaining_keys();
        let mut okm = [0u8; 64];
        kdf(&[5u8; 32], None, b"epoch_chaining_3_abc", &mut okm);
        assert_eq!(chain.as_slice(), &okm[..32]);
        assert_eq!(psk.as_slice(), &okm[32..]);
    }

    #[test]
    fn member_mac_round_trip_and_tamper() {
        let e = PendingEpoch::new(1, [9u8; 32]);
        let d = crate::device::DeviceSecrets::generate().unwrap();
        let rec = add_device_mac(&e, d.public()).unwrap();
        verify_member(&e, &rec).unwrap();
        let mut bad = rec.clone();
        bad.device_mac[0] ^= 1;
        assert_eq!(verify_member(&e, &bad), Err(Error::NotEpochMember));
        let mut bad = rec.clone();
        bad.seq = 2;
        assert_eq!(verify_member(&e, &bad), Err(Error::NotEpochMember));
        assert!(verify_member(&PendingEpoch::new(1, [8u8; 32]), &rec).is_err());
    }
}

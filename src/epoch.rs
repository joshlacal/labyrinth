//! Epochs (SPEC §5, Gate 2, `I16`).

pub mod chain;
pub mod open;

pub use chain::{OpenedEpoch, backward_chain, forward_chain};
pub use open::{NewEpoch, open_genesis, open_next, open_next_enrolling, open_next_with_additions};

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::device::DevicePublic;
use crate::encoding::{b64_decimal, kdf, kdf32, mac};
use crate::mailbox::{EpochPublic, MailboxKeys};
use crate::sign::{XSigningKey, XVerifyingKey};
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

    /// `mac(deviceKeyPub || u8(is_virtual), macKey)` (`Gate 2` domain binding).
    fn device_mac(&self, device_key_pub: &XVerifyingKey, is_virtual: bool) -> [u8; 32] {
        let mut msg = [0u8; 33];
        msg[..32].copy_from_slice(&device_key_pub.0);
        msg[32] = u8::from(is_virtual);
        mac(&msg, self.mac_key().as_slice())
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
pub fn space_epoch_id(seq: u64) -> String {
    format!("{seq:012}")
}

/// Canonical 16-hex Space epoch rkey helper (`format!("{seq:016x}")`) when hex
/// ordering is requested; note `blue.catbird.labyrinth.epoch` uses 12-digit
/// zero-padded decimal `space_epoch_id(seq)` (`000000000000..`) which is also
/// lexicographically ascending!
pub fn space_epoch_hex_rkey(seq: u64) -> String {
    format!("{seq:016x}")
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
    /// Canonical sorted cumulative set of evicted device keys bound to this epoch.
    pub revocations: Vec<XVerifyingKey>,
    /// XEdDSA signature by `opened_by` over `(did, seq, head, revocations)`.
    pub revocations_sig: Option<[u8; 64]>,
}

const EPOCH_REVOCATIONS_PREFIX: &str = "catbird.labyrinth.epoch_revocations_v1:";

fn epoch_revocations_message(
    did: &str,
    seq: u64,
    head: &[u8; 32],
    revocations: &[XVerifyingKey],
) -> Vec<u8> {
    let mut out = format!(
        "{EPOCH_REVOCATIONS_PREFIX}{did}:{seq}:{}:",
        hex::encode(head)
    )
    .into_bytes();
    out.reserve(revocations.len() * 32);
    for k in revocations {
        out.extend_from_slice(&k.0);
    }
    out
}

impl EpochRecord {
    /// Attaches a canonical sorted revocation set signed by `opener` (`opened_by`).
    pub fn sign_revocations(
        &mut self,
        did: &str,
        opener: &XSigningKey,
        revoked: impl IntoIterator<Item = XVerifyingKey>,
    ) -> Result<()> {
        if opener.public() != self.opened_by {
            return Err(Error::Malformed("epoch opener mismatch"));
        }
        let mut list: Vec<XVerifyingKey> = revoked.into_iter().collect();
        list.sort_unstable_by_key(|a| a.0);
        list.dedup_by(|a, b| a.0 == b.0);
        if list.is_empty() {
            self.revocations.clear();
            self.revocations_sig = None;
            return Ok(());
        }
        let sig = opener.sign(&epoch_revocations_message(
            did,
            self.public.seq,
            &self.public.head,
            &list,
        ))?;
        self.revocations = list;
        self.revocations_sig = Some(sig);
        Ok(())
    }

    /// Verifies canonical ordering and `opened_by` signature on `revocations`.
    pub fn verify_revocations(&self, did: &str) -> Result<()> {
        if !self.revocations.windows(2).all(|w| w[0].0 < w[1].0) {
            return Err(Error::Malformed("unsorted epoch revocations"));
        }
        match (&self.revocations.is_empty(), &self.revocations_sig) {
            (true, None) => Ok(()),
            (false, None) => Err(Error::BadSignature),
            (_, Some(sig)) => self.opened_by.verify(
                &epoch_revocations_message(
                    did,
                    self.public.seq,
                    &self.public.head,
                    &self.revocations,
                ),
                sig,
            ),
        }
    }
}

/// One device's membership of one epoch (`blue.catbird.labyrinth.epochMember`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochMemberRecord {
    pub seq: u64,
    pub device_key_pub: XVerifyingKey,
    pub device_mac: [u8; 32],
    /// `Hawk + PSK`-sealed entropy (`I16`); present for devices carried over
    /// when the epoch opened, absent for devices added mid-epoch.
    pub encrypted_entropy: Option<Vec<u8>>,
}

/// Admit a device to an epoch mid-epoch (no entropy). Verifies the
/// device's signatures first.
pub fn add_device_mac(epoch: &impl EpochKeys, device: &DevicePublic) -> Result<EpochMemberRecord> {
    device.verify()?;
    Ok(member_record(
        epoch,
        &device.device_key_pub,
        device.is_virtual,
        None,
    ))
}

pub(crate) fn member_record(
    epoch: &impl EpochKeys,
    device_key_pub: &XVerifyingKey,
    is_virtual: bool,
    encrypted_entropy: Option<Vec<u8>>,
) -> EpochMemberRecord {
    EpochMemberRecord {
        seq: epoch.seq(),
        device_key_pub: *device_key_pub,
        device_mac: epoch.device_mac(device_key_pub, is_virtual),
        encrypted_entropy,
    }
}

/// Check a membership record's sequence number and MAC (constant time, `Gate 2` `is_virtual` bound).
pub fn verify_member(
    epoch: &impl EpochKeys,
    record: &EpochMemberRecord,
    is_virtual: bool,
) -> Result<()> {
    if record.seq != epoch.seq() {
        return Err(Error::NotEpochMember);
    }
    let expected = epoch.device_mac(&record.device_key_pub, is_virtual);
    if bool::from(expected.ct_eq(&record.device_mac)) {
        Ok(())
    } else {
        Err(Error::NotEpochMember)
    }
}

/// Check that a published `EpochPublic` carries the mailbox keys derived
/// from this epoch's root.
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
    fn member_mac_round_trip_and_tamper() {
        let e = PendingEpoch::new(1, [9u8; 32]);
        let d = crate::device::DeviceSecrets::generate().unwrap();
        let rec = add_device_mac(&e, d.public()).unwrap();
        verify_member(&e, &rec, false).unwrap();
        assert_eq!(verify_member(&e, &rec, true), Err(Error::NotEpochMember));
        let mut bad = rec.clone();
        bad.device_mac[0] ^= 1;
        assert_eq!(verify_member(&e, &bad, false), Err(Error::NotEpochMember));
        let mut bad = rec.clone();
        bad.seq = 2;
        assert_eq!(verify_member(&e, &bad, false), Err(Error::NotEpochMember));
    }
}

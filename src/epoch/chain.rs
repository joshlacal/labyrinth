//! Forward and backward chaining (SPEC §5.1, §5.4–5.5, paper p.30, p.35–36).

use zeroize::Zeroizing;

use super::{
    EpochKeys, EpochMemberRecord, EpochRecord, EpochSecret, METADATA_AAD, PendingEpoch,
    entropy_aad, parse_seq, root_from_entropy, verify_member, verify_public,
};
use crate::aead::{self, Suite};
use crate::device::DevicePublic;
use crate::hpke::labyrinth::{self as lhpke, X25519Secret};
use crate::mailbox::EpochPublic;
use crate::{Error, Result};

/// The backend's view of an epoch that a device wants to chain into.
pub struct OpenedEpoch<'a> {
    /// Backend-assigned id of the new epoch.
    pub epoch_id: &'a str,
    pub record: &'a EpochRecord,
    /// The chaining device's membership of the new epoch (with entropy).
    pub my_member: &'a EpochMemberRecord,
    /// The opener's device record (`record.opened_by`).
    pub opener: &'a DevicePublic,
    /// The opener's membership of the previous epoch.
    pub opener_prev_member: &'a EpochMemberRecord,
}

/// Derive the epoch after `prev` from entropy addressed to `my_storage`.
///
/// Checks, in order: the opener is a verified physical device that was a
/// member of `prev`; the entropy decrypts under `my_storage` and the
/// opener's auth key with `distPsk`; the derived mailbox keys match the
/// published `EpochPublic`, whose head, signatures and chain link to
/// `prev_public` verify; `my_member`'s MAC verifies under the new epoch; and
/// the encrypted back-link decrypts to `prev`.
pub fn forward_chain(
    did: &str,
    prev: &EpochSecret,
    prev_public: &EpochPublic,
    opened: &OpenedEpoch<'_>,
    my_storage: &X25519Secret,
) -> Result<EpochSecret> {
    let record = opened.record;
    let seq = prev
        .seq
        .checked_add(1)
        .ok_or(Error::Malformed("epoch sequence overflow"))?;
    if record.public.seq != seq || opened.my_member.seq != seq {
        return Err(Error::Malformed("epoch sequence mismatch"));
    }
    verify_public(prev, prev_public)?;

    let opener = opened.opener;
    let opener_auth = opener.verified_auth_key()?;
    if opener.device_key_pub != record.opened_by
        || opened.opener_prev_member.device_key_pub != opener.device_key_pub
    {
        return Err(Error::Malformed("epoch opener mismatch"));
    }
    verify_member(prev, opened.opener_prev_member)?;

    let ct = opened
        .my_member
        .encrypted_entropy
        .as_deref()
        .ok_or(Error::NotEpochMember)?;
    let (chain_key, psk) = prev.chaining_keys();
    let pt = Zeroizing::new(lhpke::decrypt(
        &my_storage.public(),
        my_storage,
        &opener_auth,
        psk.as_slice(),
        &entropy_aad(seq),
        ct,
    )?);
    let entropy: &[u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("entropy length"))?;
    let epoch = PendingEpoch::new(seq, root_from_entropy(entropy, &chain_key));

    verify_public(&epoch, &record.public)?;
    record.public.verify(did, Some(prev_public))?;
    verify_member(&epoch, opened.my_member)?;
    let (back_seq, back_root) = decrypt_back_link(&epoch, record)?;
    if back_seq != prev.seq || back_root.as_slice() != prev.root() {
        return Err(Error::Malformed("epoch back-link does not match"));
    }
    Ok(epoch.assign_id(opened.epoch_id))
}

/// Recover the epoch before `cur` from `cur`'s record (p.36).
///
/// `record` must be `cur`'s own epoch record; the decrypted sequence number
/// must be a decimal of at most 11 characters equal to `cur.seq - 1`.
/// Callers can then authenticate the previous epoch's published record with
/// [`super::verify_public`].
pub fn backward_chain(
    cur: &EpochSecret,
    record: &EpochRecord,
    prev_epoch_id: &str,
) -> Result<EpochSecret> {
    verify_public(cur, &record.public)?;
    let expected = cur
        .seq
        .checked_sub(1)
        .ok_or(Error::Malformed("epoch 0 has no predecessor"))?;
    let (seq, root) = decrypt_back_link(cur, record)?;
    if seq != expected {
        return Err(Error::Malformed("previous sequence number mismatch"));
    }
    Ok(EpochSecret::from_parts(seq, prev_epoch_id, *root))
}

fn decrypt_back_link(
    epoch: &impl EpochKeys,
    record: &EpochRecord,
) -> Result<(u64, Zeroizing<[u8; 32]>)> {
    let (Some(enc_seq), Some(enc_root)) = (&record.encrypted_prev_seq, &record.encrypted_prev_root)
    else {
        return Err(Error::Malformed("epoch has no back-link"));
    };
    let key = epoch.data_key();
    let seq = parse_seq(&aead::decrypt_suite(
        Suite::DndkGcm,
        &key,
        METADATA_AAD,
        enc_seq,
    )?)?;
    let pt = Zeroizing::new(aead::decrypt_suite(
        Suite::DndkGcm,
        &key,
        METADATA_AAD,
        enc_root,
    )?);
    let root: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("previous root length"))?;
    Ok((seq, Zeroizing::new(root)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceSecrets;
    use crate::epoch::{open_genesis, open_next};
    use crate::sign::Ed25519Transport;

    #[test]
    fn back_link_refuses_the_v10_suite() {
        let did = "did:plc:chain";
        let t = Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[5; 32]));
        let me = DeviceSecrets::generate().unwrap();
        let (p0, n0) = open_genesis(did, &me, &t).unwrap();
        let e0 = p0.assign_id("000000000000");
        let (p1, n1) = open_next(did, &e0, &n0.record.public, &n0.members, &[], &me, &t).unwrap();
        let e1 = p1.assign_id("000000000001");
        assert_eq!(
            backward_chain(&e1, &n1.record, "000000000000").unwrap().seq,
            0
        );
        let mut bad = n1.record.clone();
        bad.encrypted_prev_root = Some(
            aead::encrypt(Suite::GcmExtended, &e1.data_key(), METADATA_AAD, e0.root()).unwrap(),
        );
        assert_eq!(
            backward_chain(&e1, &bad, "000000000000").err(),
            Some(Error::Unsupported(0x01))
        );
        let mut bad = n1.record.clone();
        bad.encrypted_prev_seq =
            Some(aead::encrypt(Suite::GcmExtended, &e1.data_key(), METADATA_AAD, b"0").unwrap());
        assert_eq!(
            backward_chain(&e1, &bad, "000000000000").err(),
            Some(Error::Unsupported(0x01))
        );
    }
}

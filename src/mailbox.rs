//! Per-epoch mailbox keys, `membersHash` (`Gate 2`), the epoch head, and its
//! signatures (SPEC §5.2–5.3; [CB-1], [CB-10], [CB-18]).

use labyrinth_protocol::epoch_chain::{
    EpochPublicHeader, MemberBinding, compute_epoch_head, compute_members_hash,
};
use subtle::ConstantTimeEq as _;

use crate::device::DevicePublic;
use crate::encoding::{kdf32, minos_salt};
use crate::hpke::X25519Public;
use crate::hpke::hawk::{
    HawkAuthPublic, HawkAuthSecret, HawkEncPublic, HawkEncSecret, hawk_derive_auth, hawk_derive_enc,
};
use crate::sign::{TransportSigner, XSigningKey, XVerifyingKey, verify_transport};
use crate::{Error, Result};

/// The three v1.1 mailbox keypairs of one epoch, derived from its root key.
pub struct MailboxKeys {
    pub auth_secret: HawkAuthSecret,
    pub auth_public: HawkAuthPublic,
    pub enc_secret: HawkEncSecret,
    pub enc_public: HawkEncPublic,
    pub sig_secret: XSigningKey,
    pub sig_public: XVerifyingKey,
}

impl MailboxKeys {
    /// Derive the mailbox keypairs for epoch `seq` from its root key (p.27).
    pub fn derive(epoch_root: &[u8; 32], seq: u64) -> Self {
        let salt = minos_salt();
        let label = |kind: &str| {
            format!("minos.kdf.export_root_key.{kind}_keypair:epoch_number={seq}").into_bytes()
        };
        let auth_seed = kdf32(epoch_root, Some(&salt), &label("auth"));
        let enc_seed = kdf32(epoch_root, Some(&salt), &label("encryption"));
        let sig_priv = kdf32(epoch_root, Some(&salt), &label("signing"));
        let (auth_secret, auth_public) = hawk_derive_auth(&auth_seed);
        let (enc_secret, enc_public) = hawk_derive_enc(&enc_seed);
        let sig_secret = XSigningKey::from_bytes(sig_priv);
        let sig_public = sig_secret.public();
        Self {
            auth_secret,
            auth_public,
            enc_secret,
            enc_public,
            sig_secret,
            sig_public,
        }
    }

    /// The public half, as published in `epochPublic`.
    pub fn public(&self) -> MailboxPublicKeys {
        MailboxPublicKeys {
            auth: self.auth_public,
            enc: self.enc_public.clone(),
            sig: self.sig_public,
        }
    }
}

/// Public mailbox keys of one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailboxPublicKeys {
    pub auth: HawkAuthPublic,
    pub enc: HawkEncPublic,
    pub sig: XVerifyingKey,
}

/// Compute `membersHash` (`SHA-256` over sorted active `(device_key_pub, epoch_storage_key_pub, is_virtual)`).
pub fn members_hash_for_devices(devices: &[DevicePublic]) -> Result<[u8; 32]> {
    let bindings: Vec<MemberBinding> = devices.iter().map(DevicePublic::member_binding).collect();
    compute_members_hash(&bindings).map_err(|_| Error::Malformed("invalid epoch member set"))
}

/// `get_epoch_head` ([CB-1], `Gate 2` `membersHash` bound) via `labyrinth-protocol`.
pub fn epoch_head(
    seq: u64,
    keys: &MailboxPublicKeys,
    members_hash: &[u8; 32],
    prev_head: Option<&[u8; 32]>,
    did: &str,
) -> [u8; 32] {
    compute_epoch_head(
        seq,
        &keys.auth.0,
        &keys.enc.to_bytes(),
        &keys.sig.0,
        members_hash,
        prev_head,
        did,
    )
}

const SELF_SIG_PREFIX: &[u8] = b"minos.unstructured_signature.epoch_self:";
const PREV_SIG_PREFIX: &[u8] = b"minos.unstructured_signature.epoch_prev:";
const ATTEST_PREFIX: &str = "catbird.labyrinth.epoch_head_attest:";

fn prefixed(prefix: &[u8], head: &[u8; 32]) -> Vec<u8> {
    [prefix, head.as_slice()].concat()
}

fn attest_message(did: &str, head: &[u8; 32]) -> Vec<u8> {
    [format!("{ATTEST_PREFIX}{did}:").as_bytes(), head.as_slice()].concat()
}

/// [CB-18] binding of an epoch head to a chat device transport key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportAttestation {
    pub transport_public_key: [u8; 32],
    pub sig: [u8; 64],
}

/// Everything a sender needs about a recipient's epoch (`defs#epochPublic`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochPublic {
    pub seq: u64,
    pub keys: MailboxPublicKeys,
    pub members_hash: [u8; 32],
    pub prev_head: Option<[u8; 32]>,
    pub head: [u8; 32],
    pub self_sig: [u8; 64],
    pub prev_sig: Option<[u8; 64]>,
    pub attestation: TransportAttestation,
}

impl EpochPublic {
    /// Build and sign the public record for an epoch the caller just opened.
    /// `prev_sig_key` is the previous epoch's mailbox signing key (`None` for epoch 0).
    pub fn sign(
        did: &str,
        seq: u64,
        keys: &MailboxKeys,
        members_hash: [u8; 32],
        prev_head: Option<[u8; 32]>,
        prev_sig_key: Option<&XSigningKey>,
        transport: &dyn TransportSigner,
    ) -> Result<Self> {
        if prev_head.is_some() != prev_sig_key.is_some() || (seq == 0) != prev_head.is_none() {
            return Err(Error::Malformed("epoch chain inputs inconsistent"));
        }
        let public = keys.public();
        let head = epoch_head(seq, &public, &members_hash, prev_head.as_ref(), did);
        let self_sig = keys.sig_secret.sign(&prefixed(SELF_SIG_PREFIX, &head))?;
        let prev_sig = prev_sig_key
            .map(|k| k.sign(&prefixed(PREV_SIG_PREFIX, &head)))
            .transpose()?;
        let attestation = TransportAttestation {
            transport_public_key: transport.transport_public_key(),
            sig: transport.sign_transport(&attest_message(did, &head)),
        };
        Ok(Self {
            seq,
            keys: public,
            members_hash,
            prev_head,
            head,
            self_sig,
            prev_sig,
            attestation,
        })
    }

    /// Verify the head, the self signature, the attestation, and — when the
    /// previous epoch's public record is given — the chain link to it.
    pub fn verify(&self, did: &str, previous: Option<&EpochPublic>) -> Result<()> {
        self.keys.enc.validate()?;
        let expected = epoch_head(
            self.seq,
            &self.keys,
            &self.members_hash,
            self.prev_head.as_ref(),
            did,
        );
        if !bool::from(expected.ct_eq(&self.head)) {
            return Err(Error::Malformed("epoch head mismatch"));
        }
        self.keys
            .sig
            .verify(&prefixed(SELF_SIG_PREFIX, &self.head), &self.self_sig)?;
        verify_transport(
            &self.attestation.transport_public_key,
            &attest_message(did, &self.head),
            &self.attestation.sig,
        )?;
        if self.seq == 0 {
            if self.prev_head.is_some() || self.prev_sig.is_some() {
                return Err(Error::Malformed("epoch 0 has a predecessor"));
            }
            return Ok(());
        }
        if self.prev_head.is_none() {
            return Err(Error::Malformed("missing prev_head"));
        }
        if self.prev_sig.is_none() {
            return Err(Error::Malformed("missing prev_sig"));
        }
        if let Some(prev) = previous {
            self.verify_link(prev.seq, &prev.head, &prev.keys.sig)?;
        }
        Ok(())
    }

    /// Verify that `active_devices` hashes to `self.members_hash` (`Gate 2`).
    pub fn verify_members(&self, active_devices: &[DevicePublic]) -> Result<()> {
        let computed = members_hash_for_devices(active_devices)?;
        if bool::from(computed.ct_eq(&self.members_hash)) {
            Ok(())
        } else {
            Err(Error::Malformed("epoch members_hash mismatch"))
        }
    }

    /// Check only the chain link to the previous epoch.
    pub fn verify_link(
        &self,
        prev_seq: u64,
        prev_head: &[u8; 32],
        prev_sig_key: &XVerifyingKey,
    ) -> Result<()> {
        let prev_sig = self.prev_sig.ok_or(Error::Malformed("missing prev_sig"))?;
        if prev_seq.checked_add(1) != Some(self.seq) || Some(*prev_head) != self.prev_head {
            return Err(Error::Malformed("epoch chain broken"));
        }
        prev_sig_key.verify(&prefixed(PREV_SIG_PREFIX, &self.head), &prev_sig)
    }

    /// Convert to [`labyrinth_protocol::epoch_chain::EpochPublicHeader`].
    pub fn to_protocol_header(&self) -> EpochPublicHeader {
        EpochPublicHeader {
            seq: self.seq,
            auth_pubkey: self.keys.auth.0,
            encryption_pubkey: self.keys.enc.to_bytes(),
            signing_pubkey: self.keys.sig.0,
            members_hash: self.members_hash,
            prev_head: self.prev_head,
            head: self.head,
            self_sig: self.self_sig,
            prev_sig: self.prev_sig,
            attestation_pubkey: self.attestation.transport_public_key,
            attestation_sig: self.attestation.sig,
        }
    }

    /// Parse from [`labyrinth_protocol::epoch_chain::EpochPublicHeader`].
    pub fn from_protocol_header(h: &EpochPublicHeader) -> Result<Self> {
        Ok(Self {
            seq: h.seq,
            keys: MailboxPublicKeys {
                auth: X25519Public(h.auth_pubkey),
                enc: HawkEncPublic::from_bytes(&h.encryption_pubkey)?,
                sig: XVerifyingKey(h.signing_pubkey),
            },
            members_hash: h.members_hash,
            prev_head: h.prev_head,
            head: h.head,
            self_sig: h.self_sig,
            prev_sig: h.prev_sig,
            attestation: TransportAttestation {
                transport_public_key: h.attestation_pubkey,
                sig: h.attestation_sig,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceSecrets;
    use crate::sign::Ed25519Transport;

    fn transport() -> Ed25519Transport {
        Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]))
    }

    #[test]
    fn chain_of_three_verifies_and_detects_tampering() {
        let did = "did:plc:testvector";
        let t = transport();
        let dev = DeviceSecrets::generate().unwrap();
        let mh = members_hash_for_devices(std::slice::from_ref(dev.public())).unwrap();

        let k0 = MailboxKeys::derive(&[1u8; 32], 0);
        let e0 = EpochPublic::sign(did, 0, &k0, mh, None, None, &t).unwrap();
        e0.verify(did, None).unwrap();
        let k1 = MailboxKeys::derive(&[2u8; 32], 1);
        let e1 =
            EpochPublic::sign(did, 1, &k1, mh, Some(e0.head), Some(&k0.sig_secret), &t).unwrap();
        e1.verify(did, Some(&e0)).unwrap();
        let k2 = MailboxKeys::derive(&[3u8; 32], 2);
        let e2 =
            EpochPublic::sign(did, 2, &k2, mh, Some(e1.head), Some(&k1.sig_secret), &t).unwrap();
        e2.verify(did, Some(&e1)).unwrap();

        assert!(e1.verify("did:plc:other", Some(&e0)).is_err());
        assert!(e2.verify(did, Some(&e0)).is_err());
        let mut bad = e1.clone();
        bad.keys.auth.0[0] ^= 1;
        assert!(bad.verify(did, Some(&e0)).is_err());
        let forged =
            EpochPublic::sign(did, 1, &k1, mh, Some(e0.head), Some(&k2.sig_secret), &t).unwrap();
        assert!(forged.verify(did, Some(&e0)).is_err());
    }

    #[test]
    fn null_prev_head_above_epoch_zero_is_rejected_standalone() {
        let did = "did:plc:testvector";
        let t = transport();
        let mh = [0x42u8; 32];
        let k1 = MailboxKeys::derive(&[2u8; 32], 1);
        let keys = k1.public();
        let head = epoch_head(1, &keys, &mh, None, did);
        let forged = EpochPublic {
            seq: 1,
            keys,
            members_hash: mh,
            prev_head: None,
            head,
            self_sig: k1
                .sig_secret
                .sign(&prefixed(SELF_SIG_PREFIX, &head))
                .unwrap(),
            prev_sig: Some([0u8; 64]),
            attestation: TransportAttestation {
                transport_public_key: t.transport_public_key(),
                sig: t.sign_transport(&attest_message(did, &head)),
            },
        };
        assert!(forged.verify(did, None).is_err());
        assert!(EpochPublic::sign(did, 1, &k1, mh, None, None, &t).is_err());
    }
}

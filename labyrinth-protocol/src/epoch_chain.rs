//! Zero-secrets `EpochPublic` header, `membersHash` (`Gate 2` / `Gate 3`), XEdDSA link,
//! and `L-F01` rollback-floor chain verification (`Gate 6`).

use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512};
use subtle::ConstantTimeEq as _;

use crate::{
    ProtocolError, Result,
    limits::{
        ED25519_PUBKEY_LEN, ED25519_SIG_LEN, EPOCH_HEAD_LEN, HAWK_AUTH_PUBKEY_LEN,
        HAWK_ENC_PUBKEY_LEN, MEMBERS_HASH_LEN, XEDDSA_PUBKEY_LEN, XEDDSA_SIG_LEN,
    },
    transcripts::{
        EPOCH_ATTEST_PREFIX, EPOCH_PREV_SIG_PREFIX, EPOCH_SELF_SIG_PREFIX, MEMBERS_HASH_DOMAIN,
        push_len_prefixed,
    },
};

/// `2^255 - 19`, little-endian.
const P_LE: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

fn is_reduced_field(x: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if x[i] != P_LE[i] {
            return x[i] < P_LE[i];
        }
    }
    false
}

/// Verify an XEdDSA signature under a 32-byte X25519 Montgomery public key `u`.
///
/// Enforces canonical field element `u < p`, non-small-order Edwards point, and
/// canonical scalar `s < q`.
pub fn xeddsa_verify(
    u: &[u8; XEDDSA_PUBKEY_LEN],
    msg: &[u8],
    sig: &[u8; XEDDSA_SIG_LEN],
) -> Result<()> {
    let r_bytes: &[u8; 32] = sig[..32].try_into().expect("32-byte R");
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("32-byte s");

    if !is_reduced_field(u) {
        return Err(ProtocolError::BadPublicKey("XEdDSA u >= p"));
    }
    if s_bytes[31] & 0xe0 != 0 {
        return Err(ProtocolError::BadEpochSignature("XEdDSA s >= 2^253"));
    }
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or(ProtocolError::BadEpochSignature("XEdDSA non-canonical s"))?;
    let a_point = MontgomeryPoint(*u)
        .to_edwards(0)
        .ok_or(ProtocolError::BadPublicKey("XEdDSA point not on curve"))?;
    if a_point.is_small_order() {
        return Err(ProtocolError::BadPublicKey("XEdDSA small-order key"));
    }
    let a_bytes = a_point.compress().to_bytes();

    let mut h_hasher = Sha512::new();
    h_hasher.update(r_bytes);
    h_hasher.update(a_bytes);
    h_hasher.update(msg);
    let wide: [u8; 64] = h_hasher.finalize().into();
    let h = Scalar::from_bytes_mod_order_wide(&wide);

    let r_check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&-h, &a_point, &s);
    if bool::from(r_check.compress().as_bytes().ct_eq(r_bytes)) {
        Ok(())
    } else {
        Err(ProtocolError::BadEpochSignature(
            "XEdDSA verification failed",
        ))
    }
}

/// Verify an RFC 8032 strict Ed25519 signature.
pub fn ed25519_verify_strict(
    public: &[u8; ED25519_PUBKEY_LEN],
    msg: &[u8],
    sig: &[u8; ED25519_SIG_LEN],
) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public)
        .map_err(|_| ProtocolError::BadPublicKey("invalid Ed25519 public key"))?;
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig)
        .map_err(|_| ProtocolError::BadEpochSignature("Ed25519 attestation failed"))
}

/// Canonical active-member tuple bound into `EpochPublic.membersHash` (`Gate 2` / `Gate 3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberBinding {
    pub device_key_pub: [u8; XEDDSA_PUBKEY_LEN],
    pub epoch_storage_key_pub: Vec<u8>,
    pub is_virtual: bool,
}

/// Compute `membersHash` (`SHA-256` over canonical sorted active epoch members).
///
/// Rejects empty member sets, non-1,216-byte `HawkEncPublic` keys, and duplicate
/// `device_key_pub` entries.
pub fn compute_members_hash(members: &[MemberBinding]) -> Result<[u8; MEMBERS_HASH_LEN]> {
    if members.is_empty() {
        return Err(ProtocolError::MalformedEpochChain(
            "epoch must have at least one active member",
        ));
    }
    let mut sorted: Vec<&MemberBinding> = members.iter().collect();
    sorted.sort_by_key(|a| a.device_key_pub);
    for pair in sorted.windows(2) {
        if pair[0].device_key_pub == pair[1].device_key_pub {
            return Err(ProtocolError::MalformedEpochChain(
                "duplicate device_key_pub in epoch member set",
            ));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(MEMBERS_HASH_DOMAIN);
    let count = u32::try_from(sorted.len()).expect("member count fits in u32");
    hasher.update(count.to_be_bytes());
    for m in sorted {
        if m.epoch_storage_key_pub.len() != HAWK_ENC_PUBKEY_LEN {
            return Err(ProtocolError::BadPublicKey(
                "epoch_storage_key_pub must be 1,216-byte HawkEncPublic",
            ));
        }
        hasher.update(m.device_key_pub);
        let len = m.epoch_storage_key_pub.len() as u32;
        hasher.update(len.to_be_bytes());
        hasher.update(&m.epoch_storage_key_pub);
        hasher.update([u8::from(m.is_virtual)]);
    }
    Ok(hasher.finalize().into())
}

/// Compute `epochHead` (`SPEC §5.3` + `Gate 2`/`Gate 3` `membersHash` binding).
pub fn compute_epoch_head(
    seq: u64,
    auth_pubkey: &[u8; HAWK_AUTH_PUBKEY_LEN],
    encryption_pubkey: &[u8],
    signing_pubkey: &[u8; XEDDSA_PUBKEY_LEN],
    members_hash: &[u8; MEMBERS_HASH_LEN],
    prev_head: Option<&[u8; EPOCH_HEAD_LEN]>,
    did: &str,
) -> [u8; EPOCH_HEAD_LEN] {
    let prev = prev_head.map_or_else(|| "null".to_owned(), hex::encode);
    let epoch_hash: [u8; 32] = Sha256::digest(
        format!(
            "epoch_public_data:auth_pubkey={};encryption_pubkey={};epoch_number={seq};\
             members_hash={};previous_epoch_head={prev};signing_pubkey={};user_did={did}",
            hex::encode(auth_pubkey),
            hex::encode(encryption_pubkey),
            hex::encode(members_hash),
            hex::encode(signing_pubkey),
        )
        .as_bytes(),
    )
    .into();
    Sha256::digest(
        format!(
            "epoch_head:epoch_hash={};epoch_number={seq};previous_epoch_head={prev}",
            hex::encode(epoch_hash)
        )
        .as_bytes(),
    )
    .into()
}

/// Public epoch header verified by `labyrinth`, `catbird-mls`, and `mls-ds` (`Gate 6`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochPublicHeader {
    pub seq: u64,
    pub auth_pubkey: [u8; HAWK_AUTH_PUBKEY_LEN],
    pub encryption_pubkey: Vec<u8>,
    pub signing_pubkey: [u8; XEDDSA_PUBKEY_LEN],
    pub members_hash: [u8; MEMBERS_HASH_LEN],
    pub prev_head: Option<[u8; EPOCH_HEAD_LEN]>,
    pub head: [u8; EPOCH_HEAD_LEN],
    #[serde(with = "bytes64")]
    pub self_sig: [u8; XEDDSA_SIG_LEN],
    #[serde(with = "opt_bytes64")]
    pub prev_sig: Option<[u8; XEDDSA_SIG_LEN]>,
    pub attestation_pubkey: [u8; ED25519_PUBKEY_LEN],
    #[serde(with = "bytes64")]
    pub attestation_sig: [u8; ED25519_SIG_LEN],
}

mod bytes64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(b)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(d)?;
        v.try_into()
            .map_err(|_| D::Error::custom("expected 64-byte signature"))
    }
}

mod opt_bytes64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(opt: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        match opt {
            Some(b) => s.serialize_some(&b.as_slice()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        let opt: Option<Vec<u8>> = Option::<Vec<u8>>::deserialize(d)?;
        match opt {
            Some(v) => v
                .try_into()
                .map(Some)
                .map_err(|_| D::Error::custom("expected 64-byte signature")),
            None => Ok(None),
        }
    }
}

impl EpochPublicHeader {
    /// Canonical byte serialization for deterministic hashing / transport.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1536);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.auth_pubkey);
        push_len_prefixed(&mut out, &self.encryption_pubkey);
        out.extend_from_slice(&self.signing_pubkey);
        out.extend_from_slice(&self.members_hash);
        match &self.prev_head {
            Some(ph) => {
                out.push(1);
                out.extend_from_slice(ph);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.head);
        out.extend_from_slice(&self.self_sig);
        match &self.prev_sig {
            Some(ps) => {
                out.push(1);
                out.extend_from_slice(ps);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.attestation_pubkey);
        out.extend_from_slice(&self.attestation_sig);
        out
    }

    /// Verify this single header and (when `previous` is supplied) its link to `previous`.
    pub fn verify(&self, did: &str, previous: Option<&EpochPublicHeader>) -> Result<()> {
        if self.encryption_pubkey.len() != HAWK_ENC_PUBKEY_LEN {
            return Err(ProtocolError::BadPublicKey(
                "encryption_pubkey must be 1,216-byte HawkEncPublic",
            ));
        }
        let expected_head = compute_epoch_head(
            self.seq,
            &self.auth_pubkey,
            &self.encryption_pubkey,
            &self.signing_pubkey,
            &self.members_hash,
            self.prev_head.as_ref(),
            did,
        );
        if !bool::from(expected_head.ct_eq(&self.head)) {
            return Err(ProtocolError::MalformedEpochChain("epoch head mismatch"));
        }

        let self_msg = [EPOCH_SELF_SIG_PREFIX, self.head.as_slice()].concat();
        xeddsa_verify(&self.signing_pubkey, &self_msg, &self.self_sig)?;

        let attest_msg = [
            format!("{EPOCH_ATTEST_PREFIX}{did}:").as_bytes(),
            self.head.as_slice(),
        ]
        .concat();
        ed25519_verify_strict(&self.attestation_pubkey, &attest_msg, &self.attestation_sig)?;

        if self.seq == 0 {
            if self.prev_head.is_some() || self.prev_sig.is_some() {
                return Err(ProtocolError::MalformedEpochChain(
                    "epoch 0 must not carry prev_head or prev_sig",
                ));
            }
            if previous.is_some() {
                return Err(ProtocolError::MalformedEpochChain(
                    "epoch 0 cannot link to a predecessor",
                ));
            }
            return Ok(());
        }

        // [CB-35]: above epoch 0, prev_head and prev_sig are mandatory.
        let prev_head = self.prev_head.ok_or(ProtocolError::MalformedEpochChain(
            "missing prev_head above epoch 0",
        ))?;
        let prev_sig = self.prev_sig.ok_or(ProtocolError::MalformedEpochChain(
            "missing prev_sig above epoch 0",
        ))?;

        if let Some(prev) = previous {
            if prev.seq.checked_add(1) != Some(self.seq) || !bool::from(prev.head.ct_eq(&prev_head))
            {
                return Err(ProtocolError::MalformedEpochChain(
                    "epoch chain sequence or prev_head link broken",
                ));
            }
            let prev_msg = [EPOCH_PREV_SIG_PREFIX, self.head.as_slice()].concat();
            xeddsa_verify(&prev.signing_pubkey, &prev_msg, &prev_sig)?;
        }
        Ok(())
    }
}

/// Verified `EpochPublic` chain summary returned by [`verify_epoch_public_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEpochChain {
    pub first_seq: u64,
    pub latest: EpochPublicHeader,
}

/// Verify an ascending slice of `EpochPublicHeader` records for `did` against `floor_seq` (`L-F01`, `Gate 6`).
pub fn verify_epoch_public_chain(
    did: &str,
    chain: &[EpochPublicHeader],
    floor_seq: u64,
) -> Result<VerifiedEpochChain> {
    let first = chain
        .first()
        .ok_or(ProtocolError::MalformedEpochChain("epoch chain is empty"))?;
    first.verify(did, None)?;
    for pair in chain.windows(2) {
        pair[1].verify(did, Some(&pair[0]))?;
    }
    let latest = chain.last().expect("non-empty chain").clone();
    if latest.seq < floor_seq {
        return Err(ProtocolError::EpochRollback {
            latest_seq: latest.seq,
            floor_seq,
        });
    }
    Ok(VerifiedEpochChain {
        first_seq: first.seq,
        latest,
    })
}

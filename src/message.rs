//! Message encryption (SPEC §7.1–7.2, paper p.37–39 and p.51–52).
//!
//! - **Owner mode** (v1.0, cipher version 3): the mailbox owner encrypts under
//!   a key derived from its epoch root. Versions 0, 2 and 4 decrypt too.
//! - **Sender mode** (v1.1): any participant encrypts under a shared [`Mek`]
//!   and signs the ciphertext with its chat transport key ([CB-3]).
//!
//! All plaintexts are PADMÉ-padded ([CB-7]).

use zeroize::Zeroizing;

use crate::aead;
use crate::encoding::{hex, kdf32, minos_salt};
use crate::mek::Mek;
use crate::padding::{pad, unpad};
use crate::sign::{TransportSigner, verify_transport};
use crate::{Error, Result};

/// Cipher version written by [`seal_owner`].
pub const OWNER_VERSION: u8 = 3;

/// One owner-encrypted message (`defs#ownerMessage`).
///
/// Only `thread_id`, `epoch_seq` and `version` are authenticated (they feed
/// the key or AAD); `message_id` and `timestamp` are not, as in the paper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerMessage {
    pub thread_id: String,
    pub message_id: String,
    pub timestamp: u64,
    pub epoch_seq: u64,
    pub version: u8,
    pub encrypted: Vec<u8>,
}

/// Owner message key for cipher `version` (p.37–38, p.51–52). Version 1 and
/// anything above 4 are rejected.
pub fn owner_message_key_versioned(
    version: u8,
    root: &[u8; 32],
    seq: u64,
    thread_id: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let thread = thread_id.as_bytes();
    let key = match version {
        0 => kdf32(
            root,
            Some(thread),
            format!("message_key_in_epoch_{seq}").as_bytes(),
        ),
        2 => kdf32(
            root,
            Some(thread),
            format!("message_key_in_epoch_{seq}cipher_version_2").as_bytes(),
        ),
        3 | 4 => kdf32(
            root,
            None,
            format!("message_key_in_epoch_{seq}_cipher_version_{version}_thread_{thread_id}")
                .as_bytes(),
        ),
        other => return Err(Error::Unsupported(other)),
    };
    Ok(Zeroizing::new(key))
}

/// Cipher version 3 owner message key.
pub fn owner_message_key(root: &[u8; 32], seq: u64, thread_id: &str) -> Zeroizing<[u8; 32]> {
    owner_message_key_versioned(OWNER_VERSION, root, seq, thread_id)
        .expect("version 3 is supported")
}

fn owner_aad(thread_id: &str) -> Vec<u8> {
    format!("message_thread_{thread_id}").into_bytes()
}

/// Encrypt `data` as an owner message in epoch `epoch_seq` (cipher version 3).
pub fn seal_owner(
    epoch_root: &[u8; 32],
    epoch_seq: u64,
    thread_id: &str,
    message_id: &str,
    timestamp: u64,
    data: &[u8],
) -> Result<OwnerMessage> {
    let key = owner_message_key(epoch_root, epoch_seq, thread_id);
    Ok(OwnerMessage {
        thread_id: thread_id.to_owned(),
        message_id: message_id.to_owned(),
        timestamp,
        epoch_seq,
        version: OWNER_VERSION,
        encrypted: aead::seal(&key, &owner_aad(thread_id), &pad(data))?,
    })
}

/// Decrypt an owner message; `epoch_root` is the root of `msg.epoch_seq`.
pub fn open_owner(epoch_root: &[u8; 32], msg: &OwnerMessage) -> Result<Vec<u8>> {
    let key = owner_message_key_versioned(msg.version, epoch_root, msg.epoch_seq, &msg.thread_id)?;
    let padded = Zeroizing::new(aead::decrypt(
        &key,
        &owner_aad(&msg.thread_id),
        &msg.encrypted,
    )?);
    unpad(&padded)
}

/// One sender-encrypted message (`defs#sealedMessage`). The thread id comes
/// from the enclosing `batch` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedMessage {
    pub message_id: String,
    pub timestamp: u64,
    pub mek_id: [u8; 12],
    pub sender_transport_pub: [u8; 32],
    /// `Ed25519 sig(64) || suite-tagged AEAD ciphertext`.
    pub signed_enc_message: Vec<u8>,
}

const MESSAGE_SIG_PREFIX: &[u8] = b"minos.unstructured_signature.message:";

fn sender_message_key(
    mek: &Mek,
    thread_id: &str,
    message_id: &str,
    ts: u64,
) -> Zeroizing<[u8; 32]> {
    let info = format!(
        "minos.kdf.mek.single_message_key:;message_id={message_id};thread_id={};timestamp={ts}",
        hex(thread_id.as_bytes())
    );
    Zeroizing::new(kdf32(mek.secret(), Some(&minos_salt()), info.as_bytes()))
}

fn sender_aad(
    mek_id: &[u8; 12],
    message_id: &str,
    sender_pk: &[u8; 32],
    thread_id: &str,
    ts: u64,
) -> Vec<u8> {
    format!(
        "minos.symmetric_enc.message_v2:mek_id={};message_id={message_id};\
         sender_transport_pk={};thread_id={};timestamp={ts}",
        hex(mek_id),
        hex(sender_pk),
        hex(thread_id.as_bytes()),
    )
    .into_bytes()
}

/// Encrypt and sign `data` under `mek` (p.39).
pub fn seal_sender(
    mek: &Mek,
    thread_id: &str,
    message_id: &str,
    timestamp: u64,
    data: &[u8],
    transport: &dyn TransportSigner,
) -> Result<SealedMessage> {
    let sender_pk = transport.transport_public_key();
    let key = sender_message_key(mek, thread_id, message_id, timestamp);
    let aad = sender_aad(mek.id(), message_id, &sender_pk, thread_id, timestamp);
    let ct = aead::seal(&key, &aad, &pad(data))?;
    let sig = transport.sign_transport(&[MESSAGE_SIG_PREFIX, &ct].concat());
    Ok(SealedMessage {
        message_id: message_id.to_owned(),
        timestamp,
        mek_id: *mek.id(),
        sender_transport_pub: sender_pk,
        signed_enc_message: [sig.as_slice(), &ct].concat(),
    })
}

/// Verify and decrypt a sender message (p.41). The caller must also check
/// the sender key with [`verify_sender_device`].
pub fn open_sender(sealed: &SealedMessage, thread_id: &str, mek: &Mek) -> Result<Vec<u8>> {
    if sealed.mek_id != *mek.id() {
        return Err(Error::MekMismatch);
    }
    let (sig, ct) = sealed
        .signed_enc_message
        .split_first_chunk::<64>()
        .ok_or(Error::Malformed("signed message shorter than signature"))?;
    verify_transport(
        &sealed.sender_transport_pub,
        &[MESSAGE_SIG_PREFIX, ct].concat(),
        sig,
    )?;
    let key = sender_message_key(mek, thread_id, &sealed.message_id, sealed.timestamp);
    let aad = sender_aad(
        &sealed.mek_id,
        &sealed.message_id,
        &sealed.sender_transport_pub,
        thread_id,
        sealed.timestamp,
    );
    let padded = Zeroizing::new(aead::decrypt(&key, &aad, ct)?);
    unpad(&padded)
}

/// Checks the sender's transport key is one of `allowed` — the caller's list
/// of the claimed sender's chat device keys in the MLS group ([CB-3]).
pub fn verify_sender_device(sealed: &SealedMessage, allowed: &[[u8; 32]]) -> Result<()> {
    if allowed.contains(&sealed.sender_transport_pub) {
        Ok(())
    } else {
        Err(Error::BadPublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_key_versions_follow_the_paper() {
        let root = [5u8; 32];
        let v3 = owner_message_key(&root, 7, "t");
        assert_eq!(
            *v3,
            kdf32(
                &root,
                None,
                b"message_key_in_epoch_7_cipher_version_3_thread_t"
            )
        );
        let v0 = owner_message_key_versioned(0, &root, 7, "t").unwrap();
        assert_eq!(*v0, kdf32(&root, Some(b"t"), b"message_key_in_epoch_7"));
        let v2 = owner_message_key_versioned(2, &root, 7, "t").unwrap();
        assert_eq!(
            *v2,
            kdf32(&root, Some(b"t"), b"message_key_in_epoch_7cipher_version_2")
        );
        let v4 = owner_message_key_versioned(4, &root, 7, "t").unwrap();
        assert_ne!(*v4, *v3);
        assert_eq!(
            owner_message_key_versioned(1, &root, 7, "t").unwrap_err(),
            Error::Unsupported(1)
        );
        assert!(owner_message_key_versioned(5, &root, 7, "t").is_err());
    }

    #[test]
    fn older_versions_decrypt() {
        let root = [6u8; 32];
        for v in [0u8, 2, 4] {
            let key = owner_message_key_versioned(v, &root, 2, "th").unwrap();
            let msg = OwnerMessage {
                thread_id: "th".into(),
                message_id: "m".into(),
                timestamp: 1,
                epoch_seq: 2,
                version: v,
                encrypted: aead::seal(&key, b"message_thread_th", &pad(b"old")).unwrap(),
            };
            assert_eq!(open_owner(&root, &msg).unwrap(), b"old");
            let mut v1 = msg.clone();
            v1.version = 1;
            assert_eq!(open_owner(&root, &v1), Err(Error::Unsupported(1)));
        }
    }

    #[test]
    fn sender_message_key_matches_spec_string() {
        let mek = Mek::generate(&[[1u8; 32]]).unwrap();
        let k = sender_message_key(&mek, "ab", "m1", 42);
        let info = b"minos.kdf.mek.single_message_key:;message_id=m1;thread_id=6162;timestamp=42";
        assert_eq!(*k, kdf32(mek.secret(), Some(&minos_salt()), info));
    }
}

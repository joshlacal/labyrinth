//! Message encryption (SPEC §7.1–7.2, paper p.37–39 and p.51–52).
//!
//! - **Owner mode**: the mailbox owner encrypts under a key derived from its
//!   epoch root. We write cipher version 5 ([CB-37]: version 3's key, an
//!   AAD that also binds `messageId` and `timestamp`, and a content-kind
//!   byte so delete-for-me tombstones look like messages to the server).
//!   Versions 0, 2, 3 and 4 decrypt too.
//! - **Sender mode** (v1.1): any participant encrypts under a shared [`Mek`]
//!   and signs the ciphertext with its chat transport key ([CB-3]).
//!
//! All plaintexts are PADMÉ-padded ([CB-7]).

use zeroize::Zeroizing;

use crate::aead::{self, Suite};
use crate::encoding::{hex, kdf32, minos_salt};
use crate::mek::Mek;
use crate::padding::{pad, unpad};
use crate::sign::{TransportSigner, verify_transport};
use crate::{Error, Result};

/// Cipher version written by [`seal_owner`] ([CB-37]).
pub const OWNER_VERSION: u8 = 5;

/// v5 content kind: an archived message frame.
const KIND_FRAME: u8 = 0x00;
/// v5 content kind: a delete-for-me tombstone ([CB-38]).
const KIND_TOMBSTONE: u8 = 0x01;
/// v5 content kind: an `I13` receipt-committed frame (`[frame_nonce: 32B || frame]`).
const KIND_COMMITTED_FRAME: u8 = 0x02;
/// v5 content kind: an attributed frame (`[u16 sender_len || sender_did || frame]`)
/// preserving authenticated sender attribution across `[CB-22]` leave and kick fallbacks.
const KIND_ATTRIBUTED_FRAME: u8 = 0x03;

/// Sequencer receipt carried alongside a sealed or owner-archived item (`I13`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivedReceipt {
    pub signed: labyrinth_protocol::receipt::SignedSequencerReceipt,
    pub generation: u64,
}

impl ArchivedReceipt {
    pub fn new(signed: labyrinth_protocol::receipt::SignedSequencerReceipt) -> Self {
        Self {
            signed,
            generation: 0,
        }
    }
}

/// What an owner record holds once opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerContent {
    /// An archived message frame.
    Frame(Vec<u8>),
    /// An archived message frame with authenticated sender DID preserved inside
    /// `epoch_root`-bound v5 ciphertext (`[CB-22]`, `[CB-37]`).
    AttributedFrame { sender_did: String, frame: Vec<u8> },
    /// An `I13` receipt-committed message frame with its 32-byte `frame_nonce`
    /// kept strictly inside ciphertext.
    CommittedFrame {
        frame_nonce: [u8; 32],
        frame: Vec<u8>,
    },
    /// A delete-for-me tombstone ([CB-38], v5 only): hide the message with
    /// this record's `messageId` on every device of the account; only the
    /// copies from `author` when it is set.
    Tombstone { author: Option<String> },
}

/// One owner-encrypted message (`defs#ownerMessage`).
///
/// `thread_id`, `epoch_seq` and `version` are always authenticated (they
/// feed the key or AAD). `message_id` and `timestamp` are authenticated
/// only from version 5 on ([CB-37]); in versions 0–4 they are not, as in
/// the paper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerMessage {
    pub thread_id: String,
    pub message_id: String,
    pub seq: Option<u64>,
    pub timestamp: u64,
    pub epoch_seq: u64,
    pub version: u8,
    pub encrypted: Vec<u8>,
    pub sequencer_receipt: Option<ArchivedReceipt>,
}

/// Owner message key for cipher `version` (p.37–38, p.51–52). Version 1 and
/// anything above 5 are rejected.
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
        3..=5 => kdf32(
            root,
            None,
            format!("message_key_in_epoch_{seq}_cipher_version_{version}_thread_{thread_id}")
                .as_bytes(),
        ),
        other => return Err(Error::Unsupported(other)),
    };
    Ok(Zeroizing::new(key))
}

/// Cipher version 3 owner message key (the paper's v1.0 writer).
pub fn owner_message_key(root: &[u8; 32], seq: u64, thread_id: &str) -> Zeroizing<[u8; 32]> {
    owner_message_key_versioned(3, root, seq, thread_id).expect("version 3 is supported")
}

/// Owner-message AAD: version 5 binds message id and timestamp; committed
/// owner records additionally bind the complete retained receipt. Successful
/// owner decryption therefore authenticates its sequencer authority.
fn owner_aad(
    version: u8,
    thread_id: &str,
    message_id: &str,
    timestamp: u64,
    receipt: Option<&ArchivedReceipt>,
) -> Result<Vec<u8>> {
    let mut aad = if version >= 5 {
        format!(
            "catbird.labyrinth.owner_message_v5:message_id={message_id};thread_id={};\
             timestamp={timestamp}",
            hex(thread_id.as_bytes())
        )
        .into_bytes()
    } else {
        format!("message_thread_{thread_id}").into_bytes()
    };
    if let Some(receipt) = receipt {
        let encoded = serde_ipld_dagcbor::to_vec(
            &crate::records::defs::SequencerReceiptDef::from_archived(receipt),
        )
        .map_err(|_| Error::Malformed("owner receipt DAG-CBOR"))?;
        aad.extend_from_slice(b"\0catbird.labyrinth.owner_receipt_v1\0");
        aad.extend_from_slice(&encoded);
    }
    Ok(aad)
}

#[allow(clippy::too_many_arguments)]
fn seal_owner_kind(
    epoch_root: &[u8; 32],
    epoch_seq: u64,
    thread_id: &str,
    message_id: &str,
    seq: Option<u64>,
    timestamp: u64,
    kind: u8,
    body: &[u8],
    sequencer_receipt: Option<ArchivedReceipt>,
) -> Result<OwnerMessage> {
    let key = owner_message_key_versioned(OWNER_VERSION, epoch_root, epoch_seq, thread_id)?;
    let aad = owner_aad(
        OWNER_VERSION,
        thread_id,
        message_id,
        timestamp,
        sequencer_receipt.as_ref(),
    )?;
    let content = Zeroizing::new([&[kind], body].concat());
    Ok(OwnerMessage {
        thread_id: thread_id.to_owned(),
        message_id: message_id.to_owned(),
        seq,
        timestamp,
        epoch_seq,
        version: OWNER_VERSION,
        encrypted: aead::seal(&key, &aad, &Zeroizing::new(pad(&content)))?,
        sequencer_receipt,
    })
}

/// Encrypt `data` as an owner message in epoch `epoch_seq` (cipher
/// version 5, [CB-37]).
pub fn seal_owner(
    epoch_root: &[u8; 32],
    epoch_seq: u64,
    thread_id: &str,
    message_id: &str,
    timestamp: u64,
    data: &[u8],
) -> Result<OwnerMessage> {
    seal_owner_kind(
        epoch_root, epoch_seq, thread_id, message_id, None, timestamp, KIND_FRAME, data, None,
    )
}

/// Encrypt `data` as an owner message with authenticated `sender_did` preserved
/// inside `v5` ciphertext (`[CB-22]`, `[CB-37]`).
pub fn seal_owner_attributed(
    epoch_root: &[u8; 32],
    epoch_seq: u64,
    thread_id: &str,
    message_id: &str,
    timestamp: u64,
    sender_did: &str,
    data: &[u8],
) -> Result<OwnerMessage> {
    let trimmed = sender_did.trim();
    if trimmed.is_empty() || !trimmed.starts_with("did:") || trimmed.len() > 2048 {
        return Err(Error::Malformed("owner attributed sender_did invalid"));
    }
    let sender_len = u16::try_from(trimmed.len())
        .map_err(|_| Error::Malformed("owner attributed sender_did too long"))?;
    let mut body = Zeroizing::new(Vec::with_capacity(2 + trimmed.len() + data.len()));
    body.extend_from_slice(&sender_len.to_be_bytes());
    body.extend_from_slice(trimmed.as_bytes());
    body.extend_from_slice(data);
    seal_owner_kind(
        epoch_root,
        epoch_seq,
        thread_id,
        message_id,
        None,
        timestamp,
        KIND_ATTRIBUTED_FRAME,
        &body,
        None,
    )
}

/// Encrypt an `I13` receipt-committed frame (`[frame_nonce || payload_bytes]`)
/// as an owner message in epoch `epoch_seq`.
#[allow(clippy::too_many_arguments)]
pub fn seal_owner_committed(
    epoch_root: &[u8; 32],
    epoch_seq: u64,
    thread_id: &str,
    message_id: &str,
    timestamp: u64,
    frame_nonce: &[u8; 32],
    payload_bytes: &[u8],
    receipt: &ArchivedReceipt,
) -> Result<OwnerMessage> {
    let body = Zeroizing::new([frame_nonce.as_slice(), payload_bytes].concat());
    seal_owner_kind(
        epoch_root,
        epoch_seq,
        thread_id,
        message_id,
        Some(receipt.signed.payload.seq),
        timestamp,
        KIND_COMMITTED_FRAME,
        &body,
        Some(receipt.clone()),
    )
}

/// A delete-for-me tombstone ([CB-38]) for message `message_id` (whose
/// timestamp is `timestamp`, so time-range reads see the tombstone with
/// its target), optionally only for copies from `author`. Padded like a
/// message, so the store cannot tell the two apart.
pub fn seal_owner_tombstone(
    epoch_root: &[u8; 32],
    epoch_seq: u64,
    thread_id: &str,
    message_id: &str,
    timestamp: u64,
    author: Option<&str>,
) -> Result<OwnerMessage> {
    let body = author.unwrap_or("").as_bytes();
    seal_owner_kind(
        epoch_root,
        epoch_seq,
        thread_id,
        message_id,
        None,
        timestamp,
        KIND_TOMBSTONE,
        body,
        None,
    )
}

/// Decrypt an owner record; `epoch_root` is the root of `msg.epoch_seq`.
pub fn open_owner_content(epoch_root: &[u8; 32], msg: &OwnerMessage) -> Result<OwnerContent> {
    let key = owner_message_key_versioned(msg.version, epoch_root, msg.epoch_seq, &msg.thread_id)?;
    let aad = owner_aad(
        msg.version,
        &msg.thread_id,
        &msg.message_id,
        msg.timestamp,
        msg.sequencer_receipt.as_ref(),
    )?;
    let padded = Zeroizing::new(aead::decrypt(&key, &aad, &msg.encrypted)?);
    let content = unpad(&padded)?;
    if msg.version < 5 {
        return Ok(OwnerContent::Frame(content));
    }
    let (kind, body) = content
        .split_first()
        .ok_or(Error::Malformed("owner v5 content is empty"))?;
    match *kind {
        KIND_FRAME => Ok(OwnerContent::Frame(body.to_vec())),
        KIND_ATTRIBUTED_FRAME => {
            let (len_bytes, rest) = body
                .split_first_chunk::<2>()
                .ok_or(Error::Malformed("owner attributed frame truncated"))?;
            let sender_len = u16::from_be_bytes(*len_bytes) as usize;
            if sender_len == 0 || sender_len > 2048 || rest.len() < sender_len {
                return Err(Error::Malformed(
                    "owner attributed sender_did length invalid",
                ));
            }
            let (did_bytes, frame) = rest.split_at(sender_len);
            let sender_did = core::str::from_utf8(did_bytes)
                .map_err(|_| Error::Malformed("owner attributed sender_did is not UTF-8"))?;
            if !sender_did.starts_with("did:") {
                return Err(Error::Malformed(
                    "owner attributed sender_did must start with did:",
                ));
            }
            Ok(OwnerContent::AttributedFrame {
                sender_did: sender_did.to_owned(),
                frame: frame.to_vec(),
            })
        }
        KIND_COMMITTED_FRAME => {
            if msg.sequencer_receipt.is_none() {
                return Err(Error::ReceiptCommitmentMismatch);
            }
            let (nonce, frame) = body
                .split_first_chunk::<32>()
                .ok_or(Error::ReceiptCommitmentMismatch)?;
            Ok(OwnerContent::CommittedFrame {
                frame_nonce: *nonce,
                frame: frame.to_vec(),
            })
        }
        KIND_TOMBSTONE => {
            let author = String::from_utf8(body.to_vec())
                .map_err(|_| Error::Malformed("tombstone author is not UTF-8"))?;
            Ok(OwnerContent::Tombstone {
                author: (!author.is_empty()).then_some(author),
            })
        }
        other => Err(Error::Unsupported(other)),
    }
}

/// Decrypt an owner message frame; a tombstone fails with
/// [`Error::Malformed`] (use [`open_owner_content`] to read those).
pub fn open_owner(epoch_root: &[u8; 32], msg: &OwnerMessage) -> Result<Vec<u8>> {
    match open_owner_content(epoch_root, msg)? {
        OwnerContent::Frame(f) | OwnerContent::AttributedFrame { frame: f, .. } => {
            if msg.sequencer_receipt.is_some() {
                return Err(Error::ReceiptCommitmentMismatch);
            }
            Ok(f)
        }
        OwnerContent::CommittedFrame { frame_nonce, frame } => {
            if let Some(r) = &msg.sequencer_receipt {
                labyrinth_protocol::verify_archived_item_commitment(
                    &r.signed,
                    &frame_nonce,
                    &frame,
                )
                .map_err(|_| Error::ReceiptCommitmentMismatch)?;
            }
            Ok(frame)
        }
        OwnerContent::Tombstone { .. } => Err(Error::Malformed("owner record is a tombstone")),
    }
}

/// One sender-encrypted message (`defs#sealedMessage`). The thread id comes
/// from the enclosing `batch` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedMessage {
    pub message_id: String,
    pub seq: Option<u64>,
    pub timestamp: u64,
    pub mek_id: [u8; 12],
    pub sender_transport_pub: [u8; 32],
    /// `Ed25519 sig(64) || suite-tagged AEAD ciphertext`.
    pub signed_enc_message: Vec<u8>,
    pub sequencer_receipt: Option<ArchivedReceipt>,
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
    let padded = Zeroizing::new(pad(data));
    let ct = aead::seal(&key, &aad, &padded)?;
    let sig = transport.sign_transport(&[MESSAGE_SIG_PREFIX, &ct].concat());
    Ok(SealedMessage {
        message_id: message_id.to_owned(),
        seq: None,
        timestamp,
        mek_id: *mek.id(),
        sender_transport_pub: sender_pk,
        signed_enc_message: [sig.as_slice(), &ct].concat(),
        sequencer_receipt: None,
    })
}

/// Encrypt and sign `[frame_nonce: 32B || payload_bytes]` under `mek` with an
/// `I13` sequencer receipt attached (`frame_nonce` never leaves AEAD plaintext).
#[allow(clippy::too_many_arguments)]
pub fn seal_sender_committed(
    mek: &Mek,
    thread_id: &str,
    message_id: &str,
    timestamp: u64,
    frame_nonce: &[u8; 32],
    payload_bytes: &[u8],
    receipt: &ArchivedReceipt,
    transport: &dyn TransportSigner,
) -> Result<SealedMessage> {
    let combined = Zeroizing::new([frame_nonce.as_slice(), payload_bytes].concat());
    let mut sealed = seal_sender(mek, thread_id, message_id, timestamp, &combined, transport)?;
    sealed.seq = Some(receipt.signed.payload.seq);
    sealed.sequencer_receipt = Some(receipt.clone());
    Ok(sealed)
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
    let padded = Zeroizing::new(aead::decrypt_suite(Suite::DndkGcm, &key, &aad, ct)?);
    unpad(&padded)
}

/// Verify and decrypt a committed sender message, splitting `(frame_nonce, payload_bytes)`.
pub fn open_sender_committed(
    sealed: &SealedMessage,
    thread_id: &str,
    mek: &Mek,
) -> Result<([u8; 32], Vec<u8>)> {
    let raw = open_sender(sealed, thread_id, mek)?;
    let (nonce, payload) = raw
        .split_first_chunk::<32>()
        .ok_or(Error::ReceiptCommitmentMismatch)?;
    Ok((*nonce, payload.to_vec()))
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
        let v5 = owner_message_key_versioned(5, &root, 7, "t").unwrap();
        assert_eq!(
            *v5,
            kdf32(
                &root,
                None,
                b"message_key_in_epoch_7_cipher_version_5_thread_t"
            )
        );
        assert!(owner_message_key_versioned(6, &root, 7, "t").is_err());
    }

    #[test]
    fn older_versions_decrypt() {
        let root = [6u8; 32];
        for v in [0u8, 2, 4] {
            let key = owner_message_key_versioned(v, &root, 2, "th").unwrap();
            let msg = OwnerMessage {
                thread_id: "th".into(),
                message_id: "m".into(),
                seq: None,
                timestamp: 1,
                epoch_seq: 2,
                version: v,
                encrypted: aead::seal(&key, b"message_thread_th", &pad(b"old")).unwrap(),
                sequencer_receipt: None,
            };
            assert_eq!(open_owner(&root, &msg).unwrap(), b"old");
            let mut v1 = msg.clone();
            v1.version = 1;
            assert_eq!(open_owner(&root, &v1), Err(Error::Unsupported(1)));
        }
    }

    #[test]
    fn v5_binds_message_id_timestamp_and_kind() {
        let root = [9u8; 32];
        let m = seal_owner(&root, 4, "th", "m1", 10, b"hello").unwrap();
        assert_eq!(m.version, 5);
        assert_eq!(open_owner(&root, &m).unwrap(), b"hello");
        // The server swaps the id or the timestamp: v5 notices.
        let mut swapped = m.clone();
        swapped.message_id = "m2".into();
        assert_eq!(open_owner(&root, &swapped), Err(Error::Decrypt));
        let mut moved = m.clone();
        moved.timestamp = 11;
        assert_eq!(open_owner(&root, &moved), Err(Error::Decrypt));
        // A tombstone opens as one, and is padded like the message.
        let t = seal_owner_tombstone(&root, 4, "th", "m1", 10, Some("did:plc:b")).unwrap();
        assert_eq!(t.encrypted.len(), m.encrypted.len());
        assert_eq!(
            open_owner_content(&root, &t).unwrap(),
            OwnerContent::Tombstone {
                author: Some("did:plc:b".into())
            }
        );
        assert!(open_owner(&root, &t).is_err());
        let any = seal_owner_tombstone(&root, 4, "th", "m1", 10, None).unwrap();
        assert_eq!(
            open_owner_content(&root, &any).unwrap(),
            OwnerContent::Tombstone { author: None }
        );
        // Downgrading the version byte changes key and AAD: refused.
        let mut v3 = m.clone();
        v3.version = 3;
        assert_eq!(open_owner(&root, &v3), Err(Error::Decrypt));
    }

    #[test]
    fn sender_message_key_matches_spec_string() {
        let mek = Mek::generate(&[[1u8; 32]]).unwrap();
        let k = sender_message_key(&mek, "ab", "m1", 42);
        let info = b"minos.kdf.mek.single_message_key:;message_id=m1;thread_id=6162;timestamp=42";
        assert_eq!(*k, kdf32(mek.secret(), Some(&minos_salt()), info));
    }

    #[test]
    fn sender_messages_refuse_the_v10_suite() {
        let t = crate::sign::Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[3; 32]));
        let mek = Mek::generate(&[[1; 32]]).unwrap();
        let sealed = seal_sender(&mek, "t", "m", 5, b"hi", &t).unwrap();
        assert_eq!(open_sender(&sealed, "t", &mek).unwrap(), b"hi");
        // Same key, AAD and a valid signature, but sealed under suite 0x01.
        let key = sender_message_key(&mek, "t", "m", 5);
        let aad = sender_aad(mek.id(), "m", &sealed.sender_transport_pub, "t", 5);
        let ct = aead::encrypt(Suite::GcmExtended, &key, &aad, &pad(b"hi")).unwrap();
        let sig = t.sign_transport(&[MESSAGE_SIG_PREFIX, &ct].concat());
        let mut down = sealed.clone();
        down.signed_enc_message = [sig.as_slice(), &ct].concat();
        assert_eq!(open_sender(&down, "t", &mek), Err(Error::Unsupported(0x01)));
    }

    #[test]
    fn legacy_owner_messages_still_accept_the_v10_suite() {
        let root = [5u8; 32];
        let key = owner_message_key(&root, 2, "th");
        let m = OwnerMessage {
            thread_id: "th".into(),
            message_id: "m".into(),
            seq: None,
            timestamp: 1,
            epoch_seq: 2,
            version: 3,
            encrypted: aead::encrypt(
                Suite::GcmExtended,
                &key,
                &owner_aad(3, "th", "m", 1, None).unwrap(),
                &pad(b"old"),
            )
            .unwrap(),
            sequencer_receipt: None,
        };
        assert_eq!(open_owner(&root, &m).unwrap(), b"old");
    }
}

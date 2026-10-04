//! MEK distribution records: build ([`distribute_labyrinth`],
//! [`distribute_transport`]) and [`open`] (SPEC §7.3–7.4, paper p.39–41).
//!
//! One record carries a Hawk ciphertext of the MEK for every roster member
//! ([CB-21]). Every AAD also binds the thread id ([CB-24]).

use zeroize::Zeroizing;

use super::{Mek, MekProvenance, mek_id, roster_hash};
use crate::encoding::hex;
use crate::hpke::hawk::{
    HawkAuthPublic, HawkAuthSecret, hawk_auth_keygen, hawk_decrypt, hawk_encrypt,
};
use crate::hpke::labyrinth::X25519Public;
use crate::mailbox::{EpochPublic, MailboxKeys};
use crate::sign::{TransportSigner, verify_transport};
use crate::{Error, Result};

/// Who distributed the MEK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MekSender {
    /// An enrolled device, authenticated by its mailbox auth key.
    Labyrinth {
        did: String,
        sender_epoch_head: [u8; 32],
    },
    /// A non-enrolled device, authenticated by its chat transport key.
    Transport {
        transport_pub: [u8; 32],
        ephemeral_auth_pub: [u8; 32],
        sig: [u8; 64],
    },
}

/// One recipient's copy of the MEK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MekRecipient {
    pub did: String,
    pub recipient_epoch_head: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// A `blue.catbird.labyrinth.mek` record, as plain data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MekRecord {
    pub thread_id: String,
    pub mek_id: [u8; 12],
    pub roster_hash: [u8; 32],
    pub sender: MekSender,
    pub recipients: Vec<MekRecipient>,
}

impl MekRecord {
    /// The recipients' epoch heads, in record order.
    pub fn recipient_heads(&self) -> Vec<[u8; 32]> {
        self.recipients
            .iter()
            .map(|r| r.recipient_epoch_head)
            .collect()
    }
}

fn aad(
    sender: &MekSender,
    mek_id: &[u8; 12],
    recip: &[u8; 32],
    roster: &[u8; 32],
    thread: &str,
) -> Vec<u8> {
    let (label, sender_field) = match sender {
        MekSender::Labyrinth {
            sender_epoch_head, ..
        } => (
            "minos.hpke.mek_distribution_from_minos_v2:",
            format!("sender_epoch={}", hex(sender_epoch_head)),
        ),
        MekSender::Transport { transport_pub, .. } => (
            "minos.hpke.mek_distribution_from_transport_v2:",
            format!("sender_transport_pubkey={}", hex(transport_pub)),
        ),
    };
    format!(
        "{label}mek_id={};recipient_epoch={};recipient_roster_hash={};{sender_field};thread_id={}",
        hex(mek_id),
        hex(recip),
        hex(roster),
        hex(thread.as_bytes()),
    )
    .into_bytes()
}

fn ephemeral_auth_message(eph: &[u8; 32], mek_id: &[u8; 12]) -> Vec<u8> {
    format!(
        "minos.structured_signature.mek_distribution.ephemeral_auth:k={};mek_id={}",
        hex(eph),
        hex(mek_id)
    )
    .into_bytes()
}

/// Rejects duplicate DIDs or heads, which would make the roster ambiguous.
fn check_unique<'a>(entries: impl Iterator<Item = (&'a str, &'a [u8; 32])>) -> Result<()> {
    let mut seen_dids = std::collections::BTreeSet::new();
    let mut seen_heads = std::collections::BTreeSet::new();
    for (did, head) in entries {
        if !seen_dids.insert(did) || !seen_heads.insert(head) {
            return Err(Error::Malformed("duplicate MEK recipient"));
        }
    }
    Ok(())
}

/// Verifies every recipient epoch and that the roster matches `mek`.
fn check_recipients(mek: &Mek, recipients: &[(String, EpochPublic)]) -> Result<()> {
    check_unique(recipients.iter().map(|(d, e)| (d.as_str(), &e.head)))?;
    for (did, epoch) in recipients {
        epoch.verify(did, None)?;
    }
    let heads: Vec<[u8; 32]> = recipients.iter().map(|(_, e)| e.head).collect();
    if roster_hash(&heads) != *mek.roster_hash() {
        return Err(Error::RosterMismatch);
    }
    Ok(())
}

fn seal_all(
    thread_id: &str,
    mek: &Mek,
    sender: MekSender,
    auth: (&HawkAuthSecret, &HawkAuthPublic),
    recipients: &[(String, EpochPublic)],
) -> Result<MekRecord> {
    let recipients = recipients
        .iter()
        .map(|(did, epoch)| {
            let a = aad(&sender, mek.id(), &epoch.head, mek.roster_hash(), thread_id);
            Ok(MekRecipient {
                did: did.clone(),
                recipient_epoch_head: epoch.head,
                ciphertext: hawk_encrypt(&epoch.keys.enc, auth.0, auth.1, &a, mek.secret())?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(MekRecord {
        thread_id: thread_id.to_owned(),
        mek_id: *mek.id(),
        roster_hash: *mek.roster_hash(),
        sender,
        recipients,
    })
}

/// Labyrinth sender MEK (p.40). `recipients` is the whole roster, the sender
/// included ([CB-16]); each [`EpochPublic`] is verified here, but the caller
/// must check its attestation key belongs to that DID's MLS devices ([CB-18]).
pub fn distribute_labyrinth(
    thread_id: &str,
    mek: &mut Mek,
    sender_did: &str,
    sender_epoch: &EpochPublic,
    sender_keys: &MailboxKeys,
    recipients: &[(String, EpochPublic)],
) -> Result<MekRecord> {
    if sender_keys.public() != sender_epoch.keys {
        return Err(Error::Malformed("sender keys do not match sender epoch"));
    }
    check_recipients(mek, recipients)?;
    if !recipients
        .iter()
        .any(|(d, e)| d == sender_did && e.head == sender_epoch.head)
    {
        return Err(Error::Malformed("sender epoch is not in the roster"));
    }
    let sender = MekSender::Labyrinth {
        did: sender_did.to_owned(),
        sender_epoch_head: sender_epoch.head,
    };
    let auth = (&sender_keys.auth_secret, &sender_keys.auth_public);
    let record = seal_all(thread_id, mek, sender, auth, recipients)?;
    mek.set_provenance(MekProvenance::Labyrinth {
        sender_did: sender_did.to_owned(),
        sender_epoch_head: sender_epoch.head,
    });
    Ok(record)
}

/// Transport sender MEK (p.40–41) from a device that is not enrolled.
pub fn distribute_transport(
    thread_id: &str,
    mek: &mut Mek,
    transport: &dyn TransportSigner,
    recipients: &[(String, EpochPublic)],
) -> Result<MekRecord> {
    check_recipients(mek, recipients)?;
    let (eph_priv, eph_pub) = hawk_auth_keygen()?;
    let transport_pub = transport.transport_public_key();
    let sender = MekSender::Transport {
        transport_pub,
        ephemeral_auth_pub: eph_pub.0,
        sig: transport.sign_transport(&ephemeral_auth_message(&eph_pub.0, mek.id())),
    };
    let record = seal_all(thread_id, mek, sender, (&eph_priv, &eph_pub), recipients)?;
    mek.set_provenance(MekProvenance::Transport {
        transport_pub,
        created_here: true,
    });
    Ok(record)
}

/// Open my copy of a MEK (p.41).
///
/// `my_epoch` / `my_keys` must be the epoch the record addressed me under.
/// `sender_epoch` is required for a Labyrinth sender and ignored for a
/// transport sender. The caller still checks that the sender's attestation
/// key (Labyrinth) or `transport_pub` (transport) is an MLS device of the
/// sender ([CB-3], [CB-18]); the returned provenance names it.
pub fn open(
    record: &MekRecord,
    my_did: &str,
    my_epoch: &EpochPublic,
    my_keys: &MailboxKeys,
    sender_epoch: Option<&EpochPublic>,
) -> Result<Mek> {
    let r = record;
    check_unique(
        r.recipients
            .iter()
            .map(|x| (x.did.as_str(), &x.recipient_epoch_head)),
    )?;
    if roster_hash(&r.recipient_heads()) != r.roster_hash {
        return Err(Error::RosterMismatch);
    }
    let mine = r
        .recipients
        .iter()
        .find(|x| x.did == my_did)
        .ok_or(Error::NotRecipient)?;
    if mine.recipient_epoch_head != my_epoch.head {
        return Err(Error::WrongEpoch);
    }
    my_epoch.verify(my_did, None)?;
    if my_keys.public() != my_epoch.keys {
        return Err(Error::Malformed("mailbox keys do not match my epoch"));
    }
    let (auth_pub, provenance) = sender_auth(r, sender_epoch)?;
    let a = aad(
        &r.sender,
        &r.mek_id,
        &mine.recipient_epoch_head,
        &r.roster_hash,
        &r.thread_id,
    );
    let pt = Zeroizing::new(hawk_decrypt(
        &my_keys.enc_public,
        &my_keys.enc_secret,
        &auth_pub,
        &a,
        &mine.ciphertext,
    )?);
    let secret: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| Error::Malformed("MEK length"))?;
    let secret = Zeroizing::new(secret);
    if mek_id(&secret, &r.roster_hash) != r.mek_id {
        return Err(Error::MekMismatch);
    }
    Ok(Mek::from_secret(secret, r.roster_hash, provenance))
}

/// The Hawk auth key the sender used, after authenticating it.
fn sender_auth(
    r: &MekRecord,
    sender_epoch: Option<&EpochPublic>,
) -> Result<(HawkAuthPublic, MekProvenance)> {
    match &r.sender {
        MekSender::Labyrinth {
            did,
            sender_epoch_head,
        } => {
            let epoch = sender_epoch.ok_or(Error::NotFound("sender epoch"))?;
            if epoch.head != *sender_epoch_head {
                return Err(Error::WrongEpoch);
            }
            epoch.verify(did, None)?;
            if !r
                .recipients
                .iter()
                .any(|x| x.did == *did && x.recipient_epoch_head == *sender_epoch_head)
            {
                return Err(Error::Malformed("sender epoch is not in the roster"));
            }
            let p = MekProvenance::Labyrinth {
                sender_did: did.clone(),
                sender_epoch_head: *sender_epoch_head,
            };
            Ok((epoch.keys.auth, p))
        }
        MekSender::Transport {
            transport_pub,
            ephemeral_auth_pub,
            sig,
        } => {
            verify_transport(
                transport_pub,
                &ephemeral_auth_message(ephemeral_auth_pub, &r.mek_id),
                sig,
            )?;
            let p = MekProvenance::Transport {
                transport_pub: *transport_pub,
                created_here: false,
            };
            Ok((X25519Public(*ephemeral_auth_pub), p))
        }
    }
}

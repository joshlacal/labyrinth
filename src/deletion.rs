//! Deletion primitives ([CB-38], gap audit §9, decision J1 defaults).
//!
//! | What | Who | How |
//! |---|---|---|
//! | delete for me | any device of the reader's account | an encrypted owner-mode tombstone in the reader's own mailbox ([`crate::message::seal_owner_tombstone`]); every device of the account hides the message, the server learns nothing |
//! | unsend (delete for everyone) | the message's author | [`crate::store::ThreadStore::redact_item`]: the server replaces the item's ciphertext with a signed [`Redaction`] and keeps `messageId`/`timestamp` as a tombstone, so readers render it as removed |
//! | account deletion | the account | [`crate::client::Labyrinth::purge_account`]: redact every authored item, then purge the mailbox |
//! | edit | — | frame level: a new message referencing the old id (chat frame schema); Labyrinth stores both |
//!
//! Each sealed item is signed on its own (`sig || ct`), so redacting one
//! item leaves the rest of its batch verifiable.

use crate::Result;
use crate::encoding::hex;
use crate::sign::{TransportSigner, verify_transport};

const REDACTION_PREFIX: &str = "catbird.labyrinth.redaction:";
const DS_REDACTION_PREFIX: &str = "catbird.labyrinth.ds_redaction:";

/// `defs#redaction.reason` of a server redaction for an account deletion.
pub const ACCOUNT_DELETED: &str = "accountDeleted";

/// An author's request to erase one of its messages, stored in place of
/// the item's ciphertext (`defs#redaction`).
///
/// `sig = Ed25519(author chat key, "catbird.labyrinth.redaction:did=" ||
/// did || ";message_id=" || messageId || ";thread_id=" || hex(threadId))`.
/// Readers check the key is one of the author's chat devices, so the
/// server cannot pass its own deletion off as the author's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redaction {
    pub transport_public_key: [u8; 32],
    pub sig: [u8; 64],
    /// Set by the server when it applies the redaction (RFC 3339).
    pub redacted_at: Option<String>,
}

fn redaction_message(did: &str, thread_id: &str, message_id: &str) -> Vec<u8> {
    format!(
        "{REDACTION_PREFIX}did={did};message_id={message_id};thread_id={}",
        hex(thread_id.as_bytes())
    )
    .into_bytes()
}

impl Redaction {
    /// The author `did` asks to redact `message_id` in `thread_id`.
    pub fn sign(
        did: &str,
        thread_id: &str,
        message_id: &str,
        transport: &dyn TransportSigner,
    ) -> Self {
        Self {
            transport_public_key: transport.transport_public_key(),
            sig: transport.sign_transport(&redaction_message(did, thread_id, message_id)),
            redacted_at: None,
        }
    }

    /// Checks the signature; the caller checks the key belongs to `did`.
    pub fn verify(&self, did: &str, thread_id: &str, message_id: &str) -> Result<()> {
        verify_transport(
            &self.transport_public_key,
            &redaction_message(did, thread_id, message_id),
            &self.sig,
        )
    }
}

/// A redaction the conversation's sequencer DS applied on its own: an
/// account deletion (mls-ds `deleteAccountData`). `sig` is present when
/// the DS has a redaction signing key:
///
/// `sig = Ed25519(DS key, "catbird.labyrinth.ds_redaction:by=" || by ||
/// ";did=" || author did || ";message_id=" || messageId || ";reason=" ||
/// reason || ";redacted_at=" || redactedAt || ";thread_id=" ||
/// hex(threadId))`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerRedaction {
    /// The DID of the DS that applied it.
    pub by: String,
    pub reason: String,
    pub redacted_at: String,
    pub sig: Option<[u8; 64]>,
}

fn ds_redaction_message(
    r: &ServerRedaction,
    author: &str,
    thread_id: &str,
    message_id: &str,
) -> Vec<u8> {
    format!(
        "{DS_REDACTION_PREFIX}by={};did={author};message_id={message_id};reason={};\
         redacted_at={};thread_id={}",
        r.by,
        r.reason,
        r.redacted_at,
        hex(thread_id.as_bytes())
    )
    .into_bytes()
}

impl ServerRedaction {
    /// DS `by` redacts `author`'s `message_id` in `thread_id` for an
    /// account deletion at `redacted_at`, signed when `signer` is given.
    pub fn account_deletion(
        by: &str,
        author: &str,
        thread_id: &str,
        message_id: &str,
        redacted_at: &str,
        signer: Option<&dyn TransportSigner>,
    ) -> Self {
        let mut r = Self {
            by: by.to_owned(),
            reason: ACCOUNT_DELETED.to_owned(),
            redacted_at: redacted_at.to_owned(),
            sig: None,
        };
        r.sig = signer
            .map(|s| s.sign_transport(&ds_redaction_message(&r, author, thread_id, message_id)));
        r
    }

    /// Checks this is a signed account deletion of `author`'s item under
    /// DS key `key`; the caller checks `key` is the sequencer's.
    pub fn verify_account_deletion(
        &self,
        author: &str,
        thread_id: &str,
        message_id: &str,
        key: &[u8; 32],
    ) -> Result<()> {
        if self.reason != ACCOUNT_DELETED {
            return Err(crate::Error::Malformed("server redaction reason"));
        }
        let sig = self.sig.as_ref().ok_or(crate::Error::BadSignature)?;
        verify_transport(
            key,
            &ds_redaction_message(self, author, thread_id, message_id),
            sig,
        )
    }
}

/// A stored item's redaction, as the wire record tells it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredRedaction {
    /// The author's signed unsend.
    Author(Redaction),
    /// A redaction the sequencer DS applied on its own (account deletion).
    Server(ServerRedaction),
    /// No signature and no `by`: a server removal of unknown origin.
    Unsigned { redacted_at: Option<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_binds_author_thread_and_message() {
        let t = crate::sign::Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[4; 32]));
        let r = Redaction::sign("did:plc:a", "t1", "m1", &t);
        r.verify("did:plc:a", "t1", "m1").unwrap();
        assert!(r.verify("did:plc:b", "t1", "m1").is_err());
        assert!(r.verify("did:plc:a", "t2", "m1").is_err());
        assert!(r.verify("did:plc:a", "t1", "m2").is_err());
        assert_eq!(
            redaction_message("did:plc:a", "ab", "m"),
            b"catbird.labyrinth.redaction:did=did:plc:a;message_id=m;thread_id=6162"
        );
    }

    #[test]
    fn ds_redaction_binds_every_field() {
        let ds = crate::sign::Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[6; 32]));
        let key = crate::sign::TransportSigner::transport_public_key(&ds);
        let at = "2026-10-05T12:00:00.000Z";
        let r =
            ServerRedaction::account_deletion("did:web:ds", "did:plc:a", "ab", "m", at, Some(&ds));
        assert_eq!(
            ds_redaction_message(&r, "did:plc:a", "ab", "m"),
            b"catbird.labyrinth.ds_redaction:by=did:web:ds;did=did:plc:a;message_id=m;\
              reason=accountDeleted;redacted_at=2026-10-05T12:00:00.000Z;thread_id=6162"
        );
        r.verify_account_deletion("did:plc:a", "ab", "m", &key)
            .unwrap();
        assert!(
            r.verify_account_deletion("did:plc:b", "ab", "m", &key)
                .is_err()
        );
        assert!(
            r.verify_account_deletion("did:plc:a", "ac", "m", &key)
                .is_err()
        );
        assert!(
            r.verify_account_deletion("did:plc:a", "ab", "n", &key)
                .is_err()
        );
        let mut other = r.clone();
        other.by = "did:web:other".into();
        assert!(
            other
                .verify_account_deletion("did:plc:a", "ab", "m", &key)
                .is_err()
        );
        let mut later = r.clone();
        later.redacted_at = "2026-10-05T12:00:00.001Z".into();
        assert!(
            later
                .verify_account_deletion("did:plc:a", "ab", "m", &key)
                .is_err()
        );
        let unsigned =
            ServerRedaction::account_deletion("did:web:ds", "did:plc:a", "ab", "m", at, None);
        assert!(
            unsigned
                .verify_account_deletion("did:plc:a", "ab", "m", &key)
                .is_err()
        );
    }
}

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
}

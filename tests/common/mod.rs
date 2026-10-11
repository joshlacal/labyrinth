//! Shared fixtures for MEK and message tests: members with a chat transport
//! key and an epoch-0 mailbox.

#![allow(dead_code)]

use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::mek::{self, Mek, MekRecord};
use labyrinth::sign::Ed25519Transport;

pub const THREAD: &str = "conv-3f2a";

pub struct Member {
    pub did: String,
    pub transport: Ed25519Transport,
    pub keys: MailboxKeys,
    pub epoch: EpochPublic,
}

impl Member {
    pub fn new(name: &str, n: u8) -> Self {
        Self::at_epoch(name, n, 0)
    }

    /// A member whose latest epoch is a fresh epoch 0 derived from `(n, salt)`.
    pub fn at_epoch(name: &str, n: u8, salt: u8) -> Self {
        let did = format!("did:plc:{name}");
        let transport = Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[n; 32]));
        let mut root = [n; 32];
        root[31] = salt;
        let keys = MailboxKeys::derive(&root, 0);
        let epoch = EpochPublic::sign(&did, 0, &keys, None, None, &transport).unwrap();
        Self {
            did,
            transport,
            keys,
            epoch,
        }
    }

    pub fn roster_entry(&self) -> (String, EpochPublic) {
        (self.did.clone(), self.epoch.clone())
    }

    pub fn transport_pub(&self) -> [u8; 32] {
        self.transport.0.verifying_key().to_bytes()
    }

    pub fn open(&self, record: &MekRecord, sender: Option<&Member>) -> labyrinth::Result<Mek> {
        mek::open(
            record,
            &self.did,
            &self.epoch,
            &self.keys,
            sender.map(|s| &s.epoch),
        )
    }
}

pub fn heads(members: &[&Member]) -> Vec<[u8; 32]> {
    members.iter().map(|m| m.epoch.head).collect()
}

pub fn roster(members: &[&Member]) -> Vec<(String, EpochPublic)> {
    members.iter().map(|m| m.roster_entry()).collect()
}

/// Alice distributes a fresh Labyrinth MEK to `members` (which includes her).
pub fn labyrinth_mek(alice: &Member, members: &[&Member]) -> (Mek, MekRecord) {
    let mut mek = Mek::generate(&heads(members)).unwrap();
    let record = mek::distribute_labyrinth(
        THREAD,
        &mut mek,
        &alice.did,
        &alice.epoch,
        &alice.keys,
        &roster(members),
    )
    .unwrap();
    (mek, record)
}

//! Review 2: account deletion never strands the user. A failed remote
//! `deleteAccountData` still clears the client and reports the error; the
//! remote half is retried later without any client state.

#![cfg(feature = "xrpc")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use labyrinth::client::{Backends, Labyrinth, SystemClock, delete_account_remote};
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::xrpc::server::MemoryXrpcServer;
use labyrinth::store::xrpc::{
    XrpcDirectory, XrpcError, XrpcMailboxStore, XrpcOrf, XrpcThreadStore, XrpcTransport,
};
use labyrinth::store::{MailboxDirectory as _, MailboxStore as _};

const A: &str = "did:plc:alice";
const B: &str = "did:plc:bob";

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

/// Fails `deleteAccountData` with no response while `down` is set.
struct Flaky {
    inner: Arc<dyn XrpcTransport>,
    down: Arc<AtomicBool>,
}

impl XrpcTransport for Flaky {
    fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<Vec<u8>, XrpcError> {
        self.inner.query_with_headers(nsid, params, headers)
    }
    fn procedure(&self, nsid: &str, payload: &[u8], op: [u8; 16]) -> Result<Vec<u8>, XrpcError> {
        if self.down.load(Ordering::SeqCst) && nsid.ends_with(".deleteAccountData") {
            return Err(XrpcError {
                status: 0,
                error: None,
                message: Some("connection reset".into()),
            });
        }
        self.inner.procedure(nsid, payload, op)
    }
}

fn backends(t: Arc<dyn XrpcTransport>, did: &str) -> Backends {
    Backends {
        mailbox: Box::new(XrpcMailboxStore::new(did, t.clone())),
        threads: Box::new(XrpcThreadStore::new(did, t.clone())),
        directory: Box::new(XrpcDirectory::new(t.clone())),
        orf: Box::new(XrpcOrf::new(t)),
        publishers: vec![],
        clock: Box::new(SystemClock),
    }
}

#[test]
fn remote_failure_still_purges_locally_and_the_retry_finishes_the_job() {
    let s = MemoryXrpcServer::new(MemoryBackend::new());
    let net = s.backend().clone();
    let down = Arc::new(AtomicBool::new(true));
    let key = signer(1).0.verifying_key().to_bytes();
    net.register_chat_device(A, key);
    let t: Arc<dyn XrpcTransport> = Arc::new(Flaky {
        inner: s.transport(A, key),
        down: down.clone(),
    });
    let mut alice = Labyrinth::initialize(A, Box::new(signer(1)), backends(t.clone(), A)).unwrap();
    net.register_chat_device(B, signer(2).0.verifying_key().to_bytes());
    let _bob = Labyrinth::initialize(
        B,
        Box::new(signer(2)),
        backends(s.transport(B, signer(2).0.verifying_key().to_bytes()), B),
    )
    .unwrap();
    alice.resolve_roster(&[A, B]).unwrap();
    assert!(alice.peer_pin(B).is_some());

    let report = alice.purge_account().unwrap();
    let pending = report.remote_pending.expect("remote failure is reported");
    assert!(matches!(pending, labyrinth::Error::Backend(_)));
    assert!(!report.server_side);
    // Local state is cleared regardless.
    assert!(alice.peer_pin(B).is_none());
    // The server still holds the mailbox.
    let dir = XrpcDirectory::new(s.transport(B, signer(2).0.verifying_key().to_bytes()));
    assert!(dir.latest(A).unwrap().is_some());

    // Still down: the retry fails, and says so.
    let mailbox = XrpcMailboxStore::new(A, t.clone());
    assert!(delete_account_remote(&mailbox, &[]).is_err());
    // Back up: the retry (no client state needed) deletes the account.
    down.store(false, Ordering::SeqCst);
    delete_account_remote(&mailbox, &[]).unwrap();
    assert!(dir.latest(A).unwrap().is_none());
    assert!(mailbox.list_devices().unwrap().is_empty());
    // Idempotent.
    delete_account_remote(&mailbox, &[]).unwrap();
}

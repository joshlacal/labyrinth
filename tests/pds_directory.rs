//! The PDS `mailboxKeys` directory and publisher (`store::pds`) over a mock
//! repo host, cross-checked against mls-ds in a `CompositeDirectory`.

#![cfg(feature = "xrpc")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth};
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::MailboxDirectory;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::pds::{PdsDirectory, PdsPublisher, PdsRecords, epoch_rkey};
use labyrinth::store::xrpc::server::MemoryXrpcServer;
use labyrinth::store::xrpc::{XrpcDirectory, XrpcMailboxStore, XrpcOrf, XrpcThreadStore};

const A: &str = "did:plc:alice";
const B: &str = "did:plc:bob";

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        1_791_000_000_000 + self.0.fetch_add(1, Ordering::Relaxed)
    }
}

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

/// Every account's repo: (did, rkey) → record bytes.
type Repos = Arc<Mutex<HashMap<(String, String), Vec<u8>>>>;

/// One signed-in account's view of the PDS network.
struct MockPds {
    me: String,
    repos: Repos,
}

impl PdsRecords for MockPds {
    fn put_mailbox_keys(&self, rkey: &str, record: &[u8]) -> Result<(), String> {
        self.repos
            .lock()
            .unwrap()
            .insert((self.me.clone(), rkey.to_owned()), record.to_vec());
        Ok(())
    }
    fn get_mailbox_keys(&self, did: &str, rkey: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self
            .repos
            .lock()
            .unwrap()
            .get(&(did.to_owned(), rkey.to_owned()))
            .cloned())
    }
    fn delete_all_mailbox_keys(&self) -> Result<(), String> {
        self.repos.lock().unwrap().retain(|(d, _), _| *d != self.me);
        Ok(())
    }
}

fn setup(s: &MemoryXrpcServer, repos: &Repos, did: &str, seed: u8) -> (Backends, Arc<MockPds>) {
    let key = signer(seed).0.verifying_key().to_bytes();
    s.backend().register_chat_device(did, key);
    let t = s.transport(did, key);
    let pds = Arc::new(MockPds {
        me: did.to_owned(),
        repos: repos.clone(),
    });
    let b = Backends {
        mailbox: Box::new(XrpcMailboxStore::new(did, t.clone())),
        threads: Box::new(XrpcThreadStore::new(did, t.clone())),
        directory: Box::new(CompositeDirectory::new(
            Box::new(PdsDirectory::new(pds.clone())),
            Box::new(XrpcDirectory::new(t.clone())),
        )),
        orf: Box::new(XrpcOrf::new(t)),
        publishers: vec![Box::new(PdsPublisher::new(did, pds.clone()))],
        clock: Box::new(TestClock::default()),
    };
    (b, pds)
}

#[test]
fn pds_records_are_an_independent_directory() {
    let s = MemoryXrpcServer::new(MemoryBackend::new());
    let repos = Repos::default();
    let (ab, apds) = setup(&s, &repos, A, 1);
    let alice = Labyrinth::initialize(A, Box::new(signer(1)), ab).unwrap();
    let (bb, _) = setup(&s, &repos, B, 2);
    let _bob = Labyrinth::initialize(B, Box::new(signer(2)), bb).unwrap();

    // Both the latest and the per-epoch copy are in Alice's repo.
    let pds = PdsDirectory::new(apds.clone());
    let head = alice.latest_public().unwrap().head;
    assert_eq!(pds.latest(A).unwrap().unwrap().head, head);
    assert_eq!(pds.epoch(A, 0).unwrap().unwrap().head, head);
    assert!(
        repos
            .lock()
            .unwrap()
            .contains_key(&(A.into(), epoch_rkey(0)))
    );
    assert!(matches!(
        pds.device_transport_keys(A),
        Err(Error::NotSupported(_))
    ));

    // Republishing the same epoch is fine; another one under its number is not.
    let pub_a = PdsPublisher::new(A, apds.clone());
    let rec = serde_json::from_slice(&repos.lock().unwrap()[&(A.into(), "self".into())]).unwrap();
    use labyrinth::store::KeyPublisher as _;
    pub_a.publish(&rec).unwrap();

    // A PDS lying about Alice's head is a fork against mls-ds.
    let bob_key = signer(2).0.verifying_key().to_bytes();
    let composite = CompositeDirectory::new(
        Box::new(PdsDirectory::new(apds.clone())),
        Box::new(XrpcDirectory::new(s.transport(B, bob_key))),
    );
    assert_eq!(composite.latest(A).unwrap().unwrap().head, head);
    let bob_self = repos.lock().unwrap()[&(B.into(), "self".into())].clone();
    repos
        .lock()
        .unwrap()
        .insert((A.into(), "self".into()), bob_self);
    assert!(composite.latest(A).is_err());

    // Retract removes every record of the signed-in account only.
    pub_a.retract().unwrap();
    assert!(pds.latest(A).unwrap().is_none());
    assert!(pds.latest(B).unwrap().is_some());
}

#[test]
fn pds_publisher_refuses_to_regress_mailbox_keys_self() {
    use labyrinth::records::MailboxKeysRecord;
    use labyrinth::store::KeyPublisher as _;

    let s = MemoryXrpcServer::new(MemoryBackend::new());
    let repos = Repos::default();
    let (ab, apds) = setup(&s, &repos, A, 1);
    let mut alice = Labyrinth::initialize(A, Box::new(signer(1)), ab).unwrap();

    // Enroll two siblings and revoke both so Alice advances to Epoch 2.
    for seed in [11u8, 12u8] {
        let mut r = alice.otc_offer().unwrap();
        let typed = r.code().as_str().to_owned();
        let (init, hello) = Labyrinth::otc_start(A, &typed).unwrap();
        let reply = alice.otc_respond(&mut r, &hello).unwrap();
        let (sib_b, _) = setup(&s, &repos, A, seed);
        let (sib, _) = Labyrinth::enroll_via_otc(
            A,
            init,
            &reply.message,
            &reply.sealed_payload,
            Box::new(signer(seed)),
            sib_b,
        )
        .unwrap();
        alice
            .revoke_device(&sib.device_public().device_key_pub)
            .unwrap();
    }
    assert_eq!(alice.latest_epoch(), 2);

    let pds = PdsDirectory::new(apds.clone());
    assert_eq!(pds.latest(A).unwrap().unwrap().seq, 2);

    // Grab Epoch 1's record, remove its per-epoch history copy to simulate an
    // incomplete historical backfill, and replay `publish` for Epoch 1.
    let e1_bytes = repos
        .lock()
        .unwrap()
        .remove(&(A.into(), epoch_rkey(1)))
        .unwrap();
    let rec_e1: MailboxKeysRecord = serde_json::from_slice(&e1_bytes).unwrap();
    let pub_a = PdsPublisher::new(A, apds.clone());
    assert_eq!(
        pub_a.publish(&rec_e1).unwrap_err(),
        Error::EpochRollback {
            pinned: 2,
            offered: 1
        }
    );
    // Per-epoch copy `000000000001` WAS backfilled, while `self` stayed at Epoch 2!
    assert_eq!(pds.epoch(A, 1).unwrap().unwrap().seq, 1);
    assert_eq!(pds.latest(A).unwrap().unwrap().seq, 2);

    // `finish_initialize` replays 0..=2 without regressing `self` or failing.
    repos.lock().unwrap().remove(&(A.into(), epoch_rkey(0)));
    alice.finish_initialize().unwrap();
    assert_eq!(pds.epoch(A, 0).unwrap().unwrap().seq, 0);
    assert_eq!(pds.latest(A).unwrap().unwrap().seq, 2);
}

#[test]
fn composite_directory_verifies_epoch_signatures_in_epoch_and_single_source() {
    use labyrinth::records::MailboxKeysRecord;

    let s = MemoryXrpcServer::new(MemoryBackend::new());
    let repos = Repos::default();
    let (ab, apds) = setup(&s, &repos, A, 1);
    let _alice = Labyrinth::initialize(A, Box::new(signer(1)), ab).unwrap();

    // Tamper `self_sig` in PDS `000000000000` while leaving `epoch_head` intact:
    // `CompositeDirectory::epoch` MUST verify `p.verify(did, None)` and reject!
    let orig_e0 = repos.lock().unwrap()[&(A.into(), epoch_rkey(0))].clone();
    let mut bad_e0: MailboxKeysRecord = serde_json::from_slice(&orig_e0).unwrap();
    bad_e0.current.self_sig.0[0] ^= 1;
    repos.lock().unwrap().insert(
        (A.into(), epoch_rkey(0)),
        serde_json::to_vec(&bad_e0).unwrap(),
    );

    let bob_key = signer(2).0.verifying_key().to_bytes();
    s.backend().register_chat_device(B, bob_key);
    let composite = CompositeDirectory::new(
        Box::new(PdsDirectory::new(apds.clone())),
        Box::new(XrpcDirectory::new(s.transport(B, bob_key))),
    );
    assert_eq!(composite.epoch(A, 0).unwrap_err(), Error::BadSignature);

    // Single-source fallback (`new_allowing_single_source`) must also verify `e.verify(did, None)`:
    // 1) wrong DID (`ghost`) fails `verify` with `Malformed("epoch head mismatch")`,
    // 2) right DID (`A`) against an empty DS with tampered `self_sig` fails with `BadSignature`.
    let ghost = "did:plc:ghost";
    repos.lock().unwrap().insert(
        (ghost.into(), "self".into()),
        serde_json::to_vec(&bad_e0).unwrap(),
    );
    repos.lock().unwrap().insert(
        (A.into(), "self".into()),
        serde_json::to_vec(&bad_e0).unwrap(),
    );
    assert_eq!(composite.latest(A).unwrap_err(), Error::BadSignature);
    let empty_s = MemoryXrpcServer::new(MemoryBackend::new());
    empty_s.backend().register_chat_device(B, bob_key);
    let single = CompositeDirectory::new_allowing_single_source(
        Box::new(PdsDirectory::new(apds)),
        Box::new(XrpcDirectory::new(empty_s.transport(B, bob_key))),
    );
    assert_eq!(
        single.latest(ghost).unwrap_err(),
        Error::Malformed("epoch head mismatch")
    );
    assert_eq!(single.latest(A).unwrap_err(), Error::BadSignature);
    assert_eq!(single.epoch(A, 0).unwrap_err(), Error::BadSignature);
}

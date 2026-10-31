//! The PDS `mailboxKeys` directory and publisher (`store::pds`) over a mock
//! repo host with `swapRecord` CAS, cross-checked against mls-ds in a
//! `CompositeDirectory`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth};
use labyrinth::records::MailboxKeysRecord;
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::pds::{
    MemoryPublicRepoHost, PdsDirectory, PdsPublisher, PublicRepoBackend, epoch_rkey,
};
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceThreadStore};
use labyrinth::store::{KeyPublisher, MailboxDirectory};

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

fn setup(
    net: &MemoryBackend,
    spaces: &MemorySpaceHost,
    repos: &MemoryPublicRepoHost,
    did: &str,
    seed: u8,
) -> Backends {
    let key = signer(seed).0.verifying_key().to_bytes();
    net.register_chat_device(did, key);
    let space_client = spaces.client(did);
    let pds_client = repos.client(did);
    let mb = SpaceMailboxStore::for_owner(
        did,
        space_client.clone(),
        Box::new(PdsPublisher::new(pds_client.clone(), did)),
    );
    let threads = SpaceThreadStore::new(space_client, did).with_authority_did(did);
    Backends {
        mailbox: Box::new(mb),
        threads: Box::new(threads),
        directory: Box::new(CompositeDirectory::new(
            Box::new(PdsDirectory::new(pds_client)),
            Box::new(net.ds_directory()),
        )),
        publishers: vec![Box::new(net.ds_publisher(did))],
        clock: Box::new(TestClock::default()),
    }
}

#[test]
fn pds_records_are_an_independent_directory() {
    let net = MemoryBackend::new();
    let spaces = MemorySpaceHost::new();
    let repos = MemoryPublicRepoHost::new();

    let ab = setup(&net, &spaces, &repos, A, 1);
    let alice = block_on(Labyrinth::initialize(A, Box::new(signer(1)), ab)).unwrap();
    let bb = setup(&net, &spaces, &repos, B, 2);
    let _bob = block_on(Labyrinth::initialize(B, Box::new(signer(2)), bb)).unwrap();

    // Both the latest and the per-epoch copy are in Alice's repo.
    let apds = repos.client(A);
    let pds = PdsDirectory::new(apds.clone());
    let head = alice.latest_public().unwrap().head;
    assert_eq!(block_on(pds.latest(A)).unwrap().unwrap().head, head);
    assert_eq!(block_on(pds.epoch(A, 0)).unwrap().unwrap().head, head);
    assert!(
        block_on(apds.get_mailbox_keys(A, &epoch_rkey(0)))
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        block_on(pds.device_transport_keys(A)),
        Err(Error::NotSupported(_))
    ));

    // Republishing the same epoch is fine; another one under its number is not.
    let pub_a = PdsPublisher::new(apds.clone(), A);
    let (self_bytes, _) = block_on(apds.get_mailbox_keys(A, "self")).unwrap().unwrap();
    let rec: MailboxKeysRecord = serde_json::from_slice(&self_bytes).unwrap();
    block_on(pub_a.publish(&rec)).unwrap();

    // A PDS lying about Alice's head is a fork against mls-ds.
    let composite = CompositeDirectory::new(
        Box::new(PdsDirectory::new(apds.clone())),
        Box::new(net.ds_directory()),
    );
    assert_eq!(block_on(composite.latest(A)).unwrap().unwrap().head, head);
    let (bob_self, _) = block_on(apds.get_mailbox_keys(B, "self")).unwrap().unwrap();
    let (_, a_cid) = block_on(apds.get_mailbox_keys(A, "self")).unwrap().unwrap();
    block_on(apds.put_mailbox_keys(A, "self", &bob_self, Some(&a_cid))).unwrap();
    assert!(block_on(composite.latest(A)).is_err());

    // Retract removes every record of the signed-in account only.
    block_on(pub_a.retract()).unwrap();
    assert!(block_on(pds.latest(A)).unwrap().is_none());
    assert!(block_on(pds.latest(B)).unwrap().is_some());
}

#[test]
fn pds_publisher_refuses_to_regress_mailbox_keys_self() {
    let net = MemoryBackend::new();
    let spaces = MemorySpaceHost::new();
    let repos = MemoryPublicRepoHost::new();

    let ab = setup(&net, &spaces, &repos, A, 1);
    let mut alice = block_on(Labyrinth::initialize(A, Box::new(signer(1)), ab)).unwrap();

    // Gate 3: enrolling one sibling opens Epoch 1; revoking it opens Epoch 2.
    let mut r = alice.otc_offer().unwrap();
    let typed = r.code().as_str().to_owned();
    let (init_otc, hello) = Labyrinth::otc_start(A, &typed).unwrap();
    let reply = block_on(alice.otc_respond(&mut r, &hello)).unwrap();
    let sib_b = setup(&net, &spaces, &repos, A, 11);
    let (sib, _) = block_on(Labyrinth::enroll_via_otc(
        A,
        init_otc,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(11)),
        sib_b,
    ))
    .unwrap();
    block_on(alice.revoke_device(&sib.device_public().device_key_pub)).unwrap();
    assert_eq!(alice.latest_epoch(), 2);

    let apds = repos.client(A);
    let pds = PdsDirectory::new(apds.clone());
    assert_eq!(block_on(pds.latest(A)).unwrap().unwrap().seq, 2);

    // Grab Epoch 1's record, remove its per-epoch history copy to simulate an
    // incomplete historical backfill, and replay `publish` for Epoch 1.
    let e1_bytes = repos.remove_raw(A, &epoch_rkey(1)).unwrap();
    let rec_e1: MailboxKeysRecord = serde_json::from_slice(&e1_bytes).unwrap();
    let pub_a = PdsPublisher::new(apds, A);
    assert_eq!(
        block_on(pub_a.publish(&rec_e1)).unwrap_err(),
        Error::EpochRollback {
            pinned: 2,
            offered: 1
        }
    );
    // Per-epoch copy `000000000001` WAS backfilled, while `self` stayed at Epoch 2!
    assert_eq!(block_on(pds.epoch(A, 1)).unwrap().unwrap().seq, 1);
    assert_eq!(block_on(pds.latest(A)).unwrap().unwrap().seq, 2);

    // `finish_initialize` replays 0..=2 without regressing `self` or failing.
    repos.remove_raw(A, &epoch_rkey(0));
    block_on(alice.finish_initialize()).unwrap();
    assert_eq!(block_on(pds.epoch(A, 0)).unwrap().unwrap().seq, 0);
    assert_eq!(block_on(pds.latest(A)).unwrap().unwrap().seq, 2);
}

#[test]
fn composite_directory_verifies_epoch_signatures_in_epoch_and_single_source() {
    let net = MemoryBackend::new();
    let spaces = MemorySpaceHost::new();
    let repos = MemoryPublicRepoHost::new();

    let ab = setup(&net, &spaces, &repos, A, 1);
    let _alice = block_on(Labyrinth::initialize(A, Box::new(signer(1)), ab)).unwrap();

    // Tamper `self_sig` in PDS `000000000000` while leaving `epoch_head` intact:
    // `CompositeDirectory::epoch` MUST verify `p.verify(did, None)` and reject!
    let apds = repos.client(A);
    let (orig_e0, _) = block_on(apds.get_mailbox_keys(A, &epoch_rkey(0)))
        .unwrap()
        .unwrap();
    let mut bad_e0: MailboxKeysRecord = serde_json::from_slice(&orig_e0).unwrap();
    bad_e0.current.self_sig.0[0] ^= 1;
    repos.force_overwrite(A, &epoch_rkey(0), &bad_e0);

    let composite = CompositeDirectory::new(
        Box::new(PdsDirectory::new(apds.clone())),
        Box::new(net.ds_directory()),
    );
    assert_eq!(
        block_on(composite.epoch(A, 0)).unwrap_err(),
        Error::BadSignature
    );

    // Single-source fallback (`new_allowing_single_source`) must also verify `e.verify(did, None)`:
    // 1) wrong DID (`ghost`) fails `verify` with `Malformed("epoch head mismatch")`,
    // 2) right DID (`A`) against an empty DS with tampered `self_sig` fails with `BadSignature`.
    let ghost = "did:plc:ghost";
    repos.force_overwrite(ghost, "self", &bad_e0);
    repos.force_overwrite(A, "self", &bad_e0);
    assert_eq!(
        block_on(composite.latest(A)).unwrap_err(),
        Error::BadSignature
    );

    let empty_net = MemoryBackend::new();
    let single = CompositeDirectory::new_allowing_single_source(
        Box::new(PdsDirectory::new(apds)),
        Box::new(empty_net.ds_directory()),
    );
    assert_eq!(
        block_on(single.latest(ghost)).unwrap_err(),
        Error::Malformed("epoch head mismatch")
    );
    assert_eq!(block_on(single.latest(A)).unwrap_err(), Error::BadSignature);
    assert_eq!(
        block_on(single.epoch(A, 0)).unwrap_err(),
        Error::BadSignature
    );
}

//! Review 2: per-member roster exclusion and the user-confirmed re-pin
//! after a peer legitimately resets its mailbox ([CB-29]).

#[path = "support/net.rs"]
mod net;

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::Labyrinth;
use labyrinth::store::memory::{MemoryBackend, MemoryDirectory};
use net::{A, B, TestClock, backends, init, sibling, signer, tpub};

/// Bob purges his account and starts a new mailbox with chat key `seed`.
fn reset(net: &MemoryBackend, clock: &TestClock, bob: &mut Labyrinth, seed: u8) -> Labyrinth {
    block_on(bob.purge_account()).unwrap();
    net.register_chat_device(B, tpub(seed));
    block_on(Labyrinth::initialize(
        B,
        Box::new(signer(seed)),
        backends(net, clock, B),
    ))
    .unwrap()
}

#[test]
fn reset_peer_is_excluded_and_reported_not_fatal() {
    let (net, clock) = (MemoryBackend::new(), TestClock::default());
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    block_on(alice.resolve_roster(&[A, B])).unwrap();
    let _bob = reset(&net, &clock, &mut bob, 2);

    // The strict roster still refuses; the report excludes Bob loudly.
    assert!(matches!(
        block_on(alice.resolve_roster(&[A, B])),
        Err(Error::EpochRollback { .. })
    ));
    let r = block_on(alice.resolve_roster_report(&[A, B])).unwrap();
    assert_eq!(
        r.roster.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>(),
        [A]
    );
    assert_eq!(r.excluded.len(), 1);
    assert_eq!(r.excluded[0].did, B);
    assert!(matches!(r.excluded[0].error, Error::EpochRollback { .. }));
}

#[test]
fn repin_needs_the_confirmed_head_and_changes_the_safety_number() {
    let (net, clock) = (MemoryBackend::new(), TestClock::default());
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    block_on(alice.resolve_roster(&[A, B])).unwrap();
    let old_pin = alice.peer_pin(B).unwrap().clone();
    let old_number = alice.safety_number_with(B).unwrap();
    let bob = reset(&net, &clock, &mut bob, 2);

    let p = block_on(alice.propose_repin(B)).unwrap();
    assert_eq!(p.pinned_seq, Some(old_pin.seq));
    assert_eq!(p.old_safety_number.as_deref(), Some(old_number.as_str()));
    assert_ne!(p.new_safety_number, old_number);
    assert_eq!(p.offered_head, bob.latest_public().unwrap().head);
    // Proposing changes nothing.
    assert_eq!(alice.peer_pin(B), Some(&old_pin));

    // Only the head the user saw is accepted.
    assert_eq!(
        block_on(alice.repin_peer(B, &[0; 32])),
        Err(Error::Conflict)
    );
    assert_eq!(alice.peer_pin(B), Some(&old_pin));
    block_on(alice.repin_peer(B, &p.offered_head)).unwrap();
    assert_eq!(alice.safety_number_with(B).unwrap(), p.new_safety_number);
    let r = block_on(alice.resolve_roster_report(&[A, B])).unwrap();
    assert!(r.excluded.is_empty());
    assert_eq!(r.roster.len(), 2);
}

#[test]
fn repin_refuses_a_genesis_not_attested_by_a_current_chat_device() {
    let (net, clock) = (MemoryBackend::new(), TestClock::default());
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    block_on(alice.resolve_roster(&[A, B])).unwrap();
    // The new chain's genesis is attested by chat device 5; Bob then
    // moves to device 6 and device 5 leaves his chat devices. The latest
    // epoch is attested by a current device, the genesis is not.
    let mut bob5 = reset(&net, &clock, &mut bob, 5);
    let mut bob6 = sibling(&net, &clock, &mut bob5, 6);
    let dev5 = bob5.device_public().device_key_pub;
    net.remove_chat_device(B, tpub(5), 1);
    block_on(bob6.revoke_device(&dev5)).unwrap();
    assert!(bob6.latest_epoch() > 0);

    assert_eq!(
        block_on(alice.propose_repin(B)).unwrap_err(),
        Error::Unattested
    );
    let pin = alice.peer_pin(B).unwrap().clone();
    let head = bob6.latest_public().unwrap().head;
    assert_eq!(block_on(alice.repin_peer(B, &head)), Err(Error::Unattested));
    assert_eq!(alice.peer_pin(B), Some(&pin));
}

/// A directory whose peer lookups fail with a transport error.
struct Down;

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl labyrinth::store::MailboxDirectory for Down {
    async fn latest(&self, _: &str) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        Err(Error::Backend("unreachable".into()))
    }
    async fn epoch(
        &self,
        _: &str,
        _: u64,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        Err(Error::Backend("unreachable".into()))
    }
    async fn device_transport_keys(
        &self,
        _: &str,
    ) -> labyrinth::Result<Vec<labyrinth::store::ChatDeviceKey>> {
        Err(Error::Backend("unreachable".into()))
    }
}

/// A directory whose independent sources have not both published a peer.
struct Incomplete(MemoryDirectory);

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl labyrinth::store::MailboxDirectory for Incomplete {
    async fn latest(
        &self,
        did: &str,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        if did == B {
            Err(Error::DirectoryIncomplete {
                pds_present: true,
                ds_present: false,
            })
        } else {
            self.0.latest(did).await
        }
    }

    async fn epoch(
        &self,
        did: &str,
        seq: u64,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        if did == B {
            Err(Error::DirectoryIncomplete {
                pds_present: true,
                ds_present: false,
            })
        } else {
            self.0.epoch(did, seq).await
        }
    }

    async fn device_transport_keys(
        &self,
        did: &str,
    ) -> labyrinth::Result<Vec<labyrinth::store::ChatDeviceKey>> {
        if did == B {
            Err(Error::DirectoryIncomplete {
                pds_present: true,
                ds_present: false,
            })
        } else {
            self.0.device_transport_keys(did).await
        }
    }
}

/// A peer lookup that fails for an operational reason rather than because
/// the peer supplied a cryptographically invalid epoch.
struct PeerFailure(MemoryDirectory, Error);

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl labyrinth::store::MailboxDirectory for PeerFailure {
    async fn latest(
        &self,
        did: &str,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        if did == B {
            Err(self.1.clone())
        } else {
            self.0.latest(did).await
        }
    }

    async fn epoch(
        &self,
        did: &str,
        seq: u64,
    ) -> labyrinth::Result<Option<labyrinth::mailbox::EpochPublic>> {
        if did == B {
            Err(self.1.clone())
        } else {
            self.0.epoch(did, seq).await
        }
    }

    async fn device_transport_keys(
        &self,
        did: &str,
    ) -> labyrinth::Result<Vec<labyrinth::store::ChatDeviceKey>> {
        if did == B {
            Err(self.1.clone())
        } else {
            self.0.device_transport_keys(did).await
        }
    }
}

#[test]
fn transient_directory_failure_fails_the_roster_instead_of_dropping_members() {
    let (net, clock) = (MemoryBackend::new(), TestClock::default());
    let alice = init(&net, &clock, A, 1);
    let state = alice.export_state().unwrap();
    let mut b = backends(&net, &clock, A);
    b.directory = Box::new(Down);
    let mut alice = block_on(Labyrinth::from_state(&state, A, Box::new(signer(1)), b)).unwrap();
    assert!(matches!(
        block_on(alice.resolve_roster_report(&[A, B])),
        Err(Error::Backend(_))
    ));
}

#[test]
fn incomplete_directory_fails_the_roster_instead_of_dropping_members() {
    let (net, clock) = (MemoryBackend::new(), TestClock::default());
    let alice = init(&net, &clock, A, 1);
    let state = alice.export_state().unwrap();
    let mut b = backends(&net, &clock, A);
    b.directory = Box::new(Incomplete(net.directory()));
    let mut alice = block_on(Labyrinth::from_state(&state, A, Box::new(signer(1)), b)).unwrap();
    assert_eq!(
        block_on(alice.resolve_roster_report(&[A, B])).unwrap_err(),
        Error::DirectoryIncomplete {
            pds_present: true,
            ds_present: false,
        }
    );
}

#[test]
fn operational_peer_lookup_failures_never_become_roster_exclusions() {
    for expected in [
        Error::NotFound("required peer epoch"),
        Error::Forbidden,
        Error::NotSupported("peer directory lookup"),
        Error::Malformed("directory epoch under the wrong number"),
    ] {
        let (net, clock) = (MemoryBackend::new(), TestClock::default());
        let alice = init(&net, &clock, A, 1);
        let state = alice.export_state().unwrap();
        let mut b = backends(&net, &clock, A);
        b.directory = Box::new(PeerFailure(net.directory(), expected.clone()));
        let mut alice = block_on(Labyrinth::from_state(&state, A, Box::new(signer(1)), b)).unwrap();
        assert_eq!(
            block_on(alice.resolve_roster_report(&[A, B])).unwrap_err(),
            expected
        );
    }
}

#[test]
fn discard_pending_drops_one_threads_buffer_only() {
    let (net, clock) = (MemoryBackend::new(), TestClock::default());
    let mut alice = init(&net, &clock, A, 1);
    let roster = block_on(alice.resolve_roster(&[A])).unwrap();
    block_on(alice.archive_outgoing("t1", &roster, "m1", 1, b"x")).unwrap();
    block_on(alice.archive_outgoing("t2", &roster, "m2", 2, b"y")).unwrap();
    assert_eq!(alice.discard_pending("t1"), 1);
    assert_eq!(alice.pending("t1"), 0);
    assert_eq!(block_on(alice.flush_thread("t2")).unwrap().len(), 1);
    assert_eq!(alice.pending("t2"), 0);
    assert!(block_on(alice.flush()).unwrap().is_empty());
}

#[test]
fn propose_repin_and_repin_peer_sync_own_epochs_first() {
    let (net, clock) = (MemoryBackend::new(), TestClock::default());
    let mut alice = init(&net, &clock, A, 1);
    let mut alice2 = sibling(&net, &clock, &mut alice, 3);
    let alice3 = sibling(&net, &clock, &mut alice, 4);
    let mut bob = init(&net, &clock, B, 2);
    block_on(alice.resolve_roster(&[A, B])).unwrap();

    // `resolve_roster` synced `alice` to epoch 2 (after `alice2` opened 1 and
    // `alice3` opened 2 via Gate 3). Now `alice2` rotates Alice's account to
    // epoch 3 while `alice` is still at 2.
    block_on(alice2.revoke_device(&alice3.device_public().device_key_pub)).unwrap();
    assert_eq!(alice.latest_epoch(), 2);
    let mut bob = reset(&net, &clock, &mut bob, 2);
    block_on(bob.resolve_roster(&[A, B])).unwrap();

    // `propose_repin` syncs `alice` to epoch 3 first, so the safety number it
    // shows matches Bob's view of Alice's latest head.
    let p = block_on(alice.propose_repin(B)).unwrap();
    assert_eq!(alice.latest_epoch(), 3);
    assert_eq!(p.new_safety_number, bob.safety_number_with(A).unwrap());
    block_on(alice.repin_peer(B, &p.offered_head)).unwrap();

    // Now `alice2` revokes `alice` itself; neither `propose_repin` nor
    // `repin_peer` may succeed or mutate `alice`'s pins after revocation.
    let bob = reset(&net, &clock, &mut bob, 2);
    let old_pin = alice.peer_pin(B).unwrap().clone();
    block_on(alice2.revoke_device(&alice.device_public().device_key_pub)).unwrap();
    assert_eq!(
        block_on(alice.propose_repin(B)).unwrap_err(),
        Error::NotEpochMember
    );
    let new_bob_head = bob.latest_public().unwrap().head;
    assert_eq!(
        block_on(alice.repin_peer(B, &new_bob_head)).unwrap_err(),
        Error::NotEpochMember
    );
    assert_eq!(alice.peer_pin(B), Some(&old_pin));
}

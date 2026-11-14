//! Deletion ([CB-38]), lookup by id, newest-first paging and thread
//! listing (gap audit §9, 2.2, 2.3, 1.3) on the memory backend.

#[path = "support/net.rs"]
mod net;

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Labyrinth, MessageSource, ThreadCursor, ThreadHistory};
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::{MailboxDirectory, MailboxStore, TimeRange};
use labyrinth::virtual_device::Mechanism;
use net::*;

fn send(lab: &mut Labyrinth, thread: &str, members: &[&str], id: &str, ts: u64) {
    let roster = block_on(lab.resolve_roster(members)).unwrap();
    block_on(lab.archive_outgoing(thread, &roster, id, ts, id.as_bytes())).unwrap();
}

fn ids(h: &ThreadHistory) -> Vec<&str> {
    h.messages.iter().map(|m| m.message_id.as_str()).collect()
}

fn read(lab: &mut Labyrinth, thread: &str) -> ThreadHistory {
    block_on(lab.load_thread(thread, TimeRange::ALL)).unwrap()
}

#[test]
fn delete_for_me_hides_a_message_on_every_own_device_only() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    let mut bob_laptop = sibling(&net, &clock, &mut bob, 3);
    send(&mut alice, T, &[A, B], "m1", 10);
    send(&mut alice, T, &[A, B], "m2", 20);
    block_on(alice.flush()).unwrap();
    assert_eq!(ids(&read(&mut bob, T)), ["m1", "m2"]);

    block_on(bob.delete_for_me(T, "m1", 10, Some(A), &[])).unwrap();
    // Every device of Bob's account hides it ...
    let h = read(&mut bob_laptop, T);
    assert_eq!(ids(&h), ["m2"]);
    assert_eq!(h.deleted_for_me, ["m1"]);
    let one = block_on(bob_laptop.load_message(T, "m1")).unwrap();
    assert!(one.messages.is_empty());
    assert_eq!(one.deleted_for_me, ["m1"]);
    // ... time-range reads too (the tombstone carries its target's time) ...
    let ranged = block_on(bob_laptop.load_thread(
        T,
        TimeRange {
            from_ms: Some(5),
            until_ms: Some(15),
        },
    ))
    .unwrap();
    assert!(ranged.messages.is_empty());
    // ... and nobody else's view changes.
    assert_eq!(ids(&read(&mut alice, T)), ["m1", "m2"]);
}

#[test]
fn open_owner_record_applies_tombstones_once_for_the_whole_batch() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    block_on(alice.archive_owner(T, "deleted", 10, b"deleted")).unwrap();
    block_on(alice.archive_owner(T, "kept", 20, b"kept")).unwrap();
    block_on(alice.delete_for_me(T, "deleted", 10, None, &[])).unwrap();

    let batches = block_on(net.mailbox(A).list_owner_batches(T, TimeRange::ALL)).unwrap();
    assert_eq!(batches.len(), 1);
    let batch = &batches[0].value;
    assert_eq!(batch.items.len(), 3);
    // A tombstone before its target must not resurrect it; a later frame
    // must not clear the deletion metadata either.
    for order in [[2, 0, 1], [0, 2, 1], [0, 1, 2]] {
        let mut reordered = batch.clone();
        reordered.items = order.iter().map(|&i| batch.items[i].clone()).collect();
        let history = block_on(alice.open_owner_record(reordered)).unwrap();
        assert_eq!(ids(&history), ["kept"], "item order {order:?}");
        assert_eq!(history.deleted_for_me, ["deleted"], "item order {order:?}");
        assert!(history.undecryptable.is_empty());
    }
}

#[test]
fn missing_active_space_is_not_an_owner_archive_fallback() {
    use labyrinth::store::space::{SpaceError, SpaceRpc, SpaceThreadStore};
    use std::sync::Arc;

    struct DeniedSpace(u16, &'static str);
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl SpaceRpc for DeniedSpace {
        async fn query(
            &self,
            _nsid: &str,
            _params: &[(&str, String)],
        ) -> Result<Vec<u8>, SpaceError> {
            Err(SpaceError::named(self.0, self.1, "injected read denial"))
        }
        async fn procedure(&self, _nsid: &str, _body: &[u8]) -> Result<Vec<u8>, SpaceError> {
            panic!("history reads must not write to the conversation Space")
        }
    }

    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    block_on(alice.archive_owner(T, "saved", 10, b"saved")).unwrap();
    block_on(alice.flush_owner(T)).unwrap();
    let state = alice.export_state().unwrap();
    for (status, name) in [
        (404, "SpaceNotFound"),
        (400, "SpaceNotFound"),
        (403, "Forbidden"),
    ] {
        let mut b = backends(&net, &clock, A);
        let rpc: Arc<dyn SpaceRpc> = Arc::new(DeniedSpace(status, name));
        b.threads =
            Box::new(SpaceThreadStore::new(rpc, A).with_authority_did("did:web:ds.example"));
        let mut restored =
            block_on(Labyrinth::from_state(&state, A, Box::new(signer(1)), b)).unwrap();
        let result = block_on(restored.load_thread(T, TimeRange::ALL));
        if status == 403 {
            let history = result.unwrap();
            assert!(!history.space_readable);
            assert_eq!(ids(&history), ["saved"]);
        } else {
            assert_eq!(result.unwrap_err(), Error::NotFound("space"));
        }
    }
}

#[test]
fn unsend_redacts_for_everyone_and_is_author_only() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    send(&mut alice, T, &[A, B], "m1", 10);
    send(&mut alice, T, &[A, B], "m2", 20);
    block_on(alice.flush()).unwrap();

    // Bob can publish an immutable redaction for a raced local outbox item,
    // but author scoping means it cannot hide Alice's message.
    assert_eq!(block_on(bob.unsend(T, "m2")).unwrap(), 0);
    let after_bob = read(&mut bob, T);
    assert_eq!(ids(&after_bob), ["m1", "m2"]);
    assert!(
        after_bob
            .redacted
            .iter()
            .any(|redaction| redaction.sender == B)
    );

    assert_eq!(block_on(alice.unsend(T, "m2")).unwrap(), 1);
    let h = read(&mut bob, T);
    assert_eq!(ids(&h), ["m1"]);
    let r = h
        .redacted
        .iter()
        .find(|redaction| redaction.sender == A)
        .expect("Alice's author-scoped redaction");
    assert_eq!((r.message_id.as_str(), r.timestamp), ("m2", 20));
    assert!(h.undecryptable.is_empty());
    // By id, too.
    let one = block_on(bob.load_message(T, "m2")).unwrap();
    assert!(one.messages.is_empty());
    assert!(one.redacted.iter().any(|redaction| redaction.sender == A));

    // An unflushed message is simply dropped from the outbox.
    send(&mut alice, T, &[A, B], "m3", 30);
    assert_eq!(block_on(alice.unsend(T, "m3")).unwrap(), 1);
    block_on(alice.flush()).unwrap();
    assert_eq!(ids(&read(&mut bob, T)), ["m1"]);
}

#[test]
fn newest_first_pages_cover_the_thread_exactly_once() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    // Two batches with interleaved times, a timestamp shared by two ids,
    // and an owner-archived copy of one message.
    for (id, ts) in [("a", 1), ("c", 3), ("e", 5), ("g", 7)] {
        send(&mut alice, T, &[A, B], id, ts);
    }
    block_on(alice.flush()).unwrap();
    for (id, ts) in [("b", 2), ("d", 5), ("f", 6)] {
        send(&mut bob, T, &[A, B], id, ts);
    }
    block_on(bob.flush()).unwrap();
    block_on(bob.archive_owner(T, "c", 3, b"c")).unwrap();
    block_on(bob.flush()).unwrap();

    let mut seen = Vec::new();
    let mut cursor: Option<ThreadCursor> = None;
    let mut pages = 0;
    loop {
        let page = block_on(bob.load_thread_page(T, cursor.as_ref(), 3)).unwrap();
        pages += 1;
        seen.extend(page.history.messages.iter().map(|m| m.message_id.clone()));
        // The owner copy of "c" merged with the sender copy on one page.
        assert!(page.history.messages.iter().all(|m| !m.conflict));
        match page.next {
            Some(c) => {
                assert_eq!(ThreadCursor::parse(&c.to_string()).unwrap(), c);
                cursor = Some(c);
            }
            None => break,
        }
        assert!(pages < 10);
    }
    assert_eq!(seen, ["g", "f", "e", "d", "c", "b", "a"]);
    assert_eq!(pages, 3);
    // The first page is the newest three, and only they were opened.
    let first = block_on(bob.load_thread_page(T, None, 3)).unwrap();
    assert_eq!(ids(&first.history), ["g", "f", "e"]);
    assert_eq!(first.next.as_ref().unwrap().to_string(), "5:e");
}

#[test]
fn a_restored_device_lists_threads_it_has_left() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    send(&mut alice, "t-left", &[A, B], "m1", 10);
    send(&mut alice, "t-stay", &[A, B], "m2", 20);
    block_on(alice.flush()).unwrap();
    // Bob leaves t-left on a Space: he re-archives first, then loses read
    // access to the space.
    assert_eq!(
        block_on(bob.rearchive_thread_before_leave("t-left")).unwrap(),
        1
    );
    net.revoke_thread_access("t-left", B);
    let setup = block_on(bob.create_recovery_code(Mechanism::Code)).unwrap();
    net.register_chat_device(B, tpub(9));
    let (mut restored, _) = block_on(Labyrinth::restore_with_recovery_code(
        B,
        setup.code.as_str(),
        Box::new(signer(9)),
        backends(&net, &clock, B),
    ))
    .unwrap();
    let threads = block_on(restored.list_threads()).unwrap();
    let names: Vec<_> = threads.iter().map(|t| t.thread_id.as_str()).collect();
    assert_eq!(names, ["t-left", "t-stay"]);
    assert!(threads[0].owner_archive && threads[0].sender_history);
    assert!(!threads[1].owner_archive && threads[1].sender_history);
    // The left thread still reads from the owner archive.
    let h = block_on(restored.load_thread("t-left", TimeRange::ALL)).unwrap();
    assert!(!h.space_readable);
    assert_eq!(h.messages[0].source, MessageSource::Owner);
}

#[test]
fn purge_account_redacts_authored_items_and_erases_the_mailbox() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    send(&mut alice, T, &[A, B], "m1", 10);
    send(&mut alice, "t2", &[A, B], "m2", 20);
    block_on(alice.flush()).unwrap();
    send(&mut bob, T, &[A, B], "b1", 30);
    block_on(bob.flush()).unwrap();

    let report = block_on(alice.purge_account()).unwrap();
    assert_eq!((report.threads, report.redacted), (2, 2));
    let h = read(&mut bob, T);
    assert_eq!(ids(&h), ["b1"]);
    assert!(h.redacted.iter().all(|r| r.sender == A));
    // The mailbox and its public keys are gone.
    assert!(block_on(net.directory().latest(A)).unwrap().is_none());
    assert!(net.mailbox(A).list_epochs_for_test().is_empty());
}

#[test]
fn server_removals_never_read_as_unsends() {
    // G16: no server-written redaction is evidence of anything. A bare
    // `{redactedAt}` removal is quarantined per-author and reported as
    // undecryptable (`BadSignature`) without ever appearing in `redacted` or `messages`,
    // while honest peers in the same thread still restore cleanly.
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    send(&mut alice, T, &[A, B], "m1", 10);
    block_on(alice.flush()).unwrap();
    send(&mut bob, T, &[A, B], "b1", 20);
    block_on(bob.flush()).unwrap();
    assert_eq!(net.strip_items_for_test(A), 1);
    let h = block_on(bob.load_thread(T, TimeRange::ALL)).unwrap();
    assert_eq!(ids(&h), ["b1"]);
    assert!(h.redacted.is_empty());
    assert!(
        h.quarantined
            .iter()
            .any(|q| q.author == A
                && q.reason == labyrinth::store::QuarantineReason::InvalidRedaction)
    );
    assert!(
        h.undecryptable
            .iter()
            .any(|u| u.sender.as_deref() == Some(A) && u.error == Error::BadSignature)
    );
}

trait ListEpochs {
    fn list_epochs_for_test(&self) -> Vec<u64>;
}
impl ListEpochs for labyrinth::store::memory::MemoryMailbox {
    fn list_epochs_for_test(&self) -> Vec<u64> {
        use labyrinth::store::MailboxStore as _;
        block_on(self.list_epochs())
            .unwrap()
            .iter()
            .map(|e| e.value.seq())
            .collect()
    }
}

//! Deletion ([CB-38]), lookup by id, newest-first paging and thread
//! listing (gap audit §9, 2.2, 2.3, 1.3) on the memory backend.

#[path = "support/net.rs"]
mod net;

use labyrinth::Error;
use labyrinth::client::{Labyrinth, MessageSource, ThreadCursor, ThreadHistory};
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::{MailboxDirectory, TimeRange};
use labyrinth::virtual_device::Mechanism;
use net::*;

fn send(lab: &mut Labyrinth, thread: &str, members: &[&str], id: &str, ts: u64) {
    let roster = lab.resolve_roster(members).unwrap();
    lab.archive_outgoing(thread, &roster, id, ts, id.as_bytes())
        .unwrap();
}

fn ids(h: &ThreadHistory) -> Vec<&str> {
    h.messages.iter().map(|m| m.message_id.as_str()).collect()
}

fn read(lab: &mut Labyrinth, thread: &str) -> ThreadHistory {
    lab.load_thread(thread, TimeRange::ALL).unwrap()
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
    alice.flush().unwrap();
    assert_eq!(ids(&read(&mut bob, T)), ["m1", "m2"]);

    bob.delete_for_me(T, "m1", 10, Some(A), &[]).unwrap();
    // Every device of Bob's account hides it ...
    let h = read(&mut bob_laptop, T);
    assert_eq!(ids(&h), ["m2"]);
    assert_eq!(h.deleted_for_me, ["m1"]);
    let one = bob_laptop.load_message(T, "m1").unwrap();
    assert!(one.messages.is_empty());
    assert_eq!(one.deleted_for_me, ["m1"]);
    // ... time-range reads too (the tombstone carries its target's time) ...
    let ranged = bob_laptop
        .load_thread(
            T,
            TimeRange {
                from_ms: Some(5),
                until_ms: Some(15),
            },
        )
        .unwrap();
    assert!(ranged.messages.is_empty());
    // ... and nobody else's view changes.
    assert_eq!(ids(&read(&mut alice, T)), ["m1", "m2"]);
}

#[test]
fn unsend_redacts_for_everyone_and_is_author_only() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    send(&mut alice, T, &[A, B], "m1", 10);
    send(&mut alice, T, &[A, B], "m2", 20);
    alice.flush().unwrap();

    // Bob cannot unsend Alice's message: he has no item with that id.
    assert_eq!(bob.unsend(T, "m2").unwrap_err(), Error::NotFound("message"));
    assert_eq!(alice.unsend(T, "m2").unwrap(), 1);
    let h = read(&mut bob, T);
    assert_eq!(ids(&h), ["m1"]);
    assert_eq!(h.redacted.len(), 1);
    let r = &h.redacted[0];
    assert_eq!((r.message_id.as_str(), r.timestamp), ("m2", 20));
    assert_eq!(r.sender, A);
    assert!(r.by_author, "signed by one of Alice's chat devices");
    assert!(h.undecryptable.is_empty());
    // By id, too.
    let one = bob.load_message(T, "m2").unwrap();
    assert!(one.messages.is_empty() && one.redacted.len() == 1);

    // An unflushed message is simply dropped from the outbox.
    send(&mut alice, T, &[A, B], "m3", 30);
    assert_eq!(alice.unsend(T, "m3").unwrap(), 1);
    alice.flush().unwrap();
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
    alice.flush().unwrap();
    for (id, ts) in [("b", 2), ("d", 5), ("f", 6)] {
        send(&mut bob, T, &[A, B], id, ts);
    }
    bob.flush().unwrap();
    bob.archive_owner(T, "c", 3, b"c").unwrap();
    bob.flush().unwrap();

    let mut seen = Vec::new();
    let mut cursor: Option<ThreadCursor> = None;
    let mut pages = 0;
    loop {
        let page = bob.load_thread_page(T, cursor.as_ref(), 3).unwrap();
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
    let first = bob.load_thread_page(T, None, 3).unwrap();
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
    alice.flush().unwrap();
    // Bob leaves t-left on a Space: he re-archives first, then loses read
    // access to the space.
    assert_eq!(bob.rearchive_thread_before_leave("t-left").unwrap(), 1);
    net.revoke_thread_access("t-left", B);
    let setup = bob.create_recovery_code(Mechanism::Code).unwrap();
    net.register_chat_device(B, tpub(9));
    let (mut restored, _) = Labyrinth::restore_with_recovery_code(
        B,
        setup.code.as_str(),
        Box::new(signer(9)),
        backends(&net, &clock, B),
    )
    .unwrap();
    let threads = restored.list_threads().unwrap();
    let names: Vec<_> = threads.iter().map(|t| t.thread_id.as_str()).collect();
    assert_eq!(names, ["t-left", "t-stay"]);
    assert!(threads[0].owner_archive && threads[0].sender_history);
    assert!(!threads[1].owner_archive && threads[1].sender_history);
    // The left thread still reads from the owner archive.
    let h = restored.load_thread("t-left", TimeRange::ALL).unwrap();
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
    alice.flush().unwrap();
    send(&mut bob, T, &[A, B], "b1", 30);
    bob.flush().unwrap();

    let report = alice.purge_account().unwrap();
    assert_eq!((report.threads, report.redacted), (2, 2));
    let h = read(&mut bob, T);
    assert_eq!(ids(&h), ["b1"]);
    assert!(h.redacted.iter().all(|r| r.sender == A && r.by_author));
    // The mailbox and its public keys are gone.
    assert!(net.directory().latest(A).unwrap().is_none());
    assert!(net.mailbox(A).list_epochs_for_test().is_empty());
}

trait ListEpochs {
    fn list_epochs_for_test(&self) -> Vec<u64>;
}
impl ListEpochs for labyrinth::store::memory::MemoryMailbox {
    fn list_epochs_for_test(&self) -> Vec<u64> {
        use labyrinth::store::MailboxStore as _;
        self.list_epochs()
            .unwrap()
            .iter()
            .map(|e| e.value.seq())
            .collect()
    }
}

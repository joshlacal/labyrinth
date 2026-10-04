//! Sender batches hold messages under one MEK only (design Y4: mls-ds
//! authorizes thread reads per MEK and rejects mixed-MEK batches).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use labyrinth::client::{Backends, Clock, Labyrinth};
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::{ThreadStore, TimeRange};

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        1_791_000_000_000 + self.0.fetch_add(1, Ordering::Relaxed)
    }
}

fn init(net: &MemoryBackend, did: &str, seed: u8) -> Labyrinth {
    let signer = Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]));
    net.register_chat_device(did, signer.0.verifying_key().to_bytes());
    let b = Backends {
        mailbox: Box::new(net.mailbox(did)),
        threads: Box::new(net.threads(did)),
        directory: Box::new(net.directory()),
        orf: Box::new(net.orf(did)),
        publishers: vec![],
        clock: Box::new(TestClock::default()),
    };
    Labyrinth::initialize(did, Box::new(signer), b).unwrap()
}

#[test]
fn a_new_mek_starts_a_new_batch() {
    let net = MemoryBackend::new();
    let (a, b, c) = ("did:plc:alice", "did:plc:bob", "did:plc:carol");
    let mut alice = init(&net, a, 1);
    init(&net, b, 2);
    init(&net, c, 3);
    let send = |l: &mut Labyrinth, group: &[&str], id: &str| {
        let roster = l.resolve_roster(group).unwrap();
        l.archive_outgoing("t", &roster, id, 10, b"x").unwrap()
    };
    assert!(send(&mut alice, &[a, b], "m1").flushed.is_none());
    assert!(send(&mut alice, &[a, b], "m2").flushed.is_none());
    // Carol joins: a new MEK, so the two buffered messages flush first.
    let out = send(&mut alice, &[a, b, c], "m3");
    assert!(out.mek_written.is_some());
    assert_eq!(out.flushed.unwrap().count, 2);
    assert_eq!(alice.pending("t"), 1);
    assert_eq!(alice.flush().unwrap()[0].count, 1);
    let batches = net
        .threads(a)
        .list_batches("t", None, TimeRange::ALL)
        .unwrap();
    assert_eq!(batches.len(), 2);
    for batch in &batches {
        let ids: Vec<_> = batch.value.items.iter().map(|i| &i.mek_id).collect();
        assert!(ids.windows(2).all(|w| w[0] == w[1]));
    }
    assert_ne!(
        batches[0].value.items[0].mek_id,
        batches[1].value.items[0].mek_id
    );
}

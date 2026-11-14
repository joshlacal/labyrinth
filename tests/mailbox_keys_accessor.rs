//! Public mailbox-key accessors used by callers that wrap a key to the
//! member's own mailbox encryption key and open it by trial decryption.

#[path = "support/net.rs"]
mod net;

use futures::executor::block_on;
use labyrinth::store::memory::MemoryBackend;
use net::*;

#[test]
fn mailbox_keys_for_matches_published_public_keys() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let latest = phone.latest_epoch();
    let keys = block_on(phone.mailbox_keys_for(latest)).unwrap();
    assert_eq!(keys.public(), phone.latest_public().unwrap().keys);
    assert!(block_on(phone.mailbox_keys_for(latest + 50)).is_err());
}

#[test]
fn previous_epoch_keys_survive_rotation() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let first = phone.latest_epoch();
    let first_public = phone.latest_public().unwrap();
    let rot = block_on(phone.rotate_epoch()).unwrap();
    assert_eq!(rot.new_epoch, first + 1);

    let pairs = block_on(phone.current_and_previous_mailbox_keys()).unwrap();
    assert_eq!(pairs.len(), 2);
    let latest_public = phone.latest_public().unwrap();
    assert_eq!(pairs[0].0, rot.new_epoch);
    assert_eq!(pairs[0].1, latest_public.head);
    assert_eq!(pairs[0].2.public(), latest_public.keys);
    assert_eq!(pairs[1].0, first);
    assert_eq!(pairs[1].1, first_public.head);
    assert_eq!(
        pairs[1].2.public().enc.to_bytes(),
        first_public.keys.enc.to_bytes()
    );
    assert_ne!(pairs[0].2.public(), pairs[1].2.public());
}

#[test]
fn recent_mailbox_keys_returns_bounded_window_newest_first() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    for _ in 0..9 {
        block_on(phone.rotate_epoch()).unwrap();
    }
    let latest = phone.latest_epoch();
    assert_eq!(latest, 9);

    let window = block_on(phone.recent_mailbox_keys(8)).unwrap();
    assert_eq!(window.len(), 8);
    let seqs: Vec<u64> = window.iter().map(|(seq, _, _)| *seq).collect();
    assert_eq!(seqs, vec![9, 8, 7, 6, 5, 4, 3, 2]);
    assert_eq!(window[0].2.public(), phone.latest_public().unwrap().keys);
    assert!(block_on(phone.recent_mailbox_keys(0)).unwrap().is_empty());
}

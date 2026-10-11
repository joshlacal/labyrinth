//! End-to-end MEK distribution and message flows for a 3-member thread
//! (SPEC §7).

mod common;

use common::{Member, THREAD, heads, labyrinth_mek, roster};
use labyrinth::Error;
use labyrinth::mek::{self, Mek, MekProvenance};
use labyrinth::message::{open_owner, open_sender, seal_owner, seal_sender, verify_sender_device};
use labyrinth::sign::TransportSigner;

fn trio() -> (Member, Member, Member) {
    (
        Member::new("alice", 1),
        Member::new("bob", 2),
        Member::new("carol", 3),
    )
}

#[test]
fn three_members_share_a_labyrinth_mek() {
    let (alice, bob, carol) = trio();
    let (mek, record) = labyrinth_mek(&alice, &[&alice, &bob, &carol]);
    assert_eq!(record.recipients.len(), 3);

    let for_bob = bob.open(&record, Some(&alice)).unwrap();
    let for_carol = carol.open(&record, Some(&alice)).unwrap();
    let for_alice = alice.open(&record, Some(&alice)).unwrap();
    for m in [&for_bob, &for_carol, &for_alice] {
        assert_eq!(m.id(), mek.id());
        assert_eq!(m.secret(), mek.secret());
        assert_eq!(
            *m.provenance(),
            MekProvenance::Labyrinth {
                sender_did: alice.did.clone(),
                sender_epoch_head: alice.epoch.head,
            }
        );
    }

    let sealed = seal_sender(
        &mek,
        THREAD,
        "msg-1",
        1_700_000_000_123,
        b"hi all",
        &alice.transport,
    )
    .unwrap();
    verify_sender_device(&sealed, &[alice.transport_pub()]).unwrap();
    assert_eq!(open_sender(&sealed, THREAD, &for_bob).unwrap(), b"hi all");
    assert_eq!(open_sender(&sealed, THREAD, &for_carol).unwrap(), b"hi all");

    // Bob reuses the MEK he received to reply (rule 1 and rule 2 hold).
    let current = heads(&[&carol, &alice, &bob]);
    assert!(for_bob.reusable_for(&current));
    let reply = seal_sender(
        &for_bob,
        THREAD,
        "msg-2",
        1_700_000_000_456,
        b"hey",
        &bob.transport,
    )
    .unwrap();
    assert_eq!(open_sender(&reply, THREAD, &mek).unwrap(), b"hey");
    assert!(verify_sender_device(&reply, &[alice.transport_pub()]).is_err());
}

#[test]
fn non_recipient_cannot_open() {
    let (alice, bob, carol) = trio();
    let dave = Member::new("dave", 4);
    let (_, record) = labyrinth_mek(&alice, &[&alice, &bob, &carol]);
    assert_eq!(
        dave.open(&record, Some(&alice)).unwrap_err(),
        Error::NotRecipient
    );

    // Dave claiming Bob's DID, with his own epoch, fails the epoch check.
    let r = mek::open(
        &record,
        &bob.did,
        &dave.epoch,
        &dave.keys,
        Some(&alice.epoch),
    );
    assert_eq!(r.unwrap_err(), Error::WrongEpoch);
    // ...and with Bob's public epoch but his own keys, the key check.
    let r = mek::open(
        &record,
        &bob.did,
        &bob.epoch,
        &dave.keys,
        Some(&alice.epoch),
    );
    assert!(r.is_err());
    // A Labyrinth MEK needs the sender's epoch.
    assert_eq!(
        bob.open(&record, None).unwrap_err(),
        Error::NotFound("sender epoch")
    );
    assert_eq!(
        bob.open(&record, Some(&carol)).unwrap_err(),
        Error::WrongEpoch
    );
}

#[test]
fn changing_a_recipient_head_breaks_the_roster() {
    let (alice, bob, carol) = trio();
    let (_, record) = labyrinth_mek(&alice, &[&alice, &bob, &carol]);
    let mut bad = record.clone();
    bad.recipients[2].recipient_epoch_head[0] ^= 1;
    assert_eq!(
        bob.open(&bad, Some(&alice)).unwrap_err(),
        Error::RosterMismatch
    );

    // Rewriting the roster hash to match fails AEAD (the AAD binds it) and
    // the mek_id re-derivation.
    bad.roster_hash = mek::roster_hash(&bad.recipient_heads());
    assert!(bob.open(&bad, Some(&alice)).is_err());

    // Dropping a recipient also breaks the roster.
    let mut dropped = record.clone();
    dropped.recipients.remove(2);
    assert_eq!(
        bob.open(&dropped, Some(&alice)).unwrap_err(),
        Error::RosterMismatch
    );
}

#[test]
fn removing_carol_forces_a_new_mek_she_cannot_open() {
    let (alice, bob, carol) = trio();
    let (old, _) = labyrinth_mek(&alice, &[&alice, &bob, &carol]);
    assert!(old.reusable_for(&heads(&[&alice, &bob, &carol])));

    let after = heads(&[&alice, &bob]);
    assert!(!old.reusable_for(&after));
    let (new, record) = labyrinth_mek(&alice, &[&alice, &bob]);
    assert_ne!(new.roster_hash(), old.roster_hash());
    assert!(new.reusable_for(&after));
    assert_eq!(
        carol.open(&record, Some(&alice)).unwrap_err(),
        Error::NotRecipient
    );

    let sealed = seal_sender(&new, THREAD, "msg-9", 9, b"after carol", &alice.transport).unwrap();
    assert_eq!(
        open_sender(&sealed, THREAD, &old).unwrap_err(),
        Error::MekMismatch
    );
    let bobs = bob.open(&record, Some(&alice)).unwrap();
    assert_eq!(open_sender(&sealed, THREAD, &bobs).unwrap(), b"after carol");
}

#[test]
fn a_member_rotating_epochs_invalidates_the_mek() {
    let (alice, bob, carol) = trio();
    let (mek, _) = labyrinth_mek(&alice, &[&alice, &bob, &carol]);
    let bob2 = Member::at_epoch("bob", 2, 0x77);
    assert!(!mek.reusable_for(&heads(&[&alice, &bob2, &carol])));
    // Distributing a MEK minted for the old roster to the new one is refused.
    let mut stale = mek.clone();
    let r = mek::distribute_labyrinth(
        THREAD,
        &mut stale,
        &alice.did,
        &alice.epoch,
        &alice.keys,
        &roster(&[&alice, &bob2, &carol]),
    );
    assert_eq!(r.unwrap_err(), Error::RosterMismatch);
}

#[test]
fn distribution_requires_the_sender_in_the_roster() {
    let (alice, bob, carol) = trio();
    let mut mek = Mek::generate(&heads(&[&bob, &carol])).unwrap();
    let r = mek::distribute_labyrinth(
        THREAD,
        &mut mek,
        &alice.did,
        &alice.epoch,
        &alice.keys,
        &roster(&[&bob, &carol]),
    );
    assert!(r.is_err());
    let dup = Mek::generate(&heads(&[&alice, &alice])).unwrap();
    let r = mek::distribute_labyrinth(
        THREAD,
        &mut dup.clone(),
        &alice.did,
        &alice.epoch,
        &alice.keys,
        &roster(&[&alice, &alice]),
    );
    assert!(r.is_err());
}

#[test]
fn transport_sender_mek() {
    let (alice, bob, carol) = trio();
    // A non-enrolled device (no mailbox) sending into the thread.
    let device = Member::new("newphone", 9);
    let members = [&alice, &bob, &carol];
    let mut mek = Mek::generate(&heads(&members)).unwrap();
    let record =
        mek::distribute_transport(THREAD, &mut mek, &device.transport, &roster(&members)).unwrap();
    assert!(mek.reusable_for(&heads(&members)), "creator may reuse");

    let for_bob = bob.open(&record, None).unwrap();
    assert_eq!(for_bob.secret(), mek.secret());
    assert_eq!(
        *for_bob.provenance(),
        MekProvenance::Transport {
            transport_pub: device.transport_pub(),
            created_here: false,
        }
    );
    assert!(
        !for_bob.reusable_for(&heads(&members)),
        "not epoch-authenticated"
    );

    let sealed = seal_sender(&mek, THREAD, "m", 5, b"from new phone", &device.transport).unwrap();
    assert_eq!(
        sealed.sender_transport_pub,
        device.transport.transport_public_key()
    );
    assert_eq!(
        open_sender(&sealed, THREAD, &for_bob).unwrap(),
        b"from new phone"
    );
    assert_eq!(carol.open(&record, None).unwrap().id(), mek.id());
}

#[test]
fn swapped_sender_transport_key_is_rejected() {
    let (alice, bob, carol) = trio();
    let (mek, _) = labyrinth_mek(&alice, &[&alice, &bob, &carol]);
    let sealed = seal_sender(&mek, THREAD, "m1", 1, b"by alice", &alice.transport).unwrap();

    let mut swapped = sealed.clone();
    swapped.sender_transport_pub = bob.transport_pub();
    assert_eq!(
        open_sender(&swapped, THREAD, &mek).unwrap_err(),
        Error::BadSignature
    );

    // Bob re-signs Alice's ciphertext as his own: the signature verifies, but
    // the AAD binds Alice's key, so decryption fails.
    let ct = &sealed.signed_enc_message[64..];
    let msg = [b"minos.unstructured_signature.message:".as_slice(), ct].concat();
    let resigned = [bob.transport.sign_transport(&msg).as_slice(), ct].concat();
    swapped.signed_enc_message = resigned;
    assert_eq!(
        open_sender(&swapped, THREAD, &mek).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn sealed_message_tamper_every_field() {
    let (alice, bob, carol) = trio();
    let (mek, _) = labyrinth_mek(&alice, &[&alice, &bob, &carol]);
    let sealed = seal_sender(
        &mek,
        THREAD,
        "msg-42",
        1_700_000_000_000,
        b"tamper me",
        &alice.transport,
    )
    .unwrap();
    assert!(open_sender(&sealed, THREAD, &mek).is_ok());
    assert!(open_sender(&sealed, "conv-other", &mek).is_err());

    for i in 0..sealed.message_id.len() {
        let mut bad = sealed.clone();
        let mut bytes = bad.message_id.into_bytes();
        bytes[i] ^= 1;
        bad.message_id = String::from_utf8(bytes).unwrap();
        assert!(open_sender(&bad, THREAD, &mek).is_err(), "message_id {i}");
    }
    for bit in 0..64 {
        let mut bad = sealed.clone();
        bad.timestamp ^= 1 << bit;
        assert!(
            open_sender(&bad, THREAD, &mek).is_err(),
            "timestamp bit {bit}"
        );
    }
    for i in 0..12 {
        let mut bad = sealed.clone();
        bad.mek_id[i] ^= 1;
        assert!(open_sender(&bad, THREAD, &mek).is_err(), "mek_id {i}");
    }
    for i in 0..32 {
        let mut bad = sealed.clone();
        bad.sender_transport_pub[i] ^= 1;
        assert!(
            open_sender(&bad, THREAD, &mek).is_err(),
            "transport pub {i}"
        );
    }
    for i in 0..sealed.signed_enc_message.len() {
        let mut bad = sealed.clone();
        bad.signed_enc_message[i] ^= 1;
        assert!(
            open_sender(&bad, THREAD, &mek).is_err(),
            "signed_enc_message {i}"
        );
    }
    let mut short = sealed.clone();
    short.signed_enc_message.truncate(63);
    assert!(open_sender(&short, THREAD, &mek).is_err());
}

#[test]
fn owner_mode_round_trip_and_binding() {
    let root = [0x42u8; 32];
    let msg = seal_owner(&root, 7, THREAD, "m-1", 123, b"note to self").unwrap();
    assert_eq!((msg.version, msg.epoch_seq), (5, 7));
    assert_eq!(open_owner(&root, &msg).unwrap(), b"note to self");

    // [CB-37] v5 binds the message id and timestamp too.
    let mut wrong_id = msg.clone();
    wrong_id.message_id = "m-2".into();
    assert!(open_owner(&root, &wrong_id).is_err());
    let mut wrong_ts = msg.clone();
    wrong_ts.timestamp = 124;
    assert!(open_owner(&root, &wrong_ts).is_err());

    let mut wrong_seq = msg.clone();
    wrong_seq.epoch_seq = 8;
    assert!(open_owner(&root, &wrong_seq).is_err());
    let mut wrong_thread = msg.clone();
    wrong_thread.thread_id = "conv-other".into();
    assert!(open_owner(&root, &wrong_thread).is_err());
    let mut v4 = msg.clone();
    v4.version = 4;
    assert!(open_owner(&root, &v4).is_err());
    assert!(open_owner(&[0x43; 32], &msg).is_err());
    for i in 0..msg.encrypted.len() {
        let mut bad = msg.clone();
        bad.encrypted[i] ^= 1;
        assert!(open_owner(&root, &bad).is_err(), "encrypted {i}");
    }
}

#[test]
fn padding_hides_lengths() {
    let (alice, bob, carol) = trio();
    let (mek, _) = labyrinth_mek(&alice, &[&alice, &bob, &carol]);
    let a = seal_sender(&mek, THREAD, "a", 1, &[b'x'; 11], &alice.transport).unwrap();
    let b = seal_sender(&mek, THREAD, "b", 1, &[b'x'; 12], &alice.transport).unwrap();
    assert_eq!(a.signed_enc_message.len(), b.signed_enc_message.len());
    let root = [1u8; 32];
    // v5 owner content is `kind || frame`: 11 and 12 bytes pad alike.
    let a = seal_owner(&root, 0, THREAD, "a", 1, &[0; 10]).unwrap();
    let b = seal_owner(&root, 0, THREAD, "b", 1, &[0; 11]).unwrap();
    assert_eq!(a.encrypted.len(), b.encrypted.len());
}

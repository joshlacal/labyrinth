use super::*;
use crate::device::DeviceSecrets;
use crate::epoch::open_genesis;
use crate::message::seal_owner;
use crate::records::datetime_from_ms;
use crate::records::{Batch, MekDistribution};
use crate::sign::Ed25519Transport;
use crate::store::{ChatDeviceKey, MailboxDirectory, ThreadStore, keys_valid_at};

const ALICE: &str = "did:plc:alice";
const BOB: &str = "did:plc:bob";

fn transport() -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]))
}

fn genesis_records() -> (DeviceSecrets, Epoch, Vec<EpochMember>) {
    let d = DeviceSecrets::generate().unwrap();
    let (_, n) = open_genesis(ALICE, &d, &transport()).unwrap();
    let ts = datetime_from_ms(1);
    let members = n
        .members
        .iter()
        .map(|m| EpochMember::from_record(m, ts.clone()))
        .collect();
    (d, Epoch::from_record(&n.record, ts), members)
}

#[test]
fn epoch_create_is_create_if_absent() {
    let b = MemoryBackend::new();
    let mb = b.mailbox(ALICE);
    let (_, epoch, members) = genesis_records();
    assert_eq!(mb.create_epoch(&epoch, &members).unwrap(), "000000000000");
    assert_eq!(mb.create_epoch(&epoch, &[]), Err(Error::Conflict));
    // A racing device's different epoch 0 also loses.
    let (_, other, other_members) = genesis_records();
    assert_eq!(
        mb.create_epoch(&other, &other_members),
        Err(Error::Conflict)
    );
    assert_eq!(mb.get_epoch(0).unwrap().unwrap().value, epoch);
    assert_eq!(mb.list_epochs().unwrap().len(), 1);
    // Members are immutable: re-creating one conflicts.
    assert_eq!(mb.create_epoch_member(&members[0]), Err(Error::Conflict));
    assert_eq!(mb.list_epoch_members(0).unwrap(), members);
    assert!(mb.list_epoch_members(1).unwrap().is_empty());
    // No member of an epoch that doesn't exist.
    let mut m1 = members[0].clone();
    m1.epoch_number = 1;
    assert_eq!(mb.create_epoch_member(&m1), Err(Error::NotFound("epoch")));
}

#[test]
fn mailboxes_are_per_did() {
    let b = MemoryBackend::new();
    let (d, epoch, members) = genesis_records();
    b.mailbox(ALICE).create_epoch(&epoch, &members).unwrap();
    // Bob's handle sees and writes only Bob's mailbox.
    assert!(b.mailbox(BOB).get_epoch(0).unwrap().is_none());
    b.mailbox(BOB).create_epoch(&epoch, &members).unwrap();

    let rec = Device::from_public(d.public(), datetime_from_ms(1));
    let mb = b.mailbox(ALICE);
    mb.create_device(&rec).unwrap();
    assert_eq!(mb.create_device(&rec), Err(Error::Conflict));
    assert!(
        b.mailbox(BOB)
            .get_device(&d.public().device_key_pub)
            .unwrap()
            .is_none()
    );

    // Revocation sets revokedAt once and never changes it.
    mb.set_device_revoked(&d.public().device_key_pub, "2026-01-01T00:00:00.000Z")
        .unwrap();
    mb.set_device_revoked(&d.public().device_key_pub, "2027-01-01T00:00:00.000Z")
        .unwrap();
    let got = mb.get_device(&d.public().device_key_pub).unwrap().unwrap();
    assert_eq!(got.revoked_at.as_deref(), Some("2026-01-01T00:00:00.000Z"));
}

#[test]
fn owner_batches_filter_by_thread_and_time() {
    let b = MemoryBackend::new();
    let mb = b.mailbox(ALICE);
    let root = [1u8; 32];
    let msg = |t: &str, ts| seal_owner(&root, 0, t, "m", ts, b"x").unwrap();
    let ts = datetime_from_ms(1);
    let r1 = mb
        .append_owner_batch(
            &OwnerBatch::from_messages(&[msg("t1", 10), msg("t1", 20)], ts.clone()).unwrap(),
        )
        .unwrap();
    let r2 = mb
        .append_owner_batch(&OwnerBatch::from_messages(&[msg("t1", 30)], ts.clone()).unwrap())
        .unwrap();
    mb.append_owner_batch(&OwnerBatch::from_messages(&[msg("t2", 10)], ts).unwrap())
        .unwrap();
    assert!(r1 < r2, "TIDs sort by creation");
    assert_eq!(r1.len(), 13);
    let all = mb.list_owner_batches("t1", TimeRange::ALL).unwrap();
    assert_eq!(all.len(), 2);
    let late = TimeRange {
        from_ms: Some(25),
        until_ms: None,
    };
    let got = mb.list_owner_batches("t1", late).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].rkey, r2);
    assert!(OwnerBatch::from_messages(&[msg("t1", 1), msg("t2", 1)], "x".into()).is_err());
}

#[test]
fn thread_access_can_be_revoked() {
    let b = MemoryBackend::new();
    let t = b.threads(ALICE);
    let mek = crate::mek::Mek::generate(&[[1u8; 32]]).unwrap();
    let sealed = crate::message::seal_sender(&mek, "th", "m1", 5, b"hi", &transport()).unwrap();
    let batch = Batch::from_messages("th", &[sealed], datetime_from_ms(5)).unwrap();
    t.append_batch(&batch).unwrap();
    assert_eq!(
        b.threads(BOB)
            .list_batches("th", None, TimeRange::ALL)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        b.threads(BOB)
            .list_batches("th", Some(BOB), TimeRange::ALL)
            .unwrap()
            .len(),
        0
    );
    b.revoke_thread_access("th", BOB);
    assert_eq!(
        b.threads(BOB).list_batches("th", None, TimeRange::ALL),
        Err(Error::Forbidden)
    );
    assert_eq!(b.threads(BOB).append_batch(&batch), Err(Error::Forbidden));
    assert_eq!(t.list_batches("th", None, TimeRange::ALL).unwrap().len(), 1);
}

#[test]
fn directory_tracks_current_and_removed_devices() {
    let b = MemoryBackend::new();
    b.register_chat_device(ALICE, [1; 32]);
    b.register_chat_device(ALICE, [2; 32]);
    b.remove_chat_device(ALICE, [1; 32], 500);
    let d = b.directory();
    let keys = d.device_transport_keys(ALICE).unwrap();
    assert_eq!(
        keys,
        vec![
            ChatDeviceKey::current([2; 32]),
            ChatDeviceKey {
                key: [1; 32],
                removed_at: Some(500)
            }
        ]
    );
    assert_eq!(keys_valid_at(&keys, None), vec![[2; 32]]);
    assert_eq!(keys_valid_at(&keys, Some(499)), vec![[2; 32], [1; 32]]);
    assert_eq!(keys_valid_at(&keys, Some(500)), vec![[2; 32]]);
    assert!(d.latest(ALICE).unwrap().is_none());
}

#[test]
fn server_order_stamps_writes_and_tracks_leaves() {
    let b = MemoryBackend::new();
    let t = b.threads(ALICE);
    let mek = crate::mek::Mek::generate(&[[1u8; 32]]).unwrap();
    let sealed = crate::message::seal_sender(&mek, "th", "m1", 5, b"hi", &transport()).unwrap();
    let batch = Batch::from_messages("th", &[sealed], datetime_from_ms(5)).unwrap();
    // Space mode: no stamps, no leaf view.
    t.append_batch(&batch).unwrap();
    assert!(
        b.directory()
            .member_device_keys("th", ALICE)
            .unwrap()
            .is_none()
    );

    b.enable_server_order();
    b.set_server_time(700);
    assert_eq!(b.add_leaf("th", ALICE, [9; 32]), 1);
    b.append_chat_entry("th");
    t.append_batch(&batch).unwrap();
    assert_eq!(b.remove_leaf("th", ALICE, [9; 32]), 3);
    let got = t.list_batches("th", None, TimeRange::ALL).unwrap();
    assert_eq!(got[0].order, None);
    assert_eq!(
        got[1].order,
        Some(ServerOrder {
            labyrinth_seq: 1,
            chat_seq: Some(2),
            received_at_ms: 700
        })
    );
    let leaves = b
        .directory()
        .member_device_keys("th", ALICE)
        .unwrap()
        .unwrap();
    assert_eq!(leaves.len(), 1);
    assert_eq!(
        (leaves[0].joined_chat_seq, leaves[0].removed_chat_seq),
        (1, Some(3))
    );
    assert_eq!(
        b.directory().member_device_keys("th", BOB).unwrap(),
        Some(vec![])
    );

    // MEKs are stamped too, and a conflicting create burns no seq.
    let roster = [(ALICE.to_owned(), {
        let d = DeviceSecrets::generate().unwrap();
        open_genesis(ALICE, &d, &transport())
            .unwrap()
            .1
            .record
            .public
    })];
    let mut m = crate::mek::Mek::generate(&[roster[0].1.head]).unwrap();
    let rec = crate::mek::distribute_transport("th", &mut m, &transport(), &roster).unwrap();
    let wire = MekDistribution::from_record(&rec, None, datetime_from_ms(1)).unwrap();
    t.create_mek(&wire).unwrap();
    assert_eq!(t.create_mek(&wire), Err(Error::Conflict));
    let found = t.find_meks("th", m.id()).unwrap();
    assert_eq!(found[0].order.unwrap().labyrinth_seq, 2);
    assert_eq!(found[0].order.unwrap().chat_seq, Some(3));
}

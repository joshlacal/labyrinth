//! G-P0-2 crate half: rotation drops and reports invalid or unbound
//! members instead of aborting ([CB-25] as amended, [CB-36]), aborts on a
//! store that rewrites a member it already served intact, and reports a
//! squatted next epoch instead of retrying forever ([CB-40]).

#[path = "support/net.rs"]
mod net;

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{ExcludedMember, ExclusionReason};
use labyrinth::device::DeviceSecrets;
use labyrinth::records::{Bytes, Epoch};
use labyrinth::store::MailboxStore;
use labyrinth::store::memory::MemoryBackend;
use net::*;

#[test]
fn a_planted_member_without_a_device_record_is_dropped_and_reported() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let mut laptop = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    // Gate 3: `laptop` opened epoch 1, `tablet` opened epoch 2.
    // Any chat device of the DID plants a member row in epoch 2 for a key that
    // has no device record (copying a real row's MAC and entropy).
    let mb = net.mailbox(A);
    let tablet_key = tablet.device_public().device_key_pub;
    let mut m = block_on(mb.get_epoch_member(2, &tablet_key))
        .unwrap()
        .unwrap();
    let ghost = DeviceSecrets::generate().unwrap().public().device_key_pub;
    m.device_key_pubkey = Bytes::from_slice(&ghost.0);
    block_on(mb.create_epoch_member(&m)).unwrap();

    // Every sync surfaces it ...
    let report = block_on(laptop.sync_epochs()).unwrap();
    let expected = ExcludedMember {
        device_key: Some(ghost),
        reason: ExclusionReason::MissingDeviceRecord,
    };
    assert_eq!(report.invalid_members, vec![expected.clone()]);
    assert_eq!(
        block_on(laptop.audit_members()).unwrap(),
        vec![expected.clone()]
    );
    // ... and revocation still succeeds, reporting the drop.
    let r = block_on(laptop.revoke_device(&tablet_key)).unwrap();
    assert_eq!((r.new_epoch, r.excluded), (3, vec![expected]));
    assert_eq!(block_on(phone.sync_epochs()).unwrap().to, 3);
}

#[test]
fn a_device_whose_chat_device_was_removed_is_dropped_at_rotation() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let mut laptop = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    net.remove_chat_device(A, tpub(2), clock.now_ms_for_test());

    let laptop_key = laptop.device_public().device_key_pub;
    let report = block_on(phone.sync_epochs()).unwrap();
    assert_eq!(
        report.invalid_members,
        vec![ExcludedMember {
            device_key: Some(laptop_key),
            reason: ExclusionReason::ChatDeviceNotCurrent,
        }]
    );
    let r = block_on(phone.revoke_device(&tablet.device_public().device_key_pub)).unwrap();
    assert_eq!(r.excluded.len(), 1);
    assert_eq!(r.excluded[0].device_key, Some(laptop_key));
    // The laptop is out: removing its chat device revoked its Labyrinth
    // device too, announced in the report.
    assert_eq!(
        block_on(laptop.sync_epochs()).unwrap_err(),
        Error::NotEpochMember
    );
}

#[test]
fn a_store_rewriting_a_verified_member_aborts_the_rotation() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let faulty = Faulty::new(net.mailbox(A));
    net.register_chat_device(A, tpub(1));
    let mut phone = block_on(labyrinth::client::Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(faulty.clone()), vec![]),
    ))
    .unwrap();
    let laptop = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    block_on(phone.sync_epochs()).unwrap();
    assert!(block_on(phone.audit_members()).unwrap().is_empty());
    // The store now serves the laptop's (verified in epoch 2) row with a broken
    // MAC: dropping it would be an unannounced eviction by the store.
    *faulty.tamper.lock().unwrap() = Some(laptop.device_public().device_key_pub);
    let err = block_on(phone.revoke_device(&tablet.device_public().device_key_pub)).unwrap_err();
    assert_eq!(err, Error::MemberTampered { seq: 2 });
}

#[test]
fn a_squatted_next_epoch_is_reported_not_retried() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    block_on(phone.sync_epochs()).unwrap();
    // Gate 3: `tablet` enrollment opened epoch 1. An insider chat device plants
    // epoch 2 without the epoch-1 root: it can't sign with epoch 1's mailbox key.
    let mb = net.mailbox(A);
    let e1 = block_on(mb.get_epoch(1)).unwrap().unwrap().value;
    let mut fake: Epoch = e1.clone();
    fake.public.epoch_number = 2;
    fake.public.previous_epoch_head = Some(e1.public.epoch_head.clone());
    fake.public.prev_sig = Some(e1.public.self_sig.clone());
    fake.encrypted_previous_epoch_number = Some(Bytes(vec![2; 40]));
    fake.encrypted_previous_epoch_root_key = Some(Bytes(vec![2; 60]));
    assert!(block_on(mb.create_epoch(&fake, &[])).is_err());
    net.insert_epoch_unchecked(A, &fake);

    let err = block_on(phone.revoke_device(&tablet.device_public().device_key_pub)).unwrap_err();
    assert!(
        matches!(err, Error::EpochSquatted { seq: 2, .. }),
        "{err:?}"
    );
    assert!(matches!(
        block_on(phone.sync_epochs()).unwrap_err(),
        Error::EpochSquatted { seq: 2, .. }
    ));
}

#[test]
fn an_epoch_opened_by_a_locally_revoked_device_is_a_squat() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let faulty = Faulty::new(net.mailbox(A));
    net.register_chat_device(A, tpub(1));
    let mut phone = block_on(labyrinth::client::Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(faulty.clone()), vec![]),
    ))
    .unwrap();
    let mut thief = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    // Gate 3: `thief` opened epoch 1, `tablet` opened epoch 2.
    // The phone revokes the stolen laptop, but its rotation to epoch 3 never lands.
    faulty
        .fail_epochs
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let thief_key = thief.device_public().device_key_pub;
    assert!(block_on(phone.revoke_device(&thief_key)).is_err());
    faulty
        .fail_epochs
        .store(false, std::sync::atomic::Ordering::Relaxed);
    // The thief races ahead and opens epoch 3 (it still holds epoch 1 -> 2).
    block_on(thief.revoke_device(&tablet.device_public().device_key_pub)).unwrap();
    let err = block_on(phone.sync_epochs()).unwrap_err();
    assert_eq!(
        err,
        Error::EpochSquatted {
            seq: 3,
            reason: "it was opened by a device this client revoked"
        }
    );
}

trait NowForTest {
    fn now_ms_for_test(&self) -> u64;
}
impl NowForTest for TestClock {
    fn now_ms_for_test(&self) -> u64 {
        use labyrinth::client::Clock as _;
        self.now_ms()
    }
}

#[test]
fn pq_v4_client_state_round_trips_and_rejects_legacy_versions() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let phone = init(&net, &clock, A, 1);
    let v4 = phone.export_state().unwrap();
    assert_eq!(v4[4], 4);
    let restored = block_on(labyrinth::client::Labyrinth::from_state(
        &v4,
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A),
    ))
    .unwrap();
    assert_eq!(restored.device_public(), phone.device_public());

    for legacy_version in [1u8, 2u8, 3u8] {
        let mut legacy = v4.clone();
        legacy[4] = legacy_version;
        let err = match block_on(labyrinth::client::Labyrinth::from_state(
            &legacy,
            A,
            Box::new(signer(1)),
            backends(&net, &clock, A),
        )) {
            Ok(_) => panic!("expected legacy version {legacy_version} to fail closed"),
            Err(e) => e,
        };
        assert_eq!(err, Error::Unsupported(legacy_version));
    }
}

#[test]
fn revoking_a_chat_device_revokes_the_labyrinth_device_it_bound() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let laptop = sibling(&net, &clock, &mut phone, 2);
    let laptop_key = laptop.device_public().device_key_pub;
    assert_eq!(
        block_on(phone.devices_bound_to(&tpub(2))).unwrap(),
        vec![laptop_key]
    );
    assert!(
        block_on(phone.devices_bound_to(&tpub(9)))
            .unwrap()
            .is_empty()
    );
    // The chat device goes first, then its Labyrinth device.
    net.remove_chat_device(A, tpub(2), 1);
    let reports = block_on(phone.revoke_chat_device(&tpub(2))).unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].revoked, laptop_key);
    assert!(
        block_on(phone.devices_bound_to(&tpub(2)))
            .unwrap()
            .is_empty()
    );
    // Never itself.
    assert!(
        block_on(phone.revoke_chat_device(&tpub(1)))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_store_omitting_a_verified_sibling_in_same_epoch_fails_sync_and_rotate() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let faulty = Faulty::new(net.mailbox(A));
    net.register_chat_device(A, tpub(1));
    let mut phone = block_on(labyrinth::client::Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(faulty.clone()), vec![]),
    ))
    .unwrap();
    let laptop = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    // Device A (phone) verifies Device B (laptop) and Device C (tablet) in Epoch 2.
    block_on(phone.sync_epochs()).unwrap();

    // Malicious server omits laptop's EpochMember row while still at Epoch 2.
    *faulty.omit.lock().unwrap() = Some(laptop.device_public().device_key_pub);
    assert_eq!(
        block_on(phone.sync_epochs()).unwrap_err(),
        Error::MemberTampered { seq: 2 }
    );

    // Also verify `rotate` itself fails closed if the omission starts right
    // after `revoke_device`'s `sync_epochs_allowing` pre-check (skip 1 read).
    faulty
        .omit_skip
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let err = block_on(phone.revoke_device(&tablet.device_public().device_key_pub)).unwrap_err();
    assert_eq!(err, Error::MemberTampered { seq: 2 });
}

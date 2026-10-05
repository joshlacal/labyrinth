//! G-P0-2 crate half: rotation drops and reports invalid or unbound
//! members instead of aborting ([CB-25] as amended, [CB-36]), aborts on a
//! store that rewrites a member it already served intact, and reports a
//! squatted next epoch instead of retrying forever ([CB-40]).

#[path = "support/net.rs"]
mod net;

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
    // Any chat device of the DID plants a member row for a key that has no
    // device record (copying a real row's MAC and entropy).
    let mb = net.mailbox(A);
    let tablet_key = tablet.device_public().device_key_pub;
    let mut m = mb.get_epoch_member(0, &tablet_key).unwrap().unwrap();
    let ghost = DeviceSecrets::generate().unwrap().public().device_key_pub;
    m.device_key_pubkey = Bytes::from_slice(&ghost.0);
    mb.create_epoch_member(&m).unwrap();

    // Every sync surfaces it ...
    let report = laptop.sync_epochs().unwrap();
    let expected = ExcludedMember {
        device_key: Some(ghost),
        reason: ExclusionReason::MissingDeviceRecord,
    };
    assert_eq!(report.invalid_members, vec![expected.clone()]);
    assert_eq!(laptop.audit_members().unwrap(), vec![expected.clone()]);
    // ... and revocation still succeeds, reporting the drop.
    let r = laptop.revoke_device(&tablet_key).unwrap();
    assert_eq!((r.new_epoch, r.excluded), (1, vec![expected]));
    assert_eq!(phone.sync_epochs().unwrap().to, 1);
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
    let report = phone.sync_epochs().unwrap();
    assert_eq!(
        report.invalid_members,
        vec![ExcludedMember {
            device_key: Some(laptop_key),
            reason: ExclusionReason::ChatDeviceNotCurrent,
        }]
    );
    let r = phone
        .revoke_device(&tablet.device_public().device_key_pub)
        .unwrap();
    assert_eq!(r.excluded.len(), 1);
    assert_eq!(r.excluded[0].device_key, Some(laptop_key));
    // The laptop is out: removing its chat device revoked its Labyrinth
    // device too, announced in the report.
    assert_eq!(laptop.sync_epochs().unwrap_err(), Error::NotEpochMember);
}

#[test]
fn a_store_rewriting_a_verified_member_aborts_the_rotation() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let faulty = Faulty::new(net.mailbox(A));
    net.register_chat_device(A, tpub(1));
    let mut phone = labyrinth::client::Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(faulty.clone()), vec![]),
    )
    .unwrap();
    let laptop = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    assert!(phone.audit_members().unwrap().is_empty());
    // The store now serves the laptop's (verified) row with a broken MAC:
    // dropping it would be an unannounced eviction by the store.
    *faulty.tamper.lock().unwrap() = Some(laptop.device_public().device_key_pub);
    let err = phone
        .revoke_device(&tablet.device_public().device_key_pub)
        .unwrap_err();
    assert_eq!(err, Error::MemberTampered { seq: 0 });
}

#[test]
fn a_squatted_next_epoch_is_reported_not_retried() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    // An insider chat device creates epoch 1 without the epoch-0 root: it
    // can't sign with epoch 0's mailbox key.
    let mb = net.mailbox(A);
    let e0 = mb.get_epoch(0).unwrap().unwrap().value;
    let mut fake: Epoch = e0.clone();
    fake.public.epoch_number = 1;
    fake.public.previous_epoch_head = Some(e0.public.epoch_head.clone());
    fake.public.prev_sig = Some(e0.public.self_sig.clone());
    fake.encrypted_previous_epoch_number = Some(Bytes(vec![2; 40]));
    fake.encrypted_previous_epoch_root_key = Some(Bytes(vec![2; 60]));
    mb.create_epoch(&fake, &[]).unwrap();

    let err = phone
        .revoke_device(&tablet.device_public().device_key_pub)
        .unwrap_err();
    assert!(
        matches!(err, Error::EpochSquatted { seq: 1, .. }),
        "{err:?}"
    );
    assert!(matches!(
        phone.sync_epochs().unwrap_err(),
        Error::EpochSquatted { seq: 1, .. }
    ));
}

#[test]
fn an_epoch_opened_by_a_locally_revoked_device_is_a_squat() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let faulty = Faulty::new(net.mailbox(A));
    net.register_chat_device(A, tpub(1));
    let mut phone = labyrinth::client::Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(&net, &clock, A, Box::new(faulty.clone()), vec![]),
    )
    .unwrap();
    let mut thief = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    // The phone revokes the stolen laptop, but its rotation never lands.
    faulty
        .fail_epochs
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let thief_key = thief.device_public().device_key_pub;
    assert!(phone.revoke_device(&thief_key).is_err());
    faulty
        .fail_epochs
        .store(false, std::sync::atomic::Ordering::Relaxed);
    // The thief races ahead and opens epoch 1 (it still holds epoch 0).
    thief
        .revoke_device(&tablet.device_public().device_key_pub)
        .unwrap();
    let err = phone.sync_epochs().unwrap_err();
    assert_eq!(
        err,
        Error::EpochSquatted {
            seq: 1,
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
fn version_1_client_state_still_loads() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let phone = init(&net, &clock, A, 1);
    let v2 = phone.export_state().unwrap();
    assert_eq!(v2[4], 2);
    // Strip the v2 `verified` section (seq u64, count u32, keys) that
    // follows the empty revoked list of this fresh client.
    let epochs = 4 + (8 + 2 + 12 + 32);
    let at = 4
        + 1
        + 2
        + A.len()
        + 32
        + 32
        + 32
        + 33
        + 32
        + 32
        + 32
        + 64
        + 33
        + 65
        + 1
        + 32
        + 8
        + epochs
        + 4;
    let n = u32::from_be_bytes(v2[at + 8..at + 12].try_into().unwrap()) as usize;
    assert_eq!(n, 1, "the genesis device verified itself");
    let mut v1 = v2[..at].to_vec();
    v1.extend_from_slice(&v2[at + 12 + 32 * n..]);
    v1[4] = 1;
    labyrinth::client::Labyrinth::from_state(
        &v1,
        A,
        Box::new(signer(1)),
        backends(&net, &clock, A),
    )
    .unwrap();
}

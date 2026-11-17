//! Client behaviour of the recovery-share reader: restore dispatches on the
//! code version, removing a method deletes its share first, and a client
//! without a share store behaves exactly as before.

#[path = "support/net.rs"]
mod net;
#[path = "support/shares.rs"]
mod shares;

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Clock as _, Labyrinth};
use labyrinth::device::DeviceSecrets;
use labyrinth::epoch::{EpochKeys as _, add_device_mac, verify_member};
use labyrinth::records::{Device, EpochMember, VirtualDevice, datetime_from_ms};
use labyrinth::recovery_code::{CodeVersion, ENTROPY_LEN, RecoveryCode};
use labyrinth::recovery_share::{RecoveryShare, RecoveryShares, ShareStore as _};
use labyrinth::store::MailboxStore;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::virtual_device::{Mechanism, OtcPayload, seal_virtual_device_with_share};

use net::{A, T, TestClock, backends, init, signer, tpub};
use shares::{MemoryShares, Op};

#[test]
fn without_a_share_store_methods_stay_version_2() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let setup = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    assert_eq!(setup.code.version(), CodeVersion::V2);

    let store = MemoryShares::new(A);
    phone.set_recovery_shares(Some(RecoveryShares::reader(store.boxed())));
    let setup = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    assert_eq!(
        setup.code.version(),
        CodeVersion::V2,
        "the reader never writes v3"
    );
    assert!(store.log().is_empty());

    // A v2 code restores with or without a share store, and never fetches.
    net.register_chat_device(A, tpub(9));
    block_on(Labyrinth::restore_with_recovery_code_shared(
        A,
        setup.code.as_str(),
        Box::new(signer(9)),
        backends(&net, &clock, A),
        Some(RecoveryShares::reader(store.boxed())),
    ))
    .unwrap();
    assert!(store.log().is_empty());
}

#[test]
fn version_3_restore_fetches_share_and_recovers_pre_enrollment_history() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    block_on(phone.archive_owner(T, "before-v3", 7, b"pre-enrollment secret")).unwrap();
    block_on(phone.flush_owner(T)).unwrap();

    // Obtain the real current epoch through the supported OTC transfer, then
    // build the v3 fixture directly. No Labyrinth v3 writer is enabled.
    let mut offer = phone.otc_offer().unwrap();
    let (initiator, hello) = Labyrinth::otc_start(A, offer.code().as_str()).unwrap();
    let reply = block_on(phone.otc_respond(&mut offer, &hello)).unwrap();
    let session = initiator.finish(&reply.message).unwrap();
    let current = OtcPayload::open(&session, &reply.sealed_payload)
        .unwrap()
        .epoch;
    assert_eq!(current.seq(), 0);

    let code = RecoveryCode::from_entropy_symbols_v3(&[0; ENTROPY_LEN]);
    let share = RecoveryShare::from_bytes([0x5a; 32]);
    let vdevice = DeviceSecrets::generate_virtual().unwrap();
    let created_at = datetime_from_ms(clock.now_ms());
    let record = seal_virtual_device_with_share(
        A,
        &code,
        Some(&share),
        &vdevice,
        &current,
        Mechanism::Code,
        Some(created_at.as_str()),
    )
    .unwrap();
    let member = add_device_mac(&current, &record.public).unwrap();
    let mailbox = net.mailbox(A);
    block_on(mailbox.create_device(&Device::from_public(
        &record.public,
        created_at.clone(),
    )))
    .unwrap();
    block_on(mailbox.create_virtual_device(&VirtualDevice::from_bundle(
        &record,
        None,
        created_at.clone(),
    )))
    .unwrap();
    block_on(mailbox.create_epoch_member(&EpochMember::from_record(
        &member,
        created_at,
    )))
    .unwrap();
    let persisted_member = block_on(
        mailbox.get_epoch_member(current.seq(), &record.public.device_key_pub),
    )
    .unwrap()
    .unwrap()
    .to_record()
    .unwrap();
    verify_member(&current, &persisted_member, true).unwrap();

    let derivation = code.derive_v3(A).unwrap();
    assert_eq!(derivation.vdevice_id, record.vdevice_id);
    let verifier = derivation.fetch_verifier(A);
    for seed in [7, 8, 9] {
        net.register_chat_device(A, tpub(seed));
    }

    let missing = MemoryShares::new(A);
    let error = block_on(Labyrinth::restore_with_recovery_code_shared(
        A,
        code.as_str(),
        Box::new(signer(7)),
        backends(&net, &clock, A),
        Some(RecoveryShares::reader(missing.boxed())),
    ))
    .map(|_| ())
    .unwrap_err();
    assert_eq!(error, Error::RecoveryShareUnavailable);
    assert_eq!(missing.log(), vec![Op::Get(record.vdevice_id)]);

    let wrong = MemoryShares::new(A);
    let wrong_share = RecoveryShare::from_bytes([0xff; 32]);
    block_on(wrong.put_share(
        &record.vdevice_id,
        &wrong_share,
        &verifier,
        Mechanism::Code,
    ))
    .unwrap();
    let error = block_on(Labyrinth::restore_with_recovery_code_shared(
        A,
        code.as_str(),
        Box::new(signer(8)),
        backends(&net, &clock, A),
        Some(RecoveryShares::reader(wrong.boxed())),
    ))
    .map(|_| ())
    .unwrap_err();
    assert_eq!(error, Error::Decrypt);
    assert_eq!(
        wrong.log(),
        vec![Op::Put(record.vdevice_id), Op::Get(record.vdevice_id)]
    );

    // Seed the configured test store through ShareStore itself; this is only
    // fixture construction and does not expose or enable a runtime writer.
    let shares = MemoryShares::new(A);
    block_on(shares.put_share(
        &record.vdevice_id,
        &share,
        &verifier,
        Mechanism::Code,
    ))
    .unwrap();
    let (mut restored, enrollment) = block_on(
        Labyrinth::restore_with_recovery_code_shared(
            A,
            code.as_str(),
            Box::new(signer(9)),
            backends(&net, &clock, A),
            Some(RecoveryShares::reader(shares.boxed())),
        ),
    )
    .unwrap();
    assert_eq!(restored.latest_epoch(), 1);
    assert!(enrollment.excluded.is_empty());
    assert_eq!(
        shares.log(),
        vec![Op::Put(record.vdevice_id), Op::Get(record.vdevice_id)]
    );

    // Verify the records written by the actual enrollment against its epoch,
    // including the carried v3 virtual member and the new physical member.
    let mut latest_offer = restored.otc_offer().unwrap();
    let (latest_initiator, latest_hello) =
        Labyrinth::otc_start(A, latest_offer.code().as_str()).unwrap();
    let latest_reply =
        block_on(restored.otc_respond(&mut latest_offer, &latest_hello)).unwrap();
    let latest_session = latest_initiator.finish(&latest_reply.message).unwrap();
    let latest = OtcPayload::open(&latest_session, &latest_reply.sealed_payload)
        .unwrap()
        .epoch;
    assert_eq!(latest.seq(), 1);
    for (key, is_virtual) in [
        (record.public.device_key_pub, true),
        (enrollment.device_key, false),
    ] {
        let member = block_on(mailbox.get_epoch_member(latest.seq(), &key))
            .unwrap()
            .unwrap()
            .to_record()
            .unwrap();
        verify_member(&latest, &member, is_virtual).unwrap();
    }

    let history = block_on(restored.load_owner_thread(T)).unwrap();
    assert!(history.undecryptable.is_empty());
    assert_eq!(history.messages.len(), 1);
    assert_eq!(history.messages[0].message_id, "before-v3");
    assert_eq!(history.messages[0].frame.as_slice(), b"pre-enrollment secret");
}

#[test]
fn an_unknown_code_version_is_reported_at_restore() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let setup = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let mut typed = setup.code.as_str().to_owned();
    typed.replace_range(0..1, "7");
    net.register_chat_device(A, tpub(9));
    // The backend knows the v2 method, so a mistyped version still restores.
    block_on(Labyrinth::restore_with_recovery_code(
        A,
        &typed,
        Box::new(signer(9)),
        backends(&net, &clock, A),
    ))
    .unwrap();

    // With no matching method it is reported as an unsupported version.
    let other = MemoryBackend::new();
    let mut lone = init(&other, &clock, A, 1);
    let _ = &mut lone;
    other.register_chat_device(A, tpub(9));
    assert_eq!(
        block_on(Labyrinth::restore_with_recovery_code(
            A,
            &typed,
            Box::new(signer(9)),
            backends(&other, &clock, A),
        ))
        .err(),
        Some(Error::UnsupportedCodeVersion)
    );
}

#[test]
fn removing_a_method_deletes_its_share_first() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let setup = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let store = MemoryShares::new(A);
    phone.set_recovery_shares(Some(RecoveryShares::reader(store.boxed())));

    // A refused delete aborts the removal before anything else changes.
    store.fail_delete(true);
    let latest = phone.latest_epoch();
    assert!(block_on(phone.remove_recovery_method(&setup.vdevice_id)).is_err());
    assert_eq!(store.log(), vec![Op::Delete(setup.vdevice_id)]);
    assert_eq!(phone.latest_epoch(), latest);
    assert!(
        block_on(net.mailbox(A).get_virtual_device(&setup.vdevice_id))
            .unwrap()
            .is_some()
    );

    store.fail_delete(false);
    let report = block_on(phone.remove_recovery_method(&setup.vdevice_id)).unwrap();
    assert_eq!(report.new_epoch, latest + 1);
    assert_eq!(store.log().last(), Some(&Op::Delete(setup.vdevice_id)));
    assert!(
        block_on(net.mailbox(A).get_virtual_device(&setup.vdevice_id))
            .unwrap()
            .is_none()
    );
}

//! Client behaviour of the recovery-share reader: restore dispatches on the
//! code version, removing a method deletes its share first, and a client
//! without a share store behaves exactly as before.

#[path = "support/net.rs"]
mod net;
#[path = "support/shares.rs"]
mod shares;

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::Labyrinth;
use labyrinth::recovery_code::CodeVersion;
use labyrinth::recovery_share::RecoveryShares;
use labyrinth::store::MailboxStore;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::virtual_device::Mechanism;

use net::{A, TestClock, backends, init, signer, tpub};
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

//! Attachment references ([CB-33]), recovery-method lifecycle ([CB-39]),
//! the per-epoch publish path ([CB-28]) and fingerprints ([CB-41]).

#[path = "support/net.rs"]
mod net;

use std::sync::{Arc, Mutex};

use labyrinth::Error;
use labyrinth::client::{AUTO_RECOVERY_TTL_MS, Labyrinth};
use labyrinth::records::MailboxKeysRecord;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::{KeyPublisher, MailboxDirectory, MailboxStore};
use labyrinth::virtual_device::Mechanism;
use net::*;

fn send(lab: &mut Labyrinth, members: &[&str], id: &str, ts: u64) {
    let roster = lab.resolve_roster(members).unwrap();
    lab.archive_outgoing(T, &roster, id, ts, id.as_bytes())
        .unwrap();
    lab.flush().unwrap();
}

#[test]
fn attachment_references_follow_the_message_and_the_device() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    net.put_blob("blob-1", b"gcm ciphertext");
    net.put_blob("blob-2", b"other");
    // Before the message is archived the server refuses the reference.
    assert_eq!(
        alice.attach_reference(T, "m1", "blob-1").unwrap_err(),
        Error::Forbidden
    );
    send(&mut alice, &[A, B], "m1", 10);
    send(&mut alice, &[A, B], "m2", 20);
    alice.attach_reference(T, "m1", "blob-1").unwrap();
    alice.attach_reference(T, "m1", "blob-1").unwrap(); // idempotent
    bob.attach_reference(T, "m1", "blob-1").unwrap();
    // One message per attachment object.
    assert_eq!(
        alice.attach_reference(T, "m2", "blob-1").unwrap_err(),
        Error::Conflict
    );
    // The token binds the message: the right blob under another message
    // id does not open.
    assert_eq!(
        bob.fetch_attachment(T, "m2", "blob-1").unwrap_err(),
        Error::NotFound("attachment")
    );
    // A device restored later reaches it through the evolved ORF state.
    let setup = bob.create_recovery_code(Mechanism::Code).unwrap();
    net.register_chat_device(B, tpub(8));
    let (bob2, _) = Labyrinth::restore_with_recovery_code(
        B,
        setup.code.as_str(),
        Box::new(signer(8)),
        backends(&net, &clock, B),
    )
    .unwrap();
    assert_eq!(
        bob2.fetch_attachment(T, "m1", "blob-1").unwrap(),
        b"gcm ciphertext"
    );

    // Delete for me removes Bob's reference only.
    bob.delete_for_me(T, "m1", 10, Some(A), &["blob-1"])
        .unwrap();
    assert_eq!(
        bob2.fetch_attachment(T, "m1", "blob-1").unwrap_err(),
        Error::NotFound("attachment")
    );
    assert!(alice.fetch_attachment(T, "m1", "blob-1").is_ok());
    // Unsend revokes access for everyone.
    alice.unsend(T, "m1").unwrap();
    assert_eq!(
        alice.fetch_attachment(T, "m1", "blob-1").unwrap_err(),
        Error::NotFound("attachment")
    );
    // A revoked device's ORF state is gone.
    alice.attach_reference(T, "m2", "blob-2").unwrap();
    let mut alice2 = sibling(&net, &clock, &mut alice, 5);
    assert!(alice2.fetch_attachment(T, "m2", "blob-2").is_ok());
    alice
        .revoke_device(&alice2.device_public().device_key_pub)
        .unwrap();
    assert_eq!(
        alice2.fetch_attachment(T, "m2", "blob-2").unwrap_err(),
        Error::NotFound("orf state")
    );
    let _ = alice2.sync_epochs();
}

#[test]
fn recovery_methods_expire_are_touched_and_can_be_removed() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let keychain = phone.create_recovery_code(Mechanism::Keychain).unwrap();
    let code = phone.create_recovery_code(Mechanism::Code).unwrap();
    let methods = phone.list_recovery_methods().unwrap();
    assert_eq!(methods.len(), 2);
    let kc = methods
        .iter()
        .find(|m| m.vdevice_id == keychain.vdevice_id)
        .unwrap();
    assert_eq!(
        kc.expires_at_ms,
        Some(kc.created_at_ms + AUTO_RECOVERY_TTL_MS)
    );
    let cm = methods
        .iter()
        .find(|m| m.vdevice_id == code.vdevice_id)
        .unwrap();
    assert_eq!(cm.expires_at_ms, None);

    // A restore 100 days in touches the keychain bundle (server clock).
    clock.advance(100 * 86_400_000);
    net.set_server_time(1_791_000_000_000 + 100 * 86_400_000);
    net.register_chat_device(A, tpub(6));
    let (_tablet, _) = Labyrinth::restore_with_recovery_code(
        A,
        keychain.code.as_str(),
        Box::new(signer(6)),
        backends(&net, &clock, A),
    )
    .unwrap();
    let kc = phone
        .list_recovery_methods()
        .unwrap()
        .into_iter()
        .find(|m| m.vdevice_id == keychain.vdevice_id)
        .unwrap();
    assert_eq!(
        kc.last_used_at_ms,
        Some(1_791_000_000_000 + 100 * 86_400_000)
    );

    // 181 days after creation it has not expired (it was used at day 100);
    // 281 days after creation it has, and only it is removed.
    clock.advance(81 * 86_400_000);
    assert!(phone.remove_expired_recovery_methods().unwrap().is_empty());
    clock.advance(100 * 86_400_000);
    phone.sync_epochs().unwrap();
    assert_eq!(
        phone.remove_expired_recovery_methods().unwrap(),
        vec![keychain.vdevice_id]
    );
    let left: Vec<_> = phone
        .list_recovery_methods()
        .unwrap()
        .into_iter()
        .map(|m| m.vdevice_id)
        .collect();
    assert_eq!(left, vec![code.vdevice_id]);
    let restore = |c: &str| {
        Labyrinth::restore_with_recovery_code(A, c, Box::new(signer(6)), backends(&net, &clock, A))
            .map(|_| ())
    };
    assert_eq!(restore(keychain.code.as_str()), Err(Error::BadRecoveryCode));

    // Removing the user-held code rotates it out too.
    let before = phone.latest_epoch();
    let r = phone.remove_recovery_method(&code.vdevice_id).unwrap();
    assert_eq!(r.new_epoch, before + 1);
    let vd_key = net.mailbox(A).list_devices().unwrap();
    assert!(
        vd_key
            .iter()
            .filter(|d| d.r#virtual)
            .all(|d| d.revoked_at.is_some())
    );
    assert_eq!(restore(code.code.as_str()), Err(Error::BadRecoveryCode));
}

/// Records every epoch number it is asked to publish; fails while `fail`.
#[derive(Clone, Default)]
struct Recorder {
    seen: Arc<Mutex<Vec<u64>>>,
    fail: Arc<Mutex<bool>>,
}
impl KeyPublisher for Recorder {
    fn publish(&self, record: &MailboxKeysRecord) -> labyrinth::Result<()> {
        if *self.fail.lock().unwrap() {
            return Err(Error::Backend("PDS down".into()));
        }
        self.seen.lock().unwrap().push(record.current.epoch_number);
        Ok(())
    }
}

#[test]
fn every_epoch_is_published_to_every_publisher() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let rec = Recorder::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(
            &net,
            &clock,
            A,
            Box::new(net.mailbox(A)),
            vec![Box::new(rec.clone())],
        ),
    )
    .unwrap();
    let laptop = sibling(&net, &clock, &mut phone, 2);
    let tablet = sibling(&net, &clock, &mut phone, 3);
    phone
        .revoke_device(&laptop.device_public().device_key_pub)
        .unwrap();
    let vd = phone.create_recovery_code(Mechanism::Code).unwrap();
    phone.remove_recovery_method(&vd.vdevice_id).unwrap();
    assert_eq!(*rec.seen.lock().unwrap(), vec![0, 1, 2]);
    assert_eq!(net.directory().latest(A).unwrap().unwrap().seq, 2);

    // A failed publish surfaces as an error, and the retry catches up.
    *rec.fail.lock().unwrap() = true;
    assert!(
        phone
            .revoke_device(&tablet.device_public().device_key_pub)
            .is_err()
    );
    *rec.fail.lock().unwrap() = false;
    assert_eq!(phone.latest_epoch(), 3);
    phone.publish_latest_keys().unwrap();
    assert_eq!(*rec.seen.lock().unwrap(), vec![0, 1, 2, 3]);
}

#[test]
fn safety_numbers_match_on_both_sides_and_change_on_rotation() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let mut bob = init(&net, &clock, B, 2);
    assert!(matches!(
        alice.safety_number_with(B),
        Err(Error::NotFound(_))
    ));
    alice.resolve_roster(&[A, B]).unwrap();
    bob.resolve_roster(&[A, B]).unwrap();
    let n = alice.safety_number_with(B).unwrap();
    assert_eq!(n, bob.safety_number_with(A).unwrap());
    assert_eq!(n.replace(' ', "").len(), 60);
    let before = alice.own_fingerprint().unwrap();
    let laptop = sibling(&net, &clock, &mut alice, 3);
    alice
        .revoke_device(&laptop.device_public().device_key_pub)
        .unwrap();
    assert_ne!(alice.own_fingerprint().unwrap(), before);
}

#[test]
fn expired_un_gcd_recovery_bundles_fail_with_expired() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let keychain = phone.create_recovery_code(Mechanism::Keychain).unwrap();
    let prf = [0x42u8; 32];
    let cred = b"cred-exp-1";
    phone.create_passkey_recovery(&prf, cred).unwrap();

    // Advance client clock past 180-day TTL while leaving `net` server clock
    // un-advanced so the server still serves the un-GC'd bundles.
    clock.advance(AUTO_RECOVERY_TTL_MS + 1);
    net.register_chat_device(A, tpub(8));
    let err = Labyrinth::restore_with_recovery_code(
        A,
        keychain.code.as_str(),
        Box::new(signer(8)),
        backends(&net, &clock, A),
    )
    .unwrap_err();
    assert_eq!(err, Error::Expired);

    let err = Labyrinth::restore_with_passkey(
        A,
        &prf,
        cred,
        Box::new(signer(8)),
        backends(&net, &clock, A),
    )
    .unwrap_err();
    assert_eq!(err, Error::Expired);
}

#[test]
fn restore_with_passkey_skips_expired_bundle_in_favor_of_fresh_one() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let prf = [0x55u8; 32];
    let cred = b"cred-rotate-1";
    let old = phone.create_passkey_recovery(&prf, cred).unwrap();

    // Advance client clock past 180 days; `create_bundle` stamps
    // `b.clock.now_ms()`, so keeping `net` server time at 0 leaves the old
    // bundle un-GC'd on the server while its `created_at` is >180 days old.
    clock.advance(AUTO_RECOVERY_TTL_MS + 1_000);
    let fresh = phone.create_passkey_recovery(&prf, cred).unwrap();
    assert_ne!(old.vdevice_id, fresh.vdevice_id);
    assert_eq!(net.mailbox(A).list_virtual_devices().unwrap().len(), 2);

    net.register_chat_device(A, tpub(9));
    let (restored, _) = Labyrinth::restore_with_passkey(
        A,
        &prf,
        cred,
        Box::new(signer(9)),
        backends(&net, &clock, A),
    )
    .unwrap();
    assert_eq!(restored.latest_epoch(), phone.latest_epoch());
}

#[cfg(feature = "xrpc")]
#[test]
fn xrpc_get_virtual_device_does_not_refresh_last_used_at_and_memory_backend_filters_expired() {
    use labyrinth::store::xrpc::XrpcMailboxStore;
    use labyrinth::store::xrpc::server::MemoryXrpcServer;

    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let kc = phone.create_recovery_code(Mechanism::Keychain).unwrap();

    let server = MemoryXrpcServer::new(net.clone());
    let transport = server.transport(A, tpub(1));
    let xmb = XrpcMailboxStore::new(A, transport);

    net.set_server_time(1_791_000_000_000 + 50 * 86_400_000);
    let fetched = xmb
        .get_virtual_device(&kc.vdevice_id)
        .unwrap()
        .expect("present before expiry");
    assert_eq!(
        fetched.last_used_at, None,
        "GET getVirtualDevice must not mutate last_used_at"
    );

    // Explicit touchVirtualDevice DOES update last_used_at.
    xmb.touch_virtual_device(&kc.vdevice_id).unwrap();
    let touched = xmb.get_virtual_device(&kc.vdevice_id).unwrap().unwrap();
    assert!(touched.last_used_at.is_some());

    // Once server_now passes `last_used_at + AUTO_RECOVERY_TTL_MS`, MemoryBackend
    // filters the expired virtual device from get, list, and touch.
    net.set_server_time(1_791_000_000_000 + 50 * 86_400_000 + AUTO_RECOVERY_TTL_MS);
    assert!(
        net.mailbox(A)
            .get_virtual_device(&kc.vdevice_id)
            .unwrap()
            .is_none()
    );
    assert!(net.mailbox(A).list_virtual_devices().unwrap().is_empty());
    assert_eq!(
        net.mailbox(A)
            .touch_virtual_device(&kc.vdevice_id)
            .unwrap_err(),
        Error::NotFound("virtual device")
    );
}

#[test]
fn remove_recovery_method_refuses_confused_deputy_revocation_of_physical_or_self_device() {
    use labyrinth::records::Bytes;

    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let laptop = sibling(&net, &clock, &mut phone, 2);

    let prf = [0x77u8; 32];
    let passkey_setup = phone.create_passkey_recovery(&prf, b"cred-cd").unwrap();
    let code_setup = phone.create_recovery_code(Mechanism::Code).unwrap();
    let mb = net.mailbox(A);

    // 1. VirtualDevice::to_bundle must verify sig_0x30 on the embedded DevicePublic.
    let mut bad_sig_vd = mb
        .get_virtual_device(&passkey_setup.vdevice_id)
        .unwrap()
        .unwrap();
    bad_sig_vd.epoch_storage_key_sig = Bytes(vec![0u8; 64]);
    assert_eq!(bad_sig_vd.to_bundle().unwrap_err(), Error::BadSignature);

    // 2. Malicious store points a passkey VirtualDevice record at active physical sibling `laptop`.
    let laptop_pub = laptop.device_public();
    let mut spoof_sibling = mb
        .get_virtual_device(&passkey_setup.vdevice_id)
        .unwrap()
        .unwrap();
    spoof_sibling.device_key_pubkey = Bytes::from_slice(&laptop_pub.device_key_pub.0);
    spoof_sibling.epoch_storage_key_pubkey = Bytes::from_slice(&laptop_pub.epoch_storage_key_pub.0);
    spoof_sibling.epoch_storage_key_sig = Bytes::from_slice(&laptop_pub.sig_0x30);
    mb.delete_virtual_device(&passkey_setup.vdevice_id).unwrap();
    mb.create_virtual_device(&spoof_sibling).unwrap();

    let epoch_before = phone.latest_epoch();
    assert_eq!(
        phone
            .remove_recovery_method(&passkey_setup.vdevice_id)
            .unwrap_err(),
        Error::DeviceTampered
    );
    assert_eq!(phone.latest_epoch(), epoch_before);
    assert!(
        mb.get_device(&laptop_pub.device_key_pub)
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );

    // 3. Malicious store points a recovery-code VirtualDevice record at `phone` itself.
    let self_pub = phone.device_public();
    let mut spoof_self = mb
        .get_virtual_device(&code_setup.vdevice_id)
        .unwrap()
        .unwrap();
    spoof_self.device_key_pubkey = Bytes::from_slice(&self_pub.device_key_pub.0);
    spoof_self.epoch_storage_key_pubkey = Bytes::from_slice(&self_pub.epoch_storage_key_pub.0);
    spoof_self.epoch_storage_key_sig = Bytes::from_slice(&self_pub.sig_0x30);
    mb.delete_virtual_device(&code_setup.vdevice_id).unwrap();
    mb.create_virtual_device(&spoof_self).unwrap();

    assert_eq!(
        phone
            .remove_recovery_method(&code_setup.vdevice_id)
            .unwrap_err(),
        Error::DeviceTampered
    );
    assert_eq!(phone.latest_epoch(), epoch_before);
}

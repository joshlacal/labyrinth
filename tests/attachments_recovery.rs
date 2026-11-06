//! Space attachment manifests (`Gate 5`), recovery-method lifecycle ([CB-39]),
//! the per-epoch publish path ([CB-28]) and fingerprints ([CB-41]).

#[path = "support/net.rs"]
mod net;

use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::attachment::{AttachmentCiphertextMeta, verify_attachment_ciphertext};
use labyrinth::client::{AUTO_RECOVERY_TTL_MS, Labyrinth};
use labyrinth::records::MailboxKeysRecord;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef};
use labyrinth::store::{KeyPublisher, MailboxDirectory, MailboxStore, ThreadStore};
use labyrinth::virtual_device::Mechanism;
use net::*;

#[test]
fn space_attachment_manifests_verify_integrity_and_rearchive_before_leave() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut alice = init(&net, &clock, A, 1);
    let _bob = init(&net, &clock, B, 2);

    let roster = block_on(alice.resolve_roster(&[A, B])).unwrap();
    block_on(alice.archive_outgoing(T, &roster, "m1", 10, b"photo caption")).unwrap();
    block_on(alice.flush()).unwrap();

    let ciphertext = b"aes256-gcm-sealed-attachment-bytes";
    let meta =
        AttachmentCiphertextMeta::from_ciphertext(ciphertext, Some("image/png".into())).unwrap();
    let alice_threads = net.threads(A);
    let rkey = block_on(alice_threads.upload_and_commit_attachment(
        T,
        ciphertext,
        &meta,
        "2026-10-31T00:00:00.000Z",
    ))
    .unwrap();
    assert!(!rkey.is_empty());

    let bob_threads = net.threads(B);
    let fetched = block_on(bob_threads.get_attachment_verified(T, A, &rkey)).unwrap();
    verify_attachment_ciphertext(&fetched, &meta).unwrap();
    assert_eq!(fetched, ciphertext);

    // Re-archive before leave copies Alice's message history and verified attachments
    // into Alice's personal mailbox Space and clears Alice's conversation Space repo.
    let report = block_on(alice.rearchive_and_clear_before_leave(T)).unwrap();
    assert_eq!(report.messages_archived, 1);
    assert_eq!(report.attachments_archived, 1);
    let owner_copy = block_on(net.mailbox(A).get_owner_attachment_verified(&rkey)).unwrap();
    verify_attachment_ciphertext(&owner_copy, &meta).unwrap();
    assert_eq!(owner_copy, ciphertext);
}

#[test]
fn recovery_methods_become_stale_are_touched_and_require_explicit_rotation() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let keychain = block_on(phone.create_recovery_code(Mechanism::Keychain)).unwrap();
    let code = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let methods = block_on(phone.list_recovery_methods()).unwrap();
    assert_eq!(methods.len(), 2);
    let kc = methods
        .iter()
        .find(|m| m.vdevice_id == keychain.vdevice_id)
        .unwrap();
    assert_eq!(
        kc.stale_at_ms,
        Some(kc.created_at_ms + AUTO_RECOVERY_TTL_MS)
    );
    let cm = methods
        .iter()
        .find(|m| m.vdevice_id == code.vdevice_id)
        .unwrap();
    assert_eq!(cm.stale_at_ms, None);

    // A restore 100 days in touches the keychain bundle (server clock).
    clock.advance(100 * 86_400_000);
    net.set_server_time(1_791_000_000_000 + 100 * 86_400_000);
    net.register_chat_device(A, tpub(6));
    let (_tablet, _) = block_on(Labyrinth::restore_with_recovery_code(
        A,
        keychain.code.as_str(),
        Box::new(signer(6)),
        backends(&net, &clock, A),
    ))
    .unwrap();
    let kc = block_on(phone.list_recovery_methods())
        .unwrap()
        .into_iter()
        .find(|m| m.vdevice_id == keychain.vdevice_id)
        .unwrap();
    assert_eq!(
        kc.last_used_at_ms,
        Some(1_791_000_000_000 + 100 * 86_400_000)
    );

    // At day 181 it is still fresh because the day-100 restore touched it.
    // At day 281 it is stale but remains usable until an explicit rotation.
    clock.advance(81 * 86_400_000);
    let kc = block_on(phone.list_recovery_methods())
        .unwrap()
        .into_iter()
        .find(|m| m.vdevice_id == keychain.vdevice_id)
        .unwrap();
    assert!(!kc.stale_at(1_791_000_000_000 + 181 * 86_400_000));
    clock.advance(100 * 86_400_000);
    block_on(phone.sync_epochs()).unwrap();
    let kc = block_on(phone.list_recovery_methods())
        .unwrap()
        .into_iter()
        .find(|m| m.vdevice_id == keychain.vdevice_id)
        .unwrap();
    assert!(kc.stale_at(1_791_000_000_000 + 281 * 86_400_000));
    let before = phone.latest_epoch();
    let report = block_on(phone.remove_recovery_method(&keychain.vdevice_id)).unwrap();
    assert_eq!(report.new_epoch, before + 1);
    let left: Vec<_> = block_on(phone.list_recovery_methods())
        .unwrap()
        .into_iter()
        .map(|m| m.vdevice_id)
        .collect();
    assert_eq!(left, vec![code.vdevice_id]);
    let restore = |c: &str| {
        block_on(Labyrinth::restore_with_recovery_code(
            A,
            c,
            Box::new(signer(6)),
            backends(&net, &clock, A),
        ))
        .map(|_| ())
    };
    assert_eq!(restore(keychain.code.as_str()), Err(Error::BadRecoveryCode));

    // Removing the user-held code rotates it out too.
    let before = phone.latest_epoch();
    let r = block_on(phone.remove_recovery_method(&code.vdevice_id)).unwrap();
    assert_eq!(r.new_epoch, before + 1);
    let vd_key = block_on(net.mailbox(A).list_devices()).unwrap();
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

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl KeyPublisher for Recorder {
    async fn publish(&self, record: &MailboxKeysRecord) -> labyrinth::Result<()> {
        if *self.fail.lock().unwrap() {
            return Err(Error::Backend("PDS down".into()));
        }
        self.seen.lock().unwrap().push(record.current.epoch_number);
        Ok(())
    }
}

#[test]
fn every_epoch_is_published_by_its_attesting_device() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let rec = Recorder::default();
    net.register_chat_device(A, tpub(1));
    let mut phone = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        backends_with(
            &net,
            &clock,
            A,
            Box::new(net.mailbox(A)),
            vec![Box::new(rec.clone())],
        ),
    ))
    .unwrap();
    //Enroll siblings with the same secondary publisher so every Gate 3 rotation publishes too.
    let enroll_sibling_with_rec = |existing: &mut Labyrinth, seed: u8| {
        let mut r = existing.otc_offer().unwrap();
        let typed = r.code().as_str().to_owned();
        let (init_otc, hello) = Labyrinth::otc_start(A, &typed).unwrap();
        let reply = block_on(existing.otc_respond(&mut r, &hello)).unwrap();
        net.register_chat_device(A, tpub(seed));
        let b = backends_with(
            &net,
            &clock,
            A,
            Box::new(net.mailbox(A)),
            vec![Box::new(rec.clone())],
        );
        block_on(Labyrinth::enroll_via_otc(
            A,
            init_otc,
            &reply.message,
            &reply.sealed_payload,
            Box::new(signer(seed)),
            b,
        ))
        .unwrap()
        .0
    };
    let mut laptop = enroll_sibling_with_rec(&mut phone, 2);
    let laptop_replay_start = rec.seen.lock().unwrap().len();
    block_on(laptop.publish_latest_keys()).unwrap();
    assert_eq!(
        &rec.seen.lock().unwrap()[laptop_replay_start..],
        &[1],
        "a sibling must not republish an epoch attested by another device"
    );
    let tablet = enroll_sibling_with_rec(&mut phone, 3);
    block_on(phone.revoke_device(&laptop.device_public().device_key_pub)).unwrap();
    let vd = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    block_on(phone.remove_recovery_method(&vd.vdevice_id)).unwrap();
    let seen_before_failure = rec.seen.lock().unwrap().clone();
    for epoch in 0..=4 {
        assert!(
            seen_before_failure.contains(&epoch),
            "epoch {epoch} was never published"
        );
    }
    assert_eq!(seen_before_failure.last(), Some(&4));
    assert_eq!(block_on(net.directory().latest(A)).unwrap().unwrap().seq, 4);

    // A failed publish surfaces as an error, and the retry catches up.
    *rec.fail.lock().unwrap() = true;
    assert!(block_on(phone.revoke_device(&tablet.device_public().device_key_pub)).is_err());
    *rec.fail.lock().unwrap() = false;
    assert_eq!(phone.latest_epoch(), 5);
    let replay_start = rec.seen.lock().unwrap().len();
    block_on(phone.publish_latest_keys()).unwrap();
    assert_eq!(
        &rec.seen.lock().unwrap()[replay_start..],
        &[0, 3, 4, 5],
        "a retry must skip intermediate epochs attested by sibling devices"
    );
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
    block_on(alice.resolve_roster(&[A, B])).unwrap();
    block_on(bob.resolve_roster(&[A, B])).unwrap();
    let n = alice.safety_number_with(B).unwrap();
    assert_eq!(n, bob.safety_number_with(A).unwrap());
    assert_eq!(n.replace(' ', "").len(), 60);
    let before = alice.own_fingerprint().unwrap();
    let laptop = sibling(&net, &clock, &mut alice, 3);
    block_on(alice.revoke_device(&laptop.device_public().device_key_pub)).unwrap();
    assert_ne!(alice.own_fingerprint().unwrap(), before);
}

#[test]
fn stale_local_clock_warns_but_rotation_removes_recovery_authority() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let keychain = block_on(phone.create_recovery_code(Mechanism::Keychain)).unwrap();

    // The restoring device's clock is 181 days ahead while the authoritative
    // store still serves an active bundle.
    clock.advance(AUTO_RECOVERY_TTL_MS + 86_400_000);
    net.register_chat_device(A, tpub(8));
    let (_restored, enrollment) = block_on(Labyrinth::restore_with_recovery_code(
        A,
        keychain.code.as_str(),
        Box::new(signer(8)),
        backends(&net, &clock, A),
    ))
    .unwrap();
    assert!(enrollment.stale_recovery_method);

    // Keeping the bundle document is insufficient after its virtual device is
    // authoritatively rotated out.
    block_on(phone.sync_epochs()).unwrap();
    let method = block_on(phone.list_recovery_methods())
        .unwrap()
        .into_iter()
        .find(|method| method.vdevice_id == keychain.vdevice_id)
        .unwrap();
    block_on(phone.revoke_device(&method.device_key)).unwrap();
    net.register_chat_device(A, tpub(9));
    let error = block_on(Labyrinth::restore_with_recovery_code(
        A,
        keychain.code.as_str(),
        Box::new(signer(9)),
        backends(&net, &clock, A),
    ))
    .unwrap_err();
    assert_eq!(error, Error::NotEpochMember);
}

#[test]
fn stale_passkey_bundle_restores_with_warning() {
    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let prf = [0x55u8; 32];
    let credential = b"cred-stale-1";
    block_on(phone.create_passkey_recovery(&prf, credential)).unwrap();

    clock.advance(AUTO_RECOVERY_TTL_MS + 1);
    net.register_chat_device(A, tpub(9));
    let (_restored, enrollment) = block_on(Labyrinth::restore_with_passkey(
        A,
        &prf,
        credential,
        Box::new(signer(9)),
        backends(&net, &clock, A),
    ))
    .unwrap();
    assert!(enrollment.stale_recovery_method);
}

#[test]
fn virtual_device_reads_do_not_touch_and_stale_records_remain_until_rotation() {
    let space_host = MemorySpaceHost::new();
    let space_client = space_host.client(A);
    let smb = SpaceMailboxStore::new(space_client, SpaceRef::mailbox(A), A);

    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let kc = block_on(phone.create_recovery_code(Mechanism::Keychain)).unwrap();
    let vd = block_on(net.mailbox(A).get_virtual_device(&kc.vdevice_id))
        .unwrap()
        .unwrap();
    block_on(smb.create_virtual_device(&vd)).unwrap();

    let fetched = block_on(smb.get_virtual_device(&kc.vdevice_id))
        .unwrap()
        .expect("present before expiry");
    assert_eq!(
        fetched.last_used_at, None,
        "GET getVirtualDevice must not mutate last_used_at"
    );

    // Explicit touch_virtual_device DOES update last_used_at.
    block_on(smb.touch_virtual_device(&kc.vdevice_id)).unwrap();
    let touched = block_on(smb.get_virtual_device(&kc.vdevice_id))
        .unwrap()
        .unwrap();
    assert!(touched.last_used_at.is_some());

    // Advancing server time past the advisory staleness threshold does not
    // remove authority or hide the bundle; only a rotation can do that.
    net.set_server_time(1_791_000_000_000 + 50 * 86_400_000);
    block_on(net.mailbox(A).touch_virtual_device(&kc.vdevice_id)).unwrap();
    net.set_server_time(1_791_000_000_000 + 50 * 86_400_000 + AUTO_RECOVERY_TTL_MS);
    assert!(
        block_on(net.mailbox(A).get_virtual_device(&kc.vdevice_id))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        block_on(net.mailbox(A).list_virtual_devices())
            .unwrap()
            .len(),
        1
    );
    block_on(net.mailbox(A).touch_virtual_device(&kc.vdevice_id)).unwrap();
}

#[test]
fn remove_recovery_method_refuses_confused_deputy_revocation_of_physical_or_self_device() {
    use labyrinth::records::Bytes;

    let net = MemoryBackend::new();
    let clock = TestClock::default();
    let mut phone = init(&net, &clock, A, 1);
    let laptop = sibling(&net, &clock, &mut phone, 2);
    block_on(phone.sync_epochs()).unwrap();

    let prf = [0x77u8; 32];
    let passkey_setup = block_on(phone.create_passkey_recovery(&prf, b"cred-cd")).unwrap();
    let code_setup = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let mb = net.mailbox(A);

    // 1. VirtualDevice::to_bundle must verify sig_storage on the embedded DevicePublic.
    let mut bad_sig_vd = block_on(mb.get_virtual_device(&passkey_setup.vdevice_id))
        .unwrap()
        .unwrap();
    bad_sig_vd.epoch_storage_key_sig = Bytes(vec![0u8; 64]);
    assert_eq!(bad_sig_vd.to_bundle().unwrap_err(), Error::BadSignature);

    // 2. Malicious store points a passkey VirtualDevice record at active physical sibling `laptop`.
    // Gate 2 domain separation (`0x30` physical vs `0x34` virtual) rejects the physical
    // signature immediately with `Error::BadSignature`.
    let laptop_pub = laptop.device_public();
    let mut spoof_sibling = block_on(mb.get_virtual_device(&passkey_setup.vdevice_id))
        .unwrap()
        .unwrap();
    spoof_sibling.device_key_pubkey = Bytes::from_slice(&laptop_pub.device_key_pub.0);
    spoof_sibling.epoch_storage_key_pubkey =
        Bytes::from_slice(&laptop_pub.epoch_storage_key_pub.to_bytes());
    spoof_sibling.epoch_storage_key_sig = Bytes::from_slice(&laptop_pub.sig_storage);
    block_on(mb.delete_virtual_device(&passkey_setup.vdevice_id)).unwrap();
    block_on(mb.create_virtual_device(&spoof_sibling)).unwrap();

    let epoch_before = phone.latest_epoch();
    assert_eq!(
        block_on(phone.remove_recovery_method(&passkey_setup.vdevice_id)).unwrap_err(),
        Error::BadSignature
    );
    assert_eq!(phone.latest_epoch(), epoch_before);
    assert!(
        block_on(mb.get_device(&laptop_pub.device_key_pub))
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    // Restore valid virtual device list before testing `DeviceTampered`.
    block_on(mb.delete_virtual_device(&passkey_setup.vdevice_id)).unwrap();

    // 3. Malicious store points a recovery-code VirtualDevice record at `phone` itself:
    // Gate 2 domain separation again rejects `phone`'s physical signature with `BadSignature`.
    let orig_code_vd = block_on(mb.get_virtual_device(&code_setup.vdevice_id))
        .unwrap()
        .unwrap();
    let self_pub = phone.device_public();
    let mut spoof_self = orig_code_vd.clone();
    spoof_self.device_key_pubkey = Bytes::from_slice(&self_pub.device_key_pub.0);
    spoof_self.epoch_storage_key_pubkey =
        Bytes::from_slice(&self_pub.epoch_storage_key_pub.to_bytes());
    spoof_self.epoch_storage_key_sig = Bytes::from_slice(&self_pub.sig_storage);
    block_on(mb.delete_virtual_device(&code_setup.vdevice_id)).unwrap();
    block_on(mb.create_virtual_device(&spoof_self)).unwrap();

    assert_eq!(
        block_on(phone.remove_recovery_method(&code_setup.vdevice_id)).unwrap_err(),
        Error::BadSignature
    );
    assert_eq!(phone.latest_epoch(), epoch_before);

    // 4. Even with a valid virtual-domain `VirtualDevice` bundle (`orig_code_vd`), if the
    // backing `Device` record is tampered to attach a `chat_binding` (making it look physical),
    // `remove_recovery_method` refuses revocation with `Error::DeviceTampered`.
    block_on(mb.delete_virtual_device(&code_setup.vdevice_id)).unwrap();
    block_on(mb.create_virtual_device(&orig_code_vd)).unwrap();
    let (vrec, _) = orig_code_vd.to_bundle().unwrap();
    let mut tampered_dev = block_on(mb.get_device(&vrec.public.device_key_pub))
        .unwrap()
        .unwrap();
    let laptop_dev = block_on(mb.get_device(&laptop_pub.device_key_pub))
        .unwrap()
        .unwrap();
    tampered_dev.chat_binding = laptop_dev.chat_binding;
    // Create a fresh virtual device bundle whose Device row has `chat_binding: Some(...)`:
    let rogue_vdevice = labyrinth::device::DeviceSecrets::generate_virtual().unwrap();
    let rogue_pub = rogue_vdevice.public();
    let mut rogue_dev = tampered_dev;
    rogue_dev.device_key_pubkey = Bytes::from_slice(&rogue_pub.device_key_pub.0);
    rogue_dev.epoch_storage_key_pubkey = Bytes(rogue_pub.epoch_storage_key_pub.to_bytes());
    rogue_dev.epoch_storage_key_sig = Bytes::from_slice(&rogue_pub.sig_storage);
    block_on(mb.create_device(&rogue_dev)).unwrap();
    let mut rogue_vd = orig_code_vd;
    rogue_vd.device_key_pubkey = Bytes::from_slice(&rogue_pub.device_key_pub.0);
    rogue_vd.epoch_storage_key_pubkey = Bytes(rogue_pub.epoch_storage_key_pub.to_bytes());
    rogue_vd.epoch_storage_key_sig = Bytes::from_slice(&rogue_pub.sig_storage);
    block_on(mb.delete_virtual_device(&code_setup.vdevice_id)).unwrap();
    block_on(mb.create_virtual_device(&rogue_vd)).unwrap();
    assert_eq!(
        block_on(phone.remove_recovery_method(&code_setup.vdevice_id)).unwrap_err(),
        Error::DeviceTampered
    );
    assert_eq!(phone.latest_epoch(), epoch_before);
}

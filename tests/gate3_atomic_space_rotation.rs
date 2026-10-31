//! Gate 3: Atomic Space epoch rotation + enrollment via single `space.applyWrites`
//! and `swapRecord` CAS on `mailboxKeys/self`, plus ascending `list_raw` epoch replay.

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, CompositeDirectory, Labyrinth, SystemClock};
use labyrinth::device::{ChatBinding, DeviceSecrets};
use labyrinth::epoch::open_next_enrolling;
use labyrinth::records::{
    Device, Epoch, EpochMember, MailboxKeysRecord, OtcSession, VirtualDevice, datetime_from_ms,
    nsid,
};
use labyrinth::sign::{Ed25519Transport, TransportSigner as _};
use labyrinth::store::pds::{PdsPublisher, PdsRecords};
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef, SpaceThreadStore};
use labyrinth::store::{
    AtomicEnrollBundle, EnrollCleanup, KeyPublisher as _, MailboxStore as _, MemoryBackend,
};
use labyrinth::virtual_device::Mechanism;

const DID: &str = "did:plc:alicegate3";

fn transport(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

fn build_backends(
    did: &str,
    net: &MemoryBackend,
    host: &MemorySpaceHost,
    mb_space: &SpaceRef,
) -> Backends {
    let mailbox = SpaceMailboxStore::new(host.client(did), mb_space.clone(), did.to_owned())
        .with_key_publisher(Box::new(net.pds_publisher(did)));
    let threads = SpaceThreadStore::new(host.client(did), did.to_owned());
    let directory =
        CompositeDirectory::new(Box::new(net.directory()), Box::new(net.ds_directory()));
    Backends {
        mailbox: Box::new(mailbox),
        threads: Box::new(threads),
        directory: Box::new(directory),
        publishers: vec![Box::new(net.ds_publisher(did))],
        clock: Box::new(SystemClock),
    }
}

#[test]
fn gate3_concurrent_e_to_e_plus_1_atomic_conflict_leaves_zero_orphans() {
    let net = MemoryBackend::new();
    let host = MemorySpaceHost::new();
    let mb_space = SpaceRef::parse(&format!(
        "at://{DID}/space/blue.catbird.labyrinth.mailbox/self"
    ))
    .unwrap();

    let t1 = transport(1);
    let t2 = transport(2);
    let t3 = transport(3);
    net.set_chat_devices(
        DID,
        vec![
            t1.transport_public_key(),
            t2.transport_public_key(),
            t3.transport_public_key(),
        ],
    );

    let mut d1 = block_on(Labyrinth::initialize(
        DID,
        Box::new(t1),
        build_backends(DID, &net, &host, &mb_space),
    ))
    .expect("init d1");
    assert_eq!(d1.latest_epoch(), 0);

    // Create a recovery bundle (`virtualDevice`) AND an OTC session (`otcSession`) at epoch 0.
    let setup = block_on(d1.create_recovery_code(Mechanism::Code)).expect("recovery code");
    let mb = SpaceMailboxStore::new(host.client(DID), mb_space.clone(), DID.to_owned());

    let otc_rkey = "otc-session-001".to_owned();
    let otc_session = OtcSession {
        type_: nsid::OTC_SESSION.to_owned(),
        session_id: otc_rkey.clone(),
        initiator_device_key_pubkey: labyrinth::records::Bytes::from_slice(&[0x11; 32]),
        ya: labyrinth::records::Bytes::from_slice(&[0x22; 32]),
        ek_otc: labyrinth::records::Bytes(vec![0x33; 1184]),
        yb: None,
        kem_ct: None,
        sealed_payload: None,
        expires_at: datetime_from_ms(1_900_000_000_000),
        created_at: datetime_from_ms(1_800_000_000_000),
    };
    block_on(mb.put_otc_session(&otc_session)).expect("put otcSession");

    // Read epoch 0 state so two enrolling devices simultaneously race `0 -> 1`.
    let e0_stored = block_on(mb.get_epoch(0)).unwrap().unwrap();
    let e0_rec = e0_stored.value.to_record().unwrap();
    let prev_members_raw = block_on(mb.list_epoch_members(0)).unwrap();
    let prev_members: Vec<_> = prev_members_raw
        .iter()
        .map(|m| m.to_record().unwrap())
        .collect();
    let continuing_devs: Vec<_> = block_on(mb.list_devices())
        .unwrap()
        .iter()
        .map(|d| d.to_public().unwrap())
        .collect();

    // Extract epoch 0 secret via OTC transfer to construct two independent racing `0 -> 1` bundles.
    let mut resp = d1.otc_offer().unwrap();
    let code_str = resp.code().format_grouped();
    let (init_a, msg_a) = Labyrinth::otc_start(DID, &code_str).unwrap();
    let otc_resp = block_on(d1.otc_respond(&mut resp, &msg_a)).unwrap();
    let sk_a = init_a.finish(&otc_resp.message).unwrap();
    let payload =
        labyrinth::virtual_device::OtcPayload::open(&sk_a, &otc_resp.sealed_payload).unwrap();
    let e0_secret = payload.epoch;

    let now = datetime_from_ms(1_800_000_005_000);

    // Enrolling device 2 prepares atomic bundle `0 -> 1` consuming `otcSession`.
    let dev2_secrets = DeviceSecrets::generate().unwrap();
    let bind2 = ChatBinding::sign(DID, &dev2_secrets.public().device_key_pub, &t2);
    let dev2_rec = Device::bound(dev2_secrets.public(), &bind2, now.clone());
    let (_, new_e1_a) = open_next_enrolling(
        DID,
        &e0_secret,
        &e0_rec.public,
        &prev_members,
        &continuing_devs,
        &dev2_secrets,
        &t2,
    )
    .unwrap();
    let bundle_a = AtomicEnrollBundle {
        cleanup: Some(EnrollCleanup::ConsumeOtcSession {
            rkey: otc_rkey.clone(),
        }),
        device: dev2_rec.clone(),
        epoch: Epoch::from_record(&new_e1_a.record, now.clone()),
        members: new_e1_a
            .members
            .iter()
            .map(|m| EpochMember::from_record(m, now.clone()))
            .collect(),
    };

    // Enrolling device 3 concurrently prepares conflicting atomic bundle `0 -> 1` touching `virtualDevice`.
    let mut vd_updated: VirtualDevice = block_on(mb.get_virtual_device(&setup.vdevice_id))
        .unwrap()
        .unwrap();
    vd_updated.last_used_at = Some(now.clone());
    let dev3_secrets = DeviceSecrets::generate().unwrap();
    let bind3 = ChatBinding::sign(DID, &dev3_secrets.public().device_key_pub, &t3);
    let dev3_rec = Device::bound(dev3_secrets.public(), &bind3, now.clone());
    let (_, new_e1_b) = open_next_enrolling(
        DID,
        &e0_secret,
        &e0_rec.public,
        &prev_members,
        &continuing_devs,
        &dev3_secrets,
        &t3,
    )
    .unwrap();
    let bundle_b = AtomicEnrollBundle {
        cleanup: Some(EnrollCleanup::TouchVirtualDevice {
            updated: vd_updated,
        }),
        device: dev3_rec.clone(),
        epoch: Epoch::from_record(&new_e1_b.record, now.clone()),
        members: new_e1_b
            .members
            .iter()
            .map(|m| EpochMember::from_record(m, now.clone()))
            .collect(),
    };

    let devices_before = host.record_count(&mb_space, DID, Some(nsid::DEVICE));

    // Winner (`bundle_a`) commits `0 -> 1` atomically and deletes `otcSession`.
    let rkey_1 = block_on(mb.atomic_enroll(&bundle_a)).expect("winner atomic_enroll");
    assert_eq!(rkey_1, "000000000001");
    assert!(block_on(mb.get_otc_session(&otc_rkey)).unwrap().is_none());
    assert_eq!(
        host.record_count(&mb_space, DID, Some(nsid::DEVICE)),
        devices_before + 1
    );

    // Loser (`bundle_b`) conflicts on `epoch/000000000001` and aborts ALL writes in `applyWrites`!
    let err = block_on(mb.atomic_enroll(&bundle_b)).expect_err("loser must conflict atomically");
    assert_eq!(err, Error::Conflict);

    // Zero orphaned `device` or `epochMember` records from `bundle_b`, and `virtualDevice.lastUsedAt` untouched!
    assert!(
        block_on(mb.get_device(&dev3_secrets.public().device_key_pub))
            .unwrap()
            .is_none(),
        "failed atomic_enroll must leave zero orphaned device records"
    );
    assert!(
        block_on(mb.get_epoch_member(1, &dev3_secrets.public().device_key_pub))
            .unwrap()
            .is_none(),
        "failed atomic_enroll must leave zero orphaned epochMember records"
    );
    let vd_after = block_on(mb.get_virtual_device(&setup.vdevice_id))
        .unwrap()
        .unwrap();
    assert!(
        vd_after.last_used_at.is_none(),
        "failed atomic_enroll must not mutate virtualDevice"
    );

    // Publish epoch 1 so d1 and recovery code restore see consistent directory state,
    // then prove full `restore_with_recovery_code` advances `1 -> 2` cleanly!
    let mk1 = MailboxKeysRecord::from_public(&new_e1_a.record.public, None, now);
    block_on(net.pds_publisher(DID).publish(&mk1)).unwrap();
    block_on(net.ds_publisher(DID).publish(&mk1)).unwrap();

    let (restored_d3, _) = block_on(Labyrinth::restore_with_recovery_code(
        DID,
        &setup.code.format_grouped(),
        Box::new(t3),
        build_backends(DID, &net, &host, &mb_space),
    ))
    .expect("restore advances 1 -> 2 atomically");
    assert_eq!(restored_d3.latest_epoch(), 2);

    // Verify `SpaceMailboxStore` small-page listing (`page = 1`) replays epochs in strictly
    // increasing order (`0, 1, 2`).
    let paged_mb =
        SpaceMailboxStore::new(host.client(DID), mb_space, DID.to_owned()).with_page_size(1);
    let epochs = block_on(paged_mb.list_epochs()).expect("paged list_epochs");
    let seqs: Vec<u64> = epochs.iter().map(|e| e.value.seq()).collect();
    assert_eq!(seqs, vec![0, 1, 2]);
}

#[test]
fn gate3_pds_mailbox_keys_swap_record_cas_rejects_stale_cid() {
    let mock_pds = labyrinth::store::pds::MemoryPublicRepoHost::new();
    let pds_client = mock_pds.client(DID);
    let t = transport(9);
    let dev = DeviceSecrets::generate().unwrap();
    let (p0, n0) = labyrinth::epoch::open_genesis(DID, &dev, &t).unwrap();
    let e0 = p0.assign_id("000000000000");
    let (_, n1) =
        labyrinth::epoch::open_next(DID, &e0, &n0.record.public, &n0.members, &[], &dev, &t)
            .unwrap();

    let publisher = PdsPublisher::new(pds_client.clone(), DID);
    let rec0 = MailboxKeysRecord::from_public(&n0.record.public, None, datetime_from_ms(1000));
    let rec1 = MailboxKeysRecord::from_public(&n1.record.public, None, datetime_from_ms(2000));

    block_on(publisher.publish(&rec0)).expect("publish e0");
    let (_, cid0) = block_on(PdsRecords::new(&pds_client).get_mailbox_keys_with_cid(DID))
        .unwrap()
        .unwrap();
    block_on(publisher.publish(&rec1)).expect("publish e1");

    // Attempting CAS write with stale `cid0` MUST fail with `Error::Conflict`.
    let cas_err = block_on(PdsRecords::new(&pds_client).put_mailbox_keys_cas(
        DID,
        "self",
        &rec0,
        Some(&cid0),
    ))
    .expect_err("stale swapRecord CID must conflict");
    assert_eq!(cas_err, Error::Conflict);
}

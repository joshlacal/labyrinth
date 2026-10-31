//! Gate 6 (`L-F01`): `CompositeDirectory` cross-checking PDS `mailboxKeys/self`
//! against `mls-ds` `EpochPublicHeader` chain + `floor_seq`.

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, CompositeDirectory, Labyrinth, SystemClock};
use labyrinth::device::DeviceSecrets;
use labyrinth::epoch::open_genesis;
use labyrinth::records::{MailboxKeysRecord, datetime_from_ms};
use labyrinth::sign::{Ed25519Transport, TransportSigner as _};
use labyrinth::store::{MailboxDirectory as _, MemoryBackend};

const ALICE_DID: &str = "did:plc:alicegate6";

fn transport(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

fn make_client(did: &str, seed: u8, net: &MemoryBackend) -> Labyrinth {
    let t = transport(seed);
    let mut keys = net
        .directory()
        .device_transport_keys_sync(did)
        .into_iter()
        .map(|k| k.key)
        .collect::<Vec<_>>();
    keys.push(t.transport_public_key());
    net.set_chat_devices(did, keys);

    let backends = Backends {
        mailbox: Box::new(net.mailbox(did)),
        threads: Box::new(net.threads(did)),
        directory: Box::new(CompositeDirectory::new(
            Box::new(net.directory()),
            Box::new(net.ds_directory()),
        )),
        publishers: vec![Box::new(net.ds_publisher(did))],
        clock: Box::new(SystemClock),
    };
    block_on(Labyrinth::initialize(did, Box::new(t), backends)).expect("init")
}

#[test]
fn gate6_composite_directory_verifies_epoch_public_chain_and_floor_seq() {
    let net = MemoryBackend::new();
    let t1 = transport(1);
    let t2 = transport(2);
    let t3 = transport(3);
    let t4 = transport(4);
    net.set_chat_devices(
        ALICE_DID,
        vec![
            t1.transport_public_key(),
            t2.transport_public_key(),
            t3.transport_public_key(),
            t4.transport_public_key(),
        ],
    );

    let mut d1 = make_client(ALICE_DID, 1, &net);

    // Advance Alice through epochs 0 -> 1 -> 2 -> 3 via OTC enrollments + revocations.
    for t_seed in [2u8, 3u8, 4u8] {
        let mut resp = d1.otc_offer().unwrap();
        let code = resp.code().format_grouped();
        let (init, msg) = Labyrinth::otc_start(ALICE_DID, &code).unwrap();
        let otc_resp = block_on(d1.otc_respond(&mut resp, &msg)).unwrap();
        let t_new = transport(t_seed);
        let backends = Backends {
            mailbox: Box::new(net.mailbox(ALICE_DID)),
            threads: Box::new(net.threads(ALICE_DID)),
            directory: Box::new(CompositeDirectory::new(
                Box::new(net.directory()),
                Box::new(net.ds_directory()),
            )),
            publishers: vec![Box::new(net.ds_publisher(ALICE_DID))],
            clock: Box::new(SystemClock),
        };
        let (enrolled, info) = block_on(Labyrinth::enroll_via_otc(
            ALICE_DID,
            init,
            &otc_resp.message,
            &otc_resp.sealed_payload,
            Box::new(t_new),
            backends,
        ))
        .unwrap();
        drop(enrolled);
        block_on(d1.sync_epochs()).unwrap();
        if t_seed == 4 {
            block_on(d1.revoke_device(&info.device_key)).unwrap();
        }
    }
    assert!(d1.latest_epoch() >= 3);
    let latest_seq = d1.latest_epoch();

    // Simulate `L-F01` pruning on `mls-ds`: prune epochs `< 2` so `floor_seq = 2`.
    net.prune_ds_heads_below(ALICE_DID, 2);

    let comp = CompositeDirectory::new(Box::new(net.directory()), Box::new(net.ds_directory()));
    let verified = block_on(comp.latest(ALICE_DID))
        .expect("valid pruned chain passes Gate 6")
        .expect("enrolled");
    assert_eq!(verified.seq, latest_seq);

    // Split-view fork attack: malicious PDS substitutes a forged genesis / forked record at latest_seq.
    let rogue_dev = DeviceSecrets::generate().unwrap();
    let (_, rogue_gen) = open_genesis(ALICE_DID, &rogue_dev, &t1).unwrap();
    let mut forged = rogue_gen.record.public.clone();
    forged.seq = latest_seq;
    net.tamper_pds_latest(
        ALICE_DID,
        MailboxKeysRecord::from_public(&forged, None, datetime_from_ms(9_000_000)),
    );
    let fork_err = block_on(comp.latest(ALICE_DID)).expect_err("forked PDS head must fail");
    assert!(
        matches!(
            fork_err,
            Error::DirectoryFork { .. } | Error::BadSignature | Error::Malformed(_)
        ),
        "unexpected error: {fork_err:?}"
    );

    // Restore genuine PDS latest, then simulate malicious `mls-ds` serving `floor_seq` > `latest.seq` (`L-F01` violation).
    let real_latest = d1.latest_public().unwrap();
    net.tamper_pds_latest(
        ALICE_DID,
        MailboxKeysRecord::from_public(&real_latest, None, datetime_from_ms(9_000_001)),
    );
    net.set_ds_floor_seq_override_for_test(ALICE_DID, latest_seq + 5);
    let rollback_err =
        block_on(comp.latest(ALICE_DID)).expect_err("latest_seq < floor_seq must fail Gate 6");
    assert!(
        matches!(rollback_err, Error::EpochRollback { .. }),
        "expected EpochRollback on floor_seq violation, got {rollback_err:?}"
    );
}

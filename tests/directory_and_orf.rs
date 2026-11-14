//! The PDS × mls-ds directory cross-check ([CB-28], [CB-29], Gate 6), head
//! publishing to both directories, and hybrid PQ `otcSession` mailbox Space
//! enrollment (`Gate 3`, `2A` ORF retired).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth};
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::records::MailboxKeysRecord;
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::{MemoryBackend, MemoryDirectory};
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef};
use labyrinth::store::{ChatDeviceKey, KeyPublisher, MailboxDirectory, MailboxStore};
use labyrinth::virtual_device::Mechanism;

const A: &str = "did:plc:alice";
const B: &str = "did:plc:bob";

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        1_791_000_000_000 + self.0.fetch_add(1, Ordering::Relaxed)
    }
}

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}
fn tpub(seed: u8) -> [u8; 32] {
    signer(seed).0.verifying_key().to_bytes()
}

/// A Space mailbox (publishing `mailboxKeys` to the PDS) that also
/// publishes every head to the mls-ds directory.
fn backends(
    net: &MemoryBackend,
    did: &str,
    mailbox: Box<dyn MailboxStore>,
    directory: Box<dyn MailboxDirectory>,
) -> Backends {
    Backends {
        mailbox,
        threads: Box::new(net.threads(did)),
        directory,
        publishers: vec![Box::new(net.ds_publisher(did))],
        clock: Box::new(TestClock::default()),
    }
}

fn composite(net: &MemoryBackend) -> Box<CompositeDirectory> {
    Box::new(CompositeDirectory::new(
        Box::new(net.directory()),
        Box::new(net.ds_directory()),
    ))
}

fn init(net: &MemoryBackend, did: &str, seed: u8) -> Labyrinth {
    net.register_chat_device(did, tpub(seed));
    let b = backends(net, did, Box::new(net.mailbox(did)), composite(net));
    block_on(Labyrinth::initialize(did, Box::new(signer(seed)), b)).unwrap()
}

fn enroll_otc(net: &MemoryBackend, existing: &mut Labyrinth, seed: u8) -> Labyrinth {
    let did = existing.did().to_owned();
    let mut r = existing.otc_offer().unwrap();
    let typed = r.code().as_str().to_owned();
    let (init, hello) = Labyrinth::otc_start(&did, &typed).unwrap();
    let reply = block_on(existing.otc_respond(&mut r, &hello)).unwrap();
    net.register_chat_device(&did, tpub(seed));
    let b = backends(net, &did, Box::new(net.mailbox(&did)), composite(net));
    block_on(Labyrinth::enroll_via_otc(
        &did,
        init,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(seed)),
        b,
    ))
    .unwrap()
    .0
}

#[test]
fn composite_directory_detects_truncation_by_the_mailbox_host() {
    let space_host = MemorySpaceHost::new();
    let pds_net = MemoryBackend::new();
    let ds_net = MemoryBackend::new();
    let space = SpaceRef::mailbox(A);

    let reg = |seed: u8| {
        pds_net.register_chat_device(A, tpub(seed));
        ds_net.register_chat_device(A, tpub(seed));
    };
    let make_backends = |with_ds_cross_check: bool| -> Backends {
        let mb = SpaceMailboxStore::for_owner(
            A,
            space_host.client(A),
            Box::new(pds_net.pds_publisher(A)),
        );
        let dir: Box<dyn MailboxDirectory> = if with_ds_cross_check {
            Box::new(CompositeDirectory::new(
                Box::new(pds_net.directory()),
                Box::new(ds_net.ds_directory()),
            ))
        } else {
            Box::new(pds_net.directory())
        };
        let publishers: Vec<Box<dyn KeyPublisher>> = if with_ds_cross_check {
            vec![Box::new(ds_net.ds_publisher(A))]
        } else {
            vec![]
        };
        Backends {
            mailbox: Box::new(mb),
            threads: Box::new(pds_net.threads(A)),
            directory: dir,
            publishers,
            clock: Box::new(TestClock::default()),
        }
    };

    reg(1);
    let mut phone = block_on(Labyrinth::initialize(
        A,
        Box::new(signer(1)),
        make_backends(true),
    ))
    .unwrap();
    let e0_pub = phone.latest_public().unwrap();
    let setup = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let code = setup.code.as_str().to_owned();
    let e0_vdev_rkey = hex::encode(setup.vdevice_id);
    let e0_vdev = space_host
        .record(
            &space,
            A,
            labyrinth::records::nsid::VIRTUAL_DEVICE,
            &e0_vdev_rkey,
        )
        .unwrap();
    let e0_vdev_pub = serde_json::from_value::<labyrinth::records::VirtualDevice>(e0_vdev.clone())
        .unwrap()
        .to_bundle_for_did(A)
        .unwrap()
        .0
        .public
        .device_key_pub;
    let e0_vdev_device_rkey = hex::encode(e0_vdev_pub.0);
    let e0_vdev_device = space_host
        .record(
            &space,
            A,
            labyrinth::records::nsid::DEVICE,
            &e0_vdev_device_rkey,
        )
        .unwrap();

    // Enroll laptop (opens epoch 1) and revoke phone (opens epoch 2).
    let mut r = phone.otc_offer().unwrap();
    let typed = r.code().as_str().to_owned();
    let (init_otc, hello) = Labyrinth::otc_start(A, &typed).unwrap();
    let reply = block_on(phone.otc_respond(&mut r, &hello)).unwrap();
    reg(2);
    let (mut laptop, _) = block_on(Labyrinth::enroll_via_otc(
        A,
        init_otc,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(2)),
        make_backends(true),
    ))
    .unwrap();
    block_on(laptop.revoke_device(&phone.device_public().device_key_pub)).unwrap();

    // Epoch 2 reached both directories.
    assert_eq!(
        block_on(pds_net.directory().latest(A))
            .unwrap()
            .unwrap()
            .seq,
        2
    );
    assert_eq!(
        block_on(ds_net.ds_directory().latest(A))
            .unwrap()
            .unwrap()
            .seq,
        2
    );

    // Malicious PDS rolls back the mailbox Space and its `mailboxKeys` view to epoch 0,
    // hiding epochs 1 and 2 (and restoring the epoch-0 virtual device snapshot) while
    // `mls-ds` retains epoch 2.
    for rkey in ["000000000001", "000000000002"] {
        let _ = space_host.remove(&space, A, labyrinth::records::nsid::EPOCH, rkey);
    }
    space_host.tamper(
        &space,
        A,
        labyrinth::records::nsid::VIRTUAL_DEVICE,
        &e0_vdev_rkey,
        e0_vdev,
    );
    space_host.tamper(
        &space,
        A,
        labyrinth::records::nsid::DEVICE,
        &e0_vdev_device_rkey,
        e0_vdev_device,
    );
    // Build a truncated PDS directory view serving only `e0_pub`.
    let truncated_pds = || FixedForDid {
        did: A,
        fixed: FixedPds::all(vec![e0_pub.clone()]),
        fallback: pds_net.directory(),
    };

    // With `CompositeDirectory` cross-checking `mls-ds`, the truncation is caught immediately!
    reg(6);
    let mut b_checked = make_backends(true);
    b_checked.directory = Box::new(CompositeDirectory::new(
        Box::new(truncated_pds()),
        Box::new(ds_net.ds_directory()),
    ));
    let err = match block_on(Labyrinth::restore_with_recovery_code(
        A,
        &code,
        Box::new(signer(6)),
        b_checked,
    )) {
        Ok(_) => panic!("expected truncation to be caught by CompositeDirectory"),
        Err(e) => e,
    };
    assert_eq!(
        err,
        Error::DirectoryIncomplete {
            pds_present: false,
            ds_present: true,
        }
    );
}

/// Serves fixed epochs as the PDS view.
struct FixedPds {
    latest: Option<EpochPublic>,
    epochs: Vec<EpochPublic>,
}
impl FixedPds {
    fn all(epochs: Vec<EpochPublic>) -> Self {
        Self {
            latest: epochs.last().cloned(),
            epochs,
        }
    }
}

/// Serves a fixed view only for one DID and delegates every other account.
/// This keeps adversarial peer-directory fixtures from corrupting the
/// reviewing client's own epoch-integrity check.
struct FixedForDid {
    did: &'static str,
    fixed: FixedPds,
    fallback: MemoryDirectory,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for FixedForDid {
    async fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        if did == self.did {
            self.fixed.latest(did).await
        } else {
            self.fallback.latest(did).await
        }
    }

    async fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        if did == self.did {
            self.fixed.epoch(did, seq).await
        } else {
            self.fallback.epoch(did, seq).await
        }
    }

    async fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        self.fallback.device_transport_keys(did).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl MailboxDirectory for FixedPds {
    async fn latest(&self, _: &str) -> labyrinth::Result<Option<EpochPublic>> {
        Ok(self.latest.clone())
    }
    async fn epoch(&self, _: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        Ok(self.epochs.iter().find(|e| e.seq == seq).cloned())
    }
    async fn device_transport_keys(&self, _: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        Ok(vec![])
    }
}

#[test]
fn composite_directory_rejects_one_sided_latest_and_epoch() {
    let net = MemoryBackend::new();
    let alice = init(&net, A, 1);
    let e0 = alice.latest_public().unwrap();

    let pds_only = CompositeDirectory::new(
        Box::new(FixedPds::all(vec![e0.clone()])),
        Box::new(FixedPds::all(vec![])),
    );
    let missing_ds = Error::DirectoryIncomplete {
        pds_present: true,
        ds_present: false,
    };
    assert_eq!(block_on(pds_only.latest(A)), Err(missing_ds.clone()));
    assert_eq!(block_on(pds_only.epoch(A, 0)), Err(missing_ds));

    let ds_only = CompositeDirectory::new(
        Box::new(FixedPds::all(vec![])),
        Box::new(FixedPds::all(vec![e0.clone()])),
    );
    let missing_pds = Error::DirectoryIncomplete {
        pds_present: false,
        ds_present: true,
    };
    assert_eq!(block_on(ds_only.latest(A)), Err(missing_pds.clone()));
    assert_eq!(block_on(ds_only.epoch(A, 0)), Err(missing_pds));

    let neither = CompositeDirectory::new(
        Box::new(FixedPds::all(vec![])),
        Box::new(FixedPds::all(vec![])),
    );
    assert_eq!(block_on(neither.latest(A)), Ok(None));
    assert_eq!(block_on(neither.epoch(A, 0)), Ok(None));

    let pds_tofu = CompositeDirectory::new_allowing_single_source(
        Box::new(FixedPds::all(vec![e0.clone()])),
        Box::new(FixedPds::all(vec![])),
    );
    assert_eq!(block_on(pds_tofu.latest(A)), Ok(Some(e0.clone())));
    assert_eq!(block_on(pds_tofu.epoch(A, 0)), Ok(Some(e0.clone())));
    let ds_tofu = CompositeDirectory::new_allowing_single_source(
        Box::new(FixedPds::all(vec![])),
        Box::new(FixedPds::all(vec![e0.clone()])),
    );
    assert_eq!(block_on(ds_tofu.latest(A)), Ok(Some(e0.clone())));
    assert_eq!(block_on(ds_tofu.epoch(A, 0)), Ok(Some(e0)));
}

#[test]
fn composite_directory_accepts_only_a_verified_chain() {
    let net = MemoryBackend::new();
    let mut laptop = init(&net, A, 1);
    let e0 = laptop.latest_public().unwrap();
    // Gate 3: enrolling `phone` opens epoch 1; revoking `phone` opens epoch 2.
    let phone = enroll_otc(&net, &mut laptop, 2);
    block_on(laptop.revoke_device(&phone.device_public().device_key_pub)).unwrap();
    let e1 = block_on(net.ds_directory().epoch(A, 1)).unwrap().unwrap();
    let e2 = laptop.latest_public().unwrap();
    assert_eq!(e2.seq, 2);
    let dir = |pds: Vec<EpochPublic>| {
        CompositeDirectory::new(Box::new(FixedPds::all(pds)), Box::new(net.ds_directory()))
    };

    // Equal heads pass.
    assert_eq!(
        block_on(dir(vec![e0.clone(), e1.clone(), e2.clone()]).latest(A)).unwrap(),
        Some(e2.clone())
    );

    // A lagging source may not omit the newer endpoint: otherwise the
    // other source alone chooses the first-contact recipient epoch.
    let missing_endpoint = CompositeDirectory::new(
        Box::new(FixedPds {
            latest: Some(e0.clone()),
            epochs: vec![e0.clone(), e1.clone()],
        }),
        Box::new(net.ds_directory()),
    );
    assert_eq!(
        block_on(missing_endpoint.latest(A)),
        Err(Error::DirectoryIncomplete {
            pds_present: false,
            ds_present: true,
        })
    );

    // An older `latest` does pass when every immutable epoch, including
    // the newer endpoint, is independently present in both sources. A PDS
    // writes that copy before updating its mutable `self` record.
    let lagging = CompositeDirectory::new(
        Box::new(FixedPds {
            latest: Some(e0.clone()),
            epochs: vec![e0.clone(), e1.clone(), e2.clone()],
        }),
        Box::new(net.ds_directory()),
    );
    assert_eq!(block_on(lagging.latest(A)).unwrap(), Some(e2.clone()));

    // A mutable newer head with its required immutable endpoint missing
    // from both sources is incomplete evidence, not a per-recipient trust
    // failure that callers may silently exclude.
    let missing_everywhere = CompositeDirectory::new(
        Box::new(FixedPds {
            latest: Some(e0.clone()),
            epochs: vec![e0.clone()],
        }),
        Box::new(FixedPds {
            latest: Some(e2.clone()),
            epochs: vec![e0.clone()],
        }),
    );
    assert_eq!(
        block_on(missing_everywhere.latest(A)),
        Err(Error::DirectoryIncomplete {
            pds_present: false,
            ds_present: false,
        })
    );

    // The former one-source availability fallback is explicit degraded TOFU.
    let degraded = CompositeDirectory::new_allowing_single_source(
        Box::new(FixedPds::all(vec![])),
        Box::new(net.ds_directory()),
    );
    assert_eq!(block_on(degraded.latest(A)).unwrap(), Some(e2.clone()));

    // A different, validly attested epoch 0 (the PDS lies): a fork, both
    // at the head and along the chain to mls-ds's newer head.
    let forged = EpochPublic::sign(
        A,
        0,
        &MailboxKeys::derive(&[9; 32], 0),
        [0u8; 32],
        None,
        None,
        &signer(1),
    )
    .unwrap();
    forged.verify(A, None).unwrap();
    let forked = |head: EpochPublic| {
        CompositeDirectory::new(
            Box::new(FixedPds {
                latest: Some(head.clone()),
                epochs: vec![head, e1.clone(), e2.clone()],
            }),
            Box::new(net.ds_directory()),
        )
    };
    assert_eq!(
        block_on(forked(forged.clone()).latest(A)).unwrap_err(),
        Error::DirectoryFork { pds: 0, ds: 2 }
    );
    assert_eq!(
        block_on(forked(forged).epoch(A, 0)).unwrap_err(),
        Error::DirectoryFork { pds: 0, ds: 0 }
    );

    // A client whose directories fork refuses to address the account.
    let fork = EpochPublic::sign(
        A,
        0,
        &MailboxKeys::derive(&[8; 32], 0),
        [0u8; 32],
        None,
        None,
        &signer(1),
    )
    .unwrap();
    net.register_chat_device(B, tpub(4));
    let pds = FixedForDid {
        did: A,
        fixed: FixedPds {
            latest: Some(fork.clone()),
            epochs: vec![fork, e1, e2],
        },
        fallback: net.directory(),
    };
    let peer_fork = CompositeDirectory::new(Box::new(pds), Box::new(net.ds_directory()));
    let b = backends(&net, B, Box::new(net.mailbox(B)), Box::new(peer_fork));
    let mut bob = block_on(Labyrinth::initialize(B, Box::new(signer(4)), b)).unwrap();
    assert_eq!(
        block_on(bob.resolve_roster(&[A, B])).unwrap_err(),
        Error::DirectoryFork { pds: 0, ds: 2 }
    );
}

#[test]
fn archive_outgoing_rejects_a_roster_not_anchored_in_the_directory() {
    let net = MemoryBackend::new();
    let mut alice = init(&net, A, 1);
    let bob = init(&net, B, 2);

    // This is self-consistent and attested by Bob's current chat key, but
    // it is not Bob's independently published mailbox epoch.
    let substituted = EpochPublic::sign(
        B,
        0,
        &MailboxKeys::derive(&[9; 32], 0),
        [0u8; 32],
        None,
        None,
        &signer(2),
    )
    .unwrap();
    substituted.verify(B, None).unwrap();
    assert_ne!(substituted.head, bob.latest_public().unwrap().head);

    assert!(
        block_on(alice.archive_outgoing("t", &[(B.to_owned(), substituted)], "m", 1, b"secret"))
            .is_err()
    );
    assert_eq!(alice.pending("t"), 0);
}

#[test]
fn ds_publisher_enforces_the_head_chain() {
    let net = MemoryBackend::new();
    let mut laptop = init(&net, A, 1);
    let e0 = laptop.latest_public().unwrap();
    let vd = block_on(laptop.create_recovery_code(Mechanism::Code)).unwrap();
    block_on(laptop.remove_recovery_method(&vd.vdevice_id)).unwrap();
    let e1 = laptop.latest_public().unwrap();
    assert_eq!(e1.seq, 1);
    let rec = |e: &EpochPublic| {
        MailboxKeysRecord::from_public(e, None, "2026-10-04T00:00:00.000Z".into())
    };
    let fresh = MemoryBackend::new();
    fresh.register_chat_device(A, tpub(1));
    let p = fresh.ds_publisher(A);
    // Not contiguous: epoch 1 before epoch 0.
    assert_eq!(
        block_on(p.publish(&rec(&e1))),
        Err(Error::Malformed("InvalidEpochChain"))
    );
    block_on(p.publish(&rec(&e0))).unwrap();
    block_on(p.publish(&rec(&e0))).unwrap(); // identical bytes are idempotent
    let other = EpochPublic::sign(
        A,
        0,
        &MailboxKeys::derive(&[7; 32], 0),
        [0u8; 32],
        None,
        None,
        &signer(1),
    )
    .unwrap();
    assert_eq!(block_on(p.publish(&rec(&other))), Err(Error::Conflict));
    // Only a current chat device of the DID may attest a head.
    fresh.remove_chat_device(A, tpub(1), 1);
    assert_eq!(block_on(p.publish(&rec(&e1))), Err(Error::Unattested));
}

#[test]
fn otc_session_enrolls_sibling_and_cleans_up_atomically() {
    use labyrinth::records::{Bytes, OtcSession, nsid};

    let net = MemoryBackend::new();
    let mut phone = init(&net, A, 1);
    let mut responder = phone.otc_offer().unwrap();
    let typed = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(A, &typed).unwrap();
    let reply = block_on(phone.otc_respond(&mut responder, &hello)).unwrap();

    // Persist the OTC session in the mailbox Space and enroll via `enroll_via_otc_session`,
    // proving Gate 3 atomically consumes `otcSession/<session_id>` when opening E+1.
    let session = OtcSession {
        type_: nsid::OTC_SESSION.into(),
        session_id: "sess-clean-slate-1".into(),
        initiator_device_key_pubkey: Bytes::from_slice(&tpub(2)),
        ya: Bytes::from_slice(&hello.ya),
        ek_otc: Bytes::from_slice(&hello.ek_otc),
        yb: Some(Bytes::from_slice(&reply.message.yb)),
        kem_ct: Some(Bytes::from_slice(&reply.message.kem_ct)),
        sealed_payload: Some(Bytes(reply.sealed_payload.clone())),
        created_at: "2026-10-31T00:00:00.000Z".into(),
        expires_at: "2026-10-31T00:10:00.000Z".into(),
    };
    block_on(net.mailbox(A).put_otc_session(&session)).unwrap();
    assert!(
        block_on(net.mailbox(A).get_otc_session("sess-clean-slate-1"))
            .unwrap()
            .is_some()
    );

    net.register_chat_device(A, tpub(2));
    let b = backends(&net, A, Box::new(net.mailbox(A)), composite(&net));
    let (laptop, enrollment) = block_on(Labyrinth::enroll_via_otc_session(
        A,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        Some("sess-clean-slate-1".into()),
        Box::new(signer(2)),
        b,
    ))
    .unwrap();
    assert_eq!(laptop.latest_epoch(), 1);
    assert_eq!(enrollment.device_key, laptop.device_public().device_key_pub);
    assert!(
        block_on(net.mailbox(A).get_otc_session("sess-clean-slate-1"))
            .unwrap()
            .is_none(),
        "Gate 3 atomic_enroll must consume the one-shot otcSession record"
    );
}

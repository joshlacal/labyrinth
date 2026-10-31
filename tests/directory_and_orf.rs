//! The PDS × mls-ds directory cross-check ([CB-28], [CB-29]), head
//! publishing to both directories, and the client's ORF server calls
//! ([CB-17]). Design: `docs/MLSDS_BACKEND.md` §1a, §1c, §6.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth};
use labyrinth::mailbox::{EpochPublic, MailboxKeys};
use labyrinth::records::{
    Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice,
};
use labyrinth::sign::{Ed25519Transport, XVerifyingKey};
use labyrinth::store::memory::{MemoryBackend, MemoryDirectory, MemoryMailbox};
use labyrinth::store::{
    ChatDeviceKey, KeyPublisher, MailboxDirectory, MailboxStore, Stored, TimeRange,
};
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
    mailbox: Box<dyn MailboxStore + Send>,
    directory: Box<dyn MailboxDirectory + Send>,
) -> Backends {
    Backends {
        mailbox,
        threads: Box::new(net.threads(did)),
        directory,
        orf: Box::new(net.orf(did)),
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
    Labyrinth::initialize(did, Box::new(signer(seed)), b).unwrap()
}

fn enroll_otc(net: &MemoryBackend, existing: &mut Labyrinth, seed: u8) -> Labyrinth {
    let did = existing.did().to_owned();
    let mut r = existing.otc_offer().unwrap();
    let typed = r.code().as_str().to_owned();
    let (init, hello) = Labyrinth::otc_start(&did, &typed).unwrap();
    let reply = existing.otc_respond(&mut r, &hello).unwrap();
    net.register_chat_device(&did, tpub(seed));
    let b = backends(net, &did, Box::new(net.mailbox(&did)), composite(net));
    Labyrinth::enroll_via_otc(
        &did,
        init,
        &reply.message,
        &reply.sealed_payload,
        Box::new(signer(seed)),
        b,
    )
    .unwrap()
    .0
}

/// A PDS that hides every epoch after `max_seq`, in the mailbox and in
/// `mailboxKeys` alike (it hosts both).
struct TruncatingPds {
    mailbox: MemoryMailbox,
    pds: MemoryDirectory,
    max_seq: u64,
}

impl MailboxStore for TruncatingPds {
    fn owner(&self) -> &str {
        self.mailbox.owner()
    }
    fn create_device(&self, d: &Device) -> labyrinth::Result<()> {
        self.mailbox.create_device(d)
    }
    fn set_device_revoked(&self, k: &XVerifyingKey, at: &str) -> labyrinth::Result<()> {
        self.mailbox.set_device_revoked(k, at)
    }
    fn get_device(&self, k: &XVerifyingKey) -> labyrinth::Result<Option<Device>> {
        self.mailbox.get_device(k)
    }
    fn list_devices(&self) -> labyrinth::Result<Vec<Device>> {
        self.mailbox.list_devices()
    }
    fn create_epoch(&self, e: &Epoch, m: &[EpochMember]) -> labyrinth::Result<String> {
        self.mailbox.create_epoch(e, m)
    }
    fn get_epoch(&self, seq: u64) -> labyrinth::Result<Option<Stored<Epoch>>> {
        Ok(self.mailbox.get_epoch(seq)?.filter(|_| seq <= self.max_seq))
    }
    fn list_epochs(&self) -> labyrinth::Result<Vec<Stored<Epoch>>> {
        let mut v = self.mailbox.list_epochs()?;
        v.retain(|e| e.value.seq() <= self.max_seq);
        Ok(v)
    }
    fn create_epoch_member(&self, m: &EpochMember) -> labyrinth::Result<()> {
        self.mailbox.create_epoch_member(m)
    }
    fn list_epoch_members(&self, seq: u64) -> labyrinth::Result<Vec<EpochMember>> {
        self.mailbox.list_epoch_members(seq)
    }
    fn create_virtual_device(&self, v: &VirtualDevice) -> labyrinth::Result<()> {
        self.mailbox.create_virtual_device(v)
    }
    fn get_virtual_device(&self, id: &[u8; 16]) -> labyrinth::Result<Option<VirtualDevice>> {
        self.mailbox.get_virtual_device(id)
    }
    fn list_virtual_devices(&self) -> labyrinth::Result<Vec<VirtualDevice>> {
        self.mailbox.list_virtual_devices()
    }
    fn append_owner_batch(&self, b: &OwnerBatch) -> labyrinth::Result<String> {
        self.mailbox.append_owner_batch(b)
    }
    fn list_owner_batches(
        &self,
        t: &str,
        r: TimeRange,
    ) -> labyrinth::Result<Vec<Stored<OwnerBatch>>> {
        self.mailbox.list_owner_batches(t, r)
    }
    fn publish_mailbox_keys(&self, r: &MailboxKeysRecord) -> labyrinth::Result<()> {
        self.mailbox.publish_mailbox_keys(r)
    }
}

impl MailboxDirectory for TruncatingPds {
    fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        self.epoch(did, self.max_seq)
    }
    fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        Ok(self.pds.epoch(did, seq)?.filter(|_| seq <= self.max_seq))
    }
    fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        self.pds.device_transport_keys(did)
    }
}

fn truncating(net: &MemoryBackend) -> TruncatingPds {
    TruncatingPds {
        mailbox: net.mailbox(A),
        pds: net.directory(),
        max_seq: 0,
    }
}

#[test]
fn composite_directory_detects_truncation_by_the_mailbox_host() {
    let net = MemoryBackend::new();
    let mut phone = init(&net, A, 1);
    let code = phone
        .create_recovery_code(Mechanism::Code)
        .unwrap()
        .code
        .as_str()
        .to_owned();
    let mut laptop = enroll_otc(&net, &mut phone, 2);
    laptop
        .revoke_device(&phone.device_public().device_key_pub)
        .unwrap();
    // Epoch 1 reached both directories.
    assert_eq!(net.directory().latest(A).unwrap().unwrap().seq, 1);
    assert_eq!(net.ds_directory().latest(A).unwrap().unwrap().seq, 1);

    // A PDS that hosts the mailbox and the public record can hide epoch 1
    // from a restoring device when it is the only directory ...
    let restore = |directory: Box<dyn MailboxDirectory + Send>, seed: u8| {
        net.register_chat_device(A, tpub(seed));
        let b = backends(&net, A, Box::new(truncating(&net)), directory);
        Labyrinth::restore_with_recovery_code(A, &code, Box::new(signer(seed)), b).map(|_| ())
    };
    restore(Box::new(truncating(&net)), 5).unwrap();
    // ... but not once mls-ds's head chain is cross-checked.
    let dir = CompositeDirectory::new(Box::new(truncating(&net)), Box::new(net.ds_directory()));
    assert_eq!(
        restore(Box::new(dir), 6).unwrap_err(),
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

impl MailboxDirectory for FixedForDid {
    fn latest(&self, did: &str) -> labyrinth::Result<Option<EpochPublic>> {
        if did == self.did {
            self.fixed.latest(did)
        } else {
            self.fallback.latest(did)
        }
    }

    fn epoch(&self, did: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        if did == self.did {
            self.fixed.epoch(did, seq)
        } else {
            self.fallback.epoch(did, seq)
        }
    }

    fn device_transport_keys(&self, did: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
        self.fallback.device_transport_keys(did)
    }
}
impl MailboxDirectory for FixedPds {
    fn latest(&self, _: &str) -> labyrinth::Result<Option<EpochPublic>> {
        Ok(self.latest.clone())
    }
    fn epoch(&self, _: &str, seq: u64) -> labyrinth::Result<Option<EpochPublic>> {
        Ok(self.epochs.iter().find(|e| e.seq == seq).cloned())
    }
    fn device_transport_keys(&self, _: &str) -> labyrinth::Result<Vec<ChatDeviceKey>> {
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
    assert_eq!(pds_only.latest(A), Err(missing_ds.clone()));
    assert_eq!(pds_only.epoch(A, 0), Err(missing_ds));

    let ds_only = CompositeDirectory::new(
        Box::new(FixedPds::all(vec![])),
        Box::new(FixedPds::all(vec![e0.clone()])),
    );
    let missing_pds = Error::DirectoryIncomplete {
        pds_present: false,
        ds_present: true,
    };
    assert_eq!(ds_only.latest(A), Err(missing_pds.clone()));
    assert_eq!(ds_only.epoch(A, 0), Err(missing_pds));

    let neither = CompositeDirectory::new(
        Box::new(FixedPds::all(vec![])),
        Box::new(FixedPds::all(vec![])),
    );
    assert_eq!(neither.latest(A), Ok(None));
    assert_eq!(neither.epoch(A, 0), Ok(None));

    let pds_tofu = CompositeDirectory::new_allowing_single_source(
        Box::new(FixedPds::all(vec![e0.clone()])),
        Box::new(FixedPds::all(vec![])),
    );
    assert_eq!(pds_tofu.latest(A), Ok(Some(e0.clone())));
    assert_eq!(pds_tofu.epoch(A, 0), Ok(Some(e0.clone())));
    let ds_tofu = CompositeDirectory::new_allowing_single_source(
        Box::new(FixedPds::all(vec![])),
        Box::new(FixedPds::all(vec![e0.clone()])),
    );
    assert_eq!(ds_tofu.latest(A), Ok(Some(e0.clone())));
    assert_eq!(ds_tofu.epoch(A, 0), Ok(Some(e0)));
}

#[test]
fn composite_directory_accepts_only_a_verified_chain() {
    let net = MemoryBackend::new();
    let mut laptop = init(&net, A, 1);
    let e0 = laptop.latest_public().unwrap();
    let phone = enroll_otc(&net, &mut laptop, 2);
    let tablet = enroll_otc(&net, &mut laptop, 3);
    for d in [&phone, &tablet] {
        laptop
            .revoke_device(&d.device_public().device_key_pub)
            .unwrap();
    }
    let e1 = net.ds_directory().epoch(A, 1).unwrap().unwrap();
    let e2 = laptop.latest_public().unwrap();
    let dir = |pds: Vec<EpochPublic>| {
        CompositeDirectory::new(Box::new(FixedPds::all(pds)), Box::new(net.ds_directory()))
    };

    // Equal heads pass.
    assert_eq!(
        dir(vec![e0.clone(), e1.clone(), e2.clone()])
            .latest(A)
            .unwrap(),
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
        missing_endpoint.latest(A),
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
    assert_eq!(lagging.latest(A).unwrap(), Some(e2.clone()));

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
        missing_everywhere.latest(A),
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
    assert_eq!(degraded.latest(A).unwrap(), Some(e2.clone()));

    // A different, validly attested epoch 0 (the PDS lies): a fork, both
    // at the head and along the chain to mls-ds's newer head.
    let forged = EpochPublic::sign(
        A,
        0,
        &MailboxKeys::derive(&[9; 32], 0),
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
        forked(forged.clone()).latest(A).unwrap_err(),
        Error::DirectoryFork { pds: 0, ds: 2 }
    );
    assert_eq!(
        forked(forged).epoch(A, 0).unwrap_err(),
        Error::DirectoryFork { pds: 0, ds: 0 }
    );

    // A client whose directories fork refuses to address the account.
    let fork = EpochPublic::sign(
        A,
        0,
        &MailboxKeys::derive(&[8; 32], 0),
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
    let mut bob = Labyrinth::initialize(B, Box::new(signer(4)), b).unwrap();
    assert_eq!(
        bob.resolve_roster(&[A, B]).unwrap_err(),
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
        None,
        None,
        &signer(2),
    )
    .unwrap();
    substituted.verify(B, None).unwrap();
    assert_ne!(substituted.head, bob.latest_public().unwrap().head);

    assert!(
        alice
            .archive_outgoing("t", &[(B.to_owned(), substituted)], "m", 1, b"secret")
            .is_err()
    );
    assert_eq!(alice.pending("t"), 0);
}

#[test]
fn ds_publisher_enforces_the_head_chain() {
    let net = MemoryBackend::new();
    let mut laptop = init(&net, A, 1);
    let e0 = laptop.latest_public().unwrap();
    let phone = enroll_otc(&net, &mut laptop, 2);
    laptop
        .revoke_device(&phone.device_public().device_key_pub)
        .unwrap();
    let e1 = laptop.latest_public().unwrap();
    let rec = |e: &EpochPublic| {
        MailboxKeysRecord::from_public(e, None, "2026-10-04T00:00:00.000Z".into())
    };
    let fresh = MemoryBackend::new();
    fresh.register_chat_device(A, tpub(1));
    let p = fresh.ds_publisher(A);
    // Not contiguous: epoch 1 before epoch 0.
    assert_eq!(
        p.publish(&rec(&e1)),
        Err(Error::Malformed("InvalidEpochChain"))
    );
    p.publish(&rec(&e0)).unwrap();
    p.publish(&rec(&e0)).unwrap(); // identical bytes are idempotent
    let other = EpochPublic::sign(
        A,
        0,
        &MailboxKeys::derive(&[7; 32], 0),
        None,
        None,
        &signer(1),
    )
    .unwrap();
    assert_eq!(p.publish(&rec(&other)), Err(Error::Conflict));
    // Only a current chat device of the DID may attest a head.
    fresh.remove_chat_device(A, tpub(1), 1);
    assert_eq!(p.publish(&rec(&e1)), Err(Error::Unattested));
}

#[test]
fn client_registers_and_deletes_orf_states() {
    let net = MemoryBackend::new();
    let mut phone = init(&net, A, 1);
    let orf = net.orf(A);
    let phone_key = phone.device_public().device_key_pub;
    assert!(orf.has_state(&phone_key));
    let orf_out = |l: &Labyrinth| l.orf_evaluate(b"attachment_key_scope", b"server", b"blob-1");
    let base = orf_out(&phone).unwrap();

    // Bundle, restore and one-time-code enrollment all evolve the state:
    // the full evaluation is unchanged on every new device.
    let setup = phone.create_recovery_code(Mechanism::Code).unwrap();
    let mut laptop = enroll_otc(&net, &mut phone, 2);
    assert_eq!(orf_out(&laptop).unwrap(), base);
    net.register_chat_device(A, tpub(3));
    let b = backends(&net, A, Box::new(net.mailbox(A)), composite(&net));
    let (tablet, enrollment) =
        Labyrinth::restore_with_recovery_code(A, setup.code.as_str(), Box::new(signer(3)), b)
            .unwrap();
    assert!(orf.has_state(&enrollment.device_key));
    assert_eq!(orf_out(&tablet).unwrap(), base);
    assert_ne!(
        orf_out(&tablet).unwrap(),
        tablet
            .orf_evaluate(b"attachment_key_scope", b"server", b"blob-2")
            .unwrap()
    );

    // Revocation deletes the revoked device's server state.
    laptop.revoke_device(&phone_key).unwrap();
    assert!(!orf.has_state(&phone_key));
    assert_eq!(orf_out(&phone).unwrap_err(), Error::NotFound("orf state"));
    assert_eq!(orf_out(&laptop).unwrap(), base);
}

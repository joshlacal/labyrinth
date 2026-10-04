//! Every record the crate emits validates against its lexicon JSON and
//! round-trips losslessly to the protocol structs (SPEC §9).

#[path = "support/lexicon.rs"]
mod lexicon;

use std::path::Path;

use labyrinth::device::DeviceSecrets;
use labyrinth::epoch::{EpochKeys, open_genesis, open_next, space_epoch_id};
use labyrinth::mailbox::EpochPublic;
use labyrinth::mek::{self, Mek};
use labyrinth::message::{seal_owner, seal_sender};
use labyrinth::records::mailbox::PasskeyWrap;
use labyrinth::records::{
    Batch, Device, Epoch, EpochMember, MailboxKeysRecord, MekDistribution, OwnerBatch,
    VirtualDevice, datetime_from_ms, nsid,
};
use labyrinth::recovery_code::RecoveryCode;
use labyrinth::sign::Ed25519Transport;
use labyrinth::virtual_device::{self, Mechanism, passkey};
use lexicon::Lexicons;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const DID: &str = "did:plc:recordtest";
const THREAD: &str = "conv-3f2a";

fn lexicons() -> Lexicons {
    Lexicons::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("lexicons/blue/catbird/labyrinth"))
}

fn transport(n: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[n; 32]))
}

/// Serialize, validate against the lexicon, and parse back unchanged.
fn check<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
    lex: &Lexicons,
    collection: &str,
    rec: &T,
) -> Value {
    let v = serde_json::to_value(rec).unwrap();
    lex.validate_record(collection, &v)
        .unwrap_or_else(|e| panic!("{collection}: {e}\n{v:#}"));
    let back: T = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(&back, rec, "{collection} JSON round trip");
    v
}

#[test]
fn lexicons_are_well_formed() {
    let lex = lexicons();
    assert_eq!(lex.docs().count(), 9);
    fn walk(v: &Value, cur: &str, ids: &[String]) {
        match v {
            Value::Object(o) => {
                if let Some(d) = o.get("description") {
                    assert!(
                        !d.as_str().unwrap().is_empty(),
                        "empty description in {cur}"
                    );
                }
                if let Some(Value::String(r)) = o.get("ref") {
                    let (n, _) = Lexicons::resolve(cur, r);
                    assert!(ids.contains(&n), "dangling ref {r} in {cur}");
                }
                o.values().for_each(|x| walk(x, cur, ids));
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, cur, ids)),
            _ => {}
        }
    }
    let ids: Vec<String> = lex.docs().map(|(k, _)| k.clone()).collect();
    for (id, doc) in lex.docs() {
        walk(doc, id, &ids);
    }
}

#[test]
fn mailbox_records_round_trip() {
    let lex = lexicons();
    let t = transport(1);
    let a = DeviceSecrets::generate().unwrap();
    let b = DeviceSecrets::generate().unwrap();
    let ts = datetime_from_ms(1_791_181_727_123);

    // Devices, physical and (below) virtual, incl. revokedAt.
    let mut dev = Device::from_public(a.public(), ts.clone());
    check(&lex, nsid::DEVICE, &dev);
    assert_eq!(&dev.to_public().unwrap(), a.public());
    dev.revoked_at = Some(ts.clone());
    check(&lex, nsid::DEVICE, &dev);

    // Epoch 0 and epoch 1 with entropy-bearing members.
    let (p0, n0) = open_genesis(DID, &a, &t).unwrap();
    let e0 = p0.assign_id(space_epoch_id(0));
    let ep0 = Epoch::from_record(&n0.record, ts.clone());
    check(&lex, nsid::EPOCH, &ep0);
    assert_eq!(ep0.to_record().unwrap(), n0.record);
    let mut members0 = n0.members.clone();
    members0.push(labyrinth::epoch::add_device_mac(&e0, b.public()).unwrap());
    let (_, n1) = open_next(
        DID,
        &e0,
        &n0.record.public,
        &members0,
        &[b.public().clone()],
        &a,
        &t,
    )
    .unwrap();
    let ep1 = Epoch::from_record(&n1.record, ts.clone());
    check(&lex, nsid::EPOCH, &ep1);
    assert_eq!(ep1.to_record().unwrap(), n1.record);
    for m in members0.iter().chain(&n1.members) {
        let r = EpochMember::from_record(m, ts.clone());
        check(&lex, nsid::EPOCH_MEMBER, &r);
        assert_eq!(&r.to_record().unwrap(), m);
    }
    assert!(n1.members.iter().all(|m| m.encrypted_entropy.is_some()));

    // Virtual devices, with and without the passkey wrap.
    let code = RecoveryCode::generate().unwrap();
    let (vrec, _, _) =
        virtual_device::create(DID, &code, &a, &e0, &[9u8; 32], Mechanism::Passkey).unwrap();
    let wrap = PasskeyWrap {
        wrapped_code: passkey::wrap_code(&[4u8; 32], &code).unwrap(),
        credential_id: vec![7u8; 64],
    };
    for pk in [None, Some(&wrap)] {
        let r = VirtualDevice::from_bundle(&vrec, pk, ts.clone());
        check(&lex, nsid::VIRTUAL_DEVICE, &r);
        let (back, back_pk) = r.to_bundle().unwrap();
        assert_eq!(back, vrec);
        assert_eq!(back_pk.as_ref(), pk);
        assert_eq!(r.rkey(), hex::encode(vrec.vdevice_id));
    }
    let vdev = Device::from_public(&vrec.public, ts.clone());
    check(&lex, nsid::DEVICE, &vdev);
    assert_eq!(vdev.to_public().unwrap(), vrec.public);

    // Owner batch of 256 messages.
    let msgs: Vec<_> = (0..256u64)
        .map(|i| seal_owner(e0.root(), 0, THREAD, &format!("m{i}"), i, b"frame").unwrap())
        .collect();
    let ob = OwnerBatch::from_messages(&msgs, ts.clone()).unwrap();
    check(&lex, nsid::OWNER_BATCH, &ob);
    assert_eq!(ob.to_messages().unwrap(), msgs);

    // Public mailbox keys.
    let mk = MailboxKeysRecord::from_public(&n1.record.public, Some("space"), ts);
    check(&lex, nsid::MAILBOX_KEYS, &mk);
    assert_eq!(mk.to_public().unwrap(), n1.record.public);
}

struct M {
    did: String,
    keys: labyrinth::mailbox::MailboxKeys,
    epoch: EpochPublic,
}

fn member(name: &str, n: u8) -> M {
    let did = format!("did:plc:{name}");
    let keys = labyrinth::mailbox::MailboxKeys::derive(&[n; 32], 0);
    let epoch = EpochPublic::sign(&did, 0, &keys, None, None, &transport(n)).unwrap();
    M { did, keys, epoch }
}

#[test]
fn thread_records_round_trip() {
    let lex = lexicons();
    let ts = datetime_from_ms(5);
    let (a, b) = (member("alice", 1), member("bob", 2));
    let roster = vec![
        (a.did.clone(), a.epoch.clone()),
        (b.did.clone(), b.epoch.clone()),
    ];
    let heads = [a.epoch.head, b.epoch.head];

    let mut m1 = Mek::generate(&heads).unwrap();
    let r1 =
        mek::distribute_labyrinth(THREAD, &mut m1, &a.did, &a.epoch, &a.keys, &roster).unwrap();
    let rec = MekDistribution::from_record(&r1, Some(&a.epoch), ts.clone()).unwrap();
    let v = check(&lex, nsid::MEK, &rec);
    assert_eq!(
        v["sender"]["$type"],
        json!("blue.catbird.labyrinth.mek#labyrinthSender")
    );
    assert_eq!(
        rec.to_record().unwrap(),
        (r1.clone(), Some(a.epoch.clone()))
    );
    assert!(MekDistribution::from_record(&r1, None, ts.clone()).is_err());
    assert!(MekDistribution::from_record(&r1, Some(&b.epoch), ts.clone()).is_err());

    let mut m2 = Mek::generate(&heads).unwrap();
    let r2 = mek::distribute_transport(THREAD, &mut m2, &transport(9), &roster).unwrap();
    let rec2 = MekDistribution::from_record(&r2, None, ts.clone()).unwrap();
    let v = check(&lex, nsid::MEK, &rec2);
    assert_eq!(
        v["sender"]["$type"],
        json!("blue.catbird.labyrinth.mek#transportSender")
    );
    assert_eq!(rec2.to_record().unwrap(), (r2, None));

    let sealed: Vec<_> = (0..256u64)
        .map(|i| seal_sender(&m1, THREAD, &format!("m{i}"), i, b"hello", &transport(1)).unwrap())
        .collect();
    let batch = Batch::from_messages(THREAD, &sealed, ts.clone()).unwrap();
    check(&lex, nsid::BATCH, &batch);
    assert_eq!(batch.to_messages().unwrap(), sealed);
    assert!(Batch::from_messages(THREAD, &[], ts.clone()).is_err());
    let too_many = vec![sealed[0].clone(); 257];
    assert!(Batch::from_messages(THREAD, &too_many, ts).is_err());
}

/// Positive controls: the validator catches what it claims to.
#[test]
fn validator_rejects_bad_records() {
    let lex = lexicons();
    let a = DeviceSecrets::generate().unwrap();
    let good = serde_json::to_value(Device::from_public(a.public(), datetime_from_ms(0))).unwrap();
    lex.validate_record(nsid::DEVICE, &good).unwrap();

    let mutate = |f: &dyn Fn(&mut Value)| {
        let mut v = good.clone();
        f(&mut v);
        lex.validate_record(nsid::DEVICE, &v)
    };
    assert!(
        mutate(&|v| {
            v.as_object_mut().unwrap().remove("virtual");
        })
        .is_err()
    );
    assert!(mutate(&|v| v["$type"] = json!(nsid::EPOCH)).is_err());
    assert!(mutate(&|v| v["extra"] = json!(1)).is_err());
    assert!(mutate(&|v| v["virtual"] = json!("no")).is_err());
    assert!(mutate(&|v| v["createdAt"] = json!("yesterday")).is_err());
    // 33-byte key, padded base64, raw string instead of $bytes.
    assert!(mutate(&|v| v["deviceKeyPubkey"] = json!({"$bytes": "A".repeat(44)})).is_err());
    assert!(
        mutate(&|v| v["deviceKeyPubkey"] = json!({"$bytes": format!("{}=", "A".repeat(43))}))
            .is_err()
    );
    assert!(mutate(&|v| v["deviceKeyPubkey"] = json!("AAAA")).is_err());
    // A union member with a $type outside the closed union.
    let ts = datetime_from_ms(0);
    let m = member("alice", 1);
    let mut k = Mek::generate(&[m.epoch.head]).unwrap();
    let r = mek::distribute_labyrinth(
        THREAD,
        &mut k,
        &m.did,
        &m.epoch,
        &m.keys,
        &[(m.did.clone(), m.epoch.clone())],
    )
    .unwrap();
    let mut v = serde_json::to_value(MekDistribution::from_record(&r, Some(&m.epoch), ts).unwrap())
        .unwrap();
    lex.validate_record(nsid::MEK, &v).unwrap();
    v["sender"]["$type"] = json!("blue.catbird.labyrinth.mek#other");
    assert!(lex.validate_record(nsid::MEK, &v).is_err());
    // Integer bounds.
    let ob = OwnerBatch::from_messages(
        &[seal_owner(&[1u8; 32], 0, THREAD, "m", 1, b"x").unwrap()],
        datetime_from_ms(0),
    )
    .unwrap();
    let mut v = serde_json::to_value(ob).unwrap();
    lex.validate_record(nsid::OWNER_BATCH, &v).unwrap();
    v["items"][0]["version"] = json!(5);
    assert!(lex.validate_record(nsid::OWNER_BATCH, &v).is_err());
    // epochNumber is bounded at 2^40, in the lexicon and in the records layer.
    v["items"][0]["version"] = json!(3);
    v["items"][0]["epochNumber"] = json!(labyrinth::records::MAX_EPOCH_NUMBER);
    lex.validate_record(nsid::OWNER_BATCH, &v).unwrap();
    for n in [labyrinth::records::MAX_EPOCH_NUMBER + 1, u64::MAX] {
        v["items"][0]["epochNumber"] = json!(n);
        assert!(lex.validate_record(nsid::OWNER_BATCH, &v).is_err());
        let ob: OwnerBatch = serde_json::from_value(v.clone()).unwrap();
        assert!(ob.to_messages().is_err());
    }
    let mut em = serde_json::to_value(EpochMember::from_record(
        &labyrinth::epoch::add_device_mac(
            &labyrinth::epoch::PendingEpoch::new(1, [1; 32]),
            a.public(),
        )
        .unwrap(),
        datetime_from_ms(0),
    ))
    .unwrap();
    lex.validate_record(nsid::EPOCH_MEMBER, &em).unwrap();
    em["epochNumber"] = json!(u64::MAX);
    assert!(lex.validate_record(nsid::EPOCH_MEMBER, &em).is_err());
    let rec: EpochMember = serde_json::from_value(em).unwrap();
    assert!(rec.to_record().is_err());
    let mut pubdef = labyrinth::records::EpochPublicDef::from_public(&m.epoch);
    pubdef.epoch_number = u64::MAX;
    assert!(pubdef.to_public().is_err());
}

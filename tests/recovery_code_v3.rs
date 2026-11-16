//! Recovery code version 3 (erasable share): known-answer vectors for the
//! derivation, sealing ("wrap") and opening ("unwrap") of a bundle, the
//! wrong-share and missing-share failures, version dispatch, and the
//! guarantee that version-2 behaviour is byte-identical.

use std::sync::{Arc, Mutex};

use labyrinth::Error;
use labyrinth::device::DeviceSecrets;
use labyrinth::encoding::{RandomFillHook, with_random_hook};
use labyrinth::epoch::{EpochKeys as _, EpochSecret};
use labyrinth::records::VirtualDevice;
use labyrinth::recovery_code::{CodeVersion, ENTROPY_LEN, RecoveryCode};
use labyrinth::recovery_share::{RecoveryShare, fetch_verifier, vdevice_key};
use labyrinth::virtual_device::{
    self, Mechanism, VirtualDeviceRecord, open, open_with_share, seal_virtual_device,
    seal_virtual_device_with_share,
};
use proptest::prelude::*;
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/recovery_code_v3_vectors.json");

fn fixture() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn unhex<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn entropy(v: &Value) -> [u8; ENTROPY_LEN] {
    let syms: Vec<u8> = v["entropySymbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect();
    syms.try_into().unwrap()
}

/// Deterministic randomness: a byte counter starting at `start`.
fn counter_hook(start: u8) -> RandomFillHook {
    let c = Arc::new(Mutex::new(start));
    Arc::new(move |out: &mut [u8]| {
        let mut cur = c.lock().unwrap();
        for b in out.iter_mut() {
            *b = *cur;
            *cur = cur.wrapping_add(1);
        }
        Ok(())
    })
}

/// Collects mismatches against Rust-produced fixture fields and prints the
/// actual values, so a reviewer sees exactly what changed.
#[derive(Default)]
struct Diffs(Vec<String>);
impl Diffs {
    fn check(&mut self, path: &str, expected: &Value, actual: &str) {
        if expected.as_str() != Some(actual) {
            self.0
                .push(format!("{path}: expected {expected}, actual \"{actual}\""));
        }
    }
    fn finish(self) {
        assert!(
            self.0.is_empty(),
            "fixture mismatch:\n{}",
            self.0.join("\n")
        );
    }
}

#[test]
fn derivation_vectors() {
    let f = fixture();
    let did = f["did"].as_str().unwrap();
    let mut diffs = Diffs::default();
    for (i, v) in f["vectors"].as_array().unwrap().iter().enumerate() {
        let name = v["name"].as_str().unwrap();
        let ent = entropy(v);
        let code = RecoveryCode::from_entropy_symbols_v3(&ent);
        diffs.check(&format!("vectors[{i}].code"), &v["code"], code.as_str());
        assert_eq!(code.version(), CodeVersion::V3, "{name}");
        assert!(code.as_str().starts_with("30"), "{name}");
        assert_eq!(
            code.entropy_chars(),
            v["entropyChars"].as_str().unwrap().as_bytes()
        );
        assert_eq!(RecoveryCode::parse(code.as_str()).unwrap(), code, "{name}");

        let d = code.derive_v3(did).unwrap();
        assert_eq!(
            d.vdevice_id,
            unhex::<16>(&v["vdeviceId"]),
            "{name} vdeviceId"
        );
        assert_eq!(*d.code_key, unhex::<32>(&v["codeKey"]), "{name} codeKey");
        assert_eq!(
            *d.fetch_token,
            unhex::<32>(&v["fetchToken"]),
            "{name} fetchToken"
        );
        assert_eq!(
            d.fetch_verifier(did),
            unhex::<32>(&v["fetchVerifier"]),
            "{name} fetchVerifier"
        );
        assert_eq!(
            fetch_verifier(did, &d.vdevice_id, &d.fetch_token),
            unhex::<32>(&v["fetchVerifier"])
        );
        let share = RecoveryShare::from_bytes(unhex::<32>(&v["share"]));
        assert_eq!(
            *d.vdevice_key(did, &share),
            unhex::<32>(&v["vdeviceKey"]),
            "{name} vdeviceKey"
        );
        assert_eq!(
            *vdevice_key(did, &d.vdevice_id, &d.code_key, &share),
            unhex::<32>(&v["vdeviceKey"])
        );
        // The first 48 bytes of the v3 derivation are what `derive` returns.
        let (id, key) = code.derive(did);
        assert_eq!(id, d.vdevice_id);
        assert_eq!(*key, *d.code_key);
        assert_eq!(code.vdevice_id(did), d.vdevice_id);
        let (bid, bkey) = code.bundle_key(did, Some(&share)).unwrap();
        assert_eq!(bid, d.vdevice_id);
        assert_eq!(*bkey, unhex::<32>(&v["vdeviceKey"]));
        assert_eq!(
            code.bundle_key(did, None).err(),
            Some(Error::RecoveryShareUnavailable)
        );

        // The same entropy as a version-2 code: the unchanged v2 derivation.
        let v2 = RecoveryCode::from_entropy_symbols(&ent);
        diffs.check(&format!("vectors[{i}].v2Code"), &v["v2Code"], v2.as_str());
        assert_eq!(v2.version(), CodeVersion::V2);
        assert_eq!(
            &v2.as_str()[2..],
            &code.as_str()[2..],
            "same word, other version"
        );
        let (v2id, v2key) = v2.derive(did);
        assert_eq!(v2id, unhex::<16>(&v["v2VdeviceId"]), "{name} v2 vdeviceId");
        assert_eq!(*v2key, unhex::<32>(&v["v2VdeviceKey"]), "{name} v2 key");
        assert_ne!(v2id, d.vdevice_id);
        assert!(v2.derive_v3(did).is_err());
        assert_eq!(
            v2.bundle_key(did, Some(&share)).err(),
            Some(Error::Malformed("version-2 recovery code takes no share"))
        );
    }
    diffs.finish();
}

struct Wrapped {
    vsecrets: DeviceSecrets,
    record: VirtualDeviceRecord,
}

fn wrap(code: &RecoveryCode, share: Option<&RecoveryShare>, w: &Value, did: &str) -> Wrapped {
    let epoch = EpochSecret::from_parts(
        w["epochSeq"].as_u64().unwrap(),
        w["epochId"].as_str().unwrap(),
        unhex::<32>(&w["epochRoot"]),
    );
    let start = w["randomCounterStart"].as_u64().unwrap() as u8;
    with_random_hook(counter_hook(start), || {
        let vsecrets = DeviceSecrets::generate_virtual().unwrap();
        let record = seal_virtual_device_with_share(
            did,
            code,
            share,
            &vsecrets,
            &epoch,
            Mechanism::parse(w["mechanism"].as_str().unwrap()).unwrap(),
            Some(w["createdAt"].as_str().unwrap()),
        )
        .unwrap();
        Wrapped { vsecrets, record }
    })
}

fn check_record(diffs: &mut Diffs, path: &str, expected: &Value, r: &VirtualDeviceRecord) {
    for (field, bytes) in [
        ("encryptedDeviceKeyPriv", &r.encrypted_device_key_priv),
        (
            "encryptedEpochStorageKeyPriv",
            &r.encrypted_epoch_storage_key_priv,
        ),
        ("encryptedEpochRootKey", &r.encrypted_epoch_root_key),
        ("encryptedEpochNumber", &r.encrypted_epoch_number),
    ] {
        diffs.check(
            &format!("{path}.{field}"),
            &expected[field],
            &hex::encode(bytes),
        );
    }
    diffs.check(
        &format!("{path}.metadataSig"),
        &expected["metadataSig"],
        &hex::encode(r.metadata_sig.unwrap()),
    );
}

/// The frozen record with its ciphertext fields taken from the fixture.
fn frozen(template: &VirtualDeviceRecord, expected: &Value) -> VirtualDeviceRecord {
    let b = |k: &str| hex::decode(expected[k].as_str().unwrap()).unwrap();
    let mut r = template.clone();
    r.encrypted_device_key_priv = b("encryptedDeviceKeyPriv");
    r.encrypted_epoch_storage_key_priv = b("encryptedEpochStorageKeyPriv");
    r.encrypted_epoch_root_key = b("encryptedEpochRootKey");
    r.encrypted_epoch_number = b("encryptedEpochNumber");
    r.metadata_sig = Some(
        hex::decode(expected["metadataSig"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    r
}

fn wrap_vector(f: &Value) -> (&str, RecoveryCode, RecoveryShare, RecoveryCode, &Value) {
    let did = f["did"].as_str().unwrap();
    let w = &f["wrap"];
    let v = f["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == w["vector"])
        .unwrap();
    let ent = entropy(v);
    (
        did,
        RecoveryCode::from_entropy_symbols_v3(&ent),
        RecoveryShare::from_bytes(unhex::<32>(&v["share"])),
        RecoveryCode::from_entropy_symbols(&ent),
        w,
    )
}

#[test]
fn wrap_vectors_are_byte_stable() {
    let f = fixture();
    let (did, v3, share, v2, w) = wrap_vector(&f);
    let mut diffs = Diffs::default();
    let a = wrap(&v3, Some(&share), w, did);
    check_record(&mut diffs, "wrap.v3", &w["v3"], &a.record);
    let b = wrap(&v2, None, w, did);
    check_record(&mut diffs, "wrap.v2", &w["v2"], &b.record);
    diffs.finish();
    assert_eq!(a.record.vdevice_id, v3.vdevice_id(did));
    assert_eq!(b.record.vdevice_id, v2.vdevice_id(did));
}

#[test]
fn unwrap_wrong_share_and_missing_share_vectors() {
    let f = fixture();
    let (did, v3, share, v2, w) = wrap_vector(&f);
    let template = wrap(&v3, Some(&share), w, did);
    let rec = frozen(&template.record, &w["v3"]);

    // Unwrap: the frozen bytes open with code + share.
    let opened = open_with_share(&rec, &v3, Some(&share), did).unwrap();
    assert_eq!(opened.epoch.seq(), w["epochSeq"].as_u64().unwrap());
    assert_eq!(opened.epoch.root(), &unhex::<32>(&w["epochRoot"]));
    assert_eq!(opened.device.public(), template.vsecrets.public());

    // Wrong share: authentication fails.
    let wrong = RecoveryShare::from_bytes(unhex::<32>(&f["wrongShare"]));
    assert_eq!(
        open_with_share(&rec, &v3, Some(&wrong), did).err(),
        Some(Error::Decrypt)
    );
    // Missing share: a distinct error, before any decryption.
    assert_eq!(
        open_with_share(&rec, &v3, None, did).err(),
        Some(Error::RecoveryShareUnavailable)
    );
    assert_eq!(
        open(&rec, &v3, did).err(),
        Some(Error::RecoveryShareUnavailable)
    );
    // The version-2 code with the same entropy names another bundle.
    assert_eq!(open(&rec, &v2, did).err(), Some(Error::BadRecoveryCode));
    // Another DID derives another id.
    assert_eq!(
        open_with_share(&rec, &v3, Some(&share), "did:plc:other").err(),
        Some(Error::BadRecoveryCode)
    );

    // The v2 frozen record opens with the v2 code only.
    let rec2 = frozen(&wrap(&v2, None, w, did).record, &w["v2"]);
    assert!(open(&rec2, &v2, did).is_ok());
    assert_eq!(open(&rec2, &v3, did).err(), Some(Error::BadRecoveryCode));
}

#[test]
fn v3_record_has_the_unchanged_v2_shape() {
    let f = fixture();
    let (did, v3, share, _, w) = wrap_vector(&f);
    let rec = frozen(&wrap(&v3, Some(&share), w, did).record, &w["v3"]);
    // The checks a version-2-only client runs on every bundle it meets.
    rec.validate_shape(Some(did)).unwrap();
    let created = w["createdAt"].as_str().unwrap().to_owned();
    let published = VirtualDevice::from_bundle(&rec, None, created);
    let (back, wrap) = published.to_bundle_for_did(did).unwrap();
    assert_eq!(back, rec);
    assert!(wrap.is_none());
    let json = serde_json::to_value(&published).unwrap();
    assert_eq!(json["formatVersion"], serde_json::json!(2), "{json}");
}

#[test]
fn unknown_version_is_distinct_and_version_typos_are_found() {
    let f = fixture();
    let (did, v3, _, v2, _) = wrap_vector(&f);
    let mut unknown = v3.as_str().to_owned();
    unknown.replace_range(0..1, "4");
    assert_eq!(
        RecoveryCode::parse(&unknown).err(),
        Some(Error::UnsupportedCodeVersion)
    );
    assert_eq!(
        virtual_device::find_code(&unknown, did, |_| false).err(),
        Some(Error::UnsupportedCodeVersion)
    );
    // Garbage that is not a codeword stays a bad code.
    let mut garbage = unknown.clone();
    garbage.replace_range(20..21, if &garbage[20..21] == "A" { "C" } else { "A" });
    assert_eq!(
        RecoveryCode::parse(&garbage).err(),
        Some(Error::BadRecoveryCode)
    );

    // The backend knows the v3 method; the user typed '2' or '4' for '3'.
    let v3_id = v3.vdevice_id(did);
    for typed in [v2.as_str().to_owned(), unknown] {
        let found = virtual_device::find_code(&typed, did, |id| *id == v3_id).unwrap();
        assert_eq!(found, v3);
    }
    // And the reverse for a v2 method typed with '3'.
    let v2_id = v2.vdevice_id(did);
    let found = virtual_device::find_code(v3.as_str(), did, |id| *id == v2_id).unwrap();
    assert_eq!(found, v2);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Version-2 sealing and opening are unchanged: the legacy entry points
    /// and the share-aware ones with no share produce byte-identical records.
    #[test]
    fn v2_records_round_trip_identically(
        syms in proptest::array::uniform32(0u8..32),
        extra in proptest::array::uniform2(0u8..32),
        seed in any::<u8>(),
        seq in 1u64..1_000_000,
    ) {
        let mut ent = [0u8; ENTROPY_LEN];
        ent[..32].copy_from_slice(&syms);
        ent[32..].copy_from_slice(&extra);
        let did = "did:plc:proptestv2";
        let code = RecoveryCode::from_entropy_symbols(&ent);
        prop_assert_eq!(code.version(), CodeVersion::V2);
        let (id, key) = code.derive(did);
        let (bid, bkey) = code.bundle_key(did, None).unwrap();
        prop_assert_eq!(id, bid);
        prop_assert_eq!(*key, *bkey);
        let epoch = EpochSecret::from_parts(seq, "e", [seed; 32]);
        let seal = |share_aware: bool| {
            with_random_hook(counter_hook(seed), || {
                let v = DeviceSecrets::generate_virtual().unwrap();
                if share_aware {
                    seal_virtual_device_with_share(
                        did, &code, None, &v, &epoch, Mechanism::Code,
                        Some("2026-11-16T00:00:00.000Z"),
                    )
                } else {
                    seal_virtual_device(
                        did, &code, &v, &epoch, Mechanism::Code,
                        Some("2026-11-16T00:00:00.000Z"),
                    )
                }
                .unwrap()
            })
        };
        let legacy = seal(false);
        let aware = seal(true);
        prop_assert_eq!(&legacy, &aware);
        let a = open(&legacy, &code, did).unwrap();
        let b = open_with_share(&legacy, &code, None, did).unwrap();
        prop_assert_eq!(a.epoch.seq(), seq);
        prop_assert_eq!(b.epoch.root(), a.epoch.root());
        prop_assert_eq!(a.device.public(), b.device.public());
    }
}

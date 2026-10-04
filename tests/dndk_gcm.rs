//! AES-256-DNDK-GCM against the draft's own vectors
//! (`tests/vectors/dndk_gcm.json`, draft-gueron-cfrg-dndkgcm-05).

use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use labyrinth::aead::{self, Suite, dndk_gcm};
use serde_json::Value;

fn vectors() -> Value {
    let raw = include_str!("vectors/dndk_gcm.json");
    serde_json::from_str(raw).expect("valid JSON")
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn key32(v: &Value) -> [u8; 32] {
    hx(v).try_into().expect("32-byte key")
}

/// Nonce for a vector: explicit, or `encode(counter, 12) || 0^12` (draft §4.7).
fn nonce_of(input: &Value) -> Vec<u8> {
    match &input["nonce"] {
        Value::String(_) => hx(&input["nonce"]),
        Value::Null => {
            let c = input["counter"].as_u64().expect("counter");
            let mut n = vec![0u8; 24];
            n[4..12].copy_from_slice(&c.to_be_bytes());
            n
        }
        other => panic!("bad nonce {other}"),
    }
}

#[test]
fn records_draft_revision() {
    let v = vectors();
    assert_eq!(v["draftRevision"], "draft-gueron-cfrg-dndkgcm-05");
    assert_eq!(dndk_gcm::DRAFT_REVISION, "draft-gueron-cfrg-dndkgcm-05");
    assert_eq!(v["official"]["numberOfTests"], 82);
}

/// draft-05 Appendix A, checking every AES block X_i, the derived key, the
/// GCM IV, the key commitment and the sealed output.
#[test]
fn appendix_a_with_intermediates() {
    let v = vectors();
    let cases = v["appendixA"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let kc = c["kcChoice"].as_u64().unwrap() == 1;
        let key = key32(&c["key"]);
        let nonce = hx(&c["nonce"]);
        let ln = nonce.len();

        // Each X_i = AES(K, NHead || ConfigByte + i).
        let aes = Aes256::new((&key).into());
        let config = 128 * u8::from(kc) + 8 * (ln as u8 - 12);
        let mut padded = [0u8; 27];
        padded[..ln].copy_from_slice(&nonce);
        for (i, x) in c["x"].as_array().unwrap().iter().enumerate() {
            let mut block = [0u8; 16];
            block[..15].copy_from_slice(&padded[..15]);
            block[15] = config + i as u8;
            aes.encrypt_block((&mut block).into());
            assert_eq!(block.to_vec(), hx(x), "{name} X{i}");
        }

        let d = dndk_gcm::derive(kc, &key, &nonce).unwrap();
        assert_eq!(d.derived_key.to_vec(), hx(&c["derivedKey"]), "{name} DK");
        assert_eq!(d.gcm_iv.to_vec(), hx(&c["gcmIv"]), "{name} IV");
        assert_eq!(
            d.key_commit.map(|k| k.to_vec()).unwrap_or_default(),
            hx(&c["keyCommit"]),
            "{name} KC"
        );

        let aad = hx(&c["aad"]);
        let pt = hx(&c["plaintext"]);
        let sealed = dndk_gcm::encrypt_with_params(kc, &key, &nonce, &aad, &pt).unwrap();
        assert_eq!(sealed, hx(&c["sealed"]), "{name} sealed");
        assert_eq!(
            dndk_gcm::decrypt_with_params(kc, &key, &nonce, &aad, &sealed).unwrap(),
            pt
        );
    }
}

/// Every official [DNDK-TV] case: 34 encrypt, 34 valid decrypt, 14 invalid.
#[test]
fn official_vectors() {
    let v = vectors();
    let mut counts = [0usize; 3]; // encrypt, decrypt-valid, decrypt-invalid
    let mut labyrinth_profile = 0usize;
    for group in v["official"]["testGroups"].as_array().unwrap() {
        let kc = group["kcMode"].as_bool().unwrap();
        let ty = group["type"].as_str().unwrap();
        for t in group["tests"].as_array().unwrap() {
            let id = t["tcId"].as_u64().unwrap();
            let input = &t["input"];
            let exp = &t["expected"];
            let key = key32(&input["key"]);
            let nonce = nonce_of(input);
            let aad = hx(&input["aad"]);

            if let Some(internals) = t.get("internals") {
                let d = dndk_gcm::derive(kc, &key, &nonce).unwrap();
                assert_eq!(
                    d.derived_key.to_vec(),
                    hx(&internals["derived_key"]),
                    "tc {id} DK"
                );
                assert_eq!(d.gcm_iv.to_vec(), hx(&internals["gcm_iv"]), "tc {id} IV");
            }

            match ty {
                "DndkGcmEncrypt" => {
                    let pt = hx(&input["plaintext"]);
                    let sealed =
                        dndk_gcm::encrypt_with_params(kc, &key, &nonce, &aad, &pt).unwrap();
                    assert_eq!(sealed, hx(&exp["sealed"]), "tc {id} sealed");
                    let mut parts = hx(&exp["ciphertext"]);
                    parts.extend(hx(&exp["tag"]));
                    if kc {
                        parts.extend(hx(&exp["kc"]));
                    }
                    assert_eq!(sealed, parts, "tc {id} C||T||KC");
                    if kc && nonce.len() == 24 {
                        let n24: [u8; 24] = nonce.clone().try_into().unwrap();
                        assert_eq!(
                            dndk_gcm::encrypt_with_nonce(&key, &n24, &aad, &pt).unwrap(),
                            sealed
                        );
                        labyrinth_profile += 1;
                    }
                    counts[0] += 1;
                }
                "DndkGcmDecrypt" => {
                    let sealed = hx(&input["sealed"]);
                    let got = dndk_gcm::decrypt_with_params(kc, &key, &nonce, &aad, &sealed);
                    match exp["result"].as_str().unwrap() {
                        "valid" => {
                            assert_eq!(got.unwrap(), hx(&exp["plaintext"]), "tc {id}");
                            counts[1] += 1;
                        }
                        "invalid" => {
                            assert!(got.is_err(), "tc {id} must be rejected");
                            if kc && nonce.len() == 24 {
                                let n24: [u8; 24] = nonce.clone().try_into().unwrap();
                                assert!(
                                    dndk_gcm::decrypt_with_nonce(&key, &n24, &aad, &sealed)
                                        .is_err()
                                );
                            }
                            counts[2] += 1;
                        }
                        r => panic!("tc {id}: unknown result {r}"),
                    }
                }
                other => panic!("unknown group type {other}"),
            }
        }
    }
    assert_eq!(counts, [34, 34, 14]);
    assert!(
        labyrinth_profile >= 10,
        "KC=1/LN=24 encrypt cases: {labyrinth_profile}"
    );
}

/// The suite-0x02 envelope carries exactly a draft ciphertext-blob.
#[test]
fn envelope_wraps_draft_blob() {
    let v = vectors();
    let a1 = &v["appendixA"][0];
    let key = key32(&a1["key"]);
    let mut env = vec![Suite::DndkGcm as u8];
    env.extend(hx(&a1["nonce"]));
    env.extend(hx(&a1["sealed"]));
    assert_eq!(
        aead::decrypt(&key, &hx(&a1["aad"]), &env).unwrap(),
        hx(&a1["plaintext"])
    );
}

//! Recovery-code KAT (SPEC §6.1). The vector was produced by an independent
//! Python implementation of the same rules.

use labyrinth::recovery_code::{ENTROPY_LEN, RecoveryCode};

#[test]
fn kat() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/recovery_code.json")).unwrap();
    let ent: Vec<u8> = v["entropy_symbols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect();
    let ent: [u8; ENTROPY_LEN] = ent.try_into().unwrap();
    let code = RecoveryCode::from_entropy_symbols(&ent);
    assert_eq!(code.to_string(), v["code"].as_str().unwrap());
    assert_eq!(format!("{code:#}"), v["code_grouped"].as_str().unwrap());
    assert_eq!(
        RecoveryCode::parse(v["code_grouped"].as_str().unwrap()).unwrap(),
        code
    );
    let (id, key) = code.derive(v["did"].as_str().unwrap());
    assert_eq!(hex::encode(id), v["vdevice_id"].as_str().unwrap());
    assert_eq!(
        hex::encode(key.as_slice()),
        v["vdevice_key"].as_str().unwrap()
    );
}

#[test]
fn kat_recovers_from_three_typos() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/recovery_code.json")).unwrap();
    let good = v["code"].as_str().unwrap();
    let did = v["did"].as_str().unwrap();
    let want = hex::decode(v["vdevice_id"].as_str().unwrap()).unwrap();
    // Three substitutions, one in the ECC part; lower case; grouped.
    let mut typo: Vec<u8> = good.bytes().collect();
    typo[4] = b'Z';
    typo[21] = b'7';
    typo[38] = b'A';
    let typo = String::from_utf8(typo).unwrap().to_lowercase();
    assert!(RecoveryCode::parse(&typo).is_err());
    // The caller's backend lookup: keep the candidate whose vdeviceId matches.
    let mut tried = 0;
    let found = RecoveryCode::candidates(&typo)
        .unwrap()
        .inspect(|_| tried += 1)
        .find(|c| c.derive(did).0.as_slice() == want.as_slice())
        .expect("recovered");
    assert_eq!(found.to_string(), good);
    assert!(tried > 0);
}

//! Labyrinth HPKE (SPEC §3.4), Hawk HPKE (§3.5) and ORF (§3.6) through the
//! public API, plus the regression KATs in `tests/vectors/hpke_orf.json`.

use curve25519_dalek::scalar::Scalar;
use labyrinth::Error;
use labyrinth::hpke::hawk::{self, HawkEncPublic};
use labyrinth::hpke::labyrinth::{self as lhpke, X25519Public, X25519Secret};
use labyrinth::orf::{self, EvolveToken, ObliviousId, OrfClientState, OrfServerState};
use serde_json::Value;

fn kp() -> (X25519Secret, X25519Public) {
    let s = X25519Secret::generate().unwrap();
    let p = s.public();
    (s, p)
}

/// Curve25519 points of order 1, 2, 4, 8 and their non-canonical encodings
/// (the list from libsodium / RFC 7748 test suites).
const LOW_ORDER: [&str; 7] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

fn low_order() -> impl Iterator<Item = X25519Public> {
    LOW_ORDER
        .iter()
        .map(|h| X25519Public(hex::decode(h).unwrap().try_into().unwrap()))
}

fn flip(v: &[u8], i: usize) -> Vec<u8> {
    let mut v = v.to_vec();
    v[i] ^= 0x01;
    v
}

// ---------------------------------------------------------------- Labyrinth HPKE

#[test]
fn labyrinth_round_trip() {
    let (rs, rp) = kp();
    let (ss, sp) = kp();
    for pt in [&b""[..], b"x", &[0xab; 1000]] {
        let ct = lhpke::encrypt(&rp, &sp, &ss, b"psk", b"aad", pt).unwrap();
        assert_eq!(ct.len(), 1 + 32 + pt.len() + 16);
        assert_eq!(
            lhpke::decrypt(&rp, &rs, &sp, b"psk", b"aad", &ct).unwrap(),
            pt
        );
    }
    // Fresh ephemeral each time.
    let a = lhpke::encrypt(&rp, &sp, &ss, b"", b"", b"m").unwrap();
    let b = lhpke::encrypt(&rp, &sp, &ss, b"", b"", b"m").unwrap();
    assert_ne!(a, b);
}

#[test]
fn labyrinth_tamper_each_component() {
    let (rs, rp) = kp();
    let (ss, sp) = kp();
    let ct = lhpke::encrypt(&rp, &sp, &ss, b"psk", b"aad", b"secret").unwrap();
    let dec = |rp: &X25519Public,
               rs: &X25519Secret,
               sp: &X25519Public,
               psk: &[u8],
               aad: &[u8],
               ct: &[u8]| { lhpke::decrypt(rp, rs, sp, psk, aad, ct) };
    // Ephemeral public key (byte 1..33), ciphertext body and tag.
    for i in [1, 16, 32, 33, ct.len() - 17, ct.len() - 1] {
        assert!(
            dec(&rp, &rs, &sp, b"psk", b"aad", &flip(&ct, i)).is_err(),
            "byte {i}"
        );
    }
    assert_eq!(dec(&rp, &rs, &sp, b"psk", b"aaD", &ct), Err(Error::Decrypt));
    assert_eq!(dec(&rp, &rs, &sp, b"psK", b"aad", &ct), Err(Error::Decrypt));
    assert_eq!(dec(&rp, &rs, &sp, b"", b"aad", &ct), Err(Error::Decrypt));
    let (_, other_sp) = kp();
    assert_eq!(
        dec(&rp, &rs, &other_sp, b"psk", b"aad", &ct),
        Err(Error::Decrypt)
    );
    let (other_rs, other_rp) = kp();
    assert_eq!(
        dec(&rp, &other_rs, &sp, b"psk", b"aad", &ct),
        Err(Error::Decrypt)
    );
    // Right private key, but the public key bound into inner_aad differs.
    assert_eq!(
        dec(&other_rp, &rs, &sp, b"psk", b"aad", &ct),
        Err(Error::Decrypt)
    );
    assert_eq!(
        dec(&rp, &rs, &sp, b"psk", b"aad", &ct[..ct.len() - 1]),
        Err(Error::Decrypt)
    );
    assert!(matches!(
        dec(&rp, &rs, &sp, b"psk", b"aad", &ct[..48]),
        Err(Error::Malformed(_))
    ));
    let mut v2 = ct.clone();
    v2[0] = 0x02;
    assert_eq!(
        dec(&rp, &rs, &sp, b"psk", b"aad", &v2),
        Err(Error::Unsupported(2))
    );
}

#[test]
fn labyrinth_psk_limit() {
    let (rs, rp) = kp();
    let (ss, sp) = kp();
    let psk32 = [7u8; 32];
    let ct = lhpke::encrypt(&rp, &sp, &ss, &psk32, b"", b"m").unwrap();
    assert_eq!(
        lhpke::decrypt(&rp, &rs, &sp, &psk32, b"", &ct).unwrap(),
        b"m"
    );
    assert!(matches!(
        lhpke::encrypt(&rp, &sp, &ss, &[7u8; 33], b"", b"m"),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        lhpke::decrypt(&rp, &rs, &sp, &[7u8; 33], b"", &ct),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn labyrinth_rejects_low_order_points() {
    let (rs, rp) = kp();
    let (ss, sp) = kp();
    for bad in low_order() {
        // Low-order recipient.
        assert_eq!(
            lhpke::encrypt(&bad, &sp, &ss, b"", b"", b"m").unwrap_err(),
            Error::BadPublicKey
        );
        // Low-order sender auth key on decrypt.
        let ct = lhpke::encrypt(&rp, &sp, &ss, b"", b"", b"m").unwrap();
        assert_eq!(
            lhpke::decrypt(&rp, &rs, &bad, b"", b"", &ct).unwrap_err(),
            Error::BadPublicKey
        );
        // Low-order ephemeral key spliced into the ciphertext.
        let mut forged = ct.clone();
        forged[1..33].copy_from_slice(&bad.0);
        assert_eq!(
            lhpke::decrypt(&rp, &rs, &sp, b"", b"", &forged).unwrap_err(),
            Error::BadPublicKey
        );
    }
}

// ---------------------------------------------------------------- Hawk HPKE

#[test]
fn hawk_round_trip_random_and_derived() {
    let (ss, sp) = hawk::hawk_auth_keygen().unwrap();
    let (rs, rp) = hawk::hawk_enc_keygen().unwrap();
    let ct = hawk::hawk_encrypt(&rp, &ss, &sp, b"aad", b"mek").unwrap();
    assert_eq!(ct.len(), 1 + 32 + 1088 + 3 + 16);
    assert_eq!(
        hawk::hawk_decrypt(&rp, &rs, &sp, b"aad", &ct).unwrap(),
        b"mek"
    );

    let (ss, sp) = hawk::hawk_derive_auth(&[1; 32]);
    let (rs, rp) = hawk::hawk_derive_enc(&[2; 32]);
    let ct = hawk::hawk_encrypt(&rp, &ss, &sp, b"", &[9; 32]).unwrap();
    assert_eq!(
        hawk::hawk_decrypt(&rp, &rs, &sp, b"", &ct).unwrap(),
        [9; 32]
    );
}

#[test]
fn hawk_tamper_each_component() {
    let (ss, sp) = hawk::hawk_auth_keygen().unwrap();
    let (rs, rp) = hawk::hawk_enc_keygen().unwrap();
    let ct = hawk::hawk_encrypt(&rp, &ss, &sp, b"aad", b"mek-bytes").unwrap();
    let dec = |rp: &HawkEncPublic, sp: &X25519Public, aad: &[u8], ct: &[u8]| {
        hawk::hawk_decrypt(rp, &rs, sp, aad, ct)
    };
    assert!(dec(&rp, &sp, b"aad", &ct).is_ok());
    // eph pub, kem ct (first, middle, last byte), AEAD ct, tag.
    for i in [1, 32, 33, 33 + 544, 33 + 1087, 1121, ct.len() - 1] {
        assert!(dec(&rp, &sp, b"aad", &flip(&ct, i)).is_err(), "byte {i}");
    }
    assert_eq!(dec(&rp, &sp, b"aaD", &ct), Err(Error::Decrypt));
    let (_, other_sp) = hawk::hawk_auth_keygen().unwrap();
    assert_eq!(dec(&rp, &other_sp, b"aad", &ct), Err(Error::Decrypt));
    // Wrong recipient private key.
    let (other_rs, other_rp) = hawk::hawk_enc_keygen().unwrap();
    assert_eq!(
        hawk::hawk_decrypt(&rp, &other_rs, &sp, b"aad", &ct),
        Err(Error::Decrypt)
    );
    // Public key bound into info differs (x25519 half, then ML-KEM half).
    assert_eq!(dec(&other_rp, &sp, b"aad", &ct), Err(Error::Decrypt));
    let mixed = HawkEncPublic {
        x25519: rp.x25519,
        mlkem: other_rp.mlkem.clone(),
    };
    assert_eq!(dec(&mixed, &sp, b"aad", &ct), Err(Error::Decrypt));
    assert!(matches!(
        dec(&rp, &sp, b"aad", &ct[..1121 + 15]),
        Err(Error::Malformed(_))
    ));
    let mut v2 = ct.clone();
    v2[0] = 0x02;
    assert_eq!(dec(&rp, &sp, b"aad", &v2), Err(Error::Unsupported(2)));
}

#[test]
fn hawk_rejects_low_order_points() {
    let (ss, sp) = hawk::hawk_auth_keygen().unwrap();
    let (rs, rp) = hawk::hawk_enc_keygen().unwrap();
    let ct = hawk::hawk_encrypt(&rp, &ss, &sp, b"", b"m").unwrap();
    for bad in low_order() {
        let bad_recip = HawkEncPublic {
            x25519: bad,
            mlkem: rp.mlkem.clone(),
        };
        assert_eq!(
            hawk::hawk_encrypt(&bad_recip, &ss, &sp, b"", b"m").unwrap_err(),
            Error::BadPublicKey
        );
        assert_eq!(
            hawk::hawk_decrypt(&rp, &rs, &bad, b"", &ct).unwrap_err(),
            Error::BadPublicKey
        );
        let mut forged = ct.clone();
        forged[1..33].copy_from_slice(&bad.0);
        assert_eq!(
            hawk::hawk_decrypt(&rp, &rs, &sp, b"", &forged).unwrap_err(),
            Error::BadPublicKey
        );
    }
}

#[test]
fn hawk_derivation_is_deterministic() {
    let (a1, ap1) = hawk::hawk_derive_auth(&[5; 32]);
    let (a2, ap2) = hawk::hawk_derive_auth(&[5; 32]);
    assert_eq!(a1.to_bytes(), a2.to_bytes());
    assert_eq!(ap1, ap2);
    assert_eq!(a1.public(), ap1);
    let (_, ap3) = hawk::hawk_derive_auth(&[6; 32]);
    assert_ne!(ap1, ap3);

    let (e1, ep1) = hawk::hawk_derive_enc(&[5; 32]);
    let (_, ep2) = hawk::hawk_derive_enc(&[5; 32]);
    assert_eq!(ep1, ep2);
    assert_eq!(e1.public(), ep1);
    let (_, ep3) = hawk::hawk_derive_enc(&[6; 32]);
    assert_ne!(ep1.x25519, ep3.x25519);
    assert_ne!(ep1.mlkem, ep3.mlkem);
    // Auth and enc derivations are domain separated.
    assert_ne!(ap1, ep1.x25519);
}

#[test]
fn hawk_enc_public_encoding() {
    let (_, p) = hawk::hawk_derive_enc(&[8; 32]);
    let b = p.to_bytes();
    assert_eq!(b.len(), 32 + hawk::MLKEM768_EK_LEN);
    assert_eq!(&b[..32], &p.x25519.0);
    assert_eq!(HawkEncPublic::from_bytes(&b).unwrap(), p);
    assert!(matches!(
        HawkEncPublic::from_bytes(&b[..b.len() - 1]),
        Err(Error::Malformed(_))
    ));
    let mut long = b.clone();
    long.push(0);
    assert!(matches!(
        HawkEncPublic::from_bytes(&long),
        Err(Error::Malformed(_))
    ));
    // A malformed ML-KEM key is refused at encrypt time too.
    let (ss, sp) = hawk::hawk_auth_keygen().unwrap();
    let bad = HawkEncPublic {
        x25519: p.x25519,
        mlkem: vec![0xff; hawk::MLKEM768_EK_LEN],
    };
    assert_eq!(
        hawk::hawk_encrypt(&bad, &ss, &sp, b"", b"").unwrap_err(),
        Error::BadPublicKey
    );
    let short = HawkEncPublic {
        x25519: p.x25519,
        mlkem: vec![0; 10],
    };
    assert_eq!(
        hawk::hawk_encrypt(&short, &ss, &sp, b"", b"").unwrap_err(),
        Error::BadPublicKey
    );
}

// ---------------------------------------------------------------- ORF

fn full_map(c: &OrfClientState, s: &OrfServerState, cd: &[u8], sd: &[u8], x: &[u8]) -> [u8; 32] {
    orf::orf_server_map(s, sd, &orf::orf_client_map(c, cd, x)).unwrap()
}

#[test]
fn orf_invariant_across_evolve_chains() {
    let inputs: [&[u8]; 3] = [b"", b"[\"backup\",\"object\"]", &[0xee; 200]];
    for len in 1..=5 {
        let c0 = orf::orf_client_init().unwrap();
        let s0 = orf::orf_server_init().unwrap();
        let expected: Vec<_> = inputs
            .iter()
            .map(|x| full_map(&c0, &s0, b"attachment_key_scope", b"sd", x))
            .collect();
        let (mut c, mut s) = (c0.clone(), s0.clone());
        for _ in 0..len {
            let (c2, token) = orf::orf_client_evolve(&c).unwrap();
            let s2 = orf::orf_server_evolve(&s, &token).unwrap();
            // The evolved client alone (against the old server) maps differently.
            assert_ne!(
                orf::orf_client_map(&c2, b"d", b"x"),
                orf::orf_client_map(&c, b"d", b"x")
            );
            assert_ne!(c2.to_bytes(), c.to_bytes());
            assert_ne!(s2.to_bytes(), s.to_bytes());
            (c, s) = (c2, s2);
        }
        for (x, e) in inputs.iter().zip(&expected) {
            assert_eq!(
                &full_map(&c, &s, b"attachment_key_scope", b"sd", x),
                e,
                "chain {len}"
            );
        }
        // Mixing generations breaks the mapping (revocation).
        assert_ne!(
            full_map(&c, &s0, b"attachment_key_scope", b"sd", inputs[1]),
            expected[1]
        );
        assert_ne!(
            full_map(&c0, &s, b"attachment_key_scope", b"sd", inputs[1]),
            expected[1]
        );
    }
}

#[test]
fn orf_domain_separation() {
    let c = orf::orf_client_init().unwrap();
    let s = orf::orf_server_init().unwrap();
    let base = full_map(&c, &s, b"attachment_key_scope", b"srv", b"x");
    assert_ne!(
        full_map(&c, &s, b"attachment_token_salt_scope", b"srv", b"x"),
        base
    );
    assert_ne!(
        full_map(&c, &s, b"attachment_key_scope", b"srv2", b"x"),
        base
    );
    assert_ne!(
        full_map(&c, &s, b"attachment_key_scope", b"srv", b"y"),
        base
    );
    assert_ne!(
        orf::orf_client_map(&c, b"a", b"x"),
        orf::orf_client_map(&c, b"b", b"x")
    );
    // Deterministic.
    assert_eq!(
        full_map(&c, &s, b"attachment_key_scope", b"srv", b"x"),
        base
    );
    // Different clients (unrelated keys) give unrelated ids.
    let c2 = orf::orf_client_init().unwrap();
    assert_ne!(
        orf::orf_client_map(&c, b"a", b"x"),
        orf::orf_client_map(&c2, b"a", b"x")
    );
}

#[test]
fn orf_rejects_degenerate_inputs() {
    assert!(OrfClientState::from_bytes([0; 32]).is_err());
    assert!(OrfServerState::from_bytes([0; 32]).is_err());
    // l itself is non-canonical.
    let l =
        hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").unwrap();
    assert!(OrfClientState::from_bytes(l.clone().try_into().unwrap()).is_err());
    assert!(OrfClientState::from_bytes(Scalar::ONE.to_bytes()).is_ok());
    let s = orf::orf_server_init().unwrap();
    assert!(orf::orf_server_evolve(&s, &EvolveToken([0; 32])).is_err());
    assert!(orf::orf_server_evolve(&s, &EvolveToken(l.try_into().unwrap())).is_err());
    // Identity point and invalid encodings.
    assert!(orf::orf_server_map(&s, b"d", &ObliviousId([0; 32])).is_err());
    assert!(orf::orf_server_map(&s, b"d", &ObliviousId([0xff; 32])).is_err());
    let c = OrfClientState::from_bytes(orf::orf_client_init().unwrap().to_bytes()).unwrap();
    assert!(orf::orf_server_map(&s, b"d", &orf::orf_client_map(&c, b"d", b"x")).is_ok());
}

// ---------------------------------------------------------------- KATs

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/hpke_orf.json")).unwrap()
}
fn h(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
fn a32(v: &Value, k: &str) -> [u8; 32] {
    h(v, k).try_into().unwrap()
}

#[test]
fn kat_labyrinth_hpke() {
    let v = vectors();
    let cases = v["labyrinth_hpke"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let sa = X25519Secret::from_bytes(a32(c, "sender_auth_priv"));
        let r = X25519Secret::from_bytes(a32(c, "recipient_enc_priv"));
        assert_eq!(sa.public().0, a32(c, "sender_auth_pub"));
        assert_eq!(r.public().0, a32(c, "recipient_enc_pub"));
        let ct = h(c, "ct");
        assert_eq!(
            &ct[1..33],
            &X25519Secret::from_bytes(a32(c, "ephemeral_priv"))
                .public()
                .0
        );
        let pt = lhpke::decrypt(
            &r.public(),
            &r,
            &sa.public(),
            &h(c, "psk"),
            &h(c, "aad"),
            &ct,
        )
        .unwrap();
        assert_eq!(pt, h(c, "pt"));
    }
}

#[test]
fn kat_hawk_hpke() {
    let v = vectors();
    let cases = v["hawk_hpke"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let (sa, sp) = hawk::hawk_derive_auth(&a32(c, "auth_seed"));
        assert_eq!(sa.to_bytes(), a32(c, "auth_priv"));
        assert_eq!(sp.0, a32(c, "auth_pub"));
        let (rs, rp) = hawk::hawk_derive_enc(&a32(c, "enc_seed"));
        assert_eq!(rp.to_bytes(), h(c, "enc_pub"));
        assert_eq!(HawkEncPublic::from_bytes(&h(c, "enc_pub")).unwrap(), rp);
        let pt = hawk::hawk_decrypt(&rp, &rs, &sp, &h(c, "aad"), &h(c, "ct")).unwrap();
        assert_eq!(pt, h(c, "pt"));
    }
}

#[test]
fn kat_orf() {
    let v = vectors();
    let cases = v["orf"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let cs = OrfClientState::from_bytes(a32(c, "client_state")).unwrap();
        let ss = OrfServerState::from_bytes(a32(c, "server_state")).unwrap();
        let (cd, sd, input) = (h(c, "client_domain"), h(c, "server_domain"), h(c, "input"));
        let id = orf::orf_client_map(&cs, &cd, &input);
        assert_eq!(id.0, a32(c, "oblivious_id"));
        assert_eq!(
            orf::orf_server_map(&ss, &sd, &id).unwrap(),
            a32(c, "output")
        );
        let token = EvolveToken(a32(c, "evolve_token"));
        let ss2 = orf::orf_server_evolve(&ss, &token).unwrap();
        assert_eq!(ss2.to_bytes(), a32(c, "evolved_server_state"));
        // c' = c * r (what orf_client_evolve computes for this token).
        let r = Scalar::from_canonical_bytes(token.0).unwrap();
        let c_scalar = Scalar::from_canonical_bytes(cs.to_bytes()).unwrap();
        let cs2 = OrfClientState::from_bytes((c_scalar * r).to_bytes()).unwrap();
        let id2 = orf::orf_client_map(&cs2, &cd, &input);
        assert_ne!(id2, id);
        assert_eq!(
            orf::orf_server_map(&ss2, &sd, &id2).unwrap(),
            a32(c, "output")
        );
    }
}

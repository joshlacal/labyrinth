//! draft-irtf-cfrg-cpace-21 Appendix B.3 (ristretto255 / SHA-512).

use labyrinth::otc::cpace;
use sha2::{Digest, Sha512};

fn v() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/cpace_ristretto255.json")).unwrap()
}

fn h(v: &serde_json::Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}

fn h32(v: &serde_json::Value, k: &str) -> [u8; 32] {
    h(v, k).try_into().unwrap()
}

#[test]
fn generator() {
    let v = v();
    let (prs, ci, sid) = (h(&v, "PRS"), h(&v, "CI"), h(&v, "sid"));
    let gs = cpace::generator_string(&prs, &ci, &sid);
    assert_eq!(gs.as_slice(), h(&v, "generator_string").as_slice());
    assert_eq!(
        Sha512::digest(gs.as_slice()).as_slice(),
        h(&v, "generator_hash")
    );
    let g = cpace::calculate_generator(&prs, &ci, &sid);
    assert_eq!(g.compress().to_bytes().to_vec(), h(&v, "g"));
}

#[test]
fn messages_k_and_isk() {
    let v = v();
    let (prs, ci, sid) = (h(&v, "PRS"), h(&v, "CI"), h(&v, "sid"));
    let g = cpace::calculate_generator(&prs, &ci, &sid);
    let ya = cpace::scalar_from_bytes(&h32(&v, "ya"));
    let yb = cpace::scalar_from_bytes(&h32(&v, "yb"));
    let ya_pub = cpace::scalar_mult(&ya, &g);
    let yb_pub = cpace::scalar_mult(&yb, &g);
    assert_eq!(ya_pub, h32(&v, "Ya"));
    assert_eq!(yb_pub, h32(&v, "Yb"));
    let ka = cpace::scalar_mult_vfy(&ya, &yb_pub).unwrap();
    let kb = cpace::scalar_mult_vfy(&yb, &ya_pub).unwrap();
    assert_eq!(ka, h32(&v, "K"));
    assert_eq!(kb, h32(&v, "K"));

    let (ada, adb) = (h(&v, "ADa"), h(&v, "ADb"));
    let tir = cpace::transcript_ir(&ya_pub, &ada, &yb_pub, &adb);
    assert_eq!(tir, h(&v, "transcript_ir"));
    let isk = cpace::isk_ir(&sid, &ka, &ya_pub, &ada, &yb_pub, &adb);
    assert_eq!(isk.as_bytes().to_vec(), h(&v, "ISK_IR"));

    let toc = cpace::transcript_oc(&ya_pub, &ada, &yb_pub, &adb);
    assert_eq!(toc, h(&v, "transcript_oc"));
    let isk_sy = cpace::isk(&sid, &ka, &toc);
    assert_eq!(isk_sy.as_bytes().to_vec(), h(&v, "ISK_SY"));

    let sid_ir = Sha512::digest([b"CPaceSidOutput".as_slice(), &tir].concat());
    assert_eq!(sid_ir.as_slice(), h(&v, "sid_output_ir"));
    let sid_oc = Sha512::digest([b"CPaceSidOutput".as_slice(), &toc].concat());
    assert_eq!(sid_oc.as_slice(), h(&v, "sid_output_oc"));
}

#[test]
fn scalar_mult_vfy_valid_and_invalid() {
    let v = v();
    let ok = &v["valid_scalar_mult"];
    let s = cpace::scalar_from_bytes(&h32(ok, "s"));
    assert_eq!(
        cpace::scalar_mult_vfy(&s, &h32(ok, "X")).unwrap(),
        h32(ok, "result")
    );
    let bad = &v["invalid_scalar_mult_vfy"];
    let s = cpace::scalar_from_bytes(&h32(bad, "s"));
    assert!(cpace::scalar_mult_vfy(&s, &h32(bad, "Y_i1")).is_none());
    assert!(cpace::scalar_mult_vfy(&s, &h32(bad, "Y_i2")).is_none());
}

#[test]
fn leb128_prepend_len() {
    let mut out = Vec::new();
    cpace::prepend_len(&mut out, &[0u8; 127]);
    assert_eq!(out[0], 0x7f);
    let mut out = Vec::new();
    cpace::prepend_len(&mut out, &[0u8; 128]);
    assert_eq!(&out[..2], &[0x80, 0x01]);
    let mut out = Vec::new();
    cpace::prepend_len(&mut out, &[0u8; 300]);
    assert_eq!(&out[..2], &[0xac, 0x02]);
}

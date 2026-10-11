//! Integration tests for the public primitive API: AEAD envelope + padding,
//! XEdDSA, Ed25519 transport, and encodings.

use labyrinth::Error;
use labyrinth::aead::{self, Suite};
use labyrinth::encoding;
use labyrinth::padding;
use labyrinth::sign::{Ed25519Transport, TransportSigner, XSigningKey, verify_transport};

#[test]
fn padded_message_round_trip_under_both_suites() {
    let key = [0x24u8; 32];
    for suite in [Suite::GcmExtended, Suite::DndkGcm] {
        for len in [0usize, 9, 10, 11, 255, 256, 1 << 16] {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = aead::encrypt(suite, &key, b"message_thread_t", &padding::pad(&msg)).unwrap();
            let overhead = match suite {
                Suite::GcmExtended => 1 + 28 + 16,
                Suite::DndkGcm => 1 + 24 + 16 + 32,
            };
            assert_eq!(ct.len(), overhead + 4 + padding::padme_len(len));
            let pt =
                padding::unpad(&aead::decrypt(&key, b"message_thread_t", &ct).unwrap()).unwrap();
            assert_eq!(pt, msg);
        }
    }
}

#[test]
fn padding_hides_small_length_differences() {
    let key = [1u8; 32];
    let a = aead::seal(&key, b"", &padding::pad(b"hi")).unwrap();
    let b = aead::seal(&key, b"", &padding::pad(b"hello!!")).unwrap();
    assert_eq!(a.len(), b.len());
}

#[test]
fn wrong_key_and_aad_fail() {
    let ct = aead::seal(&[1u8; 32], b"epoch_data_metadata", b"7").unwrap();
    assert_eq!(
        aead::decrypt(&[2u8; 32], b"epoch_data_metadata", &ct),
        Err(Error::Decrypt)
    );
    assert_eq!(
        aead::decrypt(&[1u8; 32], b"epoch_data_metadatA", &ct),
        Err(Error::Decrypt)
    );
    assert_eq!(
        aead::decrypt(&[1u8; 32], b"epoch_data_metadata", &ct).unwrap(),
        b"7"
    );
}

#[test]
fn xeddsa_public_api() {
    let sk = XSigningKey::generate().unwrap();
    let restored = XSigningKey::from_bytes(sk.to_bytes());
    assert_eq!(sk.public(), restored.public());
    let pk = sk.public();
    let sig = restored.sign_use_case(0x31, b"auth key").unwrap();
    pk.verify_use_case(0x31, b"auth key", &sig).unwrap();
    assert_eq!(
        pk.verify_use_case(0x30, b"auth key", &sig),
        Err(Error::BadSignature)
    );

    let prefixed = b"minos.unstructured_signature.epoch_self:\x00\x01";
    let sig = sk.sign(prefixed).unwrap();
    pk.verify(prefixed, &sig).unwrap();

    // Serde round trip of the public key.
    let json = serde_json::to_string(&pk).unwrap();
    let back: labyrinth::sign::XVerifyingKey = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pk);
}

#[test]
fn ed25519_transport_public_api() {
    let t = Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]));
    let sig = t.sign_transport(b"msg");
    verify_transport(&t.transport_public_key(), b"msg", &sig).unwrap();
    assert!(verify_transport(&t.transport_public_key(), b"msG", &sig).is_err());
    // An XEdDSA public key is not an Ed25519 key.
    let x = XSigningKey::generate().unwrap();
    let xsig = x.sign(b"msg").unwrap();
    assert!(verify_transport(&x.public().0, b"msg", &xsig).is_err());
}

#[test]
fn encodings_public_api() {
    assert_eq!(encoding::b64_decimal(3), "Mw==");
    assert_eq!(
        encoding::minos_salt(),
        encoding::sha256(b"minos encrypted backup protocol\n")
    );
    let mut two = [0u8; 64];
    encoding::kdf(b"root", None, b"epoch_chaining_0_000000000000", &mut two);
    assert_eq!(
        &two[..32],
        &encoding::kdf32(b"root", None, b"epoch_chaining_0_000000000000")
    );
    assert_eq!(encoding::hex(&encoding::mac(b"", b"")).len(), 64);
}

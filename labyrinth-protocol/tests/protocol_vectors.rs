//! Plan 03 (W6) Task 1: Conformance and security vectors for `labyrinth-protocol`.

use curve25519_dalek::{
    edwards::EdwardsPoint,
    montgomery::MontgomeryPoint,
    scalar::{Scalar, clamp_integer},
};
use ed25519_dalek::Signer as _;
use labyrinth_protocol::{
    ProtocolError,
    epoch_chain::{
        EpochPublicHeader, MemberBinding, compute_epoch_head, compute_members_hash,
        verify_epoch_public_chain,
    },
    limits::HAWK_ENC_PUBKEY_LEN,
    receipt::{
        SequencerReceiptPayload, compute_archive_commitment, sign_sequencer_receipt,
        verify_archived_item_commitment, verify_sequencer_receipt,
    },
    transcripts::{EPOCH_ATTEST_PREFIX, EPOCH_PREV_SIG_PREFIX, EPOCH_SELF_SIG_PREFIX},
};
use p256::ecdsa::SigningKey;
use sha2::{Digest as _, Sha512};

fn test_xeddsa_sign(secret: &[u8; 32], msg: &[u8], z: &[u8; 64]) -> ([u8; 32], [u8; 64]) {
    let clamped = clamp_integer(*secret);
    let mut a = Scalar::from_bytes_mod_order(clamped);
    let e = EdwardsPoint::mul_base(&a);
    let (a_point, a_scalar) = if (e.compress().as_bytes()[31] >> 7) == 1 {
        a = -a;
        (-e, a)
    } else {
        (e, a)
    };
    let a_bytes = a_point.compress().to_bytes();

    let mut hash1_prefix = [0xffu8; 32];
    hash1_prefix[0] = 0xfe;
    let mut h1 = Sha512::new();
    h1.update(hash1_prefix);
    h1.update(a_scalar.as_bytes());
    h1.update(msg);
    h1.update(z);
    let wide_r: [u8; 64] = h1.finalize().into();
    let r = Scalar::from_bytes_mod_order_wide(&wide_r);
    let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();

    let mut hc = Sha512::new();
    hc.update(r_bytes);
    hc.update(a_bytes);
    hc.update(msg);
    let wide_h: [u8; 64] = hc.finalize().into();
    let h = Scalar::from_bytes_mod_order_wide(&wide_h);
    let s = r + h * a_scalar;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(s.as_bytes());
    let mont_pub = MontgomeryPoint::mul_base_clamped(*secret).to_bytes();
    (mont_pub, sig)
}

#[test]
fn archive_commitment_is_blinded_hmac_sha256_and_detects_tampering() {
    let nonce_a = [0x42u8; 32];
    let nonce_b = [0x43u8; 32];
    let payload_ok = br#"{"$type":"blue.catbird.chat.message","text":"ok"}"#;
    let payload_no = br#"{"$type":"blue.catbird.chat.message","text":"no"}"#;

    let c1 = compute_archive_commitment(&nonce_a, payload_ok);
    let c2 = compute_archive_commitment(&nonce_a, payload_ok);
    assert_eq!(c1, c2);
    assert_ne!(c1, compute_archive_commitment(&nonce_b, payload_ok));
    assert_ne!(c1, compute_archive_commitment(&nonce_a, payload_no));

    let sk = SigningKey::from_slice(&[0x11u8; 32]).expect("valid P-256 scalar");
    let receipt = sign_sequencer_receipt(
        &sk,
        "did:web:ds.catbird.blue#mls-receipt-1",
        &SequencerReceiptPayload {
            sequencer_did: "did:web:ds.catbird.blue".to_string(),
            conversation_id: "11111111-1111-4111-8111-111111111111".to_string(),
            group_id: vec![0xaa; 32],
            epoch: 3,
            sender_device_did_url:
                "did:plc:ewvi7nxzyoun6zhxrhs64oiz#22222222-2222-4222-8222-222222222222".to_string(),
            entry_id: "33333333-3333-4333-8333-333333333333".to_string(),
            archive_commitment: c1,
            seq: 42,
            issued_at_ms: 1_793_462_400_000,
        },
    )
    .expect("receipt signs");

    verify_sequencer_receipt(sk.verifying_key(), "did:web:ds.catbird.blue", &receipt)
        .expect("did:web receipt verifies");
    verify_archived_item_commitment(&receipt, &nonce_a, payload_ok)
        .expect("matching nonce + payload verifies");

    // Gate 1 substitution attack: mutated payload or mutated nonce must fail with ReceiptCommitmentMismatch.
    assert_eq!(
        verify_archived_item_commitment(&receipt, &nonce_a, payload_no),
        Err(ProtocolError::ReceiptCommitmentMismatch)
    );
    assert_eq!(
        verify_archived_item_commitment(&receipt, &nonce_b, payload_ok),
        Err(ProtocolError::ReceiptCommitmentMismatch)
    );
}

#[test]
fn sequencer_receipt_supports_did_plc_and_rejects_wrong_authority_or_kid() {
    let sk = SigningKey::from_slice(&[0x22u8; 32]).expect("valid P-256 scalar");
    let other_sk = SigningKey::from_slice(&[0x33u8; 32]).expect("valid P-256 scalar");
    let commitment = compute_archive_commitment(&[0x99u8; 32], b"hello");

    let payload = SequencerReceiptPayload {
        sequencer_did: "did:plc:z72i7hdynmk6r22z27h6tvur".to_string(),
        conversation_id: "11111111-1111-4111-8111-111111111111".to_string(),
        group_id: vec![0xbb; 32],
        epoch: 7,
        sender_device_did_url:
            "did:plc:ewvi7nxzyoun6zhxrhs64oiz#22222222-2222-4222-8222-222222222222".to_string(),
        entry_id: "44444444-4444-4444-8444-444444444444".to_string(),
        archive_commitment: commitment,
        seq: 1,
        issued_at_ms: 1_793_462_401_234,
    };

    // Wrong kid fragment rejected on sign
    assert!(
        sign_sequencer_receipt(&sk, "did:plc:z72i7hdynmk6r22z27h6tvur#atproto", &payload).is_err()
    );

    let receipt = sign_sequencer_receipt(
        &sk,
        "did:plc:z72i7hdynmk6r22z27h6tvur#mls-receipt-1",
        &payload,
    )
    .expect("did:plc receipt signs");

    verify_sequencer_receipt(
        sk.verifying_key(),
        "did:plc:z72i7hdynmk6r22z27h6tvur",
        &receipt,
    )
    .expect("did:plc receipt verifies");

    // Wrong expected sequencer DID
    assert!(
        verify_sequencer_receipt(sk.verifying_key(), "did:web:evil.example", &receipt).is_err()
    );
    // Wrong key
    assert!(
        verify_sequencer_receipt(
            other_sk.verifying_key(),
            "did:plc:z72i7hdynmk6r22z27h6tvur",
            &receipt
        )
        .is_err()
    );
    // Tampered seq
    let mut tampered = receipt.clone();
    tampered.payload.seq = 2;
    assert!(
        verify_sequencer_receipt(
            sk.verifying_key(),
            "did:plc:z72i7hdynmk6r22z27h6tvur",
            &tampered
        )
        .is_err()
    );
}

#[test]
fn epoch_public_chain_verifies_members_hash_links_and_floor_seq() {
    let did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    let transport_sk = ed25519_dalek::SigningKey::from_bytes(&[0x55u8; 32]);
    let transport_pk = transport_sk.verifying_key().to_bytes();

    let m0 = vec![MemberBinding {
        device_key_pub: [0x01; 32],
        epoch_storage_key_pub: vec![0xaa; HAWK_ENC_PUBKEY_LEN],
        is_virtual: false,
    }];
    let mh0 = compute_members_hash(&m0).expect("valid members_hash 0");

    let sig_sk0 = [0x10u8; 32];
    let (sig_pk0, _) = test_xeddsa_sign(&sig_sk0, b"probe", &[0u8; 64]);
    let auth_pk0 = [0x20u8; 32];
    let enc_pk0 = vec![0x30u8; HAWK_ENC_PUBKEY_LEN];
    let head0 = compute_epoch_head(0, &auth_pk0, &enc_pk0, &sig_pk0, &mh0, None, did);
    let (_, self_sig0) = test_xeddsa_sign(
        &sig_sk0,
        &[EPOCH_SELF_SIG_PREFIX, head0.as_slice()].concat(),
        &[0x01u8; 64],
    );
    let attest_msg0 = [
        format!("{EPOCH_ATTEST_PREFIX}{did}:").as_bytes(),
        head0.as_slice(),
    ]
    .concat();
    let h0 = EpochPublicHeader {
        seq: 0,
        auth_pubkey: auth_pk0,
        encryption_pubkey: enc_pk0,
        signing_pubkey: sig_pk0,
        members_hash: mh0,
        prev_head: None,
        head: head0,
        self_sig: self_sig0,
        prev_sig: None,
        attestation_pubkey: transport_pk,
        attestation_sig: transport_sk.sign(&attest_msg0).to_bytes(),
    };

    let m1 = vec![
        MemberBinding {
            device_key_pub: [0x02; 32],
            epoch_storage_key_pub: vec![0xbb; HAWK_ENC_PUBKEY_LEN],
            is_virtual: true,
        },
        m0[0].clone(),
    ];
    let mh1 = compute_members_hash(&m1).expect("valid members_hash 1");
    // Order-independent canonical sorting
    let mh1_reversed =
        compute_members_hash(&[m1[1].clone(), m1[0].clone()]).expect("valid members_hash 1 rev");
    assert_eq!(mh1, mh1_reversed);

    let sig_sk1 = [0x11u8; 32];
    let (sig_pk1, _) = test_xeddsa_sign(&sig_sk1, b"probe", &[0u8; 64]);
    let auth_pk1 = [0x21u8; 32];
    let enc_pk1 = vec![0x31u8; HAWK_ENC_PUBKEY_LEN];
    let head1 = compute_epoch_head(1, &auth_pk1, &enc_pk1, &sig_pk1, &mh1, Some(&head0), did);
    let (_, self_sig1) = test_xeddsa_sign(
        &sig_sk1,
        &[EPOCH_SELF_SIG_PREFIX, head1.as_slice()].concat(),
        &[0x02u8; 64],
    );
    let (_, prev_sig1) = test_xeddsa_sign(
        &sig_sk0,
        &[EPOCH_PREV_SIG_PREFIX, head1.as_slice()].concat(),
        &[0x03u8; 64],
    );
    let attest_msg1 = [
        format!("{EPOCH_ATTEST_PREFIX}{did}:").as_bytes(),
        head1.as_slice(),
    ]
    .concat();
    let h1 = EpochPublicHeader {
        seq: 1,
        auth_pubkey: auth_pk1,
        encryption_pubkey: enc_pk1,
        signing_pubkey: sig_pk1,
        members_hash: mh1,
        prev_head: Some(head0),
        head: head1,
        self_sig: self_sig1,
        prev_sig: Some(prev_sig1),
        attestation_pubkey: transport_pk,
        attestation_sig: transport_sk.sign(&attest_msg1).to_bytes(),
    };

    let verified =
        verify_epoch_public_chain(did, &[h0.clone(), h1.clone()], 1).expect("chain verifies");
    assert_eq!(verified.latest.seq, 1);
    assert_eq!(verified.latest.members_hash, mh1);

    // L-F01 rollback check: floor_seq = 2 must reject a chain ending at seq = 1
    assert_eq!(
        verify_epoch_public_chain(did, &[h0.clone(), h1.clone()], 2),
        Err(ProtocolError::EpochRollback {
            latest_seq: 1,
            floor_seq: 2
        })
    );

    // Tampered members_hash must fail head verification
    let mut bad_mh = h1.clone();
    bad_mh.members_hash[0] ^= 0xff;
    assert!(verify_epoch_public_chain(did, &[h0.clone(), bad_mh], 1).is_err());

    // Virtual flag flip changes members_hash (Gate 2)
    let mut m1_flipped = m1.clone();
    m1_flipped[0].is_virtual = false;
    assert_ne!(compute_members_hash(&m1_flipped).unwrap(), mh1);
}

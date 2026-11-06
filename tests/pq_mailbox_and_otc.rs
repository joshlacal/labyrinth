//! Gate 2 + `I16` post-quantum mailbox `epoch_storage_key` (`Hawk HPKE` + PSK)
//! and hybrid `CPace + ephemeral ML-KEM-768` `OTC` tests.

use labyrinth::Error;
use labyrinth::device::{
    DevicePublic, DeviceSecrets, USE_CASE_STORAGE, USE_CASE_STORAGE_AUTH, USE_CASE_VIRTUAL_STORAGE,
};
use labyrinth::epoch::{
    EpochKeys as _, OpenedEpoch, forward_chain, open_genesis, open_next, verify_member,
};
use labyrinth::hpke::X25519Secret;
use labyrinth::hpke::hawk::{
    HAWK_ENC_PUBLIC_LEN, HawkEncSecret, MLKEM768_CT_LEN, MLKEM768_EK_LEN, hawk_decrypt_with_psk,
};
use labyrinth::otc::{Initiator, OneTimeCode, Responder, cpace, derive_otc_seal_key};
use labyrinth::recovery_code::RecoveryCode;
use labyrinth::sign::Ed25519Transport;
use labyrinth::virtual_device::{
    Mechanism, OtcPayload, create as create_vdevice, open as open_vdevice,
};

fn transport() -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[0x21; 32]))
}

#[test]
fn pq_post_compromise_healing_resists_epoch0_root_plus_x25519_dlog_oracle() {
    let did = "did:plc:alicepq";
    let t = transport();

    let dev_a = DeviceSecrets::generate().unwrap();
    let dev_b = DeviceSecrets::generate().unwrap();
    assert_eq!(
        dev_a.public().epoch_storage_key_pub.to_bytes().len(),
        HAWK_ENC_PUBLIC_LEN
    );
    assert_eq!(
        dev_b.public().epoch_storage_key_pub.to_bytes().len(),
        HAWK_ENC_PUBLIC_LEN
    );

    // Genesis epoch 0 opened by dev_a; dev_b admitted in epoch 0, then rotated into epoch 1,
    // and then rotated into epoch 2 so we test full carry-over entropy sealing.
    let (p0, n0) = open_genesis(did, &dev_a, &t).unwrap();
    let e0 = p0.assign_id("000000000000");
    let dev_b_m0 = labyrinth::epoch::add_device_mac(&e0, dev_b.public()).unwrap();
    let mut e0_members = n0.members.clone();
    e0_members.push(dev_b_m0);

    // Rotate 0 -> 1 carrying dev_b over.
    let (p1, n1) = open_next(
        did,
        &e0,
        &n0.record.public,
        &e0_members,
        std::slice::from_ref(dev_b.public()),
        &dev_a,
        &t,
    )
    .unwrap();
    let e1_opener_view = p1.assign_id("000000000001");

    let b_member_e1 = n1
        .member(dev_b.public())
        .expect("dev_b carried into epoch 1");
    let ct_b = b_member_e1
        .encrypted_entropy
        .as_deref()
        .expect("carried member has Hawk+PSK encrypted_entropy");
    // Hawk ciphertext layout: 0x01 || eph_x25519(32) || mlkem768_ct(1088) || aes256gcm(32 + 16)
    assert_eq!(ct_b.len(), 1 + 32 + MLKEM768_CT_LEN + 32 + 16);

    // Legitimate dev_b forward-chains cleanly into epoch 1.
    let opened_for_b = OpenedEpoch {
        epoch_id: "000000000001",
        record: &n1.record,
        my_member: b_member_e1,
        opener: dev_a.public(),
        opener_prev_member: Some(n0.member(dev_a.public()).unwrap()),
    };
    let e1_b_view = forward_chain(
        did,
        &e0,
        &n0.record.public,
        &opened_for_b,
        &dev_b.storage,
        dev_b.is_virtual(),
    )
    .unwrap();
    assert_eq!(e1_b_view.root(), e1_opener_view.root());

    // Quantum + state-compromise adversary:
    // Given epoch_0 root (hence exact dist_psk and chain_key) AND a quantum discrete-log
    // oracle revealing dev_b's exact X25519 secret key AND dev_a's X25519 auth key,
    // WITHOUT dev_b's 64-byte ML-KEM-768 seed.
    let b_storage_bytes = dev_b.storage.to_bytes();
    let mut b_x25519_raw = [0u8; 32];
    b_x25519_raw.copy_from_slice(&b_storage_bytes[..32]);
    let mut wrong_storage_bytes = [0u8; 96];
    wrong_storage_bytes[..32].copy_from_slice(&b_x25519_raw);
    wrong_storage_bytes[32..].copy_from_slice(&[0xAA; 64]); // wrong ML-KEM-768 seed
    let quantum_dlog_only_secret = HawkEncSecret::from_bytes(wrong_storage_bytes);

    // Derive exact epoch_0 dist_psk via public spec formula:
    let mut okm = [0u8; 64];
    labyrinth::encoding::kdf(e0.root(), None, b"epoch_chaining_0_000000000000", &mut okm);
    let dist_psk = &okm[32..64];
    let aad = b"epoch__1";
    let opener_auth_pub = dev_a.public().verified_auth_key().unwrap();

    let res = hawk_decrypt_with_psk(
        &dev_b.public().epoch_storage_key_pub,
        &quantum_dlog_only_secret,
        &opener_auth_pub,
        dist_psk,
        aad,
        ct_b,
    );
    assert_eq!(res, Err(Error::Decrypt));

    // Conversely, an adversary with dev_b's full HawkEncSecret (X25519 + ML-KEM-768)
    // but WITHOUT epoch_0's dist_psk also fails (forward PSK binding).
    let wrong_psk = [0x99u8; 32];
    let res_bad_psk = hawk_decrypt_with_psk(
        &dev_b.public().epoch_storage_key_pub,
        &dev_b.storage,
        &opener_auth_pub,
        &wrong_psk,
        aad,
        ct_b,
    );
    assert_eq!(res_bad_psk, Err(Error::Decrypt));
}

#[test]
fn quantum_hndl_otc_resists_known_code_and_cpace_isk_without_mlkem_dk() {
    let did = "did:plc:otcpq";
    let code = OneTimeCode::parse("654321").unwrap();

    //Deterministic CPace scalars so the HNDL test adversary can recompute the exact CPace ISK!
    let scalar_a = cpace::scalar_from_bytes(&[0x11; 32]);
    let scalar_b = cpace::scalar_from_bytes(&[0x22; 32]);
    let sid = [0x33; 16];

    let (init, m1) = Initiator::start_deterministic(&code, did, sid, scalar_a).unwrap();
    assert_eq!(m1.ek_otc.len(), MLKEM768_EK_LEN);
    assert_eq!(
        m1.ad.as_slice(),
        labyrinth::encoding::sha256(&m1.ek_otc).as_slice()
    );

    let mut resp = Responder::new(code.clone(), did);
    let (m2, resp_key) = resp.respond_deterministic(&m1, scalar_b).unwrap();
    assert_eq!(m2.kem_ct.len(), MLKEM768_CT_LEN);
    assert_eq!(
        m2.ad.as_slice(),
        labyrinth::encoding::sha256(&m2.kem_ct).as_slice()
    );

    // Enrolled device seals the salt-free OtcPayload.
    let epoch = labyrinth::epoch::EpochSecret::from_parts(4, "000000000004", [0x77; 32]);
    let payload = OtcPayload::new(epoch.clone());
    let sealed_payload = payload.seal(&resp_key).unwrap();

    // Legitimate initiator finishes with dk_otc and opens OtcPayload.
    let init_key = init.finish(&m2).unwrap();
    assert_eq!(init_key.as_bytes(), resp_key.as_bytes());
    let opened = OtcPayload::open(&init_key, &sealed_payload).unwrap();
    assert_eq!(opened.epoch.seq, 4);
    assert_eq!(opened.epoch.root(), &[0x77; 32]);

    // Quantum HNDL adversary:
    // Captures (m1, m2, sealed_payload) on the wire, later learns the 6-digit code AND
    // breaks ristretto255 discrete log with a quantum computer (recovering scalar_a & scalar_b,
    // and thus the exact 64-byte CPace ISK!).
    let k_shared = cpace::scalar_mult_vfy(&scalar_a, &m2.yb).unwrap();
    let broken_cpace_isk = cpace::isk_ir(&m1.sid, &k_shared, &m1.ya, &m1.ad, &m2.yb, &m2.ad);

    // Without dk_otc, any guessed ML-KEM-768 shared secret produces an unrelated seal key.
    let guessed_mlkem_ss = [0x00u8; 32];
    let attacker_key = derive_otc_seal_key(&broken_cpace_isk, &guessed_mlkem_ss);
    assert_ne!(attacker_key.as_bytes(), resp_key.as_bytes());
    assert_eq!(
        OtcPayload::open(&attacker_key, &sealed_payload).err(),
        Some(Error::Decrypt)
    );
}

#[test]
fn gate2_virtual_device_0x32_tag_device_mac_and_members_hash_binding() {
    let did = "did:plc:gate2";
    let t = transport();

    let phys = DeviceSecrets::generate().unwrap();
    let virt = DeviceSecrets::generate_virtual().unwrap();
    phys.public().verify().unwrap();
    virt.public().verify().unwrap();

    // 1. Physical device uses 0x30; virtual device uses 0x32.
    assert!(
        phys.public()
            .device_key_pub
            .verify_use_case(
                USE_CASE_STORAGE,
                &phys.public().epoch_storage_key_pub.to_bytes(),
                &phys.public().sig_storage,
            )
            .is_ok()
    );
    assert!(
        virt.public()
            .device_key_pub
            .verify_use_case(
                USE_CASE_VIRTUAL_STORAGE,
                &virt.public().epoch_storage_key_pub.to_bytes(),
                &virt.public().sig_storage,
            )
            .is_ok()
    );

    // Downgrade attack: stripping auth key + sig_0x31 from a physical device and setting
    // is_virtual = true MUST fail verification because sig_storage was signed under 0x30, not 0x32!
    let downgraded = DevicePublic {
        device_key_pub: phys.public().device_key_pub,
        epoch_storage_key_pub: phys.public().epoch_storage_key_pub.clone(),
        sig_storage: phys.public().sig_storage,
        epoch_storage_auth_key_pub: None,
        sig_0x31: None,
        is_virtual: true,
    };
    assert_eq!(downgraded.verify(), Err(Error::BadSignature));

    // Upgrade attack: turning a virtual device into physical with a valid 0x31 sig MUST fail!
    let fake_auth = X25519Secret::generate().unwrap();
    let fake_sig_31 = virt
        .device_key
        .sign_use_case(USE_CASE_STORAGE_AUTH, &fake_auth.public().0)
        .unwrap();
    let upgraded = DevicePublic {
        device_key_pub: virt.public().device_key_pub,
        epoch_storage_key_pub: virt.public().epoch_storage_key_pub.clone(),
        sig_storage: virt.public().sig_storage,
        epoch_storage_auth_key_pub: Some(fake_auth.public()),
        sig_0x31: Some(fake_sig_31),
        is_virtual: false,
    };
    assert_eq!(upgraded.verify(), Err(Error::BadSignature));

    // 2. device_mac binds is_virtual: physical MAC rejected when verified as virtual and vice versa.
    let (p0, n0) = open_genesis(did, &phys, &t).unwrap();
    let e0 = p0.assign_id("000000000000");
    let phys_member = &n0.members[0];
    verify_member(&e0, phys_member, false).unwrap();
    assert_eq!(
        verify_member(&e0, phys_member, true),
        Err(Error::NotEpochMember)
    );

    // Virtual device recovery bundle round-trips 96-byte HawkEncSecret without ORF.
    let code = RecoveryCode::generate().unwrap();
    let (vrec, vmember) = create_vdevice(did, &code, &phys, &e0, Mechanism::Code).unwrap();
    verify_member(&e0, &vmember, true).unwrap();
    assert_eq!(
        verify_member(&e0, &vmember, false),
        Err(Error::NotEpochMember)
    );
    let restored = open_vdevice(&vrec, &code, did).unwrap();
    assert_eq!(restored.device.public(), &vrec.public);

    // 3. EpochPublic.members_hash binds sorted (device_key_pub, epoch_storage_key_pub, is_virtual).
    let mut e0_members = n0.members.clone();
    e0_members.push(vmember);
    let (_p1, n1) = open_next(
        did,
        &e0,
        &n0.record.public,
        &e0_members,
        std::slice::from_ref(&vrec.public),
        &phys,
        &t,
    )
    .unwrap();
    n1.record
        .public
        .verify(did, Some(&n0.record.public))
        .unwrap();
    n1.record
        .public
        .verify_members(&[phys.public().clone(), vrec.public.clone()])
        .unwrap();

    // Omitting the virtual device from the member set fails verify_members!
    assert!(
        n1.record
            .public
            .verify_members(std::slice::from_ref(phys.public()))
            .is_err()
    );

    // Mutating members_hash on EpochPublic breaks epoch_head verification!
    let mut tampered_pub = n1.record.public.clone();
    tampered_pub.members_hash[0] ^= 0xff;
    assert_eq!(
        tampered_pub.verify(did, Some(&n0.record.public)),
        Err(Error::Malformed("epoch head mismatch"))
    );
}

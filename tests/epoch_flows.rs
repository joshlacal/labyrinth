//! End-to-end epoch, revocation, recovery and OTC flows against an
//! in-memory backend (SPEC §4–6).

use labyrinth::Error;
use labyrinth::device::{DevicePublic, DeviceSecrets};
use labyrinth::epoch::{
    EpochKeys, EpochMemberRecord, EpochRecord, EpochSecret, NewEpoch, OpenedEpoch, PendingEpoch,
    add_device_mac, backward_chain, forward_chain, open_genesis, open_next, space_epoch_id,
    verify_member, verify_public,
};
use labyrinth::hpke::labyrinth::X25519Secret;
use labyrinth::otc::{Initiator, Responder};
use labyrinth::recovery_code::{ALPHABET, RecoveryCode};
use labyrinth::sign::Ed25519Transport;
use labyrinth::virtual_device::{self, Mechanism, OtcPayload};
use proptest::prelude::*;

const DID: &str = "did:plc:labyrinthtest";

fn transport() -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]))
}

/// The backend's records, indexed by sequence number.
#[derive(Default)]
struct Backend {
    records: Vec<EpochRecord>,
    ids: Vec<String>,
    members: Vec<Vec<EpochMemberRecord>>,
    devices: Vec<DevicePublic>,
}

impl Backend {
    fn publish(&mut self, pending: PendingEpoch, new: NewEpoch) -> EpochSecret {
        assert_eq!(pending.seq() as usize, self.records.len());
        let id = space_epoch_id(pending.seq());
        self.records.push(new.record);
        self.members.push(new.members);
        self.ids.push(id.clone());
        pending.assign_id(id)
    }

    fn register(&mut self, d: &DevicePublic) {
        if !self.devices.contains(d) {
            self.devices.push(d.clone());
        }
    }

    fn member(&self, seq: u64, d: &DevicePublic) -> Option<&EpochMemberRecord> {
        self.members[seq as usize]
            .iter()
            .find(|m| m.device_key_pub == d.device_key_pub)
    }

    fn opener(&self, seq: u64) -> &DevicePublic {
        let by = self.records[seq as usize].opened_by;
        self.devices
            .iter()
            .find(|d| d.device_key_pub == by)
            .expect("opener registered")
    }

    fn opened<'a>(&'a self, seq: u64, my_member: &'a EpochMemberRecord) -> OpenedEpoch<'a> {
        let opener = self.opener(seq);
        OpenedEpoch {
            epoch_id: &self.ids[seq as usize],
            record: &self.records[seq as usize],
            my_member,
            opener,
            opener_prev_member: self.member(seq - 1, opener).expect("opener was a member"),
        }
    }

    /// Forward-chain `prev` → `prev.seq + 1` as device `d`.
    fn forward(
        &self,
        prev: &EpochSecret,
        d: &DevicePublic,
        storage: &X25519Secret,
    ) -> labyrinth::Result<EpochSecret> {
        let seq = prev.seq + 1;
        let mine = self.member(seq, d).ok_or(Error::NotEpochMember)?;
        forward_chain(
            DID,
            prev,
            &self.records[prev.seq as usize].public,
            &self.opened(seq, mine),
            storage,
        )
    }

    /// `me` opens the next epoch carrying over `continuing`.
    fn open_next(
        &mut self,
        prev: &EpochSecret,
        continuing: &[DevicePublic],
        me: &DeviceSecrets,
    ) -> EpochSecret {
        let (p, n) = open_next(
            DID,
            prev,
            &self.records[prev.seq as usize].public,
            &self.members[prev.seq as usize],
            continuing,
            me,
            &transport(),
        )
        .unwrap();
        let prev_public = self.records[prev.seq as usize].public.clone();
        n.record.public.verify(DID, Some(&prev_public)).unwrap();
        self.publish(p, n)
    }
}

fn genesis(b: &mut Backend, a: &DeviceSecrets) -> EpochSecret {
    b.register(a.public());
    let (p, n) = open_genesis(DID, a, &transport()).unwrap();
    n.record.public.verify(DID, None).unwrap();
    b.publish(p, n)
}

fn add_mid_epoch(b: &mut Backend, e: &EpochSecret, d: &DevicePublic) {
    b.register(d);
    let rec = add_device_mac(e, d).unwrap();
    verify_member(e, &rec).unwrap();
    b.members[e.seq as usize].push(rec);
}

#[test]
fn genesis_add_device_revoke() {
    let mut b = Backend::default();
    let a = DeviceSecrets::generate().unwrap();
    let bdev = DeviceSecrets::generate().unwrap();
    let cdev = DeviceSecrets::generate().unwrap();
    let e0 = genesis(&mut b, &a);
    add_mid_epoch(&mut b, &e0, bdev.public());
    add_mid_epoch(&mut b, &e0, cdev.public());

    // Revoke C: open epoch 1 carrying only B ([CB-11]).
    let e1 = b.open_next(&e0, &[bdev.public().clone()], &a);
    assert!(b.member(1, cdev.public()).is_none());

    let b1 = b.forward(&e0, bdev.public(), &bdev.storage).unwrap();
    assert_eq!(b1.root(), e1.root());
    assert_eq!(b1.epoch_id, e1.epoch_id);
    // The opener can chain into its own epoch too.
    let a1 = b.forward(&e0, a.public(), &a.storage).unwrap();
    assert_eq!(a1.root(), e1.root());

    // C holds the old root but no entropy addressed to it.
    assert_eq!(
        b.forward(&e0, cdev.public(), &cdev.storage).unwrap_err(),
        Error::NotEpochMember
    );
    for other in [bdev.public(), a.public()] {
        let rec = b.member(1, other).unwrap();
        assert!(
            forward_chain(
                DID,
                &e0,
                &b.records[0].public,
                &b.opened(1, rec),
                &cdev.storage
            )
            .is_err()
        );
    }
    // C can't sneak into epoch 2 either: it has no MAC in epoch 1.
    let err = open_next(
        DID,
        &e1,
        &b.records[1].public,
        &b.members[1],
        &[cdev.public().clone()],
        &a,
        &transport(),
    )
    .err();
    assert_eq!(err, Some(Error::NotEpochMember));
}

#[test]
fn virtual_devices_cannot_open_epochs() {
    let mut b = Backend::default();
    let a = DeviceSecrets::generate().unwrap();
    let e0 = genesis(&mut b, &a);
    let v = DeviceSecrets::generate_virtual(a.orf.clone()).unwrap();
    assert!(open_genesis(DID, &v, &transport()).is_err());
    add_mid_epoch(&mut b, &e0, v.public());
    assert!(
        open_next(
            DID,
            &e0,
            &b.records[0].public,
            &b.members[0],
            &[],
            &v,
            &transport()
        )
        .is_err()
    );
}

#[test]
fn backward_chain_five_to_zero() {
    let mut b = Backend::default();
    let a = DeviceSecrets::generate().unwrap();
    let mut epochs = vec![genesis(&mut b, &a)];
    for _ in 0..5 {
        let prev = epochs.last().unwrap().clone();
        epochs.push(b.open_next(&prev, &[], &a));
    }
    let mut cur = epochs[5].clone();
    for seq in (0..5u64).rev() {
        let prev =
            backward_chain(&cur, &b.records[cur.seq as usize], &b.ids[seq as usize]).unwrap();
        assert_eq!(prev.seq, seq);
        assert_eq!(prev.root(), epochs[seq as usize].root());
        verify_public(&prev, &b.records[seq as usize].public).unwrap();
        assert_eq!(
            b.records[cur.seq as usize].public.prev_head,
            Some(b.records[seq as usize].public.head)
        );
        cur = prev;
    }
    assert!(backward_chain(&cur, &b.records[0], "x").is_err());

    // Tampered back-links and mismatched records are rejected.
    let mut bad = b.records[3].clone();
    bad.encrypted_prev_seq.as_mut().unwrap()[30] ^= 1;
    assert!(backward_chain(&epochs[3], &bad, &b.ids[2]).is_err());
    let mut bad = b.records[3].clone();
    bad.encrypted_prev_root.as_mut().unwrap()[30] ^= 1;
    assert!(backward_chain(&epochs[3], &bad, &b.ids[2]).is_err());
    // The two fields share a key and AAD; the format check separates them.
    let mut bad = b.records[3].clone();
    std::mem::swap(&mut bad.encrypted_prev_seq, &mut bad.encrypted_prev_root);
    assert!(backward_chain(&epochs[3], &bad, &b.ids[2]).is_err());
    // A record from another epoch doesn't match the root.
    assert!(backward_chain(&epochs[3], &b.records[4], &b.ids[2]).is_err());
}

/// Replace two entropy characters with different alphabet characters.
fn two_typos(code: &RecoveryCode) -> String {
    let mut s = code.as_str().as_bytes().to_vec();
    for pos in [7usize, 23] {
        let idx = ALPHABET.iter().position(|&c| c == s[pos]).unwrap();
        s[pos] = ALPHABET[(idx + 5) % 32];
    }
    String::from_utf8(s).unwrap()
}

#[test]
fn recovery_from_virtual_device_with_typos() {
    let mut b = Backend::default();
    let a = DeviceSecrets::generate().unwrap();
    let salt = [0x5au8; 32];
    let mut epochs = vec![genesis(&mut b, &a)];
    for _ in 0..2 {
        let prev = epochs.last().unwrap().clone();
        epochs.push(b.open_next(&prev, &[], &a));
    }

    // Create the virtual device at epoch 2.
    let code = RecoveryCode::generate().unwrap();
    let (vrec, _token, vmember) =
        virtual_device::create(DID, &code, &a, &epochs[2], &salt, Mechanism::Code).unwrap();
    b.register(&vrec.public);
    b.members[2].push(vmember);

    // Epochs 3 and 4 carry the virtual device over.
    for _ in 0..2 {
        let prev = epochs.last().unwrap().clone();
        epochs.push(b.open_next(&prev, std::slice::from_ref(&vrec.public), &a));
    }

    // A new device types the code with two typos.
    let typed = two_typos(&code);
    assert!(RecoveryCode::parse(&typed).is_err());
    let found = virtual_device::find_code(&typed, DID, |id| *id == vrec.vdevice_id).unwrap();
    assert_eq!(found, code);
    assert_eq!(
        virtual_device::find_code(&typed, DID, |_| false).err(),
        Some(Error::BadRecoveryCode)
    );

    let restored = virtual_device::open(&vrec, &found, DID).unwrap();
    assert_eq!(restored.mailbox_root_salt, salt);
    let seq = restored.epoch.seq();
    assert_eq!(seq, 2);
    let start =
        PendingEpoch::new(seq, *restored.epoch.root()).assign_id(b.ids[seq as usize].clone());
    verify_public(&start, &b.records[2].public).unwrap();

    // Forward-chain with the virtual device's storage key to epoch 4.
    let mut cur = start.clone();
    while (cur.seq as usize) < epochs.len() - 1 {
        cur = b
            .forward(&cur, &vrec.public, &restored.device.storage)
            .unwrap();
        assert_eq!(cur.root(), epochs[cur.seq as usize].root());
    }
    assert_eq!(cur.seq, 4);

    // Enroll the new physical device into epoch 4.
    let (newdev, newpub, _tok, member) =
        virtual_device::enroll_from_virtual(&restored, &cur).unwrap();
    assert!(!newdev.is_virtual());
    newpub.verify().unwrap();
    verify_member(&cur, &member).unwrap();

    // Backward-chain from the bundle's epoch to genesis.
    let mut back = start;
    while back.seq > 0 {
        let prev_seq = back.seq as usize - 1;
        back = backward_chain(&back, &b.records[back.seq as usize], &b.ids[prev_seq]).unwrap();
        assert_eq!(back.root(), epochs[prev_seq].root());
    }

    // The new device can open epoch 5 and A can follow.
    b.register(&newpub);
    b.members[4].push(member);
    let e5 = b.open_next(&cur, &[a.public().clone()], &newdev);
    let a5 = b.forward(&epochs[4], a.public(), &a.storage).unwrap();
    assert_eq!(a5.root(), e5.root());
}

#[test]
fn otc_payload_round_trip_and_wrong_key() {
    let mut b = Backend::default();
    let a = DeviceSecrets::generate().unwrap();
    let e0 = genesis(&mut b, &a);
    let e1 = b.open_next(&e0, &[], &a);

    let mut responder = Responder::generate(DID).unwrap();
    let (init, m1) = Initiator::start(responder.code(), DID, b"").unwrap();
    let (m2, isk_existing) = responder.respond(&m1, b"").unwrap();
    let isk_new = init.finish(&m2).unwrap();
    assert_eq!(isk_new, isk_existing);

    let (payload, _token) = OtcPayload::create(&a, &e1, &[7u8; 32]).unwrap();
    let ct = payload.seal(&isk_existing).unwrap();
    let got = OtcPayload::open(&isk_new, &ct).unwrap();
    assert_eq!(got.epoch.root(), e1.root());
    assert_eq!(got.epoch.epoch_id, e1.epoch_id);
    assert_eq!(got.epoch.seq, 1);
    assert_eq!(got.mailbox_root_salt, [7u8; 32]);
    assert_eq!(
        got.temp_orf_state.to_bytes(),
        payload.temp_orf_state.to_bytes()
    );

    // A session with the wrong code yields a different ISK.
    let mut responder2 = Responder::generate(DID).unwrap();
    let wrong = labyrinth::otc::OneTimeCode::parse(if responder2.code().as_str() == "000000" {
        "000001"
    } else {
        "000000"
    })
    .unwrap();
    let (init2, m1) = Initiator::start(&wrong, DID, b"").unwrap();
    let (m2, _) = responder2.respond(&m1, b"").unwrap();
    let isk_wrong = init2.finish(&m2).unwrap();
    assert_eq!(
        OtcPayload::open(&isk_wrong, &ct).err(),
        Some(Error::Decrypt)
    );
    let mut bad = ct.clone();
    bad[40] ^= 1;
    assert!(OtcPayload::open(&isk_new, &bad).is_err());

    // The new device enrolls into the transferred epoch.
    let (newdev, _, _, member) = got.enroll().unwrap();
    verify_member(&e1, &member).unwrap();
    assert!(!newdev.is_virtual());
}

#[test]
fn tampering_is_rejected() {
    let mut b = Backend::default();
    let a = DeviceSecrets::generate().unwrap();
    let d = DeviceSecrets::generate().unwrap();
    let e0 = genesis(&mut b, &a);
    add_mid_epoch(&mut b, &e0, d.public());
    let e1 = b.open_next(&e0, &[d.public().clone()], &a);
    let good = b.forward(&e0, d.public(), &d.storage).unwrap();
    assert_eq!(good.root(), e1.root());

    let mine = b.member(1, d.public()).unwrap().clone();
    let opener = b.opener(1).clone();
    let opener_prev = b.member(0, &opener).unwrap().clone();
    let record = b.records[1].clone();
    let prev_public = b.records[0].public.clone();
    let try_chain =
        |rec: &EpochRecord, m: &EpochMemberRecord, op: &DevicePublic, opm: &EpochMemberRecord| {
            forward_chain(
                DID,
                &e0,
                &prev_public,
                &OpenedEpoch {
                    epoch_id: &b.ids[1],
                    record: rec,
                    my_member: m,
                    opener: op,
                    opener_prev_member: opm,
                },
                &d.storage,
            )
        };
    assert!(try_chain(&record, &mine, &opener, &opener_prev).is_ok());

    // Member record: MAC, entropy ciphertext, sequence.
    let mut m = mine.clone();
    m.device_mac[0] ^= 1;
    assert!(try_chain(&record, &m, &opener, &opener_prev).is_err());
    let ct_len = mine.encrypted_entropy.as_ref().unwrap().len();
    for i in [0, 1, 20, 40, ct_len - 1] {
        let mut m = mine.clone();
        m.encrypted_entropy.as_mut().unwrap()[i] ^= 1;
        assert!(
            try_chain(&record, &m, &opener, &opener_prev).is_err(),
            "{i}"
        );
    }
    // Opener record: signatures, auth key, identity.
    let mut op = opener.clone();
    op.sig_0x30[5] ^= 1;
    assert!(try_chain(&record, &mine, &op, &opener_prev).is_err());
    let mut op = opener.clone();
    op.sig_0x31.as_mut().unwrap()[5] ^= 1;
    assert!(try_chain(&record, &mine, &op, &opener_prev).is_err());
    assert!(try_chain(&record, &mine, d.public(), b.member(0, d.public()).unwrap()).is_err());
    let mut opm = opener_prev.clone();
    opm.device_mac[0] ^= 1;
    assert!(try_chain(&record, &mine, &opener, &opm).is_err());
    // Epoch record: public keys, signatures, attestation, back-link.
    let mut r = record.clone();
    r.public.self_sig[0] ^= 1;
    assert!(try_chain(&r, &mine, &opener, &opener_prev).is_err());
    let mut r = record.clone();
    r.public.prev_sig.as_mut().unwrap()[0] ^= 1;
    assert!(try_chain(&r, &mine, &opener, &opener_prev).is_err());
    let mut r = record.clone();
    r.public.attestation.sig[0] ^= 1;
    assert!(try_chain(&r, &mine, &opener, &opener_prev).is_err());
    let mut r = record.clone();
    r.public.keys.auth.0[0] ^= 1;
    assert!(try_chain(&r, &mine, &opener, &opener_prev).is_err());
    let mut r = record.clone();
    r.encrypted_prev_root.as_mut().unwrap()[30] ^= 1;
    assert!(try_chain(&r, &mine, &opener, &opener_prev).is_err());
    let mut r = record.clone();
    r.encrypted_prev_seq.as_mut().unwrap()[30] ^= 1;
    assert!(try_chain(&r, &mine, &opener, &opener_prev).is_err());
    // A different epochID for the previous epoch changes the chaining key.
    let wrong_prev = EpochSecret::from_parts(0, "other", *e0.root());
    assert!(
        forward_chain(
            DID,
            &wrong_prev,
            &prev_public,
            &b.opened(1, &mine),
            &d.storage
        )
        .is_err()
    );
    // Wrong DID.
    assert!(
        forward_chain(
            "did:plc:x",
            &e0,
            &prev_public,
            &b.opened(1, &mine),
            &d.storage
        )
        .is_err()
    );

    // open_next refuses tampered continuing devices or prev MACs.
    let mut dp = d.public().clone();
    dp.sig_0x30[1] ^= 1;
    assert!(
        open_next(
            DID,
            &e1,
            &record.public,
            &b.members[1],
            &[dp],
            &a,
            &transport()
        )
        .is_err()
    );
    let mut members = b.members[1].clone();
    for m in &mut members {
        if m.device_key_pub == d.public().device_key_pub {
            m.device_mac[3] ^= 1;
        }
    }
    assert_eq!(
        open_next(
            DID,
            &e1,
            &record.public,
            &members,
            &[d.public().clone()],
            &a,
            &transport()
        )
        .err(),
        Some(Error::NotEpochMember)
    );
    // ... and a prev public that doesn't match the root.
    assert!(open_next(DID, &e1, &prev_public, &b.members[1], &[], &a, &transport()).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6))]
    /// Two devices that independently forward-chain to epoch N agree on the
    /// root and on the mailbox head.
    #[test]
    fn independent_derivations_agree(n in 1usize..4, opener_flips in proptest::collection::vec(any::<bool>(), 4)) {
        let mut b = Backend::default();
        let x = DeviceSecrets::generate().unwrap();
        let y = DeviceSecrets::generate().unwrap();
        let e0 = genesis(&mut b, &x);
        add_mid_epoch(&mut b, &e0, y.public());
        let mut cur = e0.clone();
        for flip in opener_flips.iter().take(n) {
            let (opener, other) = if *flip { (&y, &x) } else { (&x, &y) };
            cur = b.open_next(&cur, &[other.public().clone()], opener);
        }
        let (mut cx, mut cy) = (e0.clone(), e0);
        for _ in 0..n {
            cx = b.forward(&cx, x.public(), &x.storage).unwrap();
            cy = b.forward(&cy, y.public(), &y.storage).unwrap();
        }
        prop_assert_eq!(cx.root(), cy.root());
        prop_assert_eq!(cx.root(), cur.root());
        let hx = labyrinth::mailbox::epoch_head(cx.seq, &cx.mailbox_keys().public(), b.records[n].public.prev_head.as_ref(), DID);
        let hy = labyrinth::mailbox::epoch_head(cy.seq, &cy.mailbox_keys().public(), b.records[n].public.prev_head.as_ref(), DID);
        prop_assert_eq!(hx, hy);
        prop_assert_eq!(hx, b.records[n].public.head);
    }
}

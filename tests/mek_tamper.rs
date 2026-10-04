//! Every single-byte change to a MEK record makes at least one intended
//! recipient reject it (SPEC §7.3, [CB-24]).
//!
//! A flip inside one recipient's entry only affects that recipient (nobody
//! else can check another member's ciphertext), so the property is "some
//! recipient rejects", checked by the recipient the field belongs to.

mod common;

use common::{Member, THREAD, heads, labyrinth_mek, roster};
use labyrinth::mek::{self, Mek, MekRecord, MekSender};

struct Fixture {
    members: Vec<Member>,
    /// Index of the Labyrinth sender, or None for a transport MEK.
    sender: Option<usize>,
}

impl Fixture {
    /// Members in roster order; returns true if any of them rejects.
    fn some_recipient_rejects(&self, record: &MekRecord) -> bool {
        let sender = self.sender.map(|i| &self.members[i]);
        self.members.iter().any(|m| m.open(record, sender).is_err())
    }

    fn only(&self, record: &MekRecord, idx: usize) -> bool {
        let sender = self.sender.map(|i| &self.members[i]);
        self.members[idx].open(record, sender).is_err()
    }
}

fn flip_string(s: &mut String, i: usize) {
    let mut b = std::mem::take(s).into_bytes();
    b[i] ^= 1;
    *s = String::from_utf8(b).unwrap();
}

fn check_shared_fields(fx: &Fixture, record: &MekRecord) {
    assert!(
        !fx.some_recipient_rejects(record),
        "untampered record opens"
    );
    for i in 0..record.thread_id.len() {
        let mut bad = record.clone();
        flip_string(&mut bad.thread_id, i);
        assert!(fx.only(&bad, 0), "thread_id {i}");
    }
    for i in 0..12 {
        let mut bad = record.clone();
        bad.mek_id[i] ^= 1;
        assert!(fx.only(&bad, 0), "mek_id {i}");
    }
    for i in 0..32 {
        let mut bad = record.clone();
        bad.roster_hash[i] ^= 1;
        assert!(fx.only(&bad, 0), "roster_hash {i}");
    }
}

fn check_recipient_entries(fx: &Fixture, record: &MekRecord) {
    for (r, entry) in record.recipients.iter().enumerate() {
        for i in 0..entry.did.len() {
            let mut bad = record.clone();
            flip_string(&mut bad.recipients[r].did, i);
            assert!(fx.some_recipient_rejects(&bad), "recipient {r} did {i}");
        }
        for i in 0..32 {
            let mut bad = record.clone();
            bad.recipients[r].recipient_epoch_head[i] ^= 1;
            assert!(fx.only(&bad, 0), "recipient {r} head {i}");
        }
    }
    // Ciphertext: every byte of one entry, a stride of the others (each
    // open runs ML-KEM decapsulation).
    for (r, entry) in record.recipients.iter().enumerate() {
        let step = if r == 1 { 1 } else { 13 };
        for i in (0..entry.ciphertext.len()).step_by(step) {
            let mut bad = record.clone();
            bad.recipients[r].ciphertext[i] ^= 1;
            assert!(fx.only(&bad, r), "recipient {r} ciphertext {i}");
        }
    }
}

#[test]
fn labyrinth_mek_record_tamper() {
    let fx = Fixture {
        members: vec![
            Member::new("alice", 1),
            Member::new("bob", 2),
            Member::new("carol", 3),
        ],
        sender: Some(0),
    };
    let refs: Vec<&Member> = fx.members.iter().collect();
    let (_, record) = labyrinth_mek(&fx.members[0], &refs);
    check_shared_fields(&fx, &record);
    check_recipient_entries(&fx, &record);

    let MekSender::Labyrinth { did, .. } = &record.sender else {
        unreachable!()
    };
    for i in 0..did.len() {
        let mut bad = record.clone();
        let MekSender::Labyrinth { did, .. } = &mut bad.sender else {
            unreachable!()
        };
        flip_string(did, i);
        assert!(fx.only(&bad, 1), "sender did {i}");
    }
    for i in 0..32 {
        let mut bad = record.clone();
        let MekSender::Labyrinth {
            sender_epoch_head, ..
        } = &mut bad.sender
        else {
            unreachable!()
        };
        sender_epoch_head[i] ^= 1;
        assert!(fx.only(&bad, 1), "sender head {i}");
    }
}

#[test]
fn transport_mek_record_tamper() {
    let fx = Fixture {
        members: vec![
            Member::new("alice", 1),
            Member::new("bob", 2),
            Member::new("carol", 3),
        ],
        sender: None,
    };
    let device = Member::new("newphone", 9);
    let refs: Vec<&Member> = fx.members.iter().collect();
    let mut m = Mek::generate(&heads(&refs)).unwrap();
    let record =
        mek::distribute_transport(THREAD, &mut m, &device.transport, &roster(&refs)).unwrap();
    check_shared_fields(&fx, &record);
    check_recipient_entries(&fx, &record);

    let field = |bad: &mut MekRecord, which: usize, i: usize| {
        let MekSender::Transport {
            transport_pub,
            ephemeral_auth_pub,
            sig,
        } = &mut bad.sender
        else {
            unreachable!()
        };
        match which {
            0 => transport_pub[i] ^= 1,
            1 => ephemeral_auth_pub[i] ^= 1,
            _ => sig[i] ^= 1,
        }
    };
    for (which, len) in [(0, 32), (1, 32), (2, 64)] {
        for i in 0..len {
            let mut bad = record.clone();
            field(&mut bad, which, i);
            assert!(fx.only(&bad, 1), "transport sender field {which} byte {i}");
        }
    }

    // Swapping in a different (validly signed) ephemeral auth key fails Hawk.
    let other = Member::new("other", 10);
    let mut m2 = m.clone();
    let rec2 =
        mek::distribute_transport(THREAD, &mut m2, &other.transport, &roster(&refs)).unwrap();
    let mut bad = record.clone();
    bad.sender = rec2.sender;
    assert!(fx.only(&bad, 1));
}

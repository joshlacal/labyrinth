//! User-visible fingerprints of epoch heads ([CB-41]; paper p.22: the
//! epoch head "can be used as a fingerprint").
//!
//! An epoch head commits to the account's DID, its current mailbox keys
//! and, through `previous_epoch_head`, to the whole head chain. Two people
//! comparing fingerprints (in person, or over another channel) confirm
//! that the keys a sender encrypts to are the keys the account's devices
//! hold, i.e. no backend substituted them. Fingerprints change on every
//! rotation, so compare the *current* heads (a sender's view of a peer is
//! its [CB-29] pin).
//!
//! ```text
//! fp(did, head) = kdf(head, MINOS_SALT, "catbird.labyrinth.fingerprint.v1:" || did, 30)
//! digits        = six 5-byte chunks, each big-endian mod 100000, zero-padded to 5 digits
//! safety number = digits of both accounts, ordered by DID (60 digits)
//! emoji         = the first 8 bytes of fp, each mod 64, indexing EMOJI
//! ```

use crate::encoding::{kdf, minos_salt};

const LABEL: &str = "catbird.labyrinth.fingerprint.v1:";

fn fp(did: &str, head: &[u8; 32]) -> [u8; 30] {
    let mut out = [0u8; 30];
    kdf(
        head,
        Some(&minos_salt()),
        format!("{LABEL}{did}").as_bytes(),
        &mut out,
    );
    out
}

/// 30 decimal digits for one account's epoch head, in six groups of 5
/// separated by spaces.
pub fn account_digits(did: &str, head: &[u8; 32]) -> String {
    fp(did, head)
        .chunks(5)
        .map(|c| {
            let n = c.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The 60-digit safety number of two accounts' heads, the same on both
/// sides (ordered by DID).
pub fn safety_number(a: (&str, &[u8; 32]), b: (&str, &[u8; 32])) -> String {
    let (first, second) = if a.0 <= b.0 { (a, b) } else { (b, a) };
    format!(
        "{} {}",
        account_digits(first.0, first.1),
        account_digits(second.0, second.1)
    )
}

/// 64 visually distinct emoji.
pub const EMOJI: [&str; 64] = [
    "🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵", "🐔",
    "🐧", "🐦", "🐤", "🦆", "🦅", "🦉", "🐺", "🐗", "🐴", "🦄", "🐝", "🐛", "🦋", "🐌", "🐞", "🐢",
    "🐍", "🐙", "🦑", "🦀", "🐡", "🐠", "🐬", "🐳", "🐊", "🦓", "🐘", "🦒", "🐫", "🦘", "🌵", "🌲",
    "🍄", "🌻", "🌙", "⭐", "🔥", "🌈", "⛄", "🍎", "🍋", "🍉", "🍇", "🍓", "🥕", "🌽", "🍞", "🧀",
];

/// Eight emoji for one account's epoch head.
pub fn account_emoji(did: &str, head: &[u8; 32]) -> [&'static str; 8] {
    let f = fp(did, head);
    core::array::from_fn(|i| EMOJI[usize::from(f[i] % 64)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_are_stable_symmetric_and_head_bound() {
        let d = account_digits("did:plc:a", &[1; 32]);
        assert_eq!(d.len(), 35);
        assert!(
            d.split(' ')
                .all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit()))
        );
        assert_eq!(d, account_digits("did:plc:a", &[1; 32]));
        assert_ne!(d, account_digits("did:plc:a", &[2; 32]));
        assert_ne!(d, account_digits("did:plc:b", &[1; 32]));
        let a = ("did:plc:a", &[1u8; 32]);
        let b = ("did:plc:b", &[2u8; 32]);
        assert_eq!(safety_number(a, b), safety_number(b, a));
        assert_eq!(safety_number(a, b).replace(' ', "").len(), 60);
        let e = account_emoji("did:plc:a", &[1; 32]);
        assert_eq!(e, account_emoji("did:plc:a", &[1; 32]));
        let unique: std::collections::BTreeSet<_> = EMOJI.iter().collect();
        assert_eq!(unique.len(), 64);
    }
}

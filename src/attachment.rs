//! Attachment references (SPEC §8, paper p.41–43; [CB-32], [CB-33]).
//!
//! Attachment bytes stay in chat blob storage, encrypted by chat with
//! AES-256-GCM under a per-blob key carried in the message frame ([CB-32];
//! the paper's AES-256-CBC + PKCS7 primitive is not used). Labyrinth adds a
//! per-mailbox **reference object** so a restored device can fetch the
//! blob without a chat delivery interval for it:
//!
//! ```text
//! input          = json(["<backupID>", "<objectID>"])   backupID = threadId, objectID = blobId
//! blindedIndex   = orf_client_map(c, "attachment_key_scope", input)
//! blindedSalt    = orf_client_map(c, "attachment_token_salt_scope", input)
//! index          = orf_server_map(s, INDEX_DOMAIN, blindedIndex)        (server)
//! tokenSalt      = orf_server_map(s, TOKEN_DOMAIN, blindedSalt)          (server)
//! tokenMac       = HMAC-SHA256(key = tokenSalt, json(["<threadId>", "<messageId>"]))
//! ```
//!
//! The server stores `index → {blobId, tokenMac}` (thread and message only
//! as keyed digests), so only a device holding the account's ORF client
//! state can name a reference, and the token can be computed or checked
//! only while such a device presents it. ORF evolution preserves both
//! values across restored devices; revoking a device deletes its ORF
//! server state, so its cached ids stop working.
//!
//! **One message per attachment object** (v1.1 content unlinkability): the
//! server refuses a second message for a blob, so a forwarded attachment
//! is re-uploaded as a new blob. The Labyrinth `messageId` of an
//! attachment-bearing message is the chat message UUID, which mls-ds
//! checks against the blob's binding.

use crate::encoding::mac;
use crate::orf::{ObliviousId, OrfClientState, orf_client_map};

/// Client ORF domain of the reference index (paper p.42).
pub const INDEX_SCOPE: &[u8] = b"attachment_key_scope";
/// Client ORF domain of the token salt (paper p.43).
pub const TOKEN_SALT_SCOPE: &[u8] = b"attachment_token_salt_scope";
/// Server ORF domain of the index (mls-ds constant).
pub const INDEX_DOMAIN: &[u8] = b"catbird.labyrinth.orf.attachment_index";
/// Server ORF domain of the token salt (mls-ds constant).
pub const TOKEN_DOMAIN: &[u8] = b"catbird.labyrinth.orf.attachment_token";

/// Compact JSON array of two strings with standard JSON escaping (as
/// `serde_json::to_string(&[a, b])` writes it). For ids without quotes,
/// backslashes or control characters this is the paper's literal
/// `'["' || a || '","' || b || '"]'`.
pub fn json_pair(a: &str, b: &str) -> String {
    let mut out = String::with_capacity(a.len() + b.len() + 7);
    out.push('[');
    for (i, s) in [a, b].into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0c}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

/// The client half: `(blindedIndex, blindedTokenSalt)` for blob `blob_id`
/// in thread `thread_id`.
pub fn blind(state: &OrfClientState, thread_id: &str, blob_id: &str) -> (ObliviousId, ObliviousId) {
    let input = json_pair(thread_id, blob_id);
    (
        orf_client_map(state, INDEX_SCOPE, input.as_bytes()),
        orf_client_map(state, TOKEN_SALT_SCOPE, input.as_bytes()),
    )
}

/// The server's token MAC over the message the reference belongs to.
pub fn token_mac(token_salt: &[u8; 32], thread_id: &str, message_id: &str) -> [u8; 32] {
    mac(json_pair(thread_id, message_id).as_bytes(), token_salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orf::orf_server_map;
    use crate::orf::{orf_client_evolve, orf_client_init, orf_server_evolve, orf_server_init};

    #[test]
    fn json_pair_matches_the_paper_and_escapes() {
        assert_eq!(json_pair("t-1", "b-2"), r#"["t-1","b-2"]"#);
        assert_eq!(
            json_pair("a\"b", "c\\d\n\u{1}"),
            r#"["a\"b","c\\d\n\u0001"]"#
        );
        assert_eq!(json_pair("é", ""), "[\"é\",\"\"]");
    }

    #[test]
    fn index_and_token_survive_evolution_and_bind_their_inputs() {
        let (c, s) = (orf_client_init().unwrap(), orf_server_init().unwrap());
        let (bi, bt) = blind(&c, "t", "blob");
        let idx = orf_server_map(&s, INDEX_DOMAIN, &bi).unwrap();
        let salt = orf_server_map(&s, TOKEN_DOMAIN, &bt).unwrap();
        let (c2, tok) = orf_client_evolve(&c).unwrap();
        let s2 = orf_server_evolve(&s, &tok).unwrap();
        let (bi2, bt2) = blind(&c2, "t", "blob");
        assert_ne!(bi, bi2);
        assert_eq!(orf_server_map(&s2, INDEX_DOMAIN, &bi2).unwrap(), idx);
        assert_eq!(orf_server_map(&s2, TOKEN_DOMAIN, &bt2).unwrap(), salt);
        assert_ne!(idx, salt);
        let (other, _) = blind(&c, "t", "blob2");
        assert_ne!(orf_server_map(&s, INDEX_DOMAIN, &other).unwrap(), idx);
        assert_ne!(token_mac(&salt, "t", "m1"), token_mac(&salt, "t", "m2"));
    }
}

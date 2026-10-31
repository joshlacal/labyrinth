//! Encrypted Space attachment metadata helpers (`Gate 5`, `2A` ORF retired).
//!
//! Encrypted attachment bytes are uploaded via `com.atproto.repo.uploadBlob` to
//! the sender's PDS and immediately promoted from `.staged` to `.space` by
//! committing a `blue.catbird.labyrinth.attachmentManifest` record inside the
//! conversation Space (or personal mailbox Space on leave re-archive).

use subtle::ConstantTimeEq as _;

use crate::encoding::sha256;
use crate::{Error, Result};

/// Maximum encrypted attachment blob size (128 MiB, matching `attachmentManifest` lexicon).
pub const MAX_ATTACHMENT_BLOB_BYTES: usize = 134_217_728;
/// Maximum encrypted attachment `ciphertextSize` integer bound (`134_217_728`).
pub const MAX_ATTACHMENT_CIPHERTEXT_SIZE: u64 = MAX_ATTACHMENT_BLOB_BYTES as u64;

/// Validated metadata for an encrypted attachment blob (`Gate 5`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentCiphertextMeta {
    pub sha256: [u8; 32],
    pub ciphertext_size: u64,
    pub mime_type_hint: Option<String>,
}

impl AttachmentCiphertextMeta {
    /// Compute SHA-256 and validate size bounds (`1..=134_217_728`) for an
    /// AES-256-GCM encrypted attachment blob before upload / manifest commit.
    pub fn from_ciphertext(ciphertext: &[u8], mime_type_hint: Option<String>) -> Result<Self> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_ATTACHMENT_BLOB_BYTES {
            return Err(Error::Malformed("attachment ciphertext size out of bounds"));
        }
        if let Some(ref hint) = mime_type_hint
            && hint.len() > 128
        {
            return Err(Error::Malformed("attachment mimeTypeHint too long"));
        }
        Ok(Self {
            sha256: sha256(ciphertext),
            ciphertext_size: ciphertext.len() as u64,
            mime_type_hint,
        })
    }
}

/// Verify fetched encrypted attachment bytes against `meta` (`ciphertextSize` + constant-time `SHA-256`).
pub fn verify_attachment_ciphertext(bytes: &[u8], meta: &AttachmentCiphertextMeta) -> Result<()> {
    if meta.ciphertext_size == 0 || meta.ciphertext_size > MAX_ATTACHMENT_CIPHERTEXT_SIZE {
        return Err(Error::Malformed("attachment ciphertext size out of bounds"));
    }
    if bytes.len() as u64 != meta.ciphertext_size {
        return Err(Error::Decrypt);
    }
    let digest = sha256(bytes);
    if bool::from(digest.ct_eq(&meta.sha256)) {
        Ok(())
    } else {
        Err(Error::Decrypt)
    }
}

/// Compact JSON array of two strings with standard JSON escaping.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_pair_escapes_cleanly() {
        assert_eq!(json_pair("t-1", "b-2"), r#"["t-1","b-2"]"#);
        assert_eq!(
            json_pair("a\"b", "c\\d\n\u{1}"),
            r#"["a\"b","c\\d\n\u0001"]"#
        );
    }

    #[test]
    fn attachment_meta_validates_bounds() {
        assert!(AttachmentCiphertextMeta::from_ciphertext(b"", None).is_err());
        let meta =
            AttachmentCiphertextMeta::from_ciphertext(b"ciphertext", Some("image/jpeg".into()))
                .unwrap();
        assert_eq!(meta.ciphertext_size, 10);
        assert_eq!(meta.sha256, sha256(b"ciphertext"));
    }
}

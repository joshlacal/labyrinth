//! Protocol size limits and fixed byte widths for Labyrinth 1.1 (Clean-Slate Spaces profile).

/// Maximum number of sealed messages per sender or owner batch.
pub const MAX_BATCH_ITEMS: usize = 256;

/// Maximum byte length of a single sealed message (`signedEncMessage` / `encrypted`).
pub const MAX_SEALED_MESSAGE_BYTES: usize = 262_144;

/// Maximum encrypted attachment blob size (128 MiB).
pub const MAX_ATTACHMENT_CIPHERTEXT_BYTES: usize = 134_217_728;

/// `HawkEncPublic`: `X25519(32) || ML-KEM-768 ek(1184)` = 1,216 bytes (`I16`).
pub const HAWK_ENC_PUBKEY_LEN: usize = 1216;

/// `HawkAuthPublic`: X25519 Montgomery public key = 32 bytes.
pub const HAWK_AUTH_PUBKEY_LEN: usize = 32;

/// XEdDSA Montgomery public key = 32 bytes.
pub const XEDDSA_PUBKEY_LEN: usize = 32;

/// XEdDSA signature = 64 bytes.
pub const XEDDSA_SIG_LEN: usize = 64;

/// Ed25519 public key = 32 bytes.
pub const ED25519_PUBKEY_LEN: usize = 32;

/// Ed25519 signature = 64 bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// SHA-256 epoch head digest = 32 bytes.
pub const EPOCH_HEAD_LEN: usize = 32;

/// SHA-256 canonical sorted active-member set digest = 32 bytes (`Gate 2` / `Gate 3`).
pub const MEMBERS_HASH_LEN: usize = 32;

/// `HMAC-SHA256` archive commitment = 32 bytes (`I13`).
pub const ARCHIVE_COMMITMENT_LEN: usize = 32;

/// Per-message random frame nonce = 32 bytes (`I13`).
pub const FRAME_NONCE_LEN: usize = 32;

/// MLS group ID length = 32 bytes.
pub const GROUP_ID_LEN: usize = 32;

/// ES256 raw R||S signature length = 64 bytes.
pub const ES256_SIG_LEN: usize = 64;

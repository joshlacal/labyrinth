//! Labyrinth 1.1 encrypted message-history storage, Catbird profile.
//!
//! See `docs/SPEC.md` for the protocol and every profile choice (`[CB-n]`).
//! The crate is sans-I/O: protocol state machines produce and consume
//! records; [`store`] defines where those records live.

pub mod aead;
pub mod client;
pub mod device;
pub mod encoding;
pub mod epoch;
pub mod error;
pub mod hpke;
pub mod mailbox;
pub mod mek;
pub mod message;
pub mod orf;
pub mod otc;
pub mod padding;
pub mod records;
pub mod recovery_code;
pub mod sign;
pub mod store;
pub mod virtual_device;

pub use error::{Error, Result};

//! Where Labyrinth records live (SPEC §9).
//!
//! Three traits describe the storage a client needs:
//!
//! - [`MailboxStore`]: the caller's own personal mailbox (a personal atproto
//!   Space, or mls-ds), plus publishing the public `mailboxKeys` record.
//! - [`ThreadStore`]: the conversation space, where each member writes MEK
//!   distributions and sender batches into its own repo ([CB-15], [CB-21]).
//! - [`MailboxDirectory`]: read-only discovery of other accounts' latest
//!   epoch and their MLS chat device keys ([CB-18], [CB-19]).
//! - [`KeyPublisher`]: another place a new epoch head is published (the
//!   PDS `mailboxKeys` record, or the mls-ds directory), so two
//!   independent directories can be cross-checked ([CB-28], [CB-29]).
//! - [`OrfServer`]: the server half of the ORF, always on mls-ds ([CB-17]).
//!
//! **The traits are synchronous** and return [`crate::Result`]. That keeps
//! the crate free of any async runtime: an async client (the catbird-mls
//! orchestrator) implements them by blocking on its runtime, or runs the
//! whole [`crate::client::Labyrinth`] call on a blocking thread. Backend
//! I/O failures map to [`crate::Error::Backend`].
//!
//! A store handle is bound to one authenticated DID: every write goes to
//! that DID's own repo, as Spaces enforce. Semantics every backend must
//! provide (and [`memory`] enforces):
//!
//! - `create_*` is create-if-absent: an existing rkey fails with
//!   [`crate::Error::Conflict`] (Space `RecordAlreadyExists`). Epoch rkeys
//!   are the zero-padded sequence number, so this is the race guard
//!   between devices opening the same epoch ([CB-9]).
//! - Epochs, epoch members, virtual devices, MEK distributions and batches
//!   are immutable once written. A device record changes only to gain
//!   `revokedAt`.
//! - [`crate::Error::Forbidden`] means the backend refused the read, e.g.
//!   after removal from a conversation space ([CB-22]).

pub mod keys;
pub mod memory;
#[cfg(feature = "xrpc")]
pub mod xrpc;

pub use keys::{
    ChatDeviceKey, MemberDeviceKey, ServerOrder, VouchAt, keys_valid_at, keys_valid_for,
};

use crate::Result;
use crate::mailbox::EpochPublic;
use crate::orf::{EvolveToken, ObliviousId};
use crate::records::{
    Batch, Device, Epoch, EpochMember, MailboxKeysRecord, MekDistribution, OwnerBatch,
    VirtualDevice,
};
use crate::sign::XVerifyingKey;

/// A record as read back from a store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored<T> {
    /// DID of the repo the record lives in.
    pub author: String,
    pub rkey: String,
    pub value: T,
    /// The server's stamp, when the backend assigns one (mls-ds). Readers
    /// prefer it to sender timestamps for the removed-key bound ([CB-27]).
    pub order: Option<ServerOrder>,
}

/// A half-open message time window `[from_ms, until_ms)`; `None` is unbounded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeRange {
    pub from_ms: Option<u64>,
    pub until_ms: Option<u64>,
}

impl TimeRange {
    pub const ALL: Self = Self {
        from_ms: None,
        until_ms: None,
    };

    pub fn contains(&self, ts: u64) -> bool {
        self.from_ms.is_none_or(|f| ts >= f) && self.until_ms.is_none_or(|u| ts < u)
    }
}

/// The caller's personal mailbox (owner-only reads and writes).
pub trait MailboxStore {
    /// The DID that owns this mailbox.
    fn owner(&self) -> &str;

    /// rkey = `hex(deviceKeyPubkey)`.
    fn create_device(&self, device: &Device) -> Result<()>;
    /// Sets `revokedAt` once; a no-op if already set.
    fn set_device_revoked(&self, device_key: &XVerifyingKey, revoked_at: &str) -> Result<()>;
    fn get_device(&self, device_key: &XVerifyingKey) -> Result<Option<Device>>;
    fn list_devices(&self) -> Result<Vec<Device>>;

    /// Atomically creates the epoch record and its initial members
    /// (`applyWrites`). Returns the backend-assigned `epochID` ([CB-9]).
    fn create_epoch(&self, epoch: &Epoch, members: &[EpochMember]) -> Result<String>;
    /// The epoch with this sequence number; `rkey` is its `epochID`.
    fn get_epoch(&self, seq: u64) -> Result<Option<Stored<Epoch>>>;
    /// All epochs, ascending by sequence number.
    fn list_epochs(&self) -> Result<Vec<Stored<Epoch>>>;

    /// Adds a device to an epoch mid-epoch (rkey = [`EpochMember::rkey`]).
    fn create_epoch_member(&self, member: &EpochMember) -> Result<()>;
    fn list_epoch_members(&self, seq: u64) -> Result<Vec<EpochMember>>;
    fn get_epoch_member(
        &self,
        seq: u64,
        device_key: &XVerifyingKey,
    ) -> Result<Option<EpochMember>> {
        Ok(self
            .list_epoch_members(seq)?
            .into_iter()
            .find(|m| m.device_key_pubkey.0 == device_key.0))
    }

    /// rkey = `hex(vdeviceId)`.
    fn create_virtual_device(&self, vdevice: &VirtualDevice) -> Result<()>;
    fn get_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<Option<VirtualDevice>>;
    fn list_virtual_devices(&self) -> Result<Vec<VirtualDevice>>;

    /// Appends an owner batch (rkey = TID, assigned by the store).
    fn append_owner_batch(&self, batch: &OwnerBatch) -> Result<String>;
    /// Owner batches of `thread_id` holding at least one item in `range`,
    /// oldest first.
    fn list_owner_batches(
        &self,
        thread_id: &str,
        range: TimeRange,
    ) -> Result<Vec<Stored<OwnerBatch>>>;

    /// Writes `mailboxKeys/self` in the owner's PUBLIC repo ([CB-19]), and
    /// the immutable per-epoch copy `mailboxKeys/<12-digit epochNumber>`
    /// that [`MailboxDirectory::epoch`] serves ([CB-29]).
    fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> Result<()>;
}

/// The conversation spaces the caller belongs to. Writes go to the
/// caller's own repo in the thread's space; reads see every member's repo.
pub trait ThreadStore {
    /// The DID whose repo this handle writes.
    fn author(&self) -> &str;

    /// rkey = `hex(mekId)`.
    fn create_mek(&self, mek: &MekDistribution) -> Result<()>;
    /// Every MEK record in the thread with this id, across all repos.
    fn find_meks(&self, thread_id: &str, mek_id: &[u8; 12])
    -> Result<Vec<Stored<MekDistribution>>>;

    /// Appends a sender batch (rkey = TID, assigned by the store).
    fn append_batch(&self, batch: &Batch) -> Result<String>;
    /// Batches of `thread_id` (from `sender` only, if given) holding at
    /// least one item in `range`, oldest first per author.
    fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<Stored<Batch>>>;
}

/// Read-only discovery of other accounts (public `mailboxKeys` records and
/// the MLS group's device view).
pub trait MailboxDirectory {
    /// The DID's published latest epoch (`mailboxKeys/self`), unverified;
    /// `None` if the account is not enrolled in Labyrinth.
    fn latest(&self, did: &str) -> Result<Option<EpochPublic>>;
    /// The DID's published epoch `seq` (`mailboxKeys/<12-digit seq>`),
    /// unverified; `None` if it was never published. Clients walk these to
    /// verify the `prev_sig` chain from a pinned head to a newer one
    /// ([CB-29]).
    fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>>;
    /// Every MLS chat device transport key ([CB-3]) the DID has
    /// registered, each with the time it was removed (`None` while it is
    /// still a current device).
    ///
    /// Addressing a MEK to an epoch requires its attestation key to be a
    /// *current* device ([CB-18]). Reading history accepts a removed key
    /// only for messages and MEKs written before its removal ([CB-27]):
    /// by their [`ServerOrder`] when the store assigns one, else by the
    /// sender's timestamp ([`keys_valid_for`]).
    fn device_transport_keys(&self, did: &str) -> Result<Vec<ChatDeviceKey>>;
    /// The DID's device leaves in one conversation, with the chat seqs
    /// that added and removed each ([`MemberDeviceKey`]); `None` when the
    /// backend has no per-conversation view (the Space backend). With
    /// server-ordered records, a key vouches for a message only while it
    /// had a leaf in the message's conversation ([CB-27]).
    fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> Result<Option<Vec<MemberDeviceKey>>> {
        let _ = (thread_id, did);
        Ok(None)
    }
}

/// Another destination for a newly opened epoch's public keys, besides the
/// mailbox's own [`MailboxStore::publish_mailbox_keys`]: the PDS
/// `mailboxKeys` record when the mailbox lives in mls-ds, or the mls-ds
/// directory (`publishEpochHead`) when it lives in a Space.
pub trait KeyPublisher {
    /// Publishes `record` (the epoch in `record.current`). Re-publishing
    /// identical bytes succeeds; a different epoch under a published
    /// number fails with [`crate::Error::Conflict`].
    fn publish(&self, record: &MailboxKeysRecord) -> Result<()>;
}

/// The ORF server role ([CB-17], SPEC §3.6, §8): one server state per
/// device of the handle's DID. The server computes every step itself and
/// never reveals a state.
pub trait OrfServer {
    /// Registers `device_key`'s server state: a fresh one
    /// (`orf_server_init`) without a parent, else
    /// `orf_server_evolve(parent state, token)`. Fails with
    /// [`crate::Error::Conflict`] if the device already has a state and
    /// with [`crate::Error::NotFound`] if the parent has none.
    fn register(
        &self,
        device_key: &XVerifyingKey,
        parent: Option<(&XVerifyingKey, &EvolveToken)>,
    ) -> Result<()>;
    /// `orf_server_map(state of device_key, domain, id)`. mls-ds applies
    /// this only inside its attachment-reference endpoints and exposes no
    /// raw map, so the XRPC implementation refuses it.
    fn map(&self, device_key: &XVerifyingKey, domain: &[u8], id: &ObliviousId) -> Result<[u8; 32]>;
    /// Deletes `device_key`'s state (revocation, SPEC §5.6). Idempotent.
    fn delete(&self, device_key: &XVerifyingKey) -> Result<()>;
}

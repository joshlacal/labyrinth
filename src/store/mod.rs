//! Where Labyrinth records live (SPEC §9, Spaces-only clean-slate).
//!
//! Four async traits (`?Send` on `wasm32`, `Send` on native targets) describe
//! the storage a client needs:
//!
//! - [`MailboxStore`]: the caller's own personal mailbox Space, plus publishing
//!   the public `mailboxKeys` record.
//! - [`ThreadStore`]: the conversation Space, where each member writes MEK
//!   distributions, sender batches, and encrypted attachment manifests into its
//!   own repo ([CB-15], [CB-21], Gate 5).
//! - [`MailboxDirectory`]: read-only discovery of other accounts' latest epoch,
//!   verified head chain, and MLS chat device keys ([CB-18], [CB-19], Gate 6).
//! - [`KeyPublisher`]: another destination for a newly opened epoch's public
//!   keys (PDS `mailboxKeys` with `swapRecord` CAS, or `mls-ds` `publishEpochHead`),
//!   so two independent directories can be cross-checked ([CB-28], [CB-29]).

pub mod keys;
pub mod memory;
pub mod pds;
pub mod space;

pub use keys::{
    ChatDeviceKey, MemberDeviceKey, SequencerKey, ServerOrder, VouchAt, keys_valid_at,
    keys_valid_for,
};
pub use memory::MemoryBackend;

use crate::attachment::AttachmentCiphertextMeta;
use crate::deletion::Redaction;
use crate::mailbox::EpochPublic;
use crate::records::{
    AttachmentManifest, Batch, Device, Epoch, EpochMember, MailboxKeysRecord, MekDistribution,
    OtcSession, OwnerBatch, VirtualDevice,
};
use crate::sign::XVerifyingKey;
use crate::{Error, Result};

/// Conditional `Send` bound: `Send` on native targets, unconstrained on `wasm32`.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// Conditional `Sync` bound: `Sync` on native targets, unconstrained on `wasm32`.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

/// A millisecond clock for store adapters: `Send + Sync` on native targets,
/// unconstrained on `wasm32`, like [`MaybeSend`] and [`MaybeSync`].
#[cfg(not(target_arch = "wasm32"))]
pub type ClockFn = std::sync::Arc<dyn Fn() -> u64 + Send + Sync>;
/// A millisecond clock for store adapters: `Send + Sync` on native targets,
/// unconstrained on `wasm32`, like [`MaybeSend`] and [`MaybeSync`].
#[cfg(target_arch = "wasm32")]
pub type ClockFn = std::sync::Arc<dyn Fn() -> u64>;

/// Sequencer ES256 verification key for one DID receipt method (`I13`, Gate 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequencerReceiptKey {
    pub did: String,
    pub public_key_sec1: Vec<u8>,
}

/// Ephemeral enrollment artifact consumed or touched atomically during `Gate 3` epoch rotation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollCleanup {
    ConsumeOtcSession { rkey: String },
    TouchVirtualDevice { updated: VirtualDevice },
}

/// Atomic `Gate 3` enrollment bundle committed in a single `space.applyWrites` transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicEnrollBundle {
    pub cleanup: Option<EnrollCleanup>,
    pub device: Device,
    pub epoch: Epoch,
    pub members: Vec<EpochMember>,
}

/// Summary returned by [`crate::client::Labyrinth::rearchive_and_clear_before_leave`] (`Gate 5`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeaveArchiveReport {
    pub messages_archived: usize,
    pub attachments_archived: usize,
    pub rearchived_blob_cids: Vec<String>,
}

/// A record as read back from a store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored<T> {
    /// DID of the repo the record lives in.
    pub author: String,
    pub rkey: String,
    pub value: T,
    /// The server's stamp, when the backend assigns one. Readers prefer it to
    /// sender timestamps for the removed-key bound ([CB-27]).
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

/// The caller's personal mailbox Space (owner-only reads and writes).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait MailboxStore: MaybeSend + MaybeSync {
    /// The DID that owns this mailbox.
    fn owner(&self) -> &str;

    /// rkey = `hex(deviceKeyPubkey)`.
    async fn create_device(&self, device: &Device) -> Result<()>;
    /// Sets `revokedAt` once; a no-op if already set.
    async fn set_device_revoked(&self, device_key: &XVerifyingKey, revoked_at: &str) -> Result<()>;
    async fn get_device(&self, device_key: &XVerifyingKey) -> Result<Option<Device>>;
    async fn list_devices(&self) -> Result<Vec<Device>>;

    /// Atomically creates the epoch record and its initial members
    /// (`applyWrites`). Returns the backend-assigned `epochID` ([CB-9]).
    async fn create_epoch(&self, epoch: &Epoch, members: &[EpochMember]) -> Result<String>;
    /// Atomically consumes any one-shot recovery/OTC artifact, registers the
    /// newly enrolled device, and opens epoch `E+1` (`Gate 3`).
    async fn atomic_enroll(&self, bundle: &AtomicEnrollBundle) -> Result<String>;
    /// The epoch with this sequence number; `rkey` is its `epochID`.
    async fn get_epoch(&self, seq: u64) -> Result<Option<Stored<Epoch>>>;
    /// All epochs, ascending by sequence number.
    async fn list_epochs(&self) -> Result<Vec<Stored<Epoch>>>;

    /// Adds a device (such as a virtual recovery device) to an epoch mid-epoch.
    async fn create_epoch_member(&self, member: &EpochMember) -> Result<()>;
    async fn list_epoch_members(&self, seq: u64) -> Result<Vec<EpochMember>>;
    async fn get_epoch_member(
        &self,
        seq: u64,
        device_key: &XVerifyingKey,
    ) -> Result<Option<EpochMember>> {
        Ok(self
            .list_epoch_members(seq)
            .await?
            .into_iter()
            .find(|m| m.device_key_pubkey.0 == device_key.0))
    }

    /// rkey = `hex(vdeviceId)`.
    async fn create_virtual_device(&self, vdevice: &VirtualDevice) -> Result<()>;
    async fn get_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<Option<VirtualDevice>>;
    async fn list_virtual_devices(&self) -> Result<Vec<VirtualDevice>>;

    /// Ephemeral hybrid PQ OTC pairing session (`blue.catbird.labyrinth.otcSession`, `I16`).
    async fn put_otc_session(&self, session: &OtcSession) -> Result<()> {
        let _ = session;
        Err(Error::NotSupported("putOtcSession"))
    }
    async fn get_otc_session(&self, session_id: &str) -> Result<Option<OtcSession>> {
        let _ = session_id;
        Err(Error::NotSupported("getOtcSession"))
    }

    /// Appends an owner batch (rkey = TID, assigned by the store).
    async fn append_owner_batch(&self, batch: &OwnerBatch) -> Result<String>;
    /// Owner batches of `thread_id` holding at least one item in `range`,
    /// oldest first.
    async fn list_owner_batches(
        &self,
        thread_id: &str,
        range: TimeRange,
    ) -> Result<Vec<Stored<OwnerBatch>>>;

    /// Upload and commit a re-archived encrypted attachment into the personal
    /// mailbox Space (`Gate 5`). Returns the newly committed blob CID.
    async fn upload_and_commit_owner_attachment(
        &self,
        rkey: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> Result<String> {
        let _ = (rkey, ciphertext, meta, created_at);
        Err(Error::NotSupported("uploadAndCommitOwnerAttachment"))
    }

    /// Fetch and SHA-256-verify a re-archived encrypted attachment from the
    /// personal mailbox Space (`Gate 5`).
    async fn get_owner_attachment_verified(&self, rkey: &str) -> Result<Vec<u8>> {
        let _ = rkey;
        Err(Error::NotSupported("getOwnerAttachmentVerified"))
    }

    /// Writes `mailboxKeys/self` in the owner's PUBLIC repo ([CB-19]), and
    /// the immutable per-epoch copy `mailboxKeys/<12-digit epochNumber>`.
    async fn publish_mailbox_keys(&self, record: &MailboxKeysRecord) -> Result<()>;

    /// Owner batches of `thread_id` holding any of `message_ids`.
    async fn get_owner_messages(
        &self,
        thread_id: &str,
        message_ids: &[&str],
    ) -> Result<Vec<Stored<OwnerBatch>>> {
        Ok(self
            .list_owner_batches(thread_id, TimeRange::ALL)
            .await?
            .into_iter()
            .filter(|b| {
                b.value
                    .items
                    .iter()
                    .any(|i| message_ids.contains(&i.message_id.as_str()))
            })
            .collect())
    }

    /// Newest-first paging over owner batches.
    async fn list_owner_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Stored<OwnerBatch>>> {
        let _ = limit;
        let range = TimeRange {
            from_ms: None,
            until_ms: before_ms,
        };
        let mut v = self.list_owner_batches(thread_id, range).await?;
        v.sort_by_key(|b| core::cmp::Reverse(b.value.items.iter().map(|i| i.timestamp).max()));
        Ok(v)
    }

    /// Every thread with an owner batch in this mailbox.
    async fn list_owner_threads(&self) -> Result<Vec<String>> {
        Err(Error::NotSupported("listOwnerThreads"))
    }

    /// Refresh a virtual device's `lastUsedAt` ([CB-39]).
    async fn touch_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        let _ = vdevice_id;
        Err(Error::NotSupported("touchVirtualDevice"))
    }

    /// Delete a recovery bundle ([CB-39]).
    async fn delete_virtual_device(&self, vdevice_id: &[u8; 16]) -> Result<()> {
        let _ = vdevice_id;
        Err(Error::NotSupported("deleteVirtualDevice"))
    }

    /// Delete an unattested squatted `epoch/<seq>` record and any `epochMember/<seq>-*`
    /// rows in this mailbox (`[CB-40]`). Callers MUST verify via [`MailboxDirectory`]
    /// that `seq` is not anchored by an active account device before invoking.
    async fn delete_squatted_epoch(&self, seq: u64) -> Result<()> {
        let _ = seq;
        Err(Error::NotSupported("deleteSquattedEpoch"))
    }

    /// Erase this mailbox ([CB-38], account deletion).
    async fn purge_mailbox(&self) -> Result<()> {
        Err(Error::NotSupported("purgeMailbox"))
    }

    /// Server-side account deletion ([CB-38]).
    async fn delete_account_data(&self) -> Result<()> {
        Err(Error::NotSupported("deleteAccountData"))
    }
}

/// [`ThreadStore::list_threads_report`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadListing {
    pub threads: Vec<String>,
    pub incomplete: Vec<String>,
}

/// The conversation Spaces the caller belongs to. Writes go to the caller's own
/// repo in the thread's Space; reads see every member's repo.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait ThreadStore: MaybeSend + MaybeSync {
    /// The DID whose repo this handle writes.
    fn author(&self) -> &str;

    /// rkey = `hex(mekId)`.
    async fn create_mek(&self, mek: &MekDistribution) -> Result<()>;
    /// Every MEK record in the thread with this id, across all repos.
    async fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> Result<Vec<Stored<MekDistribution>>>;

    /// Appends a sender batch (`<16-hex-first-seq>-<tid>` when sequenced, else `<tid>`).
    async fn append_batch(&self, batch: &Batch) -> Result<String>;
    /// Batches of `thread_id` (from `sender` only, if given) holding at least
    /// one item in `range`, oldest first per author.
    async fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<Stored<Batch>>>;

    /// Batches of `thread_id` holding any of `message_ids`.
    async fn get_messages(
        &self,
        thread_id: &str,
        message_ids: &[&str],
    ) -> Result<Vec<Stored<Batch>>> {
        Ok(self
            .list_batches(thread_id, None, TimeRange::ALL)
            .await?
            .into_iter()
            .filter(|b| {
                b.value
                    .items
                    .iter()
                    .any(|i| message_ids.contains(&i.message_id.as_str()))
            })
            .collect())
    }

    /// Newest-first paging.
    async fn list_batches_before(
        &self,
        thread_id: &str,
        before_ms: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Stored<Batch>>> {
        let _ = limit;
        let range = TimeRange {
            from_ms: None,
            until_ms: before_ms,
        };
        let mut v = self.list_batches(thread_id, None, range).await?;
        v.sort_by_key(|b| core::cmp::Reverse(b.value.items.iter().map(|i| i.timestamp).max()));
        Ok(v)
    }

    /// Every thread in which this DID wrote a MEK or is a MEK recipient.
    async fn list_threads(&self) -> Result<Vec<String>> {
        Err(Error::NotSupported("listThreads"))
    }

    /// [`list_threads`](Self::list_threads) with partial sequencer report.
    async fn list_threads_report(&self) -> Result<ThreadListing> {
        Ok(ThreadListing {
            threads: self.list_threads().await?,
            incomplete: Vec::new(),
        })
    }

    /// Unsend ([CB-38]): rewrite matching item(s) in-place with `redaction`,
    /// preserving sibling items and their `sequencerReceipt`s.
    async fn redact_item(
        &self,
        thread_id: &str,
        message_id: &str,
        redaction: &Redaction,
    ) -> Result<usize> {
        let _ = (thread_id, message_id, redaction);
        Err(Error::NotSupported("redactMessage"))
    }

    /// Upload encrypted attachment blob and commit `attachmentManifest` in the
    /// conversation Space (`Gate 5`). Returns the manifest `rkey`.
    async fn upload_and_commit_attachment(
        &self,
        thread_id: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> Result<String> {
        let _ = (thread_id, ciphertext, meta, created_at);
        Err(Error::NotSupported("uploadAndCommitAttachment"))
    }

    /// Read an `attachmentManifest` record from `author_did`'s repo in `thread_id`.
    async fn get_attachment_manifest(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> Result<Option<AttachmentManifest>> {
        let _ = (thread_id, author_did, rkey);
        Err(Error::NotSupported("getAttachmentManifest"))
    }

    /// Fetch `com.atproto.space.getBlob` and verify SHA-256 against `attachmentManifest` (`Gate 5`).
    async fn get_attachment_verified(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> Result<Vec<u8>> {
        let _ = (thread_id, author_did, rkey);
        Err(Error::NotSupported("getAttachmentVerified"))
    }

    /// List this caller's own `attachmentManifest` records in `thread_id` (`(rkey, manifest)`).
    async fn list_own_attachment_manifests(
        &self,
        thread_id: &str,
    ) -> Result<Vec<(String, AttachmentManifest)>> {
        let _ = thread_id;
        Ok(Vec::new())
    }

    /// Purge all records authored by this caller in `thread_id`'s Space repo (`Gate 5`).
    async fn clear_records(&self, thread_id: &str) -> Result<()> {
        let _ = thread_id;
        Err(Error::NotSupported("clearRecords"))
    }
}

/// Read-only discovery of other accounts (public `mailboxKeys` records,
/// DS epoch head chains, and MLS group device views).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait MailboxDirectory: MaybeSend + MaybeSync {
    /// The DID's published latest epoch (`mailboxKeys/self`), unverified.
    async fn latest(&self, did: &str) -> Result<Option<EpochPublic>>;
    /// The newest head independently verified from both the account PDS and
    /// `mls-ds`. Single-source directories must keep the default: absence of
    /// two-source evidence can never supersede a pending publication.
    async fn latest_two_source(&self, did: &str) -> Result<Option<EpochPublic>> {
        let _ = did;
        Ok(None)
    }
    /// The DID's published epoch `seq` (`mailboxKeys/<12-digit seq>`), unverified.
    async fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>>;
    /// Verified/unverified full epoch head chain `(headers, floor_seq)` from `mls-ds` (`Gate 6`).
    async fn epoch_chain(
        &self,
        did: &str,
    ) -> Result<Option<(Vec<labyrinth_protocol::EpochPublicHeader>, u64)>> {
        let _ = did;
        Ok(None)
    }
    /// Every MLS chat device transport key ([CB-3]) the DID has registered.
    async fn device_transport_keys(&self, did: &str) -> Result<Vec<ChatDeviceKey>>;
    /// The DID's device leaves in one conversation ([`MemberDeviceKey`]).
    async fn member_device_keys(
        &self,
        thread_id: &str,
        did: &str,
    ) -> Result<Option<Vec<MemberDeviceKey>>> {
        let _ = (thread_id, did);
        Ok(None)
    }
    /// The redaction signing key of the DS that sequences `thread_id` ([`SequencerKey`]).
    async fn sequencer_key(&self, thread_id: &str) -> Result<Option<SequencerKey>> {
        let _ = thread_id;
        Ok(None)
    }
    /// The sequencer's current ES256 receipt verification key for `thread_id` (`I13`).
    async fn sequencer_receipt_key(&self, thread_id: &str) -> Result<Option<SequencerReceiptKey>> {
        let _ = thread_id;
        Ok(None)
    }
    /// Resolve a receipt key for an authority already authenticated by owner
    /// ciphertext, never an issuer taken only from public receipt fields.
    /// The default cannot discover a new authority or override a pinned key.
    async fn sequencer_receipt_key_for_authority(
        &self,
        thread_id: &str,
        expected_authority: &str,
    ) -> Result<Option<SequencerReceiptKey>> {
        Ok(self
            .sequencer_receipt_key(thread_id)
            .await?
            .filter(|key| key.did == expected_authority))
    }
    /// Resolve the exact receipt verification method named by a signed
    /// receipt. Implementations backed by DID documents retain old methods
    /// across rotation. The default supports only the first-generation key.
    async fn sequencer_receipt_key_by_id(
        &self,
        thread_id: &str,
        expected_authority: &str,
        key_id: &str,
    ) -> Result<Option<SequencerReceiptKey>> {
        if key_id != labyrinth_protocol::expected_receipt_key_id(expected_authority) {
            return Ok(None);
        }
        self.sequencer_receipt_key_for_authority(thread_id, expected_authority)
            .await
    }
}

/// Another destination for a newly opened epoch's public keys.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait KeyPublisher: MaybeSend + MaybeSync {
    /// Publishes `record` (the epoch in `record.current`).
    async fn publish(&self, record: &MailboxKeysRecord) -> Result<()>;

    /// Remove every published epoch (account deletion, [CB-38]).
    async fn retract(&self) -> Result<()> {
        Err(Error::NotSupported("retract mailboxKeys"))
    }
}

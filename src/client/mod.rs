//! High-level Labyrinth client over the [`crate::store`] traits.
//!
//! [`Labyrinth`] is one enrolled device of one account. It owns the
//! device's secrets and its cache of epoch secrets, and turns the protocol
//! layers into the operations a chat client needs:
//!
//! | Operation | Module |
//! |---|---|
//! | [`Labyrinth::initialize`], [`Labyrinth::sync_epochs`], [`Labyrinth::revoke_device`], [`Labyrinth::check_epoch_integrity`] | [`epochs`] |
//! | recovery codes, passkey wrap, one-time-code enrollment | [`enroll`] |
//! | [`Labyrinth::archive_outgoing`], [`Labyrinth::flush`] | [`send`] |
//! | [`Labyrinth::load_thread`], [`Labyrinth::archive_owner`], [`Labyrinth::rearchive_thread_before_leave`] | [`read`] |
//! | [`Labyrinth::peer_pin`] (epoch pinning, [CB-29]), [`Labyrinth::propose_repin`] / [`Labyrinth::repin_peer`] | [`pins`] |
//! | [`CompositeDirectory`] (PDS × mls-ds cross-check, [CB-28]) | [`composite`] |
//! | [`Labyrinth::export_state`], [`Labyrinth::from_state`] | [`state`] |
//!
//! The client is synchronous and holds no locks; callers serialize access
//! to one instance (the store traits explain why). Its state (device
//! secrets, epoch cache, revoked set, peer pins, receipt key history and MEK
//! cache) survives a restart through [`Labyrinth::export_state`] /
//! [`Labyrinth::from_state`] ([`state`]); the exported bytes are secret and
//! belong in the keychain or SQLCipher.
//!
//! Before using anyone's epoch keys the client checks [CB-18]: the
//! epoch's attestation key must be one of that DID's chat devices as the
//! [`MailboxDirectory`] reports them.

pub mod archive;
pub mod composite;
pub mod delete;
pub mod enroll;
pub mod epochs;
pub mod lookup;
pub mod members;
pub mod owner_state;
pub mod pins;
pub mod read;
pub mod recovery;
pub mod send;
pub mod state;

use std::collections::{BTreeMap, BTreeSet, HashMap};

pub use crate::store::{AuthorQuarantine, LeaveArchiveReport, QuarantineReason};
pub use composite::CompositeDirectory;
pub use delete::{PurgeReport, delete_account_remote};
pub use enroll::{Enrollment, OtcResponse, RecoverySetup};
pub use epochs::{InvalidatedRecoveryMethod, RotationReport, SyncReport};
pub use lookup::{ThreadCursor, ThreadList, ThreadPage, ThreadSummary};
pub use members::{ExcludedMember, ExclusionReason};
pub use owner_state::{
    ACL_CLEARED_TOMBSTONE_PREFIX, ACL_REMOVE_PENDING, ACL_REMOVE_PENDING_ROTATED,
    ACL_TOMBSTONE_PREFIX, ACL_TOMBSTONE_VER_PREFIX, CircleOwnerState, ReadState,
};
pub use pins::{PeerPin, RepinProposal};
pub use read::{
    LoadedMessage, MessageSource, RedactedMessage, RejectedCopy, Rejection, ThreadHistory,
    Undecryptable,
};
pub use recovery::{AUTO_RECOVERY_TTL_MS, RecoveryMethod, recovery_stale_at};
pub use send::{ArchiveOutcome, FlushedBatch, ResolvedRoster, RosterExclusion};

use crate::device::{DevicePublic, DeviceSecrets};
use crate::epoch::{EpochKeys as _, EpochSecret};
use crate::mailbox::{EpochPublic, MailboxKeys};
use crate::mek::Mek;
use crate::message::{OwnerMessage, SealedMessage};
use crate::records::datetime_from_ms;
use crate::sign::TransportSigner;
use crate::store::{
    KeyPublisher, MailboxDirectory, MailboxStore, MaybeSend, MaybeSync, ThreadStore, VouchAt,
    keys_valid_for,
};
use crate::{Error, Result};

/// Wall-clock source (milliseconds since the Unix epoch) for `createdAt`.
pub trait Clock: MaybeSend + MaybeSync {
    fn now_ms(&self) -> u64;
}

/// Durable callback invoked synchronously whenever [`Labyrinth`]'s exportable
/// state mutates, closing the crash window between security state/key mutation
/// and caller-side `export_state()` persistence (`[CB-30]`).
pub trait StateSink: MaybeSend + MaybeSync {
    fn save_state(&self, exported_state: &[u8]) -> Result<()>;
}

/// [`Clock`] backed by [`web_time::SystemTime`] (native + `wasm32`-compatible).
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }
}

/// Everything the client talks to.
pub struct Backends {
    /// The account's own personal mailbox Space.
    pub mailbox: Box<dyn MailboxStore>,
    /// The conversation Spaces, writing as this account.
    pub threads: Box<dyn ThreadStore>,
    /// Discovery of other accounts and of MLS chat devices; a
    /// [`CompositeDirectory`] over the PDS and `mls-ds` in production.
    pub directory: Box<dyn MailboxDirectory>,
    /// Extra destinations where every new epoch is published besides
    /// [`MailboxStore::publish_mailbox_keys`], so both directories stay
    /// current ([CB-28]).
    pub publishers: Vec<Box<dyn KeyPublisher>>,
    pub clock: Box<dyn Clock>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiptTrust {
    authority: String,
    keys: BTreeMap<String, Vec<u8>>,
}

/// One enrolled device of one account.
pub struct Labyrinth {
    did: String,
    device: DeviceSecrets,
    transport: Box<dyn TransportSigner>,
    b: Backends,
    state_sink: Option<Box<dyn StateSink>>,
    /// An epoch head which must still reach every configured directory.
    pending_directory_publication: Option<u64>,
    /// Epoch secrets this device holds, by sequence number.
    epochs: BTreeMap<u64, EpochSecret>,
    /// Newest epoch this device has reached.
    latest: u64,
    /// Verified copy of my own record for epoch `latest` ([CB-43]). Every
    /// read of my newest epoch goes through it, so a mailbox host cannot
    /// serve a clean record when it is checked and a tampered one later.
    own_latest: Option<EpochPublic>,
    /// Whether `own_latest`'s attesting key was found in the directory. A
    /// restart with the directory unreachable leaves it unchecked until the
    /// next sync or roster resolution.
    own_attester_checked: bool,
    /// My epoch heads → sequence numbers (filled lazily from the store).
    heads: HashMap<[u8; 32], u64>,
    /// `deviceKeyPub`s whose exclusion rotation has committed; every rotation
    /// and sync excludes them, whatever the store says about `revokedAt`.
    revoked: BTreeSet<[u8; 32]>,
    /// `deviceKeyPub`s marked for revocation locally whose exclusion rotation
    /// has not yet committed, mapped to the `latest` epoch seq at decision time.
    pending_revocations: BTreeMap<[u8; 32], u64>,
    /// Most recent rotation report whose mailbox write committed while its
    /// directory publication remained pending.
    last_unanchored_rotation: Option<RotationReport>,
    /// Members of one epoch (the sequence number) this client verified;
    /// a later verification failure for one of them is store tampering
    /// ([`Error::MemberTampered`]), not a planted row.
    verified: (u64, BTreeSet<[u8; 32]>),
    /// Newest accepted epoch of every peer this client addressed ([CB-29]).
    pins: BTreeMap<String, PeerPin>,
    /// MEKs minted or opened here, per thread, newest last. Ordered so
    /// [`Labyrinth::export_state`] bytes are canonical: the same logical
    /// state always exports identically, across reloads and processes.
    meks: BTreeMap<String, Vec<Mek>>,
    /// Per-conversation receipt enforcement latch and immutable historical
    /// verification methods. A non-empty entry permanently disables
    /// receiptless fallback for that conversation.
    receipt_trust: BTreeMap<String, ReceiptTrust>,
    /// Monotonic `(spaceUri, authorDid) -> repoRev` floor persisted across
    /// restarts so a Space host cannot roll back a writer's commit head.
    writer_floors: BTreeMap<(String, String), String>,
    /// Monotonic `(collection, logicalId) -> casVersion` floor persisted across
    /// restarts so a Space host cannot roll back account-private owner state.
    owner_state_floors: BTreeMap<(String, String), u64>,
    /// Cached `(circleId, recordCid) -> casVersion` hints for explicit CAS puts.
    circle_cas_versions: HashMap<(String, String), u64>,
    outbox: BTreeMap<String, Vec<SealedMessage>>,
    /// Canonical `(DID, epoch head)` roster under which each sender buffer's
    /// MEK was distributed. Flush revalidates it so a queued ciphertext
    /// cannot cross a later device/account rotation.
    outbox_rosters: BTreeMap<String, Vec<(String, [u8; 32])>>,
    owner_outbox: BTreeMap<String, Vec<OwnerMessage>>,
    flush_cache: send::FlushDirectoryCache,
}

#[cfg(not(target_arch = "wasm32"))]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Labyrinth>();
};

impl core::fmt::Debug for Labyrinth {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Labyrinth")
            .field("did", &self.did)
            .field("latest", &self.latest)
            .finish_non_exhaustive()
    }
}

impl Labyrinth {
    fn assemble(
        did: &str,
        device: DeviceSecrets,
        transport: Box<dyn TransportSigner>,
        b: Backends,
        epochs: impl IntoIterator<Item = EpochSecret>,
    ) -> Result<Self> {
        if b.mailbox.owner() != did || b.threads.author() != did {
            return Err(Error::Malformed("store handles belong to another DID"));
        }
        let epochs: BTreeMap<u64, EpochSecret> = epochs.into_iter().map(|e| (e.seq, e)).collect();
        let latest = *epochs.keys().next_back().ok_or(Error::NotFound("epoch"))?;
        let mut writer_floors: BTreeMap<(String, String), String> = BTreeMap::new();
        for source in [
            b.mailbox.export_writer_rev_floors(),
            b.threads.export_writer_rev_floors(),
        ] {
            for ((space, author), rev) in source {
                crate::store::validate_writer_rev_floor(&space, &author, &rev)?;
                let key = (space, author);
                match writer_floors.get(&key) {
                    Some(cur) if cur.as_str() >= rev.as_str() => {}
                    Some(_) => {
                        writer_floors.insert(key, rev);
                    }
                    None => {
                        if writer_floors.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
                            return Err(Error::Malformed("writer revision floor table full"));
                        }
                        writer_floors.insert(key, rev);
                    }
                }
            }
        }
        b.mailbox.replace_writer_rev_floors(&writer_floors);
        b.threads.replace_writer_rev_floors(&writer_floors);
        let mut owner_state_floors: BTreeMap<(String, String), u64> = BTreeMap::new();
        for ((col, id), ver) in b.mailbox.export_owner_state_version_floors() {
            crate::store::validate_owner_state_version_floor(&col, &id, ver)?;
            let key = (col, id);
            match owner_state_floors.get(&key) {
                Some(&cur) if cur >= ver => {}
                Some(_) => {
                    owner_state_floors.insert(key, ver);
                }
                None => {
                    if owner_state_floors.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
                        return Err(Error::Malformed("owner state version floor table full"));
                    }
                    owner_state_floors.insert(key, ver);
                }
            }
        }
        b.mailbox
            .replace_owner_state_version_floors(&owner_state_floors);
        Ok(Self {
            did: did.to_owned(),
            device,
            transport,
            b,
            state_sink: None,
            pending_directory_publication: None,
            epochs,
            latest,
            own_latest: None,
            own_attester_checked: false,
            heads: HashMap::new(),
            revoked: BTreeSet::new(),
            pending_revocations: BTreeMap::new(),
            last_unanchored_rotation: None,
            verified: (latest, BTreeSet::new()),
            pins: BTreeMap::new(),
            meks: BTreeMap::new(),
            receipt_trust: BTreeMap::new(),
            writer_floors,
            owner_state_floors,
            circle_cas_versions: HashMap::new(),
            outbox: BTreeMap::new(),
            outbox_rosters: BTreeMap::new(),
            owner_outbox: BTreeMap::new(),
            flush_cache: send::FlushDirectoryCache::default(),
        })
    }

    /// Attach a durable [`StateSink`] so every exportable security-state
    /// mutation is persisted immediately (`[CB-30]`).
    pub fn set_state_sink(&mut self, sink: Box<dyn StateSink>) {
        self.state_sink = Some(sink);
    }

    /// Builder variant of [`set_state_sink`](Self::set_state_sink).
    pub fn with_state_sink(mut self, sink: Box<dyn StateSink>) -> Self {
        self.state_sink = Some(sink);
        self
    }

    pub(super) fn checkpoint_state(&self) -> Result<()> {
        if let Some(ref sink) = self.state_sink {
            let exported = self.export_state()?;
            sink.save_state(&exported)?;
        }
        Ok(())
    }

    pub(super) fn seed_store_writer_floors(&self) {
        self.b.mailbox.seed_writer_rev_floors(&self.writer_floors);
        self.b.threads.seed_writer_rev_floors(&self.writer_floors);
    }

    pub(super) fn replace_store_writer_floors(&self) {
        self.b
            .mailbox
            .replace_writer_rev_floors(&self.writer_floors);
        self.b
            .threads
            .replace_writer_rev_floors(&self.writer_floors);
    }

    pub(super) fn merged_writer_floors(&self) -> Result<BTreeMap<(String, String), String>> {
        let mut merged = self.writer_floors.clone();
        for source in [
            self.b.mailbox.export_writer_rev_floors(),
            self.b.threads.export_writer_rev_floors(),
        ] {
            for ((space, author), offered) in source {
                crate::store::validate_writer_rev_floor(&space, &author, &offered)?;
                let key = (space.clone(), author.clone());
                match merged.get(&key) {
                    Some(pinned) if offered.as_str() < pinned.as_str() => {
                        return Err(Error::WriterRollback {
                            space,
                            author,
                            pinned_rev: pinned.clone(),
                            offered_rev: offered,
                        });
                    }
                    Some(pinned) if offered.as_str() == pinned.as_str() => {}
                    Some(_) => {
                        merged.insert(key, offered);
                    }
                    None => {
                        if merged.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
                            return Err(Error::Malformed("writer revision floor table full"));
                        }
                        merged.insert(key, offered);
                    }
                }
            }
        }
        Ok(merged)
    }

    pub(super) fn sync_store_writer_floors(&mut self) -> Result<()> {
        let merged = match self.merged_writer_floors() {
            Ok(m) => m,
            Err(err) => {
                self.replace_store_writer_floors();
                return Err(err);
            }
        };
        if merged != self.writer_floors {
            let previous = core::mem::replace(&mut self.writer_floors, merged);
            self.replace_store_writer_floors();
            if let Err(err) = self.checkpoint_state() {
                self.writer_floors = previous;
                self.replace_store_writer_floors();
                return Err(err);
            }
        }
        Ok(())
    }

    pub(super) fn seed_store_owner_state_floors(&self) {
        self.b
            .mailbox
            .seed_owner_state_version_floors(&self.owner_state_floors);
    }

    pub(super) fn replace_store_owner_state_floors(&self) {
        self.b
            .mailbox
            .replace_owner_state_version_floors(&self.owner_state_floors);
    }

    pub(super) fn merged_owner_state_floors(&self) -> Result<BTreeMap<(String, String), u64>> {
        let mut merged = self.owner_state_floors.clone();
        for ((col, id), offered) in self.b.mailbox.export_owner_state_version_floors() {
            crate::store::validate_owner_state_version_floor(&col, &id, offered)?;
            let key = (col, id);
            match merged.get(&key) {
                Some(&pinned) if offered < pinned => {
                    return Err(Error::Malformed("owner state version rollback"));
                }
                Some(&pinned) if offered == pinned => {}
                Some(_) => {
                    merged.insert(key, offered);
                }
                None => {
                    if merged.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
                        return Err(Error::Malformed("owner state version floor table full"));
                    }
                    merged.insert(key, offered);
                }
            }
        }
        Ok(merged)
    }

    pub(super) fn sync_store_owner_state_floors(&mut self) -> Result<()> {
        let merged = match self.merged_owner_state_floors() {
            Ok(m) => m,
            Err(err) => {
                self.replace_store_owner_state_floors();
                return Err(err);
            }
        };
        if merged != self.owner_state_floors {
            let previous = core::mem::replace(&mut self.owner_state_floors, merged);
            self.replace_store_owner_state_floors();
            if let Err(err) = self.checkpoint_state() {
                self.owner_state_floors = previous;
                self.replace_store_owner_state_floors();
                return Err(err);
            }
        }
        Ok(())
    }

    /// Raise the `(collection, logical_id)` CAS version floor to `ver` after
    /// the record at that version has decrypted and authenticated. Stores only
    /// check floors on read, so an unauthenticated listing cannot pin one.
    pub(super) fn confirm_owner_state_version(
        &mut self,
        collection: &str,
        logical_id: &str,
        ver: u64,
    ) -> Result<()> {
        crate::store::validate_owner_state_version_floor(collection, logical_id, ver)?;
        let key = (collection.to_owned(), logical_id.to_owned());
        match self.owner_state_floors.get(&key) {
            Some(&pinned) if ver < pinned => {
                return Err(Error::Malformed("owner state version rollback"));
            }
            Some(&pinned) if ver == pinned => return Ok(()),
            Some(_) => {}
            None if self.owner_state_floors.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES => {
                return Err(Error::Malformed("owner state version floor table full"));
            }
            None => {}
        }
        let previous = self.owner_state_floors.insert(key.clone(), ver);
        self.replace_store_owner_state_floors();
        if let Err(err) = self.checkpoint_state() {
            match previous {
                Some(p) => self.owner_state_floors.insert(key, p),
                None => self.owner_state_floors.remove(&key),
            };
            self.replace_store_owner_state_floors();
            return Err(err);
        }
        Ok(())
    }

    /// Pinned CAS version floor for `(collection, logical_id)`, if one has been observed.
    pub fn owner_state_version_floor(&self, collection: &str, logical_id: &str) -> Option<u64> {
        self.owner_state_floors
            .get(&(collection.to_owned(), logical_id.to_owned()))
            .copied()
    }

    /// Pinned commit revision floor for `(space, author)`, if one has been observed.
    pub fn writer_rev_floor(&self, space: &str, author: &str) -> Option<&str> {
        self.writer_floors
            .get(&(space.to_owned(), author.to_owned()))
            .map(String::as_str)
    }

    /// All persisted `(space, author) -> repoRev` commit revision floors.
    pub fn writer_rev_floors(&self) -> &BTreeMap<(String, String), String> {
        &self.writer_floors
    }

    /// Observe and pin a writer's repository commit revision in `space`.
    /// Fails closed with [`Error::WriterRollback`] if `rev` regresses below the
    /// previously pinned revision for `(space, author)`.
    pub fn observe_writer_rev(&mut self, space: &str, author: &str, rev: &str) -> Result<()> {
        crate::store::validate_writer_rev_floor(space, author, rev)?;
        let key = (space.to_owned(), author.to_owned());
        if let Some(pinned) = self.writer_floors.get(&key) {
            if rev < pinned.as_str() {
                return Err(Error::WriterRollback {
                    space: space.to_owned(),
                    author: author.to_owned(),
                    pinned_rev: pinned.clone(),
                    offered_rev: rev.to_owned(),
                });
            }
            if rev == pinned.as_str() {
                return Ok(());
            }
        } else if self.writer_floors.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
            return Err(Error::Malformed("writer revision floor table full"));
        }
        let previous = self.writer_floors.insert(key.clone(), rev.to_owned());
        self.replace_store_writer_floors();
        if let Err(err) = self.checkpoint_state() {
            match previous {
                Some(old) => {
                    self.writer_floors.insert(key, old);
                }
                None => {
                    self.writer_floors.remove(&key);
                }
            }
            self.replace_store_writer_floors();
            return Err(err);
        }
        Ok(())
    }

    pub(super) async fn receipt_required(&self, thread_id: &str) -> Result<bool> {
        if self.receipt_trust.contains_key(thread_id) {
            return Ok(true);
        }
        Ok(self
            .b
            .directory
            .sequencer_receipt_key(thread_id)
            .await?
            .is_some())
    }

    /// Verify the exact receipt method and durably pin its bytes before the
    /// caller accepts or archives the record.
    pub(super) async fn verify_and_remember_receipt(
        &mut self,
        thread_id: &str,
        receipt: &labyrinth_protocol::SignedSequencerReceipt,
    ) -> Result<()> {
        if receipt.payload.conversation_id != thread_id {
            return Err(Error::ReceiptCommitmentMismatch);
        }
        let authority = receipt.payload.sequencer_did.as_str();
        if let Some(trust) = self.receipt_trust.get(thread_id) {
            if trust.authority != authority {
                return Err(Error::ReceiptCommitmentMismatch);
            }
            if let Some(public_key) = trust.keys.get(&receipt.key_id) {
                return labyrinth_protocol::verify_sequencer_receipt_sec1(
                    public_key, authority, receipt,
                )
                .map_err(|_| Error::ReceiptCommitmentMismatch);
            }
        }
        let key = self
            .b
            .directory
            .sequencer_receipt_key_by_id(thread_id, authority, &receipt.key_id)
            .await?
            .filter(|key| key.did == authority)
            .ok_or(Error::ReceiptCommitmentMismatch)?;
        labyrinth_protocol::verify_sequencer_receipt_sec1(&key.public_key_sec1, authority, receipt)
            .map_err(|_| Error::ReceiptCommitmentMismatch)?;

        let created = !self.receipt_trust.contains_key(thread_id);
        self.receipt_trust
            .entry(thread_id.to_owned())
            .or_insert_with(|| ReceiptTrust {
                authority: authority.to_owned(),
                keys: BTreeMap::new(),
            })
            .keys
            .insert(receipt.key_id.clone(), key.public_key_sec1);
        if let Err(error) = self.checkpoint_state() {
            if created {
                self.receipt_trust.remove(thread_id);
            } else if let Some(trust) = self.receipt_trust.get_mut(thread_id) {
                trust.keys.remove(&receipt.key_id);
            }
            return Err(error);
        }
        Ok(())
    }

    /// Epoch whose PDS + directory publication is durably pending.
    pub fn pending_directory_epoch(&self) -> Option<u64> {
        self.pending_directory_publication
    }

    /// The account DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// This device's public record.
    pub fn device_public(&self) -> &DevicePublic {
        self.device.public()
    }

    /// This device's chat transport key ([CB-3]).
    pub fn transport_public_key(&self) -> [u8; 32] {
        self.transport.transport_public_key()
    }

    /// Sequence number of the newest epoch this device has reached.
    pub fn latest_epoch(&self) -> u64 {
        self.latest
    }

    /// The published data of the newest epoch this device has reached:
    /// the copy verified when the device reached it ([CB-43]), not a fresh
    /// read from the mailbox.
    pub fn latest_public(&self) -> Result<EpochPublic> {
        self.own_latest
            .as_ref()
            .filter(|p| p.seq == self.latest)
            .cloned()
            .ok_or(Error::NotFound("verified latest epoch record"))
    }

    /// Mailbox key pairs for epoch `seq`, walking back-links for older
    /// epochs. Errors when `seq` is unknown.
    ///
    /// The result holds secret keys: use it only inside the process, and
    /// never serialize it or pass it across an FFI boundary.
    pub async fn mailbox_keys_for(&mut self, seq: u64) -> Result<MailboxKeys> {
        Ok(self.epoch_secret(seq).await?.mailbox_keys())
    }

    /// `(seq, epoch head, keys)` for up to `max_epochs` recent epochs ending
    /// at [`latest_epoch`](Self::latest_epoch), newest first.
    ///
    /// The keys are secret: use them only inside the process, and never
    /// serialize them or pass them across an FFI boundary.
    pub async fn recent_mailbox_keys(
        &mut self,
        max_epochs: usize,
    ) -> Result<Vec<(u64, [u8; 32], MailboxKeys)>> {
        if max_epochs == 0 {
            return Ok(Vec::new());
        }
        let latest = self.latest;
        let count = max_epochs.min((latest as usize).saturating_add(1));
        let mut out = Vec::with_capacity(count);
        for offset in 0..count {
            let seq = latest - (offset as u64);
            let keys = self.mailbox_keys_for(seq).await?;
            let (_, record) = self.epoch_record(seq).await?;
            out.push((seq, record.public.head, keys));
        }
        Ok(out)
    }

    /// `(seq, epoch head, keys)` for the latest epoch and, when one exists,
    /// the epoch before it. The head is the published
    /// [`EpochPublic::head`] of that epoch, for building associated data.
    ///
    /// The keys are secret: use them only inside the process, and never
    /// serialize them or pass them across an FFI boundary.
    pub async fn current_and_previous_mailbox_keys(
        &mut self,
    ) -> Result<Vec<(u64, [u8; 32], MailboxKeys)>> {
        self.recent_mailbox_keys(2).await
    }

    /// Verifies my record for epoch `latest` in full ([`epochs::verified_own`])
    /// and keeps it as the copy [`latest_public`](Self::latest_public)
    /// returns. When that copy is already held, only finishes a deferred
    /// attester check.
    async fn adopt_latest(&mut self) -> Result<()> {
        if self
            .own_latest
            .as_ref()
            .is_some_and(|p| p.seq == self.latest)
        {
            if !self.own_attester_checked {
                let public = self.latest_public()?;
                epochs::check_own_attester(self.b.directory.as_ref(), &self.did, &public).await?;
                self.own_attester_checked = true;
            }
            return Ok(());
        }
        let secret = self.epoch_secret(self.latest).await?;
        let public = epochs::verified_own(
            self.b.mailbox.as_ref(),
            self.b.directory.as_ref(),
            &self.did,
            &secret,
        )
        .await?;
        self.adopted(public);
        Ok(())
    }

    /// Keeps `public`, fully verified or made here, as my newest epoch.
    fn adopted(&mut self, public: EpochPublic) {
        self.own_latest = Some(public);
        self.own_attester_checked = true;
    }

    pub(super) fn all_revoked_keys(&self) -> BTreeSet<[u8; 32]> {
        self.revoked
            .iter()
            .copied()
            .chain(self.pending_revocations.keys().copied())
            .collect()
    }

    /// [`latest_public`](Self::latest_public) after finishing a deferred
    /// attester check: the copy that goes into a roster.
    #[allow(dead_code)]
    async fn own_latest_checked(&mut self) -> Result<EpochPublic> {
        self.sync_epochs().await?;
        self.adopt_latest().await?;
        self.latest_public()
    }

    /// [`latest_public`](Self::latest_public) for archiving and roster
    /// resolution: permits uncommitted pending revocations only at or below
    /// their local decision epoch while rejecting any re-admission or any
    /// previously committed revocation.
    pub(super) async fn own_latest_for_archive(&mut self) -> Result<EpochPublic> {
        self.sync_epochs_for_archive().await?;
        self.adopt_latest().await?;
        self.latest_public()
    }

    fn now(&self) -> String {
        datetime_from_ms(self.b.clock.now_ms())
    }

    /// Verifies `epoch` for `did` and checks [CB-18]: its attestation key is
    /// one of the DID's chat devices that may vouch at `at` — a current one
    /// for [`VouchAt::Current`], otherwise one not yet revoked when the
    /// record that carries the epoch was written ([CB-27]).
    async fn check_attested(&self, did: &str, epoch: &EpochPublic, at: VouchAt) -> Result<()> {
        epoch.verify(did, None)?;
        let keys = self.transport_keys(did, None, at).await?;
        if keys.contains(&epoch.attestation.transport_public_key) {
            Ok(())
        } else {
            Err(Error::Unattested)
        }
    }

    /// `did`'s chat transport keys that may vouch for a record written at
    /// `at` ([CB-27]). With `thread` set and a server stamp, the key must
    /// also have had a leaf in that conversation at the stamp's chat seq
    /// (when the directory reports the conversation's leaves).
    async fn transport_keys(
        &self,
        did: &str,
        thread: Option<&str>,
        at: VouchAt,
    ) -> Result<Vec<[u8; 32]>> {
        let keys = self.b.directory.device_transport_keys(did).await?;
        match (thread, at) {
            (Some(t), VouchAt::Server(o)) => {
                let leaves = self.b.directory.member_device_keys(t, did).await?;
                Ok(keys_valid_for(&keys, leaves.as_deref(), VouchAt::Server(o)))
            }
            (Some(t), other) => {
                let leaves = self.b.directory.member_device_keys(t, did).await?;
                let filtered: Vec<_> = match leaves {
                    Some(ref l) => keys
                        .into_iter()
                        .filter(|k| l.iter().any(|m| m.key == k.key))
                        .collect(),
                    None => keys,
                };
                Ok(keys_valid_for(&filtered, None, other))
            }
            (None, VouchAt::Server(mut o)) => {
                o.chat_seq = None;
                Ok(keys_valid_for(&keys, None, VouchAt::Server(o)))
            }
            (None, other) => Ok(keys_valid_for(&keys, None, other)),
        }
    }

    /// [`check_attested`](Self::check_attested) against the DID's
    /// *current* chat devices, then the [CB-29] pin: the epoch a MEK is
    /// about to be addressed to.
    async fn accept_for_addressing(&mut self, did: &str, epoch: &EpochPublic) -> Result<()> {
        self.check_attested(did, epoch, VouchAt::Current).await?;
        self.pin_peer(did, epoch).await
    }

    /// My epoch `seq` (backward-chained if needed) and its mailbox keys.
    async fn my_keys(&mut self, seq: u64) -> Result<(EpochSecret, crate::mailbox::MailboxKeys)> {
        let e = self.epoch_secret(seq).await?;
        let keys = e.mailbox_keys();
        Ok((e, keys))
    }
}

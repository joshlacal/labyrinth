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
//! secrets, epoch cache, revoked set, peer pins, MEK cache) survives a
//! restart through [`Labyrinth::export_state`] / [`Labyrinth::from_state`]
//! ([`state`]); the exported bytes are secret and belong in the keychain or
//! SQLCipher.
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
pub mod pins;
pub mod read;
pub mod recovery;
pub mod send;
pub mod state;

use std::collections::{BTreeMap, BTreeSet, HashMap};

pub use crate::store::LeaveArchiveReport;
pub use composite::CompositeDirectory;
pub use delete::{PurgeReport, delete_account_remote};
pub use enroll::{Enrollment, OtcResponse, RecoverySetup};
pub use epochs::{RotationReport, SyncReport};
pub use lookup::{ThreadCursor, ThreadList, ThreadPage, ThreadSummary};
pub use members::{ExcludedMember, ExclusionReason};
pub use pins::{PeerPin, RepinProposal};
pub use read::{LoadedMessage, MessageSource, RedactedMessage, ThreadHistory, Undecryptable};
pub use recovery::{AUTO_RECOVERY_TTL_MS, RecoveryMethod, recovery_expiry};
pub use send::{ArchiveOutcome, FlushedBatch, ResolvedRoster, RosterExclusion};

use crate::device::{DevicePublic, DeviceSecrets};
use crate::epoch::{EpochKeys as _, EpochSecret};
use crate::mailbox::EpochPublic;
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
/// state (`epochs`, `revoked`, `pins`, `meks`) mutates, closing the crash window
/// between state/key mutation and caller-side `export_state()` persistence (`[CB-30]`).
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

/// One enrolled device of one account.
pub struct Labyrinth {
    did: String,
    device: DeviceSecrets,
    transport: Box<dyn TransportSigner>,
    b: Backends,
    state_sink: Option<Box<dyn StateSink>>,
    mailbox_root_salt: [u8; 32],
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
    /// `deviceKeyPub`s this client revoked; every rotation excludes them,
    /// whatever the store says about `revokedAt`.
    revoked: BTreeSet<[u8; 32]>,
    /// Members of one epoch (the sequence number) this client verified;
    /// a later verification failure for one of them is store tampering
    /// ([`Error::MemberTampered`]), not a planted row.
    verified: (u64, BTreeSet<[u8; 32]>),
    /// Newest accepted epoch of every peer this client addressed ([CB-29]).
    pins: BTreeMap<String, PeerPin>,
    /// MEKs minted or opened here, per thread, newest last.
    meks: HashMap<String, Vec<Mek>>,
    outbox: BTreeMap<String, Vec<SealedMessage>>,
    /// Canonical `(DID, epoch head)` roster under which each sender buffer's
    /// MEK was distributed. Flush revalidates it so a queued ciphertext
    /// cannot cross a later device/account rotation.
    outbox_rosters: BTreeMap<String, Vec<(String, [u8; 32])>>,
    owner_outbox: BTreeMap<String, Vec<OwnerMessage>>,
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
        mailbox_root_salt: [u8; 32],
        epochs: impl IntoIterator<Item = EpochSecret>,
    ) -> Result<Self> {
        if b.mailbox.owner() != did || b.threads.author() != did {
            return Err(Error::Malformed("store handles belong to another DID"));
        }
        let epochs: BTreeMap<u64, EpochSecret> = epochs.into_iter().map(|e| (e.seq, e)).collect();
        let latest = *epochs.keys().next_back().ok_or(Error::NotFound("epoch"))?;
        Ok(Self {
            did: did.to_owned(),
            device,
            transport,
            b,
            state_sink: None,
            mailbox_root_salt,
            epochs,
            latest,
            own_latest: None,
            own_attester_checked: false,
            heads: HashMap::new(),
            revoked: BTreeSet::new(),
            verified: (latest, BTreeSet::new()),
            pins: BTreeMap::new(),
            meks: HashMap::new(),
            outbox: BTreeMap::new(),
            outbox_rosters: BTreeMap::new(),
            owner_outbox: BTreeMap::new(),
        })
    }

    /// Attach a durable [`StateSink`] so `export_state()` is persisted immediately
    /// whenever `MEK`s, `[CB-29]` peer pins, `epochs`, or `revoked` mutate (`[CB-30]`).
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

    /// [`latest_public`](Self::latest_public) after finishing a deferred
    /// attester check: the copy that goes into a roster.
    async fn own_latest_checked(&mut self) -> Result<EpochPublic> {
        // A failed revocation deliberately remains in the persisted local
        // revoked set. Before this account contributes a recipient epoch to
        // any new archive, prove that the active epoch excludes every such
        // device; otherwise it may still know the encryption root.
        self.sync_epochs().await?;
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

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
//!
//! The client is synchronous and holds no locks; callers serialize access
//! to one instance (the store traits explain why). It does **not** persist
//! device secrets: a client that restarts re-enrolls (one-time code or
//! recovery code). Persisting [`crate::device::DeviceSecrets`] and the
//! epoch cache is the embedding app's job and is not yet provided here.
//!
//! Before using anyone's epoch keys the client checks [CB-18]: the
//! epoch's attestation key must be one of that DID's chat devices as the
//! [`MailboxDirectory`] reports them.

pub mod enroll;
pub mod epochs;
pub mod pins;
pub mod read;
pub mod send;

use std::collections::{BTreeMap, BTreeSet, HashMap};

pub use enroll::{Enrollment, OtcResponse, RecoverySetup};
pub use epochs::{RotationReport, SyncReport};
pub use pins::PeerPin;
pub use read::{LoadedMessage, MessageSource, ThreadHistory, Undecryptable};
pub use send::{ArchiveOutcome, FlushedBatch};

use crate::device::{DevicePublic, DeviceSecrets};
use crate::epoch::{EpochKeys as _, EpochSecret};
use crate::mailbox::EpochPublic;
use crate::mek::Mek;
use crate::message::{OwnerMessage, SealedMessage};
use crate::records::datetime_from_ms;
use crate::sign::TransportSigner;
use crate::store::{MailboxDirectory, MailboxStore, ThreadStore, keys_valid_at};
use crate::{Error, Result};

/// Wall-clock source (milliseconds since the Unix epoch) for `createdAt`.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// [`Clock`] backed by [`std::time::SystemTime`].
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }
}

/// Everything the client talks to.
pub struct Backends {
    /// The account's own personal mailbox.
    pub mailbox: Box<dyn MailboxStore + Send>,
    /// The conversation spaces, writing as this account.
    pub threads: Box<dyn ThreadStore + Send>,
    /// Discovery of other accounts and of MLS chat devices.
    pub directory: Box<dyn MailboxDirectory + Send>,
    pub clock: Box<dyn Clock + Send>,
}

/// One enrolled device of one account.
pub struct Labyrinth {
    did: String,
    device: DeviceSecrets,
    transport: Box<dyn TransportSigner + Send>,
    b: Backends,
    mailbox_root_salt: [u8; 32],
    /// Epoch secrets this device holds, by sequence number.
    epochs: BTreeMap<u64, EpochSecret>,
    /// Newest epoch this device has reached.
    latest: u64,
    /// My epoch heads → sequence numbers (filled lazily from the store).
    heads: HashMap<[u8; 32], u64>,
    /// `deviceKeyPub`s this client revoked; every rotation excludes them,
    /// whatever the store says about `revokedAt`.
    revoked: BTreeSet<[u8; 32]>,
    /// Newest accepted epoch of every peer this client addressed ([CB-29]).
    pins: BTreeMap<String, PeerPin>,
    /// MEKs minted or opened here, per thread, newest last.
    meks: HashMap<String, Vec<Mek>>,
    outbox: BTreeMap<String, Vec<SealedMessage>>,
    owner_outbox: BTreeMap<String, Vec<OwnerMessage>>,
}

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
        transport: Box<dyn TransportSigner + Send>,
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
            mailbox_root_salt,
            epochs,
            latest,
            heads: HashMap::new(),
            revoked: BTreeSet::new(),
            pins: BTreeMap::new(),
            meks: HashMap::new(),
            outbox: BTreeMap::new(),
            owner_outbox: BTreeMap::new(),
        })
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

    /// The published data of the newest epoch this device has reached.
    pub fn latest_public(&self) -> Result<EpochPublic> {
        Ok(self.epoch_record(self.latest)?.1.public)
    }

    fn now(&self) -> String {
        datetime_from_ms(self.b.clock.now_ms())
    }

    /// Verifies `epoch` for `did` and checks [CB-18]: its attestation key is
    /// one of the DID's chat devices — a current one if `at_ms` is `None`,
    /// otherwise one that had not been removed by `at_ms` ([CB-27]).
    fn check_attested(&self, did: &str, epoch: &EpochPublic, at_ms: Option<u64>) -> Result<()> {
        epoch.verify(did, None)?;
        let keys = self.transport_keys(did, at_ms)?;
        if keys.contains(&epoch.attestation.transport_public_key) {
            Ok(())
        } else {
            Err(Error::Unattested)
        }
    }

    /// `did`'s chat transport keys that are current (`at_ms = None`) or were
    /// not yet removed at `at_ms` ([CB-27]).
    fn transport_keys(&self, did: &str, at_ms: Option<u64>) -> Result<Vec<[u8; 32]>> {
        Ok(keys_valid_at(
            &self.b.directory.device_transport_keys(did)?,
            at_ms,
        ))
    }

    /// [`check_attested`](Self::check_attested) against the DID's
    /// *current* chat devices, then the [CB-29] pin: the epoch a MEK is
    /// about to be addressed to.
    fn accept_for_addressing(&mut self, did: &str, epoch: &EpochPublic) -> Result<()> {
        self.check_attested(did, epoch, None)?;
        self.pin_peer(did, epoch)
    }

    /// My epoch `seq` (backward-chained if needed) and its mailbox keys.
    fn my_keys(&mut self, seq: u64) -> Result<(EpochSecret, crate::mailbox::MailboxKeys)> {
        let e = self.epoch_secret(seq)?;
        let keys = e.mailbox_keys();
        Ok((e, keys))
    }
}

//! Persisting a client across restarts: [`Labyrinth::export_state`] and
//! [`Labyrinth::from_state`].
//!
//! The state is **secret**: it holds the device's private keys, every
//! cached epoch root and every cached MEK. Callers must store it only in
//! the platform keychain or an encrypted database (SQLCipher), never in
//! plain files, logs or backups, and should overwrite the stored copy on
//! every change. The returned buffer zeroizes on drop.
//!
//! What it holds: the device secrets and public record, every known epoch
//! `(seq, epochID, root)`, the locally revoked device set ([CB-11]), the peer
//! epoch pins ([CB-29]), the durable receipt-required/key-history latch and
//! the MEK cache. It does **not** hold unflushed batches: call
//! [`Labyrinth::flush`] first.
//!
//! Encoding (version 4), all integers big-endian, strings and lists
//! length-prefixed, no trailing bytes:
//!
//! ```text
//! "LBYS" 0x04            (clean-slate state; earlier versions rejected)
//! did                      str16
//! transportPub             32
//! deviceKey                32
//! storage                  96   (Hawk HPKE EncSecret)
//! storageAuth              opt(32)
//! public: deviceKeyPub     32
//!         storagePub       1216 (Hawk HPKE EncPublic)
//!         sigStorage       64   (0x30 physical / 0x34 virtual)
//!         authPub sig0x31 isVirtual  opt(32) opt(64) u8
//! latest                   u64
//! pendingPublication       opt(u64)
//! epochs   u32 × (seq u64, epochID str16, root 32)
//! revoked  u32 × 32
//! pendingRevocations u32 × (key 32, decisionSeq u64)
//! verified seq u64, u32 × 32          members verified in epoch seq ([CB-25])
//! pins     u32 × (did str16, seq u64, head 32, sigKey 32)
//! receipts u32 × (threadId str16, authority str16,
//!                 u32 × (verificationMethod str16, SEC1 key blob16))
//! writerFloors u32 × (space str16, author str16, rev str16)
//! meks     u32 × (threadId str16, u32 × (secret 32, rosterHash 32, provenance))
//!          maps in ascending key byte order, MEKs oldest first;
//!          decode accepts any map order, export is always canonical
//! provenance = 0x00 | 0x01 senderDid str16 head 32 | 0x02 transportPub 32 createdHere u8
//! opt(x)   = 0x00 | 0x01 x;   str16/blob16 = u16 length || bytes
//! ```

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use super::{Backends, Labyrinth, PeerPin, ReceiptTrust};
use crate::device::{DevicePublic, DeviceSecrets};
use crate::epoch::{EpochKeys as _, EpochSecret};
use crate::hpke::hawk::{HAWK_ENC_PUBLIC_LEN, HAWK_ENC_SECRET_LEN, HawkEncPublic, HawkEncSecret};
use crate::hpke::{X25519Public, X25519Secret};
use crate::mek::{Mek, MekProvenance};
use crate::sign::{TransportSigner, XSigningKey, XVerifyingKey};
use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"LBYS";
/// Version byte of the clean-slate state encoding.
pub const STATE_VERSION: u8 = 0x04;

/// Writer. A first pass with `buf = None` only measures, so the real
/// buffer is allocated once at its final size and never reallocates
/// (a reallocation would leave an unzeroized copy of the secrets behind).
struct W {
    len: usize,
    buf: Option<Zeroizing<Vec<u8>>>,
}

impl W {
    fn bytes(&mut self, b: &[u8]) {
        self.len += b.len();
        if let Some(buf) = &mut self.buf {
            debug_assert!(buf.len() + b.len() <= buf.capacity());
            buf.extend_from_slice(b);
        }
    }
    fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }
    fn u32(&mut self, v: usize) -> Result<()> {
        let v = u32::try_from(v).map_err(|_| Error::Malformed("state list too long"))?;
        self.bytes(&v.to_be_bytes());
        Ok(())
    }
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_be_bytes());
    }
    fn str(&mut self, s: &str) -> Result<()> {
        let n = u16::try_from(s.len()).map_err(|_| Error::Malformed("state string too long"))?;
        self.bytes(&n.to_be_bytes());
        self.bytes(s.as_bytes());
        Ok(())
    }
    fn blob(&mut self, b: &[u8]) -> Result<()> {
        let n = u16::try_from(b.len()).map_err(|_| Error::Malformed("state blob too long"))?;
        self.bytes(&n.to_be_bytes());
        self.bytes(b);
        Ok(())
    }
    fn opt(&mut self, b: Option<&[u8]>) {
        match b {
            Some(b) => {
                self.u8(1);
                self.bytes(b);
            }
            None => self.u8(0),
        }
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::Malformed("state truncated"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn secret(&mut self) -> Result<Zeroizing<[u8; 32]>> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }
    fn secret_n<const N: usize>(&mut self) -> Result<Zeroizing<[u8; N]>> {
        let mut out = Zeroizing::new([0u8; N]);
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Malformed("state flag")),
        }
    }
    /// A list length, checked against the bytes left (each item is at
    /// least `min_item` bytes) so a corrupt count cannot force a huge
    /// allocation.
    fn count(&mut self, min_item: usize) -> Result<usize> {
        let n = u32::from_be_bytes(self.arr()?) as usize;
        if n.saturating_mul(min_item) > self.0.len() {
            return Err(Error::Malformed("state list length"));
        }
        Ok(n)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    fn str(&mut self) -> Result<String> {
        let n = u16::from_be_bytes(self.arr()?) as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Error::Malformed("state string"))
    }
    fn blob(&mut self) -> Result<Vec<u8>> {
        let n = u16::from_be_bytes(self.arr()?) as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn opt<const N: usize>(&mut self) -> Result<Option<[u8; N]>> {
        if self.bool()? {
            Ok(Some(self.arr()?))
        } else {
            Ok(None)
        }
    }
}

impl Labyrinth {
    /// Serialize this client's state (see the module docs). The bytes are
    /// secret: keep them in the keychain or SQLCipher only.
    pub fn export_state(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut measure = W { len: 0, buf: None };
        self.write_state(&mut measure)?;
        let mut w = W {
            len: 0,
            buf: Some(Zeroizing::new(Vec::with_capacity(measure.len))),
        };
        self.write_state(&mut w)?;
        Ok(w.buf.expect("writing pass"))
    }

    fn write_state(&self, w: &mut W) -> Result<()> {
        w.bytes(MAGIC);
        w.u8(STATE_VERSION);
        w.str(&self.did)?;
        w.bytes(&self.transport.transport_public_key());

        let d = &self.device;
        w.bytes(Zeroizing::new(d.device_key.to_bytes()).as_slice());
        w.bytes(Zeroizing::new(d.storage.to_bytes()).as_slice());
        let auth = d
            .storage_auth
            .as_ref()
            .map(|a| Zeroizing::new(a.to_bytes()));
        w.opt(auth.as_ref().map(|a| a.as_slice()));
        let p = d.public();
        w.bytes(&p.device_key_pub.0);
        w.bytes(&p.epoch_storage_key_pub.to_bytes());
        w.bytes(&p.sig_storage);
        w.opt(
            p.epoch_storage_auth_key_pub
                .as_ref()
                .map(|k| k.0.as_slice()),
        );
        w.opt(p.sig_0x31.as_ref().map(|s| s.as_slice()));
        w.u8(p.is_virtual.into());

        w.u64(self.latest);
        match self.pending_directory_publication {
            Some(seq) => {
                w.u8(1);
                w.u64(seq);
            }
            None => w.u8(0),
        }
        w.u32(self.epochs.len())?;
        for e in self.epochs.values() {
            w.u64(e.seq);
            w.str(&e.epoch_id)?;
            w.bytes(e.root());
        }
        w.u32(self.revoked.len())?;
        for k in &self.revoked {
            w.bytes(k);
        }
        w.u32(self.pending_revocations.len())?;
        for (k, decision_seq) in &self.pending_revocations {
            w.bytes(k);
            w.u64(*decision_seq);
        }
        w.u64(self.verified.0);
        w.u32(self.verified.1.len())?;
        for k in &self.verified.1 {
            w.bytes(k);
        }
        w.u32(self.pins.len())?;
        for (did, pin) in &self.pins {
            w.str(did)?;
            w.u64(pin.seq);
            w.bytes(&pin.head);
            w.bytes(&pin.sig_key.0);
        }
        w.u32(self.receipt_trust.len())?;
        for (thread, trust) in &self.receipt_trust {
            w.str(thread)?;
            w.str(&trust.authority)?;
            w.u32(trust.keys.len())?;
            for (key_id, public_key) in &trust.keys {
                w.str(key_id)?;
                w.blob(public_key)?;
            }
        }
        let writer_floors = self.merged_writer_floors()?;
        w.u32(writer_floors.len())?;
        for ((space, author), rev) in &writer_floors {
            w.str(space)?;
            w.str(author)?;
            w.str(rev)?;
        }
        let owner_state_floors = self.merged_owner_state_floors()?;
        w.u32(owner_state_floors.len())?;
        for ((collection, logical_id), &ver) in &owner_state_floors {
            w.str(collection)?;
            w.str(logical_id)?;
            w.u64(ver);
        }
        w.u32(self.meks.len())?;
        for (thread, meks) in &self.meks {
            w.str(thread)?;
            w.u32(meks.len())?;
            for m in meks {
                w.bytes(m.secret());
                w.bytes(m.roster_hash());
                match m.provenance() {
                    MekProvenance::Unsent => w.u8(0),
                    MekProvenance::Labyrinth {
                        sender_did,
                        sender_epoch_head,
                    } => {
                        w.u8(1);
                        w.str(sender_did)?;
                        w.bytes(sender_epoch_head);
                    }
                    MekProvenance::Transport {
                        transport_pub,
                        created_here,
                    } => {
                        w.u8(2);
                        w.bytes(transport_pub);
                        w.u8((*created_here).into());
                    }
                }
            }
        }
        Ok(())
    }

    /// Rebuild a client from [`export_state`](Self::export_state) output.
    ///
    /// `did` and `transport` must be the ones the state was exported with,
    /// the device secrets must match their public record, and the newest
    /// epoch must match the record in `b.mailbox`. Call
    /// [`sync_epochs`](Self::sync_epochs) afterwards to catch up.
    pub async fn from_state(
        bytes: &[u8],
        did: &str,
        transport: Box<dyn TransportSigner>,
        b: Backends,
    ) -> Result<Self> {
        let mut r = R(bytes);
        if r.take(4)? != MAGIC {
            return Err(Error::Malformed("not a labyrinth client state"));
        }
        let version = r.u8()?;
        if version != STATE_VERSION {
            return Err(Error::Unsupported(version));
        }
        if r.str()? != did {
            return Err(Error::Malformed("state belongs to another DID"));
        }
        if r.arr::<32>()? != transport.transport_public_key() {
            return Err(Error::Malformed("state belongs to another transport key"));
        }

        let device_key = XSigningKey::from_bytes(*r.secret()?);
        let storage = HawkEncSecret::from_bytes(*r.secret_n::<HAWK_ENC_SECRET_LEN>()?);
        let storage_auth = if r.bool()? {
            Some(X25519Secret::from_bytes(*r.secret()?))
        } else {
            None
        };
        let public = DevicePublic {
            device_key_pub: XVerifyingKey(r.arr()?),
            epoch_storage_key_pub: HawkEncPublic::from_bytes(r.take(HAWK_ENC_PUBLIC_LEN)?)?,
            sig_storage: r.arr()?,
            epoch_storage_auth_key_pub: r.opt()?.map(X25519Public),
            sig_0x31: r.opt()?,
            is_virtual: r.bool()?,
        };
        let device = DeviceSecrets::from_parts(device_key, storage, storage_auth, public)?;

        let latest = r.u64()?;
        let pending_directory_publication = if r.bool()? { Some(r.u64()?) } else { None };
        let mut epochs = Vec::new();
        for _ in 0..r.count(8 + 2 + 32)? {
            let seq = r.u64()?;
            let id = r.str()?;
            epochs.push(EpochSecret::from_parts(seq, id, *r.secret()?));
        }
        let mut revoked = BTreeSet::new();
        for _ in 0..r.count(32)? {
            if !revoked.insert(r.arr::<32>()?) {
                return Err(Error::Malformed("duplicate state revocation"));
            }
        }
        let mut pending_revocations = BTreeMap::new();
        for _ in 0..r.count(32 + 8)? {
            let key = r.arr::<32>()?;
            let decision_seq = r.u64()?;
            if revoked.contains(&key) || pending_revocations.insert(key, decision_seq).is_some() {
                return Err(Error::Malformed("duplicate state pending revocation"));
            }
        }
        let mut verified = (r.u64()?, BTreeSet::new());
        for _ in 0..r.count(32)? {
            verified.1.insert(r.arr::<32>()?);
        }
        let mut pins = BTreeMap::new();
        for _ in 0..r.count(2 + 8 + 64)? {
            let peer = r.str()?;
            let pin = PeerPin {
                seq: r.u64()?,
                head: r.arr()?,
                sig_key: XVerifyingKey(r.arr()?),
            };
            pins.insert(peer, pin);
        }
        let mut receipt_trust = BTreeMap::new();
        for _ in 0..r.count(2 + 2 + 4)? {
            let thread = r.str()?;
            let authority = r.str()?;
            let mut keys = BTreeMap::new();
            for _ in 0..r.count(2 + 2)? {
                let key_id = r.str()?;
                labyrinth_protocol::receipt_key_generation(&authority, &key_id)
                    .map_err(|_| Error::Malformed("state receipt verification method"))?;
                let public_key = r.blob()?;
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key)
                    .map_err(|_| Error::Malformed("state receipt public key"))?;
                if keys.insert(key_id, public_key).is_some() {
                    return Err(Error::Malformed("duplicate state receipt method"));
                }
            }
            if thread.is_empty() || keys.is_empty() {
                return Err(Error::Malformed("empty state receipt trust"));
            }
            if receipt_trust
                .insert(thread, ReceiptTrust { authority, keys })
                .is_some()
            {
                return Err(Error::Malformed("duplicate state receipt conversation"));
            }
        }
        let writer_floor_count = r.count(2 + 2 + 2)?;
        if writer_floor_count > crate::store::MAX_WRITER_FLOOR_ENTRIES {
            return Err(Error::Malformed("state writer revision floor table full"));
        }
        let mut writer_floors = BTreeMap::new();
        for _ in 0..writer_floor_count {
            let space = r.str()?;
            let author = r.str()?;
            let rev = r.str()?;
            crate::store::validate_writer_rev_floor(&space, &author, &rev)?;
            if writer_floors.insert((space, author), rev).is_some() {
                return Err(Error::Malformed("duplicate state writer revision floor"));
            }
        }
        let owner_floor_count = r.count(2 + 2 + 8)?;
        if owner_floor_count > crate::store::MAX_WRITER_FLOOR_ENTRIES {
            return Err(Error::Malformed(
                "state owner state version floor table full",
            ));
        }
        let mut owner_state_floors = BTreeMap::new();
        for _ in 0..owner_floor_count {
            let collection = r.str()?;
            let logical_id = r.str()?;
            let ver = r.u64()?;
            crate::store::validate_owner_state_version_floor(&collection, &logical_id, ver)?;
            if owner_state_floors
                .insert((collection, logical_id), ver)
                .is_some()
            {
                return Err(Error::Malformed(
                    "duplicate state owner state version floor",
                ));
            }
        }
        let mut meks = BTreeMap::new();
        for _ in 0..r.count(2 + 4)? {
            let thread = r.str()?;
            let mut list = Vec::new();
            for _ in 0..r.count(65)? {
                let secret = r.secret()?;
                let roster_hash = r.arr()?;
                let provenance = match r.u8()? {
                    0 => MekProvenance::Unsent,
                    1 => MekProvenance::Labyrinth {
                        sender_did: r.str()?,
                        sender_epoch_head: r.arr()?,
                    },
                    2 => MekProvenance::Transport {
                        transport_pub: r.arr()?,
                        created_here: r.bool()?,
                    },
                    _ => return Err(Error::Malformed("state MEK provenance")),
                };
                list.push(Mek::from_secret(secret, roster_hash, provenance));
            }
            meks.insert(thread, list);
        }
        if !r.0.is_empty() {
            return Err(Error::Malformed("trailing bytes after state"));
        }

        let mut me = Self::assemble(did, device, transport, b, epochs)?;
        if me.latest != latest {
            return Err(Error::Malformed("state latest epoch is not cached"));
        }
        if pending_directory_publication.is_some_and(|seq| seq != latest) {
            return Err(Error::Malformed("state pending publication is not latest"));
        }
        for ((space, author), pinned) in writer_floors {
            let key = (space.clone(), author.clone());
            match me.writer_floors.get(&key) {
                Some(existing) if existing.as_str() < pinned.as_str() => {
                    return Err(Error::WriterRollback {
                        space,
                        author,
                        pinned_rev: pinned,
                        offered_rev: existing.clone(),
                    });
                }
                Some(existing) if existing.as_str() >= pinned.as_str() => {}
                None => {
                    if me.writer_floors.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
                        return Err(Error::Malformed("writer revision floor table full"));
                    }
                    me.writer_floors.insert(key, pinned);
                }
                Some(_) => {
                    me.writer_floors.insert(key, pinned);
                }
            }
        }
        me.replace_store_writer_floors();
        for ((col, id), pinned) in owner_state_floors {
            let key = (col, id);
            match me.owner_state_floors.get(&key) {
                Some(&existing) if existing < pinned => {
                    return Err(Error::Malformed("owner state version rollback"));
                }
                Some(&existing) if existing >= pinned => {}
                None => {
                    if me.owner_state_floors.len() >= crate::store::MAX_WRITER_FLOOR_ENTRIES {
                        return Err(Error::Malformed("owner state version floor table full"));
                    }
                    me.owner_state_floors.insert(key, pinned);
                }
                Some(_) => {
                    me.owner_state_floors.insert(key, pinned);
                }
            }
        }
        me.replace_store_owner_state_floors();
        // [CB-43] Everything the mailbox alone can prove is checked now.
        // The attester lookup may wait for the directory: a restart must
        // work offline, and nothing is addressed to this epoch until a
        // sync or roster resolution finishes the check.
        let newest = me.epoch_secret(latest).await?;
        match super::epochs::verified_own_signatures(me.b.mailbox.as_ref(), &me.did, &newest).await
        {
            Ok(public) => {
                me.own_latest = Some(public.clone());
                me.own_attester_checked = match super::epochs::check_own_attester(
                    me.b.directory.as_ref(),
                    &me.did,
                    &public,
                )
                .await
                {
                    Ok(()) => true,
                    Err(Error::Unattested) => return Err(Error::Unattested),
                    Err(_) => false,
                };
            }
            Err(
                Error::Malformed("epoch public keys do not match root") | Error::NotFound("epoch"),
            ) if pending_directory_publication == Some(latest) && latest > 0 => {
                let base = me.epoch_secret(latest - 1).await?;
                let _ =
                    super::epochs::verified_own_signatures(me.b.mailbox.as_ref(), &me.did, &base)
                        .await?;
                me.own_latest = None;
                me.own_attester_checked = false;
            }
            Err(err) => return Err(err),
        }
        me.pending_directory_publication = pending_directory_publication;
        me.revoked = revoked;
        me.pending_revocations = pending_revocations;
        me.verified = verified;
        me.pins = pins;
        me.receipt_trust = receipt_trust;
        me.meks = meks;
        Ok(me)
    }
}

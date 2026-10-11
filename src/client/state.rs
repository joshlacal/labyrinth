//! Persisting a client across restarts: [`Labyrinth::export_state`] and
//! [`Labyrinth::from_state`].
//!
//! The state is **secret**: it holds the device's private keys, every
//! cached epoch root and every cached MEK. Callers must store it only in
//! the platform keychain or an encrypted database (SQLCipher), never in
//! plain files, logs or backups, and should overwrite the stored copy on
//! every change. The returned buffer zeroizes on drop.
//!
//! What it holds: the device secrets and public record, the mailbox root
//! salt, every known epoch `(seq, epochID, root)`, the locally revoked
//! device set ([CB-11]), the peer epoch pins ([CB-29]) and the MEK cache.
//! It does **not** hold unflushed batches: call [`Labyrinth::flush`]
//! first.
//!
//! Encoding (version 2), all integers big-endian, strings and lists
//! length-prefixed, no trailing bytes:
//!
//! ```text
//! "LBYS" 0x02            (0x01 = the same without `verified`)
//! did                      str16
//! transportPub             32
//! deviceKey storage        32 32
//! storageAuth              opt(32)
//! orfClientState           32
//! public: deviceKeyPub storagePub sig0x30   32 32 64
//!         authPub sig0x31 isVirtual         opt(32) opt(64) u8
//! mailboxRootSalt          32
//! latest                   u64
//! epochs   u32 × (seq u64, epochID str16, root 32)
//! revoked  u32 × 32
//! verified seq u64, u32 × 32          members verified in epoch seq ([CB-25])
//! pins     u32 × (did str16, seq u64, head 32, sigKey 32)
//! meks     u32 × (threadId str16, u32 × (secret 32, rosterHash 32, provenance))
//! provenance = 0x00 | 0x01 senderDid str16 head 32 | 0x02 transportPub 32 createdHere u8
//! opt(x)   = 0x00 | 0x01 x;   str16 = u16 length || UTF-8
//! ```

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use super::{Backends, Labyrinth, PeerPin};
use crate::device::{DevicePublic, DeviceSecrets};
use crate::epoch::{EpochKeys as _, EpochSecret, verify_public};
use crate::hpke::labyrinth::{X25519Public, X25519Secret};
use crate::mek::{Mek, MekProvenance};
use crate::orf::OrfClientState;
use crate::sign::{TransportSigner, XSigningKey, XVerifyingKey};
use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"LBYS";
/// Version byte of the state encoding.
pub const STATE_VERSION: u8 = 0x02;

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
        w.bytes(Zeroizing::new(d.orf.to_bytes()).as_slice());
        let p = d.public();
        w.bytes(&p.device_key_pub.0);
        w.bytes(&p.epoch_storage_key_pub.0);
        w.bytes(&p.sig_0x30);
        w.opt(
            p.epoch_storage_auth_key_pub
                .as_ref()
                .map(|k| k.0.as_slice()),
        );
        w.opt(p.sig_0x31.as_ref().map(|s| s.as_slice()));
        w.u8(p.is_virtual.into());

        w.bytes(&self.mailbox_root_salt);
        w.u64(self.latest);
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
    pub fn from_state(
        bytes: &[u8],
        did: &str,
        transport: Box<dyn TransportSigner + Send>,
        b: Backends,
    ) -> Result<Self> {
        let mut r = R(bytes);
        if r.take(4)? != MAGIC {
            return Err(Error::Malformed("not a labyrinth client state"));
        }
        let version = r.u8()?;
        if version != STATE_VERSION && version != 0x01 {
            return Err(Error::Unsupported(version));
        }
        if r.str()? != did {
            return Err(Error::Malformed("state belongs to another DID"));
        }
        if r.arr::<32>()? != transport.transport_public_key() {
            return Err(Error::Malformed("state belongs to another transport key"));
        }

        let device_key = XSigningKey::from_bytes(*r.secret()?);
        let storage = X25519Secret::from_bytes(*r.secret()?);
        let storage_auth = if r.bool()? {
            Some(X25519Secret::from_bytes(*r.secret()?))
        } else {
            None
        };
        let orf = OrfClientState::from_bytes(*r.secret()?)?;
        let public = DevicePublic {
            device_key_pub: XVerifyingKey(r.arr()?),
            epoch_storage_key_pub: X25519Public(r.arr()?),
            sig_0x30: r.arr()?,
            epoch_storage_auth_key_pub: r.opt()?.map(X25519Public),
            sig_0x31: r.opt()?,
            is_virtual: r.bool()?,
        };
        let device = DeviceSecrets::from_parts(device_key, storage, storage_auth, orf, public)?;

        let salt = *r.secret()?;
        let latest = r.u64()?;
        let mut epochs = Vec::new();
        for _ in 0..r.count(8 + 2 + 32)? {
            let seq = r.u64()?;
            let id = r.str()?;
            epochs.push(EpochSecret::from_parts(seq, id, *r.secret()?));
        }
        let mut revoked = BTreeSet::new();
        for _ in 0..r.count(32)? {
            revoked.insert(r.arr::<32>()?);
        }
        let mut verified = (latest, BTreeSet::new());
        if version >= 0x02 {
            verified.0 = r.u64()?;
            for _ in 0..r.count(32)? {
                verified.1.insert(r.arr::<32>()?);
            }
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
        let mut meks: std::collections::HashMap<String, Vec<Mek>> = Default::default();
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

        let mut me = Self::assemble(did, device, transport, b, salt, epochs)?;
        if me.latest != latest {
            return Err(Error::Malformed("state latest epoch is not cached"));
        }
        let (id, record) = me.epoch_record(latest)?;
        let newest = me.epochs.get(&latest).expect("latest is cached");
        if id != newest.epoch_id {
            return Err(Error::Malformed("state epoch id does not match store"));
        }
        verify_public(newest, &record.public)?;
        me.revoked = revoked;
        me.verified = verified;
        me.pins = pins;
        me.meks = meks;
        Ok(me)
    }
}

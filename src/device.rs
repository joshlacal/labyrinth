//! Device keys (SPEC §4, paper p.24, p.32, p.35).
//!
//! A device holds an XEdDSA `deviceKey`, an X25519 `epochStorageKey` that
//! receives epoch entropy, an X25519 `epochStorageAuthKey` that authenticates
//! entropy it sends (physical devices only), and an ORF client state. The
//! device key signs the two storage keys under use-case bytes `0x30` / `0x31`.

use crate::hpke::labyrinth::{X25519Public, X25519Secret};
use crate::orf::{OrfClientState, orf_client_init};
use crate::sign::{TransportSigner, XSigningKey, XVerifyingKey, verify_transport};
use crate::{Error, Result};

/// Signature prefix of a [`ChatBinding`].
const BINDING_PREFIX: &str = "catbird.labyrinth.device_binding:";

/// [CB-36] A physical device's binding to the MLS chat device that
/// enrolled it: `Ed25519(chatKey, "catbird.labyrinth.device_binding:" ||
/// did || ":" || deviceKeyPub)`. A rotating client carries a physical
/// device over only while its binding verifies and names a *current* chat
/// device of the DID, so revoking the chat device also drops the
/// Labyrinth device, and a device record planted by some other chat
/// device can't pass as this one. Virtual devices carry no binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatBinding {
    pub transport_public_key: [u8; 32],
    pub sig: [u8; 64],
}

fn binding_message(did: &str, device_key: &XVerifyingKey) -> Vec<u8> {
    [
        format!("{BINDING_PREFIX}{did}:").as_bytes(),
        device_key.0.as_slice(),
    ]
    .concat()
}

impl ChatBinding {
    /// Binds `device_key` of `did` to the chat key behind `transport`.
    pub fn sign(did: &str, device_key: &XVerifyingKey, transport: &dyn TransportSigner) -> Self {
        Self {
            transport_public_key: transport.transport_public_key(),
            sig: transport.sign_transport(&binding_message(did, device_key)),
        }
    }

    /// Checks the signature. The caller separately checks that
    /// `transport_public_key` is a current chat device of `did`.
    pub fn verify(&self, did: &str, device_key: &XVerifyingKey) -> Result<()> {
        verify_transport(
            &self.transport_public_key,
            &binding_message(did, device_key),
            &self.sig,
        )
    }
}

/// Use-case byte for `pk_sign(deviceKey, 0x30, epochStorageKeyPub)`.
pub const USE_CASE_STORAGE: u8 = 0x30;
/// Use-case byte for `pk_sign(deviceKey, 0x31, epochStorageAuthKeyPub)`.
pub const USE_CASE_STORAGE_AUTH: u8 = 0x31;

/// The public record of a device (`blue.catbird.labyrinth.device`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevicePublic {
    pub device_key_pub: XVerifyingKey,
    pub epoch_storage_key_pub: X25519Public,
    /// `pk_sign(deviceKey, 0x30, epochStorageKeyPub)`.
    pub sig_0x30: [u8; 64],
    /// Absent for virtual devices.
    pub epoch_storage_auth_key_pub: Option<X25519Public>,
    /// `pk_sign(deviceKey, 0x31, epochStorageAuthKeyPub)`; present iff the auth key is.
    pub sig_0x31: Option<[u8; 64]>,
    /// True for a recovery (virtual) device.
    pub is_virtual: bool,
}

impl DevicePublic {
    /// Check both use-case signatures and the physical/virtual shape: a
    /// physical device has an auth key and its `0x31` signature, a virtual
    /// device has neither.
    pub fn verify(&self) -> Result<()> {
        self.device_key_pub.verify_use_case(
            USE_CASE_STORAGE,
            &self.epoch_storage_key_pub.0,
            &self.sig_0x30,
        )?;
        match (
            self.is_virtual,
            &self.epoch_storage_auth_key_pub,
            &self.sig_0x31,
        ) {
            (false, Some(auth), Some(sig)) => {
                self.device_key_pub
                    .verify_use_case(USE_CASE_STORAGE_AUTH, &auth.0, sig)
            }
            (true, None, None) => Ok(()),
            _ => Err(Error::Malformed("device auth key shape")),
        }
    }

    /// The verified auth key of a physical device.
    pub fn verified_auth_key(&self) -> Result<X25519Public> {
        self.verify()?;
        self.epoch_storage_auth_key_pub
            .ok_or(Error::Malformed("virtual device has no auth key"))
    }
}

/// A device's private state. The public record is computed once at
/// generation (XEdDSA signatures are randomized) and kept alongside.
pub struct DeviceSecrets {
    pub device_key: XSigningKey,
    pub storage: X25519Secret,
    /// `None` for virtual devices, which never send entropy.
    pub storage_auth: Option<X25519Secret>,
    pub orf: OrfClientState,
    public: DevicePublic,
}

impl DeviceSecrets {
    /// A fresh physical device with a fresh ORF client state — the first
    /// device of a mailbox (paper p.24).
    pub fn generate() -> Result<Self> {
        Self::generate_physical(orf_client_init()?)
    }

    /// A fresh physical device whose ORF state was evolved from another
    /// device (enrollment from a recovery code or one-time code, p.35).
    pub fn generate_physical(orf: OrfClientState) -> Result<Self> {
        let device_key = XSigningKey::generate()?;
        let storage = X25519Secret::generate()?;
        let auth = X25519Secret::generate()?;
        Self::assemble(device_key, storage, Some(auth), orf)
    }

    /// A fresh virtual device (no auth key; p.32). `orf` is the evolved
    /// state from the creating device.
    pub fn generate_virtual(orf: OrfClientState) -> Result<Self> {
        let device_key = XSigningKey::generate()?;
        let storage = X25519Secret::generate()?;
        Self::assemble(device_key, storage, None, orf)
    }

    fn assemble(
        device_key: XSigningKey,
        storage: X25519Secret,
        storage_auth: Option<X25519Secret>,
        orf: OrfClientState,
    ) -> Result<Self> {
        let storage_pub = storage.public();
        let sig_0x30 = device_key.sign_use_case(USE_CASE_STORAGE, &storage_pub.0)?;
        let (auth_pub, sig_0x31) = match &storage_auth {
            Some(a) => {
                let p = a.public();
                (
                    Some(p),
                    Some(device_key.sign_use_case(USE_CASE_STORAGE_AUTH, &p.0)?),
                )
            }
            None => (None, None),
        };
        let public = DevicePublic {
            device_key_pub: device_key.public(),
            epoch_storage_key_pub: storage_pub,
            sig_0x30,
            epoch_storage_auth_key_pub: auth_pub,
            sig_0x31,
            is_virtual: storage_auth.is_none(),
        };
        Ok(Self {
            device_key,
            storage,
            storage_auth,
            orf,
            public,
        })
    }

    /// Rebuild a device from stored secrets and its published record,
    /// checking that the record verifies and matches the secrets.
    pub fn from_parts(
        device_key: XSigningKey,
        storage: X25519Secret,
        storage_auth: Option<X25519Secret>,
        orf: OrfClientState,
        public: DevicePublic,
    ) -> Result<Self> {
        public.verify()?;
        let auth_matches = match (&storage_auth, &public.epoch_storage_auth_key_pub) {
            (Some(s), Some(p)) => s.public() == *p,
            (None, None) => true,
            _ => false,
        };
        if device_key.public() != public.device_key_pub
            || storage.public() != public.epoch_storage_key_pub
            || !auth_matches
        {
            return Err(Error::Malformed("device secrets do not match record"));
        }
        Ok(Self {
            device_key,
            storage,
            storage_auth,
            orf,
            public,
        })
    }

    /// The device's public record.
    pub fn public(&self) -> &DevicePublic {
        &self.public
    }

    pub fn is_virtual(&self) -> bool {
        self.storage_auth.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_and_virtual_verify() {
        let d = DeviceSecrets::generate().unwrap();
        d.public().verify().unwrap();
        assert!(!d.is_virtual());
        assert!(d.public().verified_auth_key().is_ok());

        let v = DeviceSecrets::generate_virtual(orf_client_init().unwrap()).unwrap();
        v.public().verify().unwrap();
        assert!(v.is_virtual() && v.public().is_virtual);
        assert!(v.public().verified_auth_key().is_err());
    }

    #[test]
    fn tampering_rejected() {
        let d = DeviceSecrets::generate().unwrap();
        let mut p = d.public().clone();
        p.sig_0x30[3] ^= 1;
        assert!(p.verify().is_err());
        let mut p = d.public().clone();
        p.sig_0x31.as_mut().unwrap()[3] ^= 1;
        assert!(p.verify().is_err());
        let mut p = d.public().clone();
        p.epoch_storage_key_pub.0[0] ^= 1;
        assert!(p.verify().is_err());
        let mut p = d.public().clone();
        p.epoch_storage_auth_key_pub.as_mut().unwrap().0[0] ^= 1;
        assert!(p.verify().is_err());
        // Swapping the two signatures fails: the use-case bytes differ.
        let mut p = d.public().clone();
        let s30 = p.sig_0x30;
        p.sig_0x30 = p.sig_0x31.unwrap();
        p.sig_0x31 = Some(s30);
        assert!(p.verify().is_err());
        // A physical device claiming to be virtual (and vice versa) fails.
        let mut p = d.public().clone();
        p.is_virtual = true;
        assert!(p.verify().is_err());
        let mut p = d.public().clone();
        p.epoch_storage_auth_key_pub = None;
        assert!(p.verify().is_err());
    }

    #[test]
    fn chat_binding_binds_did_and_device() {
        let t = crate::sign::Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
        let d = DeviceSecrets::generate().unwrap();
        let k = d.public().device_key_pub;
        let b = ChatBinding::sign("did:plc:a", &k, &t);
        b.verify("did:plc:a", &k).unwrap();
        assert!(b.verify("did:plc:b", &k).is_err());
        let other = DeviceSecrets::generate().unwrap().public().device_key_pub;
        assert!(b.verify("did:plc:a", &other).is_err());
    }

    #[test]
    fn from_parts_checks_match() {
        let d = DeviceSecrets::generate().unwrap();
        let rebuilt = DeviceSecrets::from_parts(
            d.device_key.clone(),
            d.storage.clone(),
            d.storage_auth.clone(),
            d.orf.clone(),
            d.public().clone(),
        )
        .unwrap();
        assert_eq!(rebuilt.public(), d.public());
        assert!(
            DeviceSecrets::from_parts(
                d.device_key.clone(),
                X25519Secret::generate().unwrap(),
                d.storage_auth.clone(),
                d.orf.clone(),
                d.public().clone(),
            )
            .is_err()
        );
    }
}

//! Device keys (SPEC §4, Gate 2, `I16`).
//!
//! A device holds an XEdDSA `deviceKey`, a 1,216-byte Hawk `epochStorageKey`
//! (`X25519 + ML-KEM-768`) that receives epoch entropy, and an X25519
//! `epochStorageAuthKey` that authenticates entropy it sends (physical devices
//! only). Physical devices sign `epochStorageKeyPub` under use-case byte `0x30`
//! and `epochStorageAuthKeyPub` under `0x31`; virtual devices sign
//! `epochStorageKeyPub` under `0x32` (`Gate 2` domain separation).

use labyrinth_protocol::epoch_chain::MemberBinding;

use crate::hpke::hawk::{HawkEncPublic, HawkEncSecret, hawk_enc_keygen};
use crate::hpke::{X25519Public, X25519Secret};
use crate::sign::{TransportSigner, XSigningKey, XVerifyingKey, verify_transport};
use crate::{Error, Result};

/// Signature prefix of a [`ChatBinding`].
const BINDING_PREFIX: &str = "catbird.labyrinth.device_binding:";

/// [CB-36] A physical device's binding to the MLS chat device that enrolled it:
/// `Ed25519(chatKey, "catbird.labyrinth.device_binding:" || did || ":" || deviceKeyPub)`.
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

/// Use-case byte for physical `pk_sign(deviceKey, 0x30, epochStorageKeyPub)`.
pub const USE_CASE_STORAGE: u8 = 0x30;
/// Use-case byte for physical `pk_sign(deviceKey, 0x31, epochStorageAuthKeyPub)`.
pub const USE_CASE_STORAGE_AUTH: u8 = 0x31;
/// Use-case byte for virtual `pk_sign(deviceKey, 0x32, epochStorageKeyPub)` (`Gate 2`).
pub const USE_CASE_VIRTUAL_STORAGE: u8 = 0x32;

/// The public record of a device (`blue.catbird.labyrinth.device`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevicePublic {
    pub device_key_pub: XVerifyingKey,
    pub epoch_storage_key_pub: HawkEncPublic,
    /// `pk_sign(deviceKey, 0x30, epochStorageKeyPub)` for physical devices, or
    /// `pk_sign(deviceKey, 0x32, epochStorageKeyPub)` for virtual devices (`Gate 2`).
    pub sig_storage: [u8; 64],
    /// Absent for virtual devices.
    pub epoch_storage_auth_key_pub: Option<X25519Public>,
    /// `pk_sign(deviceKey, 0x31, epochStorageAuthKeyPub)`; present iff the auth key is.
    pub sig_0x31: Option<[u8; 64]>,
    /// True for a recovery (virtual) device.
    pub is_virtual: bool,
}

impl DevicePublic {
    /// Check both use-case signatures, FIPS 203 ML-KEM-768 encapsulation key
    /// validity, and physical/virtual domain separation (`0x30` vs `0x32`).
    pub fn verify(&self) -> Result<()> {
        let storage_bytes = self.epoch_storage_key_pub.to_bytes();
        let _ = HawkEncPublic::from_bytes(&storage_bytes)?;
        let storage_tag = if self.is_virtual {
            USE_CASE_VIRTUAL_STORAGE
        } else {
            USE_CASE_STORAGE
        };
        self.device_key_pub
            .verify_use_case(storage_tag, &storage_bytes, &self.sig_storage)?;
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

    /// Canonical [`MemberBinding`] tuple for `EpochPublic.members_hash` (`Gate 2`).
    pub fn member_binding(&self) -> MemberBinding {
        MemberBinding {
            device_key_pub: self.device_key_pub.0,
            epoch_storage_key_pub: self.epoch_storage_key_pub.to_bytes(),
            is_virtual: self.is_virtual,
        }
    }
}

/// A device's private state. The public record is computed once at generation
/// (XEdDSA signatures are randomized) and kept alongside.
pub struct DeviceSecrets {
    pub device_key: XSigningKey,
    pub storage: HawkEncSecret,
    /// `None` for virtual devices, which never send entropy.
    pub storage_auth: Option<X25519Secret>,
    public: DevicePublic,
}

impl DeviceSecrets {
    /// A fresh physical device (`I16` Hawk `epoch_storage_key`).
    pub fn generate() -> Result<Self> {
        Self::generate_physical()
    }

    /// A fresh physical device (`I16` Hawk `epoch_storage_key`).
    pub fn generate_physical() -> Result<Self> {
        let device_key = XSigningKey::generate()?;
        let (storage, _) = hawk_enc_keygen()?;
        let auth = X25519Secret::generate()?;
        Self::assemble(device_key, storage, Some(auth))
    }

    /// A fresh virtual device (no auth key, `0x32` storage signature; `Gate 2`).
    pub fn generate_virtual() -> Result<Self> {
        let device_key = XSigningKey::generate()?;
        let (storage, _) = hawk_enc_keygen()?;
        Self::assemble(device_key, storage, None)
    }

    fn assemble(
        device_key: XSigningKey,
        storage: HawkEncSecret,
        storage_auth: Option<X25519Secret>,
    ) -> Result<Self> {
        let is_virtual = storage_auth.is_none();
        let storage_pub = storage.public();
        let storage_tag = if is_virtual {
            USE_CASE_VIRTUAL_STORAGE
        } else {
            USE_CASE_STORAGE
        };
        let sig_storage = device_key.sign_use_case(storage_tag, &storage_pub.to_bytes())?;
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
            sig_storage,
            epoch_storage_auth_key_pub: auth_pub,
            sig_0x31,
            is_virtual,
        };
        Ok(Self {
            device_key,
            storage,
            storage_auth,
            public,
        })
    }

    /// Rebuild a device from stored secrets and its published record,
    /// checking that the record verifies and matches the secrets.
    pub fn from_parts(
        device_key: XSigningKey,
        storage: HawkEncSecret,
        storage_auth: Option<X25519Secret>,
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
            || storage_auth.is_none() != public.is_virtual
            || !auth_matches
        {
            return Err(Error::Malformed("device secrets do not match record"));
        }
        Ok(Self {
            device_key,
            storage,
            storage_auth,
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

        let v = DeviceSecrets::generate_virtual().unwrap();
        v.public().verify().unwrap();
        assert!(v.is_virtual() && v.public().is_virtual);
        assert!(v.public().verified_auth_key().is_err());
    }

    #[test]
    fn tampering_and_domain_downgrade_rejected() {
        let d = DeviceSecrets::generate().unwrap();
        let mut p = d.public().clone();
        p.sig_storage[3] ^= 1;
        assert!(p.verify().is_err());
        let mut p = d.public().clone();
        p.sig_0x31.as_mut().unwrap()[3] ^= 1;
        assert!(p.verify().is_err());
        let mut p = d.public().clone();
        p.epoch_storage_key_pub.x25519.0[0] ^= 1;
        assert!(p.verify().is_err());
        let mut p = d.public().clone();
        p.epoch_storage_auth_key_pub.as_mut().unwrap().0[0] ^= 1;
        assert!(p.verify().is_err());

        // Gate 2: stripping auth key + sig_0x31 from a physical device and
        // marking is_virtual = true fails because 0x30 != 0x32!
        let mut p = d.public().clone();
        p.epoch_storage_auth_key_pub = None;
        p.sig_0x31 = None;
        p.is_virtual = true;
        assert_eq!(p.verify(), Err(Error::BadSignature));
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
            d.public().clone(),
        )
        .unwrap();
        assert_eq!(rebuilt.public(), d.public());
        let (other_storage, _) = hawk_enc_keygen().unwrap();
        assert!(
            DeviceSecrets::from_parts(
                d.device_key.clone(),
                other_storage,
                d.storage_auth.clone(),
                d.public().clone(),
            )
            .is_err()
        );
    }
}

//! Device-signed reads: every `blue.catbird.labyrinth.*` query carries a
//! claim signed by the calling chat device, so a stolen service-auth token
//! alone cannot read a mailbox or a conversation's history.
//!
//! Two headers, both base64url without padding:
//!
//! - [`READ_HEADER`] (`catbird-labyrinth-read`): the claim, as canonical
//!   JSON with exactly these keys in this order:
//!   `{"v":1,"nsid":…,"query":…,"did":…,"deviceId":…,"issuedAt":…}`.
//!   `query` is [`canonical_query`] of every query parameter on the wire
//!   (`actorDeviceId` included); `issuedAt` is milliseconds since the Unix
//!   epoch, a JSON integer.
//! - [`READ_SIGNATURE_HEADER`] (`catbird-labyrinth-read-signature`):
//!   Ed25519 by the device's chat signing key over
//!   [`READ_DOMAIN`] (`CATBIRD-LABYRINTH-READ\0`) followed by the decoded
//!   claim bytes.
//!
//! A verifier decodes the claim, checks the signature against the chat
//! device named by `did` / `deviceId`, then checks the claim is
//! byte-for-byte canonical ([`ReadClaim::parse`]) and that `nsid`, `query`,
//! `did` and `deviceId` match the request, and `issuedAt` its clock window
//! ([`READ_WINDOW_MS`]). The golden vector is
//! `tests/vectors/labyrinth_read_header.json`.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use super::{NSID_PREFIX, XrpcError, XrpcTransport};
use crate::sign::{TransportSigner, verify_transport};
use crate::{Error, Result};

/// The claim header.
pub const READ_HEADER: &str = "catbird-labyrinth-read";
/// The signature header.
pub const READ_SIGNATURE_HEADER: &str = "catbird-labyrinth-read-signature";
/// Signature domain, prepended to the decoded claim bytes.
pub const READ_DOMAIN: &[u8] = b"CATBIRD-LABYRINTH-READ\0";
/// Claim version.
pub const READ_VERSION: u64 = 1;
/// How far `issuedAt` may be from the verifier's clock, either way.
pub const READ_WINDOW_MS: u64 = 300_000;

/// RFC 3986 percent-encoding: every byte but the unreserved set
/// (`A-Z a-z 0-9 - . _ ~`) becomes `%XX` with uppercase hex.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The canonical query string: the parameters sorted by key, then value
/// (both compared as raw UTF-8 bytes, before encoding), each
/// `percent_encode(key)=percent_encode(value)`, joined with `&`. Repeated
/// keys stay repeated. No parameters is the empty string.
pub fn canonical_query(params: &[(&str, String)]) -> String {
    let mut p: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    p.sort_unstable();
    p.iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The signed claim of one read.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadClaim {
    pub v: u64,
    pub nsid: String,
    pub query: String,
    pub did: String,
    pub device_id: String,
    pub issued_at: u64,
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("a string always serializes")
}

impl ReadClaim {
    /// The claim for `GET /xrpc/{nsid}?{params}` by chat device
    /// `device_id` of `did` at `issued_at_ms`. `params` are every query
    /// parameter sent on the wire.
    pub fn new(
        nsid: &str,
        params: &[(&str, String)],
        did: &str,
        device_id: &str,
        issued_at_ms: u64,
    ) -> Self {
        Self {
            v: READ_VERSION,
            nsid: nsid.to_owned(),
            query: canonical_query(params),
            did: did.to_owned(),
            device_id: device_id.to_owned(),
            issued_at: issued_at_ms,
        }
    }

    /// The canonical JSON bytes (keys in the fixed order, no whitespace,
    /// `serde_json` string escaping).
    pub fn to_json(&self) -> Vec<u8> {
        format!(
            "{{\"v\":{},\"nsid\":{},\"query\":{},\"did\":{},\"deviceId\":{},\"issuedAt\":{}}}",
            self.v,
            json_string(&self.nsid),
            json_string(&self.query),
            json_string(&self.did),
            json_string(&self.device_id),
            self.issued_at
        )
        .into_bytes()
    }

    /// Parses claim bytes; they must be exactly [`to_json`](Self::to_json)
    /// of the parsed claim, at version [`READ_VERSION`].
    pub fn parse(json: &[u8]) -> Result<Self> {
        let c: Self =
            serde_json::from_slice(json).map_err(|_| Error::Malformed("read claim json"))?;
        if c.v != READ_VERSION {
            return Err(Error::Malformed("read claim version"));
        }
        if c.to_json() != json {
            return Err(Error::Malformed("read claim is not canonical"));
        }
        Ok(c)
    }

    /// The Ed25519 signing input for claim bytes `json`.
    pub fn signing_input(json: &[u8]) -> Vec<u8> {
        [READ_DOMAIN, json].concat()
    }

    /// Signs the claim with the chat device key: both headers, ready to send.
    pub fn sign(&self, signer: &dyn TransportSigner) -> Vec<(String, String)> {
        let json = self.to_json();
        let sig = signer.sign_transport(&Self::signing_input(&json));
        read_headers(&json, &sig)
    }
}

/// The two headers for claim bytes `json` and their signature.
pub fn read_headers(json: &[u8], signature: &[u8; 64]) -> Vec<(String, String)> {
    vec![
        (READ_HEADER.to_owned(), URL_SAFE_NO_PAD.encode(json)),
        (
            READ_SIGNATURE_HEADER.to_owned(),
            URL_SAFE_NO_PAD.encode(signature),
        ),
    ]
}

/// Verifies the two header values under chat key `key` and returns the
/// claim. The caller still checks it against the request
/// ([`ReadClaim::matches`]).
pub fn verify_read(header: &str, signature: &str, key: &[u8; 32]) -> Result<ReadClaim> {
    let json = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| Error::Malformed("read claim encoding"))?;
    let sig: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Malformed("read signature encoding"))?;
    verify_transport(key, &ReadClaim::signing_input(&json), &sig)?;
    ReadClaim::parse(&json)
}

impl ReadClaim {
    /// True if the claim names exactly this request, by `did`'s device
    /// `device_id`, issued within [`READ_WINDOW_MS`] of `now_ms`.
    pub fn matches(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        did: &str,
        device_id: &str,
        now_ms: u64,
    ) -> bool {
        self.nsid == nsid
            && self.query == canonical_query(params)
            && self.did == did
            && self.device_id == device_id
            && self.issued_at.abs_diff(now_ms) <= READ_WINDOW_MS
    }
}

/// An [`XrpcTransport`] that signs every Labyrinth query as chat device
/// `device_id` of `did` and forwards it to `inner`. Procedures and
/// non-Labyrinth queries pass through unchanged.
pub struct SignedReadTransport {
    inner: Arc<dyn XrpcTransport>,
    did: String,
    device_id: String,
    signer: Arc<dyn TransportSigner + Send + Sync>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl SignedReadTransport {
    /// `clock` gives `issuedAt` (ms since the Unix epoch).
    pub fn new(
        inner: Arc<dyn XrpcTransport>,
        did: &str,
        device_id: &str,
        signer: Arc<dyn TransportSigner + Send + Sync>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            inner,
            did: did.to_owned(),
            device_id: device_id.to_owned(),
            signer,
            clock,
        }
    }
}

impl XrpcTransport for SignedReadTransport {
    fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> core::result::Result<Vec<u8>, XrpcError> {
        if !nsid.starts_with(NSID_PREFIX) {
            return self.inner.query_with_headers(nsid, params, headers);
        }
        let claim = ReadClaim::new(nsid, params, &self.did, &self.device_id, (self.clock)());
        let mut all = headers.to_vec();
        all.extend(claim.sign(self.signer.as_ref()));
        self.inner.query_with_headers(nsid, params, &all)
    }

    fn procedure(
        &self,
        nsid: &str,
        payload: &[u8],
        operation_id: [u8; 16],
    ) -> core::result::Result<Vec<u8>, XrpcError> {
        self.inner.procedure(nsid, payload, operation_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Transport;

    #[test]
    fn canonical_query_sorts_raw_then_encodes() {
        let p = [
            ("threadId", "t 1".to_owned()),
            ("messageIds", "b".to_owned()),
            ("messageIds", "a:z".to_owned()),
            ("actorDeviceId", "dev~1".to_owned()),
        ];
        assert_eq!(
            canonical_query(&p),
            "actorDeviceId=dev~1&messageIds=a%3Az&messageIds=b&threadId=t%201"
        );
        assert_eq!(canonical_query(&[]), "");
        assert_eq!(percent_encode("é/+"), "%C3%A9%2F%2B");
    }

    #[test]
    fn claim_round_trips_and_rejects_non_canonical() {
        let c = ReadClaim::new("n", &[("a", "1".into())], "did:x", "d\"1", 7);
        let json = c.to_json();
        assert_eq!(
            json,
            br#"{"v":1,"nsid":"n","query":"a=1","did":"did:x","deviceId":"d\"1","issuedAt":7}"#
        );
        assert_eq!(ReadClaim::parse(&json).unwrap(), c);
        let reordered =
            br#"{"nsid":"n","v":1,"query":"a=1","did":"did:x","deviceId":"d\"1","issuedAt":7}"#;
        assert!(ReadClaim::parse(reordered).is_err());
        let spaced =
            br#"{"v":1, "nsid":"n","query":"a=1","did":"did:x","deviceId":"d\"1","issuedAt":7}"#;
        assert!(ReadClaim::parse(spaced).is_err());
        let v2 =
            br#"{"v":2,"nsid":"n","query":"a=1","did":"did:x","deviceId":"d\"1","issuedAt":7}"#;
        assert!(ReadClaim::parse(v2).is_err());
    }

    #[test]
    fn sign_verify_and_tamper() {
        let t = Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
        let p = [("threadId", "t".to_owned())];
        let c = ReadClaim::new("blue.catbird.labyrinth.listBatches", &p, "did:x", "d", 1000);
        let h = c.sign(&t);
        let key = t.transport_public_key();
        let got = verify_read(&h[0].1, &h[1].1, &key).unwrap();
        assert!(got.matches("blue.catbird.labyrinth.listBatches", &p, "did:x", "d", 1000));
        assert!(got.matches(
            "blue.catbird.labyrinth.listBatches",
            &p,
            "did:x",
            "d",
            301_000
        ));
        assert!(!got.matches(
            "blue.catbird.labyrinth.listBatches",
            &p,
            "did:x",
            "d",
            301_001
        ));
        assert!(!got.matches("blue.catbird.labyrinth.getMessages", &p, "did:x", "d", 1000));
        assert!(!got.matches(
            "blue.catbird.labyrinth.listBatches",
            &[],
            "did:x",
            "d",
            1000
        ));
        assert!(!got.matches("blue.catbird.labyrinth.listBatches", &p, "did:y", "d", 1000));
        assert!(!got.matches("blue.catbird.labyrinth.listBatches", &p, "did:x", "e", 1000));
        let other = Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[8; 32]));
        assert!(verify_read(&h[0].1, &h[1].1, &other.transport_public_key()).is_err());
        let forged = URL_SAFE_NO_PAD.encode(
            ReadClaim::new(
                "blue.catbird.labyrinth.listBatches",
                &[],
                "did:x",
                "d",
                1000,
            )
            .to_json(),
        );
        assert!(verify_read(&forged, &h[1].1, &key).is_err());
    }
}

//! A memory-backed reference implementation of the mls-ds Labyrinth
//! endpoints, for tests and as an executable statement of their semantics
//! (design `docs/MLSDS_BACKEND.md` §1–§3).
//!
//! [`MemoryXrpcServer`] serves every `blue.catbird.labyrinth.*` NSID the
//! stores call, plus the `labyrinthHead` projection of
//! `blue.catbird.chat.getConversationState`, over a [`MemoryBackend`] with
//! server order enabled. It enforces what mls-ds enforces at the API
//! boundary: the caller is a *current* chat device of its DID; thread
//! writes come from the writer's own key, name a known MEK and keep to one
//! MEK per batch (Y4); thread reads are authorized per MEK ([CB-16],
//! [CB-22]); heads form a contiguous attested chain (§1a); a physical
//! device carries a chat binding by the calling chat device, and epoch
//! writes come from a bound caller naming registered members ([CB-36],
//! [`binding`]); procedures replay their response for a repeated
//! `operationId`.
//!
//! Labyrinth queries carrying the device-signed read headers
//! ([`super::read_auth`]) are verified against the calling chat device
//! (`deviceId` = lowercase hex of its key here); with
//! [`MemoryXrpcServer::require_signed_reads`] an unsigned query is refused,
//! as mls-ds does.
//!
//! It does not model service auth, federation, quotas or retention.

mod attachments;
mod binding;
mod lookup;
mod mailbox;
mod retention;
mod thread;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde::de::DeserializeOwned;

pub(crate) use super::XrpcError;
use super::read_auth::{READ_HEADER, READ_SIGNATURE_HEADER, SignedReadTransport, verify_read};
use super::{MAX_PAGE, NSID_PREFIX, XrpcTransport};
use crate::Error;
use crate::sign::TransportSigner;
use crate::store::MailboxDirectory;
use crate::store::memory::MemoryBackend;

pub(crate) type Reply = core::result::Result<Vec<u8>, XrpcError>;

/// The reference server. Cheap to clone.
#[derive(Clone)]
pub struct MemoryXrpcServer {
    net: MemoryBackend,
    page_size: usize,
    replays: Arc<Mutex<HashMap<[u8; 16], Reply>>>,
    signed_reads: bool,
    /// Remote sequencers `listThreads` reports as `incomplete`.
    unreachable: Arc<Mutex<Vec<String>>>,
}

/// The authenticated caller of one request.
pub(crate) struct Caller {
    pub did: String,
    pub device: [u8; 32],
}

/// The request input: query parameters or a JSON body.
pub(crate) enum Input<'a> {
    Params(&'a [(&'a str, String)]),
    Body(&'a [u8]),
}

impl MemoryXrpcServer {
    /// Serves `net`, switching it to server order.
    pub fn new(net: MemoryBackend) -> Self {
        net.enable_server_order();
        Self {
            net,
            page_size: MAX_PAGE,
            replays: Arc::default(),
            signed_reads: false,
            unreachable: Arc::default(),
        }
    }

    /// From now on `listThreads` answers with `incomplete: dids`, as the
    /// home DS does when those remote sequencers are unreachable (empty:
    /// complete again).
    pub fn set_unreachable_sequencers(&self, dids: &[&str]) {
        *self.unreachable.lock().unwrap_or_else(|e| e.into_inner()) =
            dids.iter().map(|d| (*d).to_owned()).collect();
    }

    /// Refuse every Labyrinth query without valid device-signed read
    /// headers (`InvalidSignature`), as mls-ds does.
    pub fn require_signed_reads(mut self) -> Self {
        self.signed_reads = true;
        self
    }

    /// Pages hold at most `n` items (exercises the stores' paging).
    pub fn with_page_size(mut self, n: usize) -> Self {
        self.page_size = n.clamp(1, MAX_PAGE);
        self
    }

    pub fn backend(&self) -> &MemoryBackend {
        &self.net
    }

    /// A transport authenticated as chat device `device` of `did`.
    pub fn transport(&self, did: &str, device: [u8; 32]) -> Arc<dyn XrpcTransport> {
        Arc::new(MemoryTransport {
            server: self.clone(),
            caller: Caller {
                did: did.to_owned(),
                device,
            },
        })
    }

    /// A transport for chat device `signer` of `did` that signs every
    /// Labyrinth query ([`SignedReadTransport`]) with the server clock.
    pub fn signed_transport(
        &self,
        did: &str,
        signer: Arc<dyn TransportSigner + Send + Sync>,
    ) -> Arc<dyn XrpcTransport> {
        let key = signer.transport_public_key();
        let net = self.net.clone();
        Arc::new(SignedReadTransport::new(
            self.transport(did, key),
            did,
            &hex::encode(key),
            signer,
            Arc::new(move || net.server_time()),
        ))
    }

    /// Checks the device-signed read headers of a Labyrinth query.
    fn check_read(
        &self,
        c: &Caller,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> core::result::Result<(), XrpcError> {
        if !nsid.starts_with(NSID_PREFIX) {
            return Ok(());
        }
        let find = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        // mls-ds: a signature that does not verify is 401 InvalidSignature;
        // a missing header, a non-canonical claim, or a claim that does not
        // match the request or the clock window is 400 InvalidRequest.
        let invalid = |m: &str| XrpcError::named(400, "InvalidRequest", m);
        match (find(READ_HEADER), find(READ_SIGNATURE_HEADER)) {
            (None, None) if !self.signed_reads => Ok(()),
            (Some(h), Some(s)) => {
                let claim = verify_read(h, s, &c.device).map_err(|e| match e {
                    crate::Error::BadSignature | crate::Error::BadPublicKey => {
                        XrpcError::named(401, "InvalidSignature", "bad read signature")
                    }
                    _ => invalid("malformed read claim"),
                })?;
                let now = self.net.server_time();
                if claim.matches(nsid, params, &c.did, &hex::encode(c.device), now) {
                    Ok(())
                } else {
                    Err(invalid("read claim does not match the request"))
                }
            }
            _ => Err(invalid("missing signed read headers")),
        }
    }

    fn handle(&self, c: &Caller, nsid: &str, input: Input<'_>) -> Reply {
        let current = self
            .net
            .directory()
            .device_transport_keys(&c.did)
            .map_err(err)?
            .iter()
            .any(|k| k.is_current() && k.key == c.device);
        if !current {
            return Err(XrpcError::named(
                401,
                "DeviceRevoked",
                "not a current chat device",
            ));
        }
        if nsid == "blue.catbird.chat.getConversationState" {
            return thread::conversation_state(self, &input);
        }
        let name = nsid
            .strip_prefix(NSID_PREFIX)
            .ok_or_else(|| XrpcError::named(501, "MethodNotImplemented", nsid))?;
        mailbox::handle(self, c, name, &input)
            .or_else(|| thread::handle(self, c, name, &input))
            .or_else(|| retention::handle(self, c, name, &input))
            .or_else(|| attachments::handle(self, c, name, &input))
            .or_else(|| lookup::handle(self, c, name, &input))
            .unwrap_or_else(|| Err(XrpcError::named(501, "MethodNotImplemented", nsid)))
    }
}

struct MemoryTransport {
    server: MemoryXrpcServer,
    caller: Caller,
}

impl XrpcTransport for MemoryTransport {
    fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Reply {
        self.server
            .check_read(&self.caller, nsid, params, headers)?;
        self.server
            .handle(&self.caller, nsid, Input::Params(params))
    }

    fn procedure(&self, nsid: &str, payload: &[u8], operation_id: [u8; 16]) -> Reply {
        let replays = &self.server.replays;
        if let Some(r) = replays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&operation_id)
        {
            return r.clone();
        }
        let r = self.server.handle(&self.caller, nsid, Input::Body(payload));
        replays
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(operation_id, r.clone());
        r
    }
}

/// Maps a store error to the endpoint error mls-ds returns.
pub(crate) fn err(e: Error) -> XrpcError {
    let named = |status, name: &str| XrpcError::named(status, name, e.to_string());
    match &e {
        Error::Conflict => named(409, "RecordAlreadyExists"),
        Error::Forbidden => named(403, "NotAuthorized"),
        Error::NotFound("device") => named(404, "DeviceNotFound"),
        Error::NotFound("epoch") => named(404, "EpochNotFound"),
        Error::NotFound("orf state") => named(404, "OrfStateNotFound"),
        Error::NotFound(_) => named(404, "NotFound"),
        Error::Unattested => named(400, "AttestationNotCurrent"),
        Error::Malformed("InvalidEpochChain") => named(400, "InvalidEpochChain"),
        _ => named(400, "InvalidRequest"),
    }
}

pub(crate) fn bad(msg: &str) -> XrpcError {
    XrpcError::named(400, "InvalidRequest", msg)
}

pub(crate) fn json<T: Serialize>(v: &T) -> Reply {
    serde_json::to_vec(v).map_err(|e| XrpcError::named(500, "InternalServerError", e.to_string()))
}

pub(crate) fn body<T: DeserializeOwned>(input: &Input<'_>) -> core::result::Result<T, XrpcError> {
    match input {
        Input::Body(b) => serde_json::from_slice(b).map_err(|e| bad(&e.to_string())),
        Input::Params(_) => Err(bad("procedure called as a query")),
    }
}

/// Query parameter `k`, if present.
pub(crate) fn param<'a>(input: &'a Input<'_>, k: &str) -> Option<&'a str> {
    match input {
        Input::Params(p) => p.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str()),
        Input::Body(_) => None,
    }
}

pub(crate) fn req<'a>(input: &'a Input<'_>, k: &str) -> core::result::Result<&'a str, XrpcError> {
    param(input, k).ok_or_else(|| bad(&format!("missing parameter {k}")))
}

pub(crate) fn num(input: &Input<'_>, k: &str) -> core::result::Result<Option<u64>, XrpcError> {
    param(input, k)
        .map(|v| {
            v.parse()
                .map_err(|_| bad(&format!("{k} is not an integer")))
        })
        .transpose()
}

pub(crate) fn hex_param<const N: usize>(
    input: &Input<'_>,
    k: &str,
) -> core::result::Result<[u8; N], XrpcError> {
    hex::decode(req(input, k)?)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad(&format!("{k} is not {N} hex bytes")))
}

impl MemoryXrpcServer {
    /// One page of `items` per the `cursor` / `limit` parameters.
    pub(crate) fn page<T: Serialize>(&self, items: Vec<T>, input: &Input<'_>) -> Reply {
        self.page_with(items, input, None)
    }

    /// [`page`](Self::page) with `incomplete` sequencers (`listThreads`).
    pub(crate) fn page_with<T: Serialize>(
        &self,
        items: Vec<T>,
        input: &Input<'_>,
        incomplete: Option<Vec<String>>,
    ) -> Reply {
        let start = num(input, "cursor")?.unwrap_or(0) as usize;
        let limit =
            num(input, "limit")?.map_or(self.page_size, |l| (l as usize).clamp(1, self.page_size));
        let end = start.saturating_add(limit).min(items.len());
        let cursor = (end < items.len()).then(|| end.to_string());
        let items: Vec<T> = items
            .into_iter()
            .skip(start)
            .take(end.saturating_sub(start))
            .collect();
        json(&super::wire::Page {
            items,
            cursor,
            incomplete,
        })
    }
}

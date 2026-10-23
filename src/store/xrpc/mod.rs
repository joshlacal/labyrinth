//! Store implementations over the mls-ds `blue.catbird.labyrinth.*` XRPC
//! endpoints (design `docs/MLSDS_BACKEND.md` §2, §5; feature `xrpc`).
//!
//! The stores are generic over a small synchronous [`XrpcTransport`] that
//! the embedding app implements (catbird-mls owns the HTTP client, service
//! auth and the device signing key, and blocks on its runtime). This
//! module owns everything else: request and response shapes, pagination,
//! error mapping and server stamps, so they are tested once, here, against
//! the memory-backed reference server in [`server`].
//!
//! | Trait | Implementation | Endpoints |
//! |---|---|---|
//! | [`crate::store::MailboxStore`] | [`XrpcMailboxStore`] | `createDevice` … `listOwnerBatches`, `listOwnerThreads`, `publishEpochHead`, `touchVirtualDevice`, `deleteVirtualDevice`, `purgeMailbox`, `deleteAccountData` |
//! | [`crate::store::ThreadStore`] | [`XrpcThreadStore`] | `createMek`, `findMeks`, `appendBatch`, `listBatches`, `getMessages`, `listThreads`, `redactMessage` |
//! | [`crate::store::MailboxDirectory`], [`crate::store::KeyPublisher`] | [`XrpcDirectory`] | `getEpochHead`, `getChatDeviceKeys`, `getMemberDevices`, `publishEpochHead`; `retract` is `purgeMailbox` |
//! | [`crate::store::OrfServer`] | [`XrpcOrf`] | `registerOrfState`, `deleteOrfState`, `putAttachmentRef`, `getAttachmentRef`, `getAttachmentBlob`, `deleteAttachmentRef` |
//!
//! `labyrinthRelay` is server-to-server only; no store calls it.
//!
//! Errors map as: `RecordAlreadyExists`/`EpochHeadConflict`/
//! `AttachmentAlreadyReferenced` → [`Error::Conflict`];
//! `NotAuthorized`/`NotRecipient`/`NotParticipant`/`DeviceRevoked`/
//! `LabyrinthDeviceNotBound`/`AttachmentNotEntitled` → [`Error::Forbidden`];
//! `*NotFound` → [`Error::NotFound`] (a `get*` query returns `None`
//! instead; the bare `NotFound` of the attachment reads is
//! `NotFound("attachment")`); `MemberDeviceNotRegistered` →
//! `NotFound("device")`; `InvalidChatBinding`/`InvalidRedaction` →
//! [`Error::BadSignature`]; `AttestationNotCurrent` → [`Error::Unattested`];
//! everything else (including the transient `RelayUnavailable`,
//! `ConversationMoved` and `AttachmentsUnavailable`) → [`Error::Backend`].

mod directory;
mod mailbox;
pub mod read_auth;
pub mod server;
mod thread;
pub(crate) mod wire;

use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;

pub use directory::{LabyrinthHead, XrpcDirectory, XrpcOrf};
pub use mailbox::XrpcMailboxStore;
pub use thread::XrpcThreadStore;

use crate::{Error, Result};

/// NSID prefix of every Labyrinth endpoint.
pub const NSID_PREFIX: &str = "blue.catbird.labyrinth.";

/// Most items the server returns per page; the stores follow `cursor`.
pub const MAX_PAGE: usize = 100;

/// A failed XRPC call: the HTTP status and the atproto error body
/// (`{"error", "message"}`). `status = 0` means no response arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XrpcError {
    pub status: u16,
    pub error: Option<String>,
    pub message: Option<String>,
}

impl XrpcError {
    /// An error response named `error`.
    pub fn named(status: u16, error: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            error: Some(error.to_owned()),
            message: Some(message.into()),
        }
    }
}

/// How the stores reach mls-ds. Implementations add authentication: a
/// service-auth token whose `lxm` is the NSID plus `actorDeviceId` on
/// every call; on procedures a `labyrinthWriteBody` signature by the chat
/// device key over `{operationId, actorDeviceId, endpointNsid,
/// sha256(payload), signedAt}` (design §3); on Labyrinth queries the
/// device-signed read headers of [`read_auth`] (built with
/// [`read_auth::ReadClaim`], or added by [`read_auth::SignedReadTransport`]).
pub trait XrpcTransport: Send + Sync {
    /// `GET /xrpc/{nsid}?{params}` with extra request `headers` (sent
    /// verbatim); returns the response body. A wrapping transport must
    /// forward `headers`: dropping them makes signed reads fail.
    fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> core::result::Result<Vec<u8>, XrpcError>;
    /// `GET /xrpc/{nsid}?{params}` with no extra headers.
    fn query(
        &self,
        nsid: &str,
        params: &[(&str, String)],
    ) -> core::result::Result<Vec<u8>, XrpcError> {
        self.query_with_headers(nsid, params, &[])
    }
    /// `POST /xrpc/{nsid}` with the JSON `payload`; returns the response
    /// body. A retry must reuse `operation_id`, so mls-ds replays the
    /// original response instead of applying the write twice.
    fn procedure(
        &self,
        nsid: &str,
        payload: &[u8],
        operation_id: [u8; 16],
    ) -> core::result::Result<Vec<u8>, XrpcError>;
}

/// Maps an XRPC error to the store error the traits promise.
pub fn map_error(e: XrpcError) -> Error {
    match e.error.as_deref() {
        Some("RecordAlreadyExists" | "EpochHeadConflict" | "AttachmentAlreadyReferenced") => {
            Error::Conflict
        }
        Some(
            "NotAuthorized"
            | "NotRecipient"
            | "NotParticipant"
            | "DeviceRevoked"
            | "LabyrinthDeviceNotBound"
            | "AttachmentNotEntitled",
        ) => Error::Forbidden,
        Some("DeviceNotFound" | "MemberDeviceNotRegistered") => Error::NotFound("device"),
        Some("NotFound") => Error::NotFound("attachment"),
        Some("InvalidChatBinding" | "InvalidRedaction") => Error::BadSignature,
        Some("EpochNotFound") => Error::NotFound("epoch"),
        Some("VirtualDeviceNotFound") => Error::NotFound("virtual device"),
        Some("OrfStateNotFound") => Error::NotFound("orf state"),
        Some("ConversationNotFound") => Error::NotFound("conversation"),
        Some("AttestationNotCurrent") => Error::Unattested,
        name => Error::Backend(format!(
            "xrpc {}: {}: {}",
            e.status,
            name.unwrap_or("no error name"),
            e.message.as_deref().unwrap_or("")
        )),
    }
}

/// The shared transport plus JSON (de)serialization and paging.
#[derive(Clone)]
pub(crate) struct Xrpc(Arc<dyn XrpcTransport>);

fn nsid(name: &str) -> String {
    format!("{NSID_PREFIX}{name}")
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|e| Error::Backend(format!("bad xrpc response: {e}")))
}

impl Xrpc {
    pub(crate) fn get<T: DeserializeOwned>(
        &self,
        name: &str,
        params: &[(&str, String)],
    ) -> Result<T> {
        decode(&self.0.query(&nsid(name), params).map_err(map_error)?)
    }

    /// Like [`get`](Self::get), but a `*NotFound` error is `None`.
    pub(crate) fn get_opt<T: DeserializeOwned>(
        &self,
        name: &str,
        params: &[(&str, String)],
    ) -> Result<Option<T>> {
        match self.get(name, params) {
            Err(Error::NotFound(_)) => Ok(None),
            r => r.map(Some),
        }
    }

    pub(crate) fn post<I: Serialize, T: DeserializeOwned>(
        &self,
        name: &str,
        input: &I,
    ) -> Result<T> {
        let payload =
            serde_json::to_vec(input).map_err(|e| Error::Backend(format!("encode: {e}")))?;
        let mut op = [0u8; 16];
        crate::encoding::random(&mut op)?;
        decode(
            &self
                .0
                .procedure(&nsid(name), &payload, op)
                .map_err(map_error)?,
        )
    }

    /// Every item of a paged list query, following `cursor`. A page that
    /// reports `incomplete` sequencers fails the listing (see
    /// [`list_all_report`](Self::list_all_report)).
    pub(crate) fn list_all<T: DeserializeOwned>(
        &self,
        name: &str,
        params: &[(&str, String)],
    ) -> Result<Vec<T>> {
        let (items, incomplete) = self.list_all_report(name, params)?;
        if incomplete.is_empty() {
            Ok(items)
        } else {
            Err(Error::Backend(format!(
                "{name} incomplete: unreachable sequencers {}",
                incomplete.join(", ")
            )))
        }
    }

    /// Every item of a paged list query, plus every sequencer DID any page
    /// reported `incomplete` (sorted, deduplicated).
    pub(crate) fn list_all_report<T: DeserializeOwned>(
        &self,
        name: &str,
        params: &[(&str, String)],
    ) -> Result<(Vec<T>, Vec<String>)> {
        const MAX_PAGES: usize = 100_000;
        let mut incomplete = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut p = params.to_vec();
            if let Some(c) = &cursor {
                p.push(("cursor", c.clone()));
            }
            let page: wire::Page<T> = self.get(name, &p)?;
            out.extend(page.items);
            incomplete.extend(page.incomplete.unwrap_or_default());
            match page.cursor {
                Some(c) if Some(&c) != cursor.as_ref() => cursor = Some(c),
                Some(_) => return Err(Error::Backend("xrpc cursor did not advance".into())),
                None => return Ok((out, incomplete.into_iter().collect())),
            }
        }
        Err(Error::Backend("xrpc listing too long".into()))
    }
}

impl Xrpc {
    pub(crate) fn new(t: Arc<dyn XrpcTransport>) -> Self {
        Self(t)
    }

    /// A query whose output is raw bytes (`getAttachmentBlob`, `*/*`).
    pub(crate) fn get_raw(&self, name: &str, params: &[(&str, String)]) -> Result<Vec<u8>> {
        self.0.query(&nsid(name), params).map_err(map_error)
    }

    /// A query outside the Labyrinth namespace, by full NSID.
    pub(crate) fn get_full<T: DeserializeOwned>(
        &self,
        full_nsid: &str,
        params: &[(&str, String)],
    ) -> Result<T> {
        decode(&self.0.query(full_nsid, params).map_err(map_error)?)
    }
}

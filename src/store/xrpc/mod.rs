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

/// Upper bounds are applied after the embedding transport has materialized
/// the response `Vec`; transports should enforce the same limits while
/// streaming so an oversized peer cannot force the allocation in the first
/// place.
/// Maximum encoded body for one successful JSON response. Transports must
/// enforce this while streaming, before allocating their returned `Vec`.
pub const MAX_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum successful raw attachment response. Transports must enforce this
/// while streaming.
pub const MAX_RAW_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
/// Total encoded response bytes retained while following one paged query.
/// A per-page cap alone permits a unique-cursor peer to multiply memory by
/// [`MAX_PAGES`].
pub const MAX_LIST_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum encoded cursor length accepted from a paged endpoint.
pub const MAX_CURSOR_BYTES: usize = 64;
/// Maximum pages followed for one list operation.
pub const MAX_PAGES: usize = 1_024;
/// Maximum decoded items retained for one list or batched lookup operation.
pub const MAX_LIST_ITEMS: usize = 10_000;
const MAX_INCOMPLETE_PER_PAGE: usize = 1_024;

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
/// Implementations must cap successful and error response bodies while
/// streaming, before allocating the returned `Vec` or `XrpcError` strings.
/// This module's 16 MiB JSON and 10 MiB raw checks are defense in depth after
/// the transport has already materialized a success body.
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
    let is_not_found_status = e.status == 404 || e.status == 400;
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
            | "SpaceDeleted"
            | "AttachmentNotEntitled",
        ) => Error::Forbidden,
        Some("DeviceNotFound" | "MemberDeviceNotRegistered") if is_not_found_status => {
            Error::NotFound("device")
        }
        Some("NotFound") if is_not_found_status => Error::NotFound("attachment"),
        Some("InvalidChatBinding" | "InvalidRedaction") => Error::BadSignature,
        Some("EpochNotFound") if is_not_found_status => Error::NotFound("epoch"),
        Some("VirtualDeviceNotFound") if is_not_found_status => Error::NotFound("virtual device"),
        Some("OrfStateNotFound") if is_not_found_status => Error::NotFound("orf state"),
        Some("ConversationNotFound") if is_not_found_status => Error::NotFound("conversation"),
        Some("SpaceNotFound") if is_not_found_status => Error::NotFound("space"),
        Some("AttestationNotCurrent") => Error::Unattested,
        _ if e.status == 403 => Error::Forbidden,
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
    if body.len() > MAX_JSON_RESPONSE_BYTES {
        return Err(Error::Backend(format!(
            "xrpc JSON response exceeds {MAX_JSON_RESPONSE_BYTES} bytes"
        )));
    }
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
        let endpoint = nsid(name);
        let first = self.0.procedure(&endpoint, &payload, op);
        let response = match first {
            Err(error)
                if error.status == 0 && error.error.as_deref() != Some("ChatKeySigningFailed") =>
            {
                self.0.procedure(&endpoint, &payload, op)
            }
            result => result,
        };
        decode(&response.map_err(map_error)?)
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
        self.list_all_report_with_budget(name, params, MAX_LIST_RESPONSE_BYTES)
    }

    /// Streams pages of a paged list query, calling `on_page(items, has_more)`
    /// for each page (including empty pages when `cursor` is `Some`). Stops
    /// early without fetching further pages when `on_page` returns `Ok(false)`.
    pub(crate) fn list_pages<T, F>(
        &self,
        name: &str,
        params: &[(&str, String)],
        mut on_page: F,
    ) -> Result<()>
    where
        T: DeserializeOwned,
        F: FnMut(Vec<T>, bool) -> Result<bool>,
    {
        let incomplete = self.list_pages_report_with_budget(
            name,
            params,
            MAX_LIST_RESPONSE_BYTES,
            &mut on_page,
        )?;
        if incomplete.is_empty() {
            Ok(())
        } else {
            Err(Error::Backend(format!(
                "{name} incomplete: unreachable sequencers {}",
                incomplete.join(", ")
            )))
        }
    }

    fn list_all_report_with_budget<T: DeserializeOwned>(
        &self,
        name: &str,
        params: &[(&str, String)],
        max_response_bytes: usize,
    ) -> Result<(Vec<T>, Vec<String>)> {
        let mut out = Vec::new();
        let incomplete = self.list_pages_report_with_budget(
            name,
            params,
            max_response_bytes,
            &mut |items, _| {
                out.extend(items);
                Ok(true)
            },
        )?;
        Ok((out, incomplete))
    }

    fn list_pages_report_with_budget<T, F>(
        &self,
        name: &str,
        params: &[(&str, String)],
        max_response_bytes: usize,
        on_page: &mut F,
    ) -> Result<Vec<String>>
    where
        T: DeserializeOwned,
        F: FnMut(Vec<T>, bool) -> Result<bool>,
    {
        let mut incomplete = std::collections::BTreeSet::new();
        let mut seen_cursors = std::collections::BTreeSet::new();
        let mut total_items = 0usize;
        let mut cursor: Option<String> = None;
        let mut response_bytes = 0usize;
        for _ in 0..MAX_PAGES {
            let mut p = params.to_vec();
            if let Some(c) = &cursor {
                p.push(("cursor", c.clone()));
            }
            let body = self.0.query(&nsid(name), &p).map_err(map_error)?;
            response_bytes = response_bytes.checked_add(body.len()).ok_or_else(|| {
                Error::Backend("xrpc listing response byte count overflow".into())
            })?;
            if response_bytes > max_response_bytes {
                return Err(Error::Backend(format!(
                    "xrpc listing responses exceed {max_response_bytes} bytes"
                )));
            }
            let page: wire::Page<T> = decode(&body)?;
            if page.items.len() > MAX_PAGE {
                return Err(Error::Backend(format!(
                    "xrpc page exceeds {MAX_PAGE} items"
                )));
            }
            total_items = total_items
                .checked_add(page.items.len())
                .ok_or_else(|| Error::Backend("xrpc listing item count overflow".into()))?;
            if total_items > MAX_LIST_ITEMS {
                return Err(Error::Backend(format!(
                    "xrpc listing exceeds {MAX_LIST_ITEMS} items"
                )));
            }
            let page_incomplete = page.incomplete.unwrap_or_default();
            if page_incomplete.len() > MAX_INCOMPLETE_PER_PAGE {
                return Err(Error::Backend(format!(
                    "xrpc page exceeds {MAX_INCOMPLETE_PER_PAGE} incomplete sequencers"
                )));
            }
            incomplete.extend(page_incomplete);
            if incomplete.len() > MAX_LIST_ITEMS {
                return Err(Error::Backend(format!(
                    "xrpc listing exceeds {MAX_LIST_ITEMS} incomplete sequencers"
                )));
            }
            let next_cursor = match page.cursor {
                Some(c) => {
                    if c.len() > MAX_CURSOR_BYTES {
                        return Err(Error::Backend(format!(
                            "xrpc cursor exceeds {MAX_CURSOR_BYTES} bytes"
                        )));
                    }
                    if !seen_cursors.insert(c.clone()) {
                        return Err(Error::Backend("xrpc cursor cycle".into()));
                    }
                    Some(c)
                }
                None => None,
            };
            if !on_page(page.items, next_cursor.is_some())? {
                return Ok(incomplete.into_iter().collect());
            }
            match next_cursor {
                Some(c) => cursor = Some(c),
                None => return Ok(incomplete.into_iter().collect()),
            }
        }
        Err(Error::Backend(format!(
            "xrpc listing exceeds {MAX_PAGES} pages"
        )))
    }
}

impl Xrpc {
    pub(crate) fn new(t: Arc<dyn XrpcTransport>) -> Self {
        Self(t)
    }

    /// A query whose output is raw bytes (`getAttachmentBlob`, `*/*`).
    pub(crate) fn get_raw(&self, name: &str, params: &[(&str, String)]) -> Result<Vec<u8>> {
        let body = self.0.query(&nsid(name), params).map_err(map_error)?;
        if body.len() > MAX_RAW_RESPONSE_BYTES {
            return Err(Error::Backend(format!(
                "xrpc raw response exceeds {MAX_RAW_RESPONSE_BYTES} bytes"
            )));
        }
        Ok(body)
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use serde_json::json;

    use super::*;
    use crate::device::{ChatBinding, DeviceSecrets};
    use crate::records::{Device, datetime_from_ms};
    use crate::sign::Ed25519Transport;
    use crate::store::memory::MemoryBackend;
    use crate::store::{MailboxStore as _, ThreadStore as _};

    type Reply = core::result::Result<Vec<u8>, XrpcError>;
    type QueryCall = (String, Vec<(String, String)>);
    type ProcedureCall = (String, Vec<u8>, [u8; 16]);

    #[derive(Default)]
    struct Scripted {
        replies: Mutex<VecDeque<Reply>>,
        queries: Mutex<Vec<QueryCall>>,
        procedures: Mutex<Vec<ProcedureCall>>,
    }

    impl Scripted {
        fn with_replies(replies: impl IntoIterator<Item = Reply>) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies.into_iter().collect()),
                ..Self::default()
            })
        }

        fn next(&self) -> Reply {
            self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
                Err(XrpcError {
                    status: 599,
                    error: Some("ScriptExhausted".into()),
                    message: None,
                })
            })
        }
    }

    impl XrpcTransport for Scripted {
        fn query_with_headers(
            &self,
            nsid: &str,
            params: &[(&str, String)],
            _headers: &[(String, String)],
        ) -> Reply {
            self.queries.lock().unwrap().push((
                nsid.to_owned(),
                params
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), value.clone()))
                    .collect(),
            ));
            self.next()
        }

        fn procedure(&self, nsid: &str, payload: &[u8], operation_id: [u8; 16]) -> Reply {
            self.procedures
                .lock()
                .unwrap()
                .push((nsid.to_owned(), payload.to_vec(), operation_id));
            self.next()
        }
    }

    fn no_response() -> Reply {
        Err(XrpcError {
            status: 0,
            error: None,
            message: Some("response lost".into()),
        })
    }

    fn page(items: Vec<u16>, cursor: Option<String>) -> Reply {
        page_with_incomplete(items, cursor, None)
    }

    fn page_with_incomplete(
        items: Vec<u16>,
        cursor: Option<String>,
        incomplete: Option<Vec<String>>,
    ) -> Reply {
        Ok(serde_json::to_vec(&wire::Page::<u16> {
            items,
            cursor,
            incomplete,
        })
        .unwrap())
    }

    fn backend_message(error: Error) -> String {
        match error {
            Error::Backend(message) => message,
            other => panic!("expected backend error, got {other:?}"),
        }
    }

    #[test]
    fn post_retries_one_transport_uncertainty_with_identical_request() {
        let transport = Scripted::with_replies([no_response(), Ok(b"{}".to_vec())]);
        let x = Xrpc::new(transport.clone());

        let _: wire::Empty = x.post("createDevice", &json!({ "record": 7 })).unwrap();

        let calls = transport.procedures.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1], "retry changed payload or operation id");
    }

    #[test]
    fn committed_write_with_lost_response_replays_instead_of_applying_twice() {
        struct DropFirstCommittedResponse {
            inner: Arc<dyn XrpcTransport>,
            dropped: AtomicBool,
            operations: Mutex<Vec<[u8; 16]>>,
        }

        impl XrpcTransport for DropFirstCommittedResponse {
            fn query_with_headers(
                &self,
                nsid: &str,
                params: &[(&str, String)],
                headers: &[(String, String)],
            ) -> Reply {
                self.inner.query_with_headers(nsid, params, headers)
            }

            fn procedure(&self, nsid: &str, payload: &[u8], operation_id: [u8; 16]) -> Reply {
                self.operations.lock().unwrap().push(operation_id);
                let committed = self.inner.procedure(nsid, payload, operation_id);
                if !self.dropped.swap(true, Ordering::SeqCst) {
                    committed.expect("reference server committed the first attempt");
                    no_response()
                } else {
                    committed
                }
            }
        }

        const DID: &str = "did:plc:alice";
        let server = server::MemoryXrpcServer::new(MemoryBackend::new());
        let signer = Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
        let chat_key = signer.0.verifying_key().to_bytes();
        server.backend().register_chat_device(DID, chat_key);
        let transport = Arc::new(DropFirstCommittedResponse {
            inner: server.transport(DID, chat_key),
            dropped: AtomicBool::new(false),
            operations: Mutex::new(Vec::new()),
        });
        let mailbox = XrpcMailboxStore::new(DID, transport.clone());
        let device = DeviceSecrets::generate().unwrap();
        let binding = ChatBinding::sign(DID, &device.public().device_key_pub, &signer);
        let record = Device::bound(device.public(), &binding, datetime_from_ms(1));

        mailbox.create_device(&record).unwrap();

        assert_eq!(
            mailbox.get_device(&device.public().device_key_pub).unwrap(),
            Some(record)
        );
        let operations = transport.operations.lock().unwrap();
        assert_eq!(operations.len(), 2);
        assert_eq!(operations[0], operations[1]);
    }

    #[test]
    fn post_retries_transport_uncertainty_only_once() {
        let transport = Scripted::with_replies([no_response(), no_response()]);
        let x = Xrpc::new(transport.clone());

        assert!(
            x.post::<_, wire::Empty>("createDevice", &json!({}))
                .is_err()
        );
        assert_eq!(transport.procedures.lock().unwrap().len(), 2);
    }

    #[test]
    fn post_does_not_retry_a_server_error() {
        for failure in [
            XrpcError::named(409, "RecordAlreadyExists", "exists"),
            XrpcError {
                status: 503,
                error: None,
                message: Some("unavailable".into()),
            },
        ] {
            let transport = Scripted::with_replies([Err(failure)]);
            let x = Xrpc::new(transport.clone());
            assert!(
                x.post::<_, wire::Empty>("createDevice", &json!({}))
                    .is_err()
            );
            assert_eq!(transport.procedures.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn json_and_raw_responses_have_independent_size_limits() {
        for path in ["get", "get_full", "post"] {
            let transport = Scripted::with_replies([Ok(vec![b' '; MAX_JSON_RESPONSE_BYTES + 1])]);
            let x = Xrpc::new(transport);
            let error = match path {
                "get" => x.get::<serde_json::Value>("getEpochHead", &[]).unwrap_err(),
                "get_full" => x
                    .get_full::<serde_json::Value>("blue.catbird.other", &[])
                    .unwrap_err(),
                "post" => x
                    .post::<_, serde_json::Value>("createDevice", &json!({}))
                    .unwrap_err(),
                _ => unreachable!(),
            };
            let message = backend_message(error);
            assert!(message.contains("JSON response exceeds 16777216 bytes"));
        }

        let raw_transport = Scripted::with_replies([Ok(vec![0; 10 * 1024 * 1024 + 1])]);
        let message = backend_message(
            Xrpc::new(raw_transport)
                .get_raw("getAttachmentBlob", &[])
                .unwrap_err(),
        );
        assert!(message.contains("raw response exceeds 10485760 bytes"));
    }

    #[test]
    fn listing_rejects_an_oversized_page() {
        let transport = Scripted::with_replies([page(vec![0; 101], None)]);
        let message = backend_message(
            Xrpc::new(transport)
                .list_all::<u16>("listDevices", &[])
                .unwrap_err(),
        );
        assert!(message.contains("page exceeds 100 items"));
    }

    #[test]
    fn listing_rejects_an_oversized_cursor() {
        let transport = Scripted::with_replies([page(vec![], Some("x".repeat(65)))]);
        let message = backend_message(
            Xrpc::new(transport)
                .list_all::<u16>("listDevices", &[])
                .unwrap_err(),
        );
        assert!(message.contains("cursor exceeds 64 bytes"));
    }

    #[test]
    fn listing_rejects_a_cursor_cycle_not_just_an_immediate_repeat() {
        let transport = Scripted::with_replies([
            page(vec![], Some("a".into())),
            page(vec![], Some("b".into())),
            page(vec![], Some("a".into())),
        ]);
        let message = backend_message(
            Xrpc::new(transport.clone())
                .list_all::<u16>("listDevices", &[])
                .unwrap_err(),
        );
        assert!(message.contains("cursor cycle"));
        assert_eq!(transport.queries.lock().unwrap().len(), 3);
    }

    #[test]
    fn listing_rejects_an_aggregate_response_byte_overflow() {
        let first = serde_json::to_vec(&wire::Page::<String> {
            items: vec!["a".repeat(64)],
            cursor: Some("next".into()),
            incomplete: None,
        })
        .unwrap();
        let second = serde_json::to_vec(&wire::Page::<String> {
            items: vec!["b".repeat(64)],
            cursor: None,
            incomplete: None,
        })
        .unwrap();
        let exact = first.len() + second.len();
        let transport = Scripted::with_replies([Ok(first.clone()), Ok(second.clone())]);
        let message = backend_message(
            Xrpc::new(transport.clone())
                .list_all_report_with_budget::<String>("listDevices", &[], exact - 1)
                .unwrap_err(),
        );
        assert!(message.contains("listing responses exceed"));
        assert_eq!(transport.queries.lock().unwrap().len(), 2);

        let transport = Scripted::with_replies([Ok(first), Ok(second)]);
        assert_eq!(
            Xrpc::new(transport)
                .list_all_report_with_budget::<String>("listDevices", &[], exact)
                .unwrap()
                .0
                .len(),
            2
        );
    }

    #[test]
    fn listing_stops_after_1024_pages() {
        let replies = (0..1024).map(|i| page(vec![], Some(format!("c{i}"))));
        let transport = Scripted::with_replies(replies);
        let message = backend_message(
            Xrpc::new(transport.clone())
                .list_all::<u16>("listDevices", &[])
                .unwrap_err(),
        );
        assert!(message.contains("listing exceeds 1024 pages"));
        assert_eq!(transport.queries.lock().unwrap().len(), 1024);
    }

    #[test]
    fn listing_stops_before_collecting_more_than_10000_items() {
        let mut replies = Vec::new();
        for i in 0..100 {
            replies.push(page(vec![0; 100], Some(format!("c{i}"))));
        }
        replies.push(page(vec![0], None));
        let transport = Scripted::with_replies(replies);
        let message = backend_message(
            Xrpc::new(transport.clone())
                .list_all::<u16>("listDevices", &[])
                .unwrap_err(),
        );
        assert!(message.contains("listing exceeds 10000 items"));
        assert_eq!(transport.queries.lock().unwrap().len(), 101);
    }

    #[test]
    fn message_lookup_rejects_more_than_10000_requested_ids() {
        let transport = Scripted::with_replies([]);
        let store = XrpcThreadStore::new("did:plc:alice", transport);
        let ids = (0..=MAX_LIST_ITEMS)
            .map(|i| format!("m{i}"))
            .collect::<Vec<_>>();
        let ids = ids.iter().map(String::as_str).collect::<Vec<_>>();

        let message = backend_message(store.get_messages("thread", &ids).unwrap_err());
        assert!(message.contains("message lookup exceeds 10000 ids"));
    }

    #[test]
    fn listing_bounds_incomplete_sequencers_per_page_and_in_aggregate() {
        let page_wide = Scripted::with_replies([page_with_incomplete(
            vec![],
            None,
            Some(
                (0..=MAX_INCOMPLETE_PER_PAGE)
                    .map(|i| format!("did:web:s{i}"))
                    .collect(),
            ),
        )]);
        let message = backend_message(
            Xrpc::new(page_wide)
                .list_all_report::<u16>("listThreads", &[])
                .unwrap_err(),
        );
        assert!(message.contains("page exceeds 1024 incomplete sequencers"));

        let replies = (0..101).map(|page_number| {
            let incomplete = (0..100)
                .map(|item| format!("did:web:s{page_number}-{item}"))
                .collect();
            let cursor = (page_number < 100).then(|| format!("c{page_number}"));
            page_with_incomplete(vec![], cursor, Some(incomplete))
        });
        let aggregate = Scripted::with_replies(replies);
        let message = backend_message(
            Xrpc::new(aggregate)
                .list_all_report::<u16>("listThreads", &[])
                .unwrap_err(),
        );
        assert!(message.contains("listing exceeds 10000 incomplete sequencers"));
    }

    #[test]
    fn exact_response_and_listing_limits_are_accepted() {
        let mut json = vec![b'a'; MAX_JSON_RESPONSE_BYTES];
        json[0] = b'"';
        json[MAX_JSON_RESPONSE_BYTES - 1] = b'"';
        let json_transport = Scripted::with_replies([Ok(json)]);
        assert!(
            Xrpc::new(json_transport)
                .get::<String>("getEpochHead", &[])
                .is_ok()
        );

        let raw_transport = Scripted::with_replies([Ok(vec![0; MAX_RAW_RESPONSE_BYTES])]);
        assert_eq!(
            Xrpc::new(raw_transport)
                .get_raw("getAttachmentBlob", &[])
                .unwrap()
                .len(),
            MAX_RAW_RESPONSE_BYTES
        );

        let incomplete = Scripted::with_replies([page_with_incomplete(
            vec![],
            None,
            Some(
                (0..MAX_INCOMPLETE_PER_PAGE)
                    .map(|i| format!("did:web:s{i}"))
                    .collect(),
            ),
        )]);
        assert_eq!(
            Xrpc::new(incomplete)
                .list_all_report::<u16>("listThreads", &[])
                .unwrap()
                .1
                .len(),
            MAX_INCOMPLETE_PER_PAGE
        );

        let replies = (0..100).map(|page_number| {
            page(
                vec![0; MAX_PAGE],
                (page_number < 99).then(|| format!("c{page_number:0>63}")),
            )
        });
        let listing = Scripted::with_replies(replies);
        assert_eq!(
            Xrpc::new(listing)
                .list_all::<u16>("listDevices", &[])
                .unwrap()
                .len(),
            MAX_LIST_ITEMS
        );

        let replies = (0..MAX_PAGES).map(|page_number| {
            page(
                vec![],
                (page_number + 1 < MAX_PAGES).then(|| format!("c{page_number}")),
            )
        });
        let pages = Scripted::with_replies(replies);
        assert!(
            Xrpc::new(pages)
                .list_all::<u16>("listDevices", &[])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn post_does_not_retry_chat_key_signing_failed_status_zero() {
        let transport = Scripted::with_replies([
            Err(XrpcError {
                status: 0,
                error: Some("ChatKeySigningFailed".into()),
                message: Some("hardware key locked".into()),
            }),
            Ok(b"{}".to_vec()),
        ]);
        let err = Xrpc::new(transport.clone())
            .post::<_, serde_json::Value>("touchVirtualDevice", &serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, Error::Backend(_)), "got {err:?}");
        assert_eq!(transport.procedures.lock().unwrap().len(), 1);
    }

    #[test]
    fn map_error_gates_not_found_on_400_or_404_status() {
        assert_eq!(
            map_error(XrpcError::named(404, "VirtualDeviceNotFound", "gone")),
            Error::NotFound("virtual device")
        );
        assert_eq!(
            map_error(XrpcError::named(400, "NotFound", "gone")),
            Error::NotFound("attachment")
        );
        assert_eq!(
            map_error(XrpcError::named(404, "SpaceNotFound", "gone")),
            Error::NotFound("space")
        );
        for status in [401, 502, 503] {
            for code in [
                "NotFound",
                "VirtualDeviceNotFound",
                "SpaceNotFound",
                "EpochNotFound",
                "DeviceNotFound",
                "OrfStateNotFound",
                "ConversationNotFound",
            ] {
                assert!(
                    matches!(
                        map_error(XrpcError::named(status, code, "gateway")),
                        Error::Backend(_)
                    ),
                    "status={status} code={code} should not map to NotFound"
                );
            }
        }
        assert_eq!(
            map_error(XrpcError::named(403, "NotFound", "denied")),
            Error::Forbidden
        );
    }

    #[test]
    fn list_pages_continues_across_empty_pages_and_stops_early() {
        let transport = Scripted::with_replies([
            page(vec![], Some("c1".into())),
            page(vec![], Some("c2".into())),
            page(vec![10u16, 20], Some("c3".into())),
            page(vec![30u16], None),
        ]);
        let mut collected = Vec::new();
        Xrpc::new(transport.clone())
            .list_pages::<u16, _>("listBatches", &[], |items, has_more| {
                collected.extend(items);
                Ok(!(has_more && collected.len() >= 2))
            })
            .unwrap();
        assert_eq!(collected, vec![10, 20]);
        assert_eq!(transport.queries.lock().unwrap().len(), 3);
    }
}

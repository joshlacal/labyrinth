//! Spaces-only conversation thread store (`com.atproto.space.*`, Gates 1 & 5).
//!
//! Each conversation maps to a single ATProto Space
//! (`at:space/{authorityDid}/blue.catbird.labyrinth.conversation/{skey}`).
//! Members write MEK distributions, sender batches
//! (`<16-hex-first-seq>-<8-hex-device-tag>-<tid>`), and encrypted attachment
//! manifests directly into their own Space repo. `mls-ds` holds zero long-term
//! history or ciphertext index (`G6`, `I14`).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use atproto_spaces::star::ParsedStarRepo;
use petrel_spaces::MacProfile;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    ApplyWritesIn, ApplyWritesOut, AuthorizeSpaceSyncOut, GetRecordOut, LIST_LIMIT, ListRecordsOut,
    MAX_SPACE_CURSOR_BYTES, MAX_SPACE_LIST_ITEMS, MAX_SPACE_LIST_RESPONSE_BYTES, MAX_SPACE_PAGES,
    MAX_SPACE_RESPONSE_BYTES, MAX_WRITES, MemberAccess, SpaceRef, SpaceRpc, WriteOp,
    WriterRevFloors, WriterUpdate, decode, decode_body, encode, endpoint,
    map_member_repo_space_error, map_space_error, uri_rkey,
};
use crate::attachment::{AttachmentCiphertextMeta, verify_attachment_ciphertext};
use crate::deletion::Redaction;
use crate::encoding::sha256;
use crate::records::{
    AttachmentManifest, AuthorRedaction, Batch, Bytes, MekDistribution, SealedMessageDef,
    datetime_from_ms, ms_from_datetime, nsid,
};
use crate::store::{Stored, ThreadStore, TimeRange};
use crate::{Error, Result};

const THREAD_COLLECTIONS: [&str; 3] = [nsid::MEK, nsid::BATCH, nsid::ATTACHMENT_MANIFEST];

fn overlay_author_redactions(
    thread_id: &str,
    author: &str,
    batches: &mut Vec<Stored<Batch>>,
    redactions: Vec<(String, AuthorRedaction)>,
) -> Result<()> {
    for (rkey, record) in redactions {
        if record.thread_id != thread_id || record.rkey() != rkey {
            return Err(Error::Malformed("authorRedaction coordinates or rkey"));
        }
        let redaction = record.to_redaction()?;
        redaction.verify(author, thread_id, &record.message_id)?;
        let mut found = false;
        for batch in batches.iter_mut() {
            for item in batch
                .value
                .items
                .iter_mut()
                .filter(|item| item.message_id == record.message_id)
            {
                item.redaction = Some(record.redaction.clone());
                found = true;
            }
        }
        if !found {
            batches.push(Stored {
                author: author.to_owned(),
                rkey: format!("redaction-{rkey}"),
                order: None,
                value: Batch {
                    type_: nsid::BATCH.into(),
                    thread_id: thread_id.to_owned(),
                    items: vec![SealedMessageDef {
                        message_id: record.message_id,
                        seq: None,
                        timestamp: ms_from_datetime(&record.created_at).unwrap_or(0),
                        mek_id: Bytes::default(),
                        sender_transport_pubkey: Bytes::default(),
                        signed_enc_message: Bytes::default(),
                        sequencer_receipt: None,
                        redaction: Some(record.redaction),
                    }],
                    created_at: record.created_at,
                },
            });
        }
    }
    Ok(())
}

/// Canonical DRISL bytes and CID v1 (DAG-CBOR, SHA-256) of a sender batch record.
pub fn batch_cid(batch: &Batch) -> Result<String> {
    batch.entries()?;
    let encoded = serde_ipld_dagcbor::to_vec(batch)
        .map_err(|_| Error::Malformed("conversation batch DRISL"))?;
    if encoded.len() > 1_048_576 {
        return Err(Error::Malformed("conversation batch exceeds 1 MiB"));
    }
    let digest = cid::multihash::Multihash::<64>::wrap(0x12, &sha256(&encoded))
        .map_err(|_| Error::Malformed("conversation batch CID"))?;
    Ok(cid::Cid::new_v1(0x71, digest).to_string())
}

fn system_now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct ListWritersOut {
    #[serde(default)]
    repos: Vec<WriterUpdate>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpaceView {
    space: String,
    #[serde(default)]
    repo_rev: Option<String>,
}

#[derive(Deserialize)]
struct ListSpacesOut {
    #[serde(default)]
    spaces: Vec<SpaceView>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizeSpaceSyncIn<'a> {
    space: String,
    credential_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegation_token: Option<&'a str>,
}

#[derive(Serialize)]
struct PutMembersIn<'a> {
    space: String,
    members: &'a [MemberAccess],
}

#[derive(Serialize)]
struct RemoveMembersIn<'a> {
    space: String,
    dids: &'a [String],
}

#[derive(Deserialize)]
struct ListMembersOut {
    #[serde(default)]
    members: Vec<MemberAccess>,
    #[serde(default)]
    cursor: Option<String>,
}

fn extract_single_header<'a>(
    headers: &'a [(String, String)],
    target_lower: &str,
) -> Result<&'a str> {
    let mut found: Option<&'a str> = None;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(target_lower) {
            if found.is_some() {
                return Err(Error::BadSignature);
            }
            found = Some(v.as_str());
        }
    }
    found.ok_or(Error::BadSignature)
}

struct MacHeaders<'a> {
    covered: &'a str,
    input: &'a str,
    signature: &'a str,
}

fn mac_headers(profile: MacProfile, headers: &[(String, String)]) -> Result<MacHeaders<'_>> {
    Ok(MacHeaders {
        covered: extract_single_header(headers, profile.response_header())?,
        input: extract_single_header(headers, "signature-input")?,
        signature: extract_single_header(headers, "signature")?,
    })
}

/// Alias retained for sequenced conversation Space thread store callers.
pub type SequencedSpaceThreadStore = SpaceThreadStore;

/// How a Space read response is authenticated.
enum ReadAuth {
    /// This store verifies the host's HPKE `0xFFFF` Export MAC itself.
    Host(String),
    /// The transport declared that it verifies every response itself
    /// ([`SpaceRpc::authenticates_responses`]).
    Transport,
}

/// Spaces-only [`ThreadStore`] reading and writing directly against conversation Spaces.
pub struct SpaceThreadStore {
    did: String,
    t: Arc<dyn SpaceRpc>,
    spaces: Mutex<HashMap<String, SpaceRef>>,
    default_authority_did: Option<String>,
    host_kem_did_key: Option<String>,
    tid_counter: AtomicU64,
    now_ms: crate::store::ClockFn,
    page: usize,
    device_tag: [u8; 4],
    floors: WriterRevFloors,
}

impl SpaceThreadStore {
    pub fn new(transport: impl Into<Arc<dyn SpaceRpc>>, did: impl Into<String>) -> Self {
        let did_str = did.into();
        let mut device_tag = [0u8; 4];
        if crate::encoding::random(&mut device_tag).is_err() {
            device_tag.copy_from_slice(&sha256(did_str.as_bytes())[..4]);
        }
        Self {
            did: did_str,
            t: transport.into(),
            spaces: Mutex::new(HashMap::new()),
            default_authority_did: None,
            host_kem_did_key: None,
            tid_counter: AtomicU64::new(1),
            now_ms: Arc::new(system_now_ms),
            page: LIST_LIMIT,
            device_tag,
            floors: WriterRevFloors::new(),
        }
    }

    pub fn with_authority_did(mut self, authority_did: impl Into<String>) -> Self {
        self.default_authority_did = Some(authority_did.into());
        self
    }

    /// Configures an explicit host P-256 `#atproto_kem` `did:key:zDn...` for RFC 9421 +
    /// HPKE `0xFFFF` Export MAC verification on `getRecord` and `getRepo` STAR reads.
    pub fn with_host_kem_did_key(mut self, host_kem_did_key: impl Into<String>) -> Self {
        self.host_kem_did_key = Some(host_kem_did_key.into());
        self
    }

    pub fn with_page_size(mut self, n: usize) -> Self {
        self.page = n.clamp(1, 1_000);
        self
    }

    pub fn with_clock(mut self, now_ms: crate::store::ClockFn) -> Self {
        self.now_ms = now_ms;
        self
    }

    /// Sets an explicit 4-byte device tag (`<dev8>`) used in `<seq:016x>-<dev8>-<tid>` batch keys.
    pub fn with_device_tag(mut self, tag: [u8; 4]) -> Self {
        self.device_tag = tag;
        self
    }

    /// Derives the 4-byte `<dev8>` tag deterministically from a device public key.
    pub fn with_device_pubkey(mut self, pubkey: &[u8]) -> Self {
        let digest = sha256(pubkey);
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&digest[..4]);
        self.device_tag = tag;
        self
    }

    /// Attaches a shared [`WriterRevFloors`] tracker.
    pub fn with_writer_rev_floors(mut self, floors: WriterRevFloors) -> Self {
        self.floors = floors;
        self
    }

    pub fn writer_rev_floors(&self) -> &WriterRevFloors {
        &self.floors
    }

    /// Lists every conversation Space (`com.atproto.space.listSpaces`) the caller owns or wrote to.
    pub async fn owned_spaces(transport: &dyn SpaceRpc) -> Result<Vec<String>> {
        Self::owned_spaces_inner(transport, None).await
    }

    /// Lists every conversation Space via this store while enforcing `(space_uri, did)` `repoRev` floors.
    pub async fn list_owned_spaces(&self) -> Result<Vec<String>> {
        Self::owned_spaces_inner(
            self.t.as_ref(),
            Some((&self.did, &self.floors, self.host_kem_did_key.as_deref())),
        )
        .await
    }

    async fn owned_spaces_inner(
        transport: &dyn SpaceRpc,
        floor_ctx: Option<(&str, &WriterRevFloors, Option<&str>)>,
    ) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        for _ in 0..MAX_SPACE_PAGES {
            let mut p = vec![
                ("spaceType", super::CONVERSATION_SPACE_TYPE.to_owned()),
                ("limit", "100".to_owned()),
            ];
            if let Some(c) = &cursor {
                p.push(("cursor", c.clone()));
            }
            let body = transport
                .query(endpoint::LIST_SPACES, &p)
                .await
                .map_err(map_space_error)?;
            let page: ListSpacesOut = decode_body(&body)?;
            for entry in page.spaces {
                if let Some((did, floors, explicit_kem)) = floor_ctx {
                    if let Some(rev) = entry.repo_rev.as_deref() {
                        floors.check_not_rolled_back(&entry.space, did, rev)?;
                    }
                    let kem = match explicit_kem {
                        Some(k) => Some(k.to_owned()),
                        None => transport
                            .host_kem_did_key(&entry.space)
                            .await
                            .map_err(map_space_error)?,
                    };
                    if kem.is_none() && !transport.authenticates_responses() {
                        return Err(Error::Unauthenticated("listSpaces repository revision"));
                    }
                    if let Some(kem_key) = kem {
                        match Self::fetch_repo_star_authenticated_raw(
                            transport,
                            floors,
                            &entry.space,
                            did,
                            &kem_key,
                        )
                        .await
                        {
                            Ok(_) | Err(Error::NotFound("repo" | "record")) => {}
                            Err(e) => return Err(e),
                        }
                    }
                }
                out.push(entry.space);
            }
            match page.cursor {
                Some(c) if c.len() > MAX_SPACE_CURSOR_BYTES => {
                    return Err(Error::Backend(format!(
                        "space cursor exceeds {MAX_SPACE_CURSOR_BYTES} bytes"
                    )));
                }
                Some(c) if seen_cursors.insert(c.clone()) => cursor = Some(c),
                Some(_) => return Err(Error::Backend("space cursor cycle".into())),
                None => return Ok(out),
            }
        }
        Err(Error::Backend("space listing too long".into()))
    }

    /// Calls `com.atproto.space.authorizeSpaceSync` on the thread's Space host.
    pub async fn authorize_space_sync(
        &self,
        thread_id: &str,
        credential_key: &str,
        delegation_token: Option<&str>,
    ) -> Result<AuthorizeSpaceSyncOut> {
        let space = self.space_for(thread_id)?;
        let input = AuthorizeSpaceSyncIn {
            space: space.to_string(),
            credential_key,
            delegation_token,
        };
        let payload =
            serde_json::to_vec(&input).map_err(|e| Error::Backend(format!("encode: {e}")))?;
        let body = self
            .t
            .procedure(endpoint::AUTHORIZE_SPACE_SYNC, &payload)
            .await
            .map_err(map_space_error)?;
        decode_body(&body)
    }

    /// Batched `com.atproto.memberspace.putMembers` (`<= 100` members per commit).
    pub async fn put_members(&self, thread_id: &str, members: &[MemberAccess]) -> Result<()> {
        if members.is_empty() {
            return Ok(());
        }
        let space = self.space_for(thread_id)?;
        for chunk in members.chunks(100) {
            let input = PutMembersIn {
                space: space.to_string(),
                members: chunk,
            };
            let payload =
                serde_json::to_vec(&input).map_err(|e| Error::Backend(format!("encode: {e}")))?;
            self.t
                .procedure(endpoint::PUT_MEMBERS, &payload)
                .await
                .map_err(map_space_error)?;
        }
        Ok(())
    }

    /// Batched `com.atproto.memberspace.removeMembers` (`<= 100` DIDs per commit).
    pub async fn remove_members(&self, thread_id: &str, dids: &[String]) -> Result<()> {
        if dids.is_empty() {
            return Ok(());
        }
        let space = self.space_for(thread_id)?;
        for chunk in dids.chunks(100) {
            let input = RemoveMembersIn {
                space: space.to_string(),
                dids: chunk,
            };
            let payload =
                serde_json::to_vec(&input).map_err(|e| Error::Backend(format!("encode: {e}")))?;
            self.t
                .procedure(endpoint::REMOVE_MEMBERS, &payload)
                .await
                .map_err(map_space_error)?;
        }
        Ok(())
    }

    /// Paginated `com.atproto.memberspace.listMembers`.
    pub async fn list_members(&self, thread_id: &str) -> Result<Vec<MemberAccess>> {
        let space = self.space_for(thread_id)?;
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        for _ in 0..MAX_SPACE_PAGES {
            let mut p = vec![("space", space.to_string()), ("limit", "100".to_owned())];
            if let Some(c) = &cursor {
                p.push(("cursor", c.clone()));
            }
            let body = self
                .t
                .query(endpoint::LIST_MEMBERS, &p)
                .await
                .map_err(map_space_error)?;
            let page: ListMembersOut = decode_body(&body)?;
            out.extend(page.members);
            match page.cursor {
                Some(c) if c.len() > MAX_SPACE_CURSOR_BYTES => {
                    return Err(Error::Backend(format!(
                        "space cursor exceeds {MAX_SPACE_CURSOR_BYTES} bytes"
                    )));
                }
                Some(c) if seen_cursors.insert(c.clone()) => cursor = Some(c),
                Some(_) => return Err(Error::Backend("space cursor cycle".into())),
                None => return Ok(out),
            }
        }
        Err(Error::Backend("space listing too long".into()))
    }

    async fn resolve_host_kem_did_key(&self, space_str: &str) -> Result<Option<String>> {
        if let Some(ref k) = self.host_kem_did_key {
            return Ok(Some(k.clone()));
        }
        self.t
            .host_kem_did_key(space_str)
            .await
            .map_err(map_member_repo_space_error)
    }

    /// Resolves how reads of `space_str` are authenticated, refusing with
    /// [`Error::Unauthenticated`] when neither a host KEM key nor an
    /// authenticating transport is available.
    async fn read_auth(&self, space_str: &str) -> Result<ReadAuth> {
        match self.resolve_host_kem_did_key(space_str).await? {
            Some(k) => Ok(ReadAuth::Host(k)),
            None if self.t.authenticates_responses() => Ok(ReadAuth::Transport),
            None => Err(Error::Unauthenticated("space host KEM key")),
        }
    }

    /// `getRecord` whose response is authenticated by the host MAC or by the
    /// transport; never an unauthenticated read.
    async fn get_checked<T: DeserializeOwned>(
        &self,
        space: &SpaceRef,
        repo: &str,
        collection: &str,
        rkey: &str,
    ) -> Result<Option<T>> {
        match self.read_auth(&space.to_string()).await? {
            ReadAuth::Host(kem_key) => Ok(self
                .get_record_authenticated_in_space::<T>(space, repo, collection, rkey, &kem_key)
                .await?
                .map(|(_, v)| v)),
            ReadAuth::Transport => self.get_from(space, repo, collection, rkey).await,
        }
    }

    async fn get_record_authenticated_in_space<T: DeserializeOwned>(
        &self,
        space: &SpaceRef,
        repo: &str,
        collection: &str,
        rkey: &str,
        host_kem_did_key: &str,
    ) -> Result<Option<(String, T)>> {
        let space_str = space.to_string();
        let enc = petrel_spaces::kem::encapsulate_p256(host_kem_did_key)
            .map_err(|_| Error::BadPublicKey)?;
        let accept = petrel_spaces::format_accept_signature(MacProfile::Record, &enc.key_share)
            .map_err(|_| Error::Malformed("accept-signature"))?;
        let p = [
            ("space", space_str.clone()),
            ("repo", repo.to_owned()),
            ("collection", collection.to_owned()),
            ("rkey", rkey.to_owned()),
        ];
        let req_headers = [("accept-signature".to_owned(), accept)];
        match self
            .t
            .query_with_headers(endpoint::GET_RECORD, &p, &req_headers)
            .await
            .map_err(map_member_repo_space_error)
        {
            Ok((resp_headers, body)) => {
                let out: GetRecordOut = decode_body(&body)?;
                let expected_uri = format!("{space_str}/{repo}/{collection}/{rkey}");
                if out.uri.as_deref() != Some(expected_uri.as_str()) {
                    return Err(Error::BadSignature);
                }
                let cid = out.cid.ok_or(Error::BadSignature)?;
                let headers = mac_headers(MacProfile::Record, &resp_headers)?;
                let verified = petrel_spaces::verify_record_mac(
                    &enc.shared_secret,
                    headers.covered,
                    headers.input,
                    headers.signature,
                )
                .map_err(|_| Error::BadSignature)?;
                if verified.keyid != enc.key_share
                    || verified.uri.as_str() != expected_uri
                    || verified.cid.to_string() != cid
                {
                    return Err(Error::BadSignature);
                }
                petrel_spaces::verify_record_cid(&out.value, &verified.cid)
                    .map_err(|_| Error::BadSignature)?;
                Ok(Some((cid, decode(out.value)?)))
            }
            Err(Error::NotFound("record" | "repo")) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn fetch_repo_star_authenticated_raw(
        transport: &dyn SpaceRpc,
        floors: &WriterRevFloors,
        space_str: &str,
        repo: &str,
        host_kem_did_key: &str,
    ) -> Result<ParsedStarRepo> {
        let enc = petrel_spaces::kem::encapsulate_p256(host_kem_did_key)
            .map_err(|_| Error::BadPublicKey)?;
        let accept = petrel_spaces::format_accept_signature(MacProfile::Commit, &enc.key_share)
            .map_err(|_| Error::Malformed("accept-signature"))?;
        let p = [("space", space_str.to_owned()), ("repo", repo.to_owned())];
        let req_headers = [("accept-signature".to_owned(), accept)];
        let (resp_headers, body) = transport
            .query_with_headers(endpoint::GET_REPO, &p, &req_headers)
            .await
            .map_err(map_member_repo_space_error)?;
        let headers = mac_headers(MacProfile::Commit, &resp_headers)?;
        let verified = petrel_spaces::verify_commit_mac(
            &enc.shared_secret,
            headers.covered,
            headers.input,
            headers.signature,
        )
        .map_err(|_| Error::BadSignature)?;
        if verified.keyid != enc.key_share
            || verified.space.as_str() != space_str
            || verified.repo.as_str() != repo
        {
            return Err(Error::BadSignature);
        }
        let mut floor_error = None;
        let parsed =
            atproto_spaces::star::read_star_repo_authenticated(&body, space_str, repo, |meta| {
                if meta.rev != verified.rev.as_str() || meta.data != verified.data {
                    return Err(atproto_spaces::SpacesError::MacMismatch(
                        "STAR metadata and signed commit differ".into(),
                    ));
                }
                if let Err(error) = floors.observe(space_str, repo, &meta.rev) {
                    floor_error = Some(error);
                    return Err(atproto_spaces::SpacesError::FutureRev(meta.rev.clone()));
                }
                Ok(())
            });
        if let Some(error) = floor_error {
            return Err(error);
        }
        parsed.map_err(|error| match error {
            atproto_spaces::SpacesError::MacMismatch(_) => Error::BadSignature,
            _ => Error::Malformed("STAR repository archive"),
        })
    }

    /// Fetches a foreign Space record and authenticates `(uri, cid)` via Nov-12 RFC 9421 +
    /// HPKE `0xFFFF` Export MAC (`Atproto-Space-Record`).
    pub async fn get_record_authenticated<T: DeserializeOwned>(
        &self,
        thread_id: &str,
        repo: &str,
        collection: &str,
        rkey: &str,
        host_kem_did_key: &str,
    ) -> Result<Option<(String, T)>> {
        let space = self.space_for(thread_id)?;
        self.get_record_authenticated_in_space(&space, repo, collection, rkey, host_kem_did_key)
            .await
    }

    /// Downloads a writer's repository as a Nov-12 `STAR` v0.2 archive (`com.atproto.space.getRepo`),
    /// verifying the commit MAC and rollback floor before reading raw record frames.
    /// Raw frames let recovery quarantine out-of-range timestamps per author.
    pub async fn get_repo_star_authenticated(
        &self,
        thread_id: &str,
        repo: &str,
        host_kem_did_key: &str,
    ) -> Result<ParsedStarRepo> {
        let space = self.space_for(thread_id)?;
        let space_str = space.to_string();
        Self::fetch_repo_star_authenticated_raw(
            self.t.as_ref(),
            &self.floors,
            &space_str,
            repo,
            host_kem_did_key,
        )
        .await
    }

    pub fn register_thread_space(&mut self, thread_id: &str, space: SpaceRef) {
        self.spaces
            .lock()
            .unwrap()
            .insert(thread_id.to_owned(), space);
    }

    pub fn set_thread_space(&self, thread_id: &str, space: SpaceRef) {
        self.spaces
            .lock()
            .unwrap()
            .insert(thread_id.to_owned(), space);
    }

    fn space_for(&self, thread_id: &str) -> Result<SpaceRef> {
        if let Some(s) = self.spaces.lock().unwrap().get(thread_id).cloned() {
            return Ok(s);
        }
        if let Some(auth) = &self.default_authority_did {
            return Ok(SpaceRef::conversation(auth, thread_id));
        }
        Err(Error::NotFound("thread space"))
    }

    fn next_tid(&self) -> String {
        const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
        let c = self.tid_counter.fetch_add(1, Ordering::Relaxed);
        let us = (self.now_ms)().saturating_mul(1_000).wrapping_add(c);
        let v = ((us & ((1u64 << 53) - 1)) << 10) | (c & 0x3ff);
        (0..13)
            .rev()
            .map(|i| S32[((v >> (5 * i)) & 31) as usize] as char)
            .collect()
    }

    async fn apply(&self, space: &SpaceRef, writes: &[WriteOp]) -> Result<Vec<Option<String>>> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        if writes.len() > MAX_WRITES {
            return Err(Error::Backend(format!(
                "space applyWrites: {} writes, max {MAX_WRITES}",
                writes.len()
            )));
        }
        let input = ApplyWritesIn {
            space: space.to_string(),
            repo: &self.did,
            validate: false,
            writes,
        };
        let payload =
            serde_json::to_vec(&input).map_err(|e| Error::Backend(format!("encode: {e}")))?;
        let body = self
            .t
            .procedure(endpoint::APPLY_WRITES, &payload)
            .await
            .map_err(map_member_repo_space_error)?;
        let out: ApplyWritesOut = decode_body(&body)?;
        Ok(out.results.into_iter().map(|r| r.uri).collect())
    }

    async fn get_from<T: DeserializeOwned>(
        &self,
        space: &SpaceRef,
        repo: &str,
        collection: &str,
        rkey: &str,
    ) -> Result<Option<T>> {
        let p = [
            ("space", space.to_string()),
            ("repo", repo.to_owned()),
            ("collection", collection.to_owned()),
            ("rkey", rkey.to_owned()),
        ];
        match self
            .t
            .query(endpoint::GET_RECORD, &p)
            .await
            .map_err(map_member_repo_space_error)
        {
            Ok(body) => decode(decode_body::<GetRecordOut>(&body)?.value).map(Some),
            Err(Error::NotFound("record" | "repo")) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Paginated `com.atproto.space.listWriters` (`#repoWrite` / `#repoRemoved`).
    pub async fn list_writers(&self, space: &SpaceRef) -> Result<Vec<WriterUpdate>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        let mut response_bytes = 0usize;
        for _ in 0..MAX_SPACE_PAGES {
            let mut p = vec![
                ("space", space.to_string()),
                ("limit", self.page.to_string()),
            ];
            if let Some(c) = &cursor {
                p.push(("cursor", c.clone()));
            }
            let body = self
                .t
                .query(endpoint::LIST_WRITERS, &p)
                .await
                .map_err(map_member_repo_space_error)?;
            if body.len() > MAX_SPACE_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "space response exceeds {MAX_SPACE_RESPONSE_BYTES} bytes"
                )));
            }
            response_bytes = response_bytes.checked_add(body.len()).ok_or_else(|| {
                Error::Backend("space listing response byte count overflow".into())
            })?;
            if response_bytes > MAX_SPACE_LIST_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "space listing responses exceed {MAX_SPACE_LIST_RESPONSE_BYTES} bytes"
                )));
            }
            let page: ListWritersOut = decode_body(&body)?;
            if page.repos.len() > self.page {
                return Err(Error::Backend(format!(
                    "space page exceeds {} records",
                    self.page
                )));
            }
            let total = out
                .len()
                .checked_add(page.repos.len())
                .ok_or_else(|| Error::Backend("space listing item count overflow".into()))?;
            if total > MAX_SPACE_LIST_ITEMS {
                return Err(Error::Backend(format!(
                    "space listing exceeds {MAX_SPACE_LIST_ITEMS} records"
                )));
            }
            out.extend(page.repos);
            match page.cursor {
                Some(c) if c.len() > MAX_SPACE_CURSOR_BYTES => {
                    return Err(Error::Backend(format!(
                        "space cursor exceeds {MAX_SPACE_CURSOR_BYTES} bytes"
                    )));
                }
                Some(c) if seen_cursors.insert(c.clone()) => cursor = Some(c),
                Some(_) => return Err(Error::Backend("space cursor cycle".into())),
                None => return Ok(out),
            }
        }
        Err(Error::Backend("space listing too long".into()))
    }

    async fn list_repos(&self, space: &SpaceRef) -> Result<Vec<String>> {
        let updates = self.list_writers(space).await?;
        let space_str = space.to_string();
        let mut active = std::collections::BTreeSet::new();
        let mut seen_in_stream: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for update in updates {
            match update {
                WriterUpdate::RepoWrite {
                    repo,
                    repo_rev,
                    space_rev,
                    ..
                } => {
                    // Validate structure & check against authenticated floors without
                    // mutating persistent floors from unauthenticated listWriters JSON.
                    self.floors
                        .check_not_rolled_back(&space_str, &repo, &repo_rev)?;
                    if !crate::store::is_valid_atproto_tid(&space_rev) {
                        return Err(Error::Malformed("invalid writer spaceRev"));
                    }
                    if let Some(prev_in_stream) = seen_in_stream.get(&repo)
                        && repo_rev.as_str() < prev_in_stream.as_str()
                    {
                        return Err(Error::WriterRollback {
                            space: space_str.clone(),
                            author: repo,
                            pinned_rev: prev_in_stream.clone(),
                            offered_rev: repo_rev,
                        });
                    }
                    seen_in_stream.insert(repo.clone(), repo_rev);
                    active.insert(repo);
                }
                WriterUpdate::RepoRemoved {
                    repo, space_rev, ..
                } => {
                    if petrel_spaces::Did::parse(&repo).is_err()
                        || repo.len() > crate::store::MAX_WRITER_FLOOR_AUTHOR_LEN
                    {
                        return Err(Error::Malformed("invalid writer revision author"));
                    }
                    if !crate::store::is_valid_atproto_tid(&space_rev) {
                        return Err(Error::Malformed("invalid writer spaceRev"));
                    }
                    active.remove(&repo);
                }
            }
        }
        // The listing is not authenticated: it may add candidate writers but
        // cannot remove one whose repository this client already
        // authenticated in this Space. Those stay candidates and are
        // re-verified by the authenticated per-writer read.
        active.extend(self.floors.authors_in(&space_str));
        Ok(active.into_iter().collect())
    }

    async fn list_repo_raw(
        &self,
        space: &SpaceRef,
        repo: &str,
        collection: &str,
        values: bool,
    ) -> Result<Vec<(String, Value)>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::BTreeSet::new();
        let mut response_bytes = 0usize;
        for _ in 0..MAX_SPACE_PAGES {
            let mut p = vec![
                ("space", space.to_string()),
                ("repo", repo.to_owned()),
                ("collection", collection.to_owned()),
                ("limit", self.page.to_string()),
            ];
            if !values {
                p.push(("excludeValues", "true".to_owned()));
            }
            if let Some(c) = &cursor {
                p.push(("cursor", c.clone()));
            }
            let body = match self
                .t
                .query(endpoint::LIST_RECORDS, &p)
                .await
                .map_err(map_member_repo_space_error)
            {
                Ok(body) => body,
                Err(Error::NotFound("repo")) => return Ok(out),
                Err(e) => return Err(e),
            };
            if body.len() > MAX_SPACE_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "space response exceeds {MAX_SPACE_RESPONSE_BYTES} bytes"
                )));
            }
            response_bytes = response_bytes.checked_add(body.len()).ok_or_else(|| {
                Error::Backend("space listing response byte count overflow".into())
            })?;
            if response_bytes > MAX_SPACE_LIST_RESPONSE_BYTES {
                return Err(Error::Backend(format!(
                    "space listing responses exceed {MAX_SPACE_LIST_RESPONSE_BYTES} bytes"
                )));
            }
            let page: ListRecordsOut = decode_body(&body)?;
            if page.records.len() > self.page {
                return Err(Error::Backend(format!(
                    "space page exceeds {} records",
                    self.page
                )));
            }
            let total = out
                .len()
                .checked_add(page.records.len())
                .ok_or_else(|| Error::Backend("space listing item count overflow".into()))?;
            if total > MAX_SPACE_LIST_ITEMS {
                return Err(Error::Backend(format!(
                    "space listing exceeds {MAX_SPACE_LIST_ITEMS} records"
                )));
            }
            out.extend(
                page.records
                    .into_iter()
                    .map(|r| (r.rkey, r.value.unwrap_or(Value::Null))),
            );
            match page.cursor {
                Some(c) if c.len() > MAX_SPACE_CURSOR_BYTES => {
                    return Err(Error::Backend(format!(
                        "space cursor exceeds {MAX_SPACE_CURSOR_BYTES} bytes"
                    )));
                }
                Some(c) if seen_cursors.insert(c.clone()) => cursor = Some(c),
                Some(_) => return Err(Error::Backend("space cursor cycle".into())),
                None => {
                    out.sort_by(|a, b| a.0.cmp(&b.0));
                    return Ok(out);
                }
            }
        }
        Err(Error::Backend("space listing too long".into()))
    }

    async fn list_repo<T: DeserializeOwned>(
        &self,
        space: &SpaceRef,
        repo: &str,
        collection: &str,
    ) -> Result<Vec<(String, T)>> {
        self.list_repo_raw(space, repo, collection, true)
            .await?
            .into_iter()
            .map(|(k, v)| Ok((k, decode(v)?)))
            .collect()
    }

    async fn probe_mek_repo(
        &self,
        space: &SpaceRef,
        did: &str,
        rkey: &str,
    ) -> Result<Option<Stored<MekDistribution>>> {
        let fetched = self
            .get_checked::<MekDistribution>(space, did, nsid::MEK, rkey)
            .await;
        match fetched {
            Ok(Some(m)) => Ok(Some(Stored {
                author: did.to_owned(),
                rkey: rkey.to_owned(),
                value: m,
                order: None,
            })),
            Ok(None) | Err(Error::Malformed(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn probe_meks_bounded(
        &self,
        space: &SpaceRef,
        repos: &[String],
        rkey: &str,
    ) -> Result<Vec<Stored<MekDistribution>>> {
        const MEK_FALLBACK_CONCURRENCY: usize = 8;
        if repos.is_empty() {
            return Ok(Vec::new());
        }
        let mut results: Vec<Option<Stored<MekDistribution>>> = vec![None; repos.len()];
        let mut next_idx = 0usize;
        let mut in_flight = Vec::with_capacity(repos.len().min(MEK_FALLBACK_CONCURRENCY));
        while next_idx < repos.len() && in_flight.len() < MEK_FALLBACK_CONCURRENCY {
            let idx = next_idx;
            next_idx += 1;
            in_flight.push((idx, Box::pin(self.probe_mek_repo(space, &repos[idx], rkey))));
        }
        while !in_flight.is_empty() {
            let (done_pos, outcome) = core::future::poll_fn(|cx| {
                for (pos, (_, fut)) in in_flight.iter_mut().enumerate() {
                    if let core::task::Poll::Ready(res) = fut.as_mut().poll(cx) {
                        return core::task::Poll::Ready((pos, res));
                    }
                }
                core::task::Poll::Pending
            })
            .await;
            let (idx, _) = in_flight.swap_remove(done_pos);
            results[idx] = outcome?;
            if next_idx < repos.len() {
                let new_idx = next_idx;
                next_idx += 1;
                in_flight.push((
                    new_idx,
                    Box::pin(self.probe_mek_repo(space, &repos[new_idx], rkey)),
                ));
            }
        }
        Ok(results.into_iter().flatten().collect())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl ThreadStore for SpaceThreadStore {
    fn author(&self) -> &str {
        &self.did
    }

    async fn create_mek(&self, mek: &MekDistribution) -> Result<()> {
        let space = self.space_for(&mek.thread_id)?;
        self.apply(
            &space,
            &[WriteOp::Create {
                collection: nsid::MEK,
                rkey: Some(mek.rkey()),
                value: encode(mek)?,
            }],
        )
        .await?;
        Ok(())
    }

    async fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> Result<Vec<Stored<MekDistribution>>> {
        self.find_meks_with_hint(thread_id, mek_id, None).await
    }

    fn supports_author_mek_fast_path(&self) -> bool {
        true
    }

    async fn find_mek_from_author(
        &self,
        thread_id: &str,
        author_did: &str,
        mek_id: &[u8; 12],
    ) -> Result<Option<Stored<MekDistribution>>> {
        let space = self.space_for(thread_id)?;
        let rkey = hex::encode(mek_id);
        self.probe_mek_repo(&space, author_did, &rkey).await
    }

    async fn find_meks_excluding_author(
        &self,
        thread_id: &str,
        excluded_author: &str,
        mek_id: &[u8; 12],
    ) -> Result<Vec<Stored<MekDistribution>>> {
        let space = self.space_for(thread_id)?;
        let rkey = hex::encode(mek_id);
        let repos: Vec<String> = self
            .list_repos(&space)
            .await?
            .into_iter()
            .filter(|did| did.as_str() != excluded_author)
            .collect();
        self.probe_meks_bounded(&space, &repos, &rkey).await
    }

    async fn find_meks_with_hint(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
        preferred_author: Option<&str>,
    ) -> Result<Vec<Stored<MekDistribution>>> {
        let space = self.space_for(thread_id)?;
        let rkey = hex::encode(mek_id);
        let mut out = Vec::new();
        if let Some(preferred) = preferred_author
            && let Some(hit) = self.probe_mek_repo(&space, preferred, &rkey).await?
        {
            out.push(hit);
        }
        let repos: Vec<String> = self
            .list_repos(&space)
            .await?
            .into_iter()
            .filter(|did| preferred_author != Some(did.as_str()))
            .collect();
        out.extend(self.probe_meks_bounded(&space, &repos, &rkey).await?);
        Ok(out)
    }

    async fn append_batch(&self, batch: &Batch) -> Result<String> {
        let space = self.space_for(&batch.thread_id)?;
        let dev8 = hex::encode(self.device_tag);
        let first_seq = batch
            .items
            .first()
            .and_then(|i| {
                i.seq
                    .or_else(|| i.sequencer_receipt.as_ref().map(|r| r.seq))
            })
            .unwrap_or(0);
        let explicit_rkey = Some(format!("{first_seq:016x}-{dev8}-{}", self.next_tid()));
        let uris = self
            .apply(
                &space,
                &[WriteOp::Create {
                    collection: nsid::BATCH,
                    rkey: explicit_rkey,
                    value: encode(batch)?,
                }],
            )
            .await?;
        match uris.as_slice() {
            [Some(uri)] => uri_rkey(uri),
            _ => Err(Error::Backend(
                "space applyWrites returned no create result".into(),
            )),
        }
    }

    async fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<Stored<Batch>>> {
        let space = self.space_for(thread_id)?;
        let space_str = space.to_string();
        let host_kem = match self.read_auth(&space_str).await? {
            ReadAuth::Host(k) => Some(k),
            ReadAuth::Transport => None,
        };
        let repos = self.list_repos(&space).await?;
        let mut out = Vec::new();
        for did in repos {
            if sender.is_some_and(|s| s != did.as_str()) {
                continue;
            }
            let (mut batches, redactions) = if let Some(ref kem_key) = host_kem {
                let parsed = match Self::fetch_repo_star_authenticated_raw(
                    self.t.as_ref(),
                    &self.floors,
                    &space_str,
                    &did,
                    kem_key,
                )
                .await
                {
                    Ok(p) => p,
                    Err(Error::NotFound("repo" | "record"))
                        if self.floors.get(&space_str, &did).is_some() =>
                    {
                        return Err(Error::WriterWithheld {
                            space: space_str.clone(),
                            author: did,
                        });
                    }
                    Err(Error::NotFound("repo" | "record")) => continue,
                    Err(e) => return Err(e),
                };
                if parsed.records.len() > MAX_SPACE_LIST_ITEMS {
                    return Err(Error::Backend(format!(
                        "space listing exceeds {MAX_SPACE_LIST_ITEMS} records"
                    )));
                }
                let mut batches = Vec::new();
                let mut redactions = Vec::new();
                for entry in parsed.records {
                    let Some((collection, rkey)) = entry.path.split_once('/') else {
                        return Err(Error::Malformed("space record"));
                    };
                    if collection == nsid::BATCH {
                        let value: Batch = serde_ipld_dagcbor::from_slice(&entry.record_dagcbor)
                            .map_err(|_| Error::Malformed("space record"))?;
                        batches.push(Stored {
                            author: did.clone(),
                            rkey: rkey.to_owned(),
                            value,
                            order: None,
                        });
                    } else if collection == nsid::AUTHOR_REDACTION {
                        let record: AuthorRedaction =
                            serde_ipld_dagcbor::from_slice(&entry.record_dagcbor)
                                .map_err(|_| Error::Malformed("space record"))?;
                        redactions.push((rkey.to_owned(), record));
                    }
                }
                (batches, redactions)
            } else {
                let batches: Vec<Stored<Batch>> = self
                    .list_repo::<Batch>(&space, &did, nsid::BATCH)
                    .await?
                    .into_iter()
                    .map(|(rkey, value)| Stored {
                        author: did.clone(),
                        rkey,
                        value,
                        order: None,
                    })
                    .collect();
                let redactions = self.list_repo(&space, &did, nsid::AUTHOR_REDACTION).await?;
                (batches, redactions)
            };
            overlay_author_redactions(thread_id, &did, &mut batches, redactions)?;
            out.extend(batches.into_iter().filter(|batch| {
                batch.value.thread_id == thread_id
                    && batch
                        .value
                        .items
                        .iter()
                        .any(|item| range.contains(item.timestamp))
            }));
        }
        Ok(out)
    }

    async fn list_batches_quarantined(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<(Vec<Stored<Batch>>, Vec<crate::store::AuthorQuarantine>)> {
        use crate::store::{QuarantineReason, push_quarantine};
        let is_listing_overflow = |e: &Error| match e {
            Error::Backend(msg) => {
                msg.starts_with("space listing")
                    || msg.starts_with("space page")
                    || msg.starts_with("space cursor")
                    || msg.starts_with("space response exceeds")
            }
            _ => false,
        };
        let space = self.space_for(thread_id)?;
        let space_str = space.to_string();
        let host_kem = match self.read_auth(&space_str).await? {
            ReadAuth::Host(k) => Some(k),
            ReadAuth::Transport => None,
        };
        let repos = self.list_repos(&space).await?;
        let mut out = Vec::new();
        let mut quarantined = Vec::new();
        for did in repos {
            if sender.is_some_and(|s| s != did.as_str()) {
                continue;
            }
            if let Some(ref kem_key) = host_kem {
                let parsed = match Self::fetch_repo_star_authenticated_raw(
                    self.t.as_ref(),
                    &self.floors,
                    &space_str,
                    &did,
                    kem_key,
                )
                .await
                {
                    Ok(p) => p,
                    Err(Error::NotFound("repo" | "record"))
                        if self.floors.get(&space_str, &did).is_some() =>
                    {
                        push_quarantine(
                            &mut quarantined,
                            did,
                            QuarantineReason::WithheldRepository,
                            "authenticated writer repository is no longer served".to_owned(),
                        );
                        continue;
                    }
                    Err(Error::NotFound("repo" | "record")) => continue,
                    Err(e) => return Err(e),
                };
                if parsed.records.len() > MAX_SPACE_LIST_ITEMS {
                    push_quarantine(
                        &mut quarantined,
                        did,
                        QuarantineReason::RepositoryOverflow,
                        format!("space listing exceeds {MAX_SPACE_LIST_ITEMS} records"),
                    );
                    continue;
                }
                let mut batches = Vec::new();
                let mut raw_redactions = Vec::new();
                for entry in parsed.records {
                    let Some((collection, rkey)) = entry.path.split_once('/') else {
                        push_quarantine(
                            &mut quarantined,
                            did.clone(),
                            QuarantineReason::MalformedRecord,
                            format!("invalid STAR record path {}", entry.path),
                        );
                        continue;
                    };
                    if collection == nsid::BATCH {
                        match serde_ipld_dagcbor::from_slice::<Batch>(&entry.record_dagcbor) {
                            Ok(value) => batches.push(Stored {
                                author: did.clone(),
                                rkey: rkey.to_owned(),
                                value,
                                order: None,
                            }),
                            Err(e) => push_quarantine(
                                &mut quarantined,
                                did.clone(),
                                QuarantineReason::MalformedRecord,
                                format!("batch {rkey}: {e}"),
                            ),
                        }
                    } else if collection == nsid::AUTHOR_REDACTION {
                        raw_redactions.push((rkey.to_owned(), entry.record_dagcbor));
                    }
                }
                for (rkey, raw_cbor) in raw_redactions {
                    match serde_ipld_dagcbor::from_slice::<AuthorRedaction>(&raw_cbor) {
                        Ok(record) => {
                            if let Err(e) = overlay_author_redactions(
                                thread_id,
                                &did,
                                &mut batches,
                                vec![(rkey.clone(), record)],
                            ) {
                                push_quarantine(
                                    &mut quarantined,
                                    did.clone(),
                                    QuarantineReason::InvalidRedaction,
                                    format!("authorRedaction {rkey}: {e}"),
                                );
                            }
                        }
                        Err(e) => push_quarantine(
                            &mut quarantined,
                            did.clone(),
                            QuarantineReason::MalformedRecord,
                            format!("authorRedaction {rkey}: {e}"),
                        ),
                    }
                }
                out.extend(batches.into_iter().filter(|batch| {
                    batch.value.thread_id == thread_id
                        && batch
                            .value
                            .items
                            .iter()
                            .any(|item| range.contains(item.timestamp))
                }));
                continue;
            }
            let raw_batches = match self.list_repo_raw(&space, &did, nsid::BATCH, true).await {
                Ok(v) => v,
                Err(e) if is_listing_overflow(&e) => {
                    push_quarantine(
                        &mut quarantined,
                        did,
                        QuarantineReason::RepositoryOverflow,
                        e.to_string(),
                    );
                    continue;
                }
                Err(e) => return Err(e),
            };
            let mut batches = Vec::with_capacity(raw_batches.len());
            for (rkey, raw) in raw_batches {
                match decode::<Batch>(raw) {
                    Ok(value) => batches.push(Stored {
                        author: did.clone(),
                        rkey,
                        value,
                        order: None,
                    }),
                    Err(e) => push_quarantine(
                        &mut quarantined,
                        did.clone(),
                        QuarantineReason::MalformedRecord,
                        format!("batch {rkey}: {e}"),
                    ),
                }
            }
            match self
                .list_repo_raw(&space, &did, nsid::AUTHOR_REDACTION, true)
                .await
            {
                Ok(raw_redactions) => {
                    for (rkey, raw) in raw_redactions {
                        match decode::<AuthorRedaction>(raw) {
                            Ok(record) => {
                                if let Err(e) = overlay_author_redactions(
                                    thread_id,
                                    &did,
                                    &mut batches,
                                    vec![(rkey.clone(), record)],
                                ) {
                                    push_quarantine(
                                        &mut quarantined,
                                        did.clone(),
                                        QuarantineReason::InvalidRedaction,
                                        format!("authorRedaction {rkey}: {e}"),
                                    );
                                }
                            }
                            Err(e) => push_quarantine(
                                &mut quarantined,
                                did.clone(),
                                QuarantineReason::MalformedRecord,
                                format!("authorRedaction {rkey}: {e}"),
                            ),
                        }
                    }
                }
                Err(e) if is_listing_overflow(&e) => {
                    push_quarantine(
                        &mut quarantined,
                        did.clone(),
                        QuarantineReason::RepositoryOverflow,
                        e.to_string(),
                    );
                }
                Err(e) => return Err(e),
            }
            out.extend(batches.into_iter().filter(|batch| {
                batch.value.thread_id == thread_id
                    && batch
                        .value
                        .items
                        .iter()
                        .any(|item| range.contains(item.timestamp))
            }));
        }
        Ok((out, quarantined))
    }

    async fn list_threads(&self) -> Result<Vec<String>> {
        let mut ids: Vec<String> = self.spaces.lock().unwrap().keys().cloned().collect();
        ids.sort();
        Ok(ids)
    }

    async fn redact_item(
        &self,
        thread_id: &str,
        message_id: &str,
        redaction: &Redaction,
    ) -> Result<usize> {
        redaction.verify(&self.did, thread_id, message_id)?;
        let space = self.space_for(thread_id)?;
        let mut stamped = redaction.clone();
        if stamped.redacted_at.is_none() {
            stamped.redacted_at = Some(datetime_from_ms((self.now_ms)()));
        }
        let record = AuthorRedaction::new(
            thread_id,
            message_id,
            &stamped,
            stamped
                .redacted_at
                .clone()
                .ok_or(Error::Malformed("redaction timestamp"))?,
        );
        let rkey = record.rkey();
        let batches = self
            .list_repo::<Batch>(&space, &self.did, nsid::BATCH)
            .await?;
        let count = batches
            .iter()
            .flat_map(|(_, batch)| &batch.items)
            .filter(|item| item.message_id == message_id)
            .count();

        if let Some(existing) = self
            .get_checked::<AuthorRedaction>(&space, &self.did, nsid::AUTHOR_REDACTION, &rkey)
            .await?
        {
            existing
                .to_redaction()?
                .verify(&self.did, thread_id, message_id)?;
            if existing.thread_id != thread_id
                || existing.message_id != message_id
                || existing.rkey() != rkey
            {
                return Err(Error::Conflict);
            }
            return Ok(count);
        }

        match self
            .apply(
                &space,
                &[WriteOp::Create {
                    collection: nsid::AUTHOR_REDACTION,
                    rkey: Some(rkey.clone()),
                    value: encode(&record)?,
                }],
            )
            .await
        {
            Ok(_) => Ok(count),
            Err(Error::Conflict) => {
                let existing = self
                    .get_checked::<AuthorRedaction>(
                        &space,
                        &self.did,
                        nsid::AUTHOR_REDACTION,
                        &rkey,
                    )
                    .await?
                    .ok_or(Error::Conflict)?;
                existing
                    .to_redaction()?
                    .verify(&self.did, thread_id, message_id)?;
                if existing.thread_id == thread_id
                    && existing.message_id == message_id
                    && existing.rkey() == rkey
                {
                    Ok(count)
                } else {
                    Err(Error::Conflict)
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn upload_and_commit_attachment(
        &self,
        thread_id: &str,
        ciphertext: &[u8],
        meta: &AttachmentCiphertextMeta,
        created_at: &str,
    ) -> Result<String> {
        verify_attachment_ciphertext(ciphertext, meta)?;
        let space = self.space_for(thread_id)?;
        let mime = meta
            .mime_type_hint
            .as_deref()
            .unwrap_or("application/octet-stream");
        let cid = self
            .t
            .upload_blob(ciphertext, mime)
            .await
            .map_err(map_space_error)?;
        let manifest = AttachmentManifest::from_meta(&cid, meta, created_at.to_owned());
        let uris = self
            .apply(
                &space,
                &[WriteOp::Create {
                    collection: nsid::ATTACHMENT_MANIFEST,
                    rkey: None,
                    value: encode(&manifest)?,
                }],
            )
            .await?;
        match uris.as_slice() {
            [Some(uri)] => uri_rkey(uri),
            _ => Err(Error::Backend(
                "space applyWrites returned no create result".into(),
            )),
        }
    }

    async fn get_attachment_manifest(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> Result<Option<AttachmentManifest>> {
        let space = self.space_for(thread_id)?;
        self.get_checked(&space, author_did, nsid::ATTACHMENT_MANIFEST, rkey)
            .await
    }

    async fn get_attachment_verified(
        &self,
        thread_id: &str,
        author_did: &str,
        rkey: &str,
    ) -> Result<Vec<u8>> {
        let space = self.space_for(thread_id)?;
        let manifest: AttachmentManifest = self
            .get_checked(&space, author_did, nsid::ATTACHMENT_MANIFEST, rkey)
            .await?
            .ok_or(Error::NotFound("attachmentManifest"))?;
        let (cid, meta) = manifest.to_meta()?;
        let bytes = self
            .t
            .get_blob(&space.to_string(), author_did, &cid)
            .await
            .map_err(map_member_repo_space_error)?;
        verify_attachment_ciphertext(&bytes, &meta)?;
        Ok(bytes)
    }

    async fn list_own_attachment_manifests(
        &self,
        thread_id: &str,
    ) -> Result<Vec<(String, AttachmentManifest)>> {
        let space = self.space_for(thread_id)?;
        self.list_repo(&space, &self.did, nsid::ATTACHMENT_MANIFEST)
            .await
    }

    /// Account cleanup: deletes this account's ciphertext and key material.
    /// Immutable `authorRedaction` records survive. Leaving a conversation
    /// never calls this: remaining members may hold no other copy.
    async fn clear_records(&self, thread_id: &str) -> Result<()> {
        let space = self.space_for(thread_id)?;
        for collection in THREAD_COLLECTIONS {
            let rkeys: Vec<String> = self
                .list_repo_raw(&space, &self.did, collection, false)
                .await?
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            for chunk in rkeys.chunks(MAX_WRITES) {
                let writes: Vec<WriteOp> = chunk
                    .iter()
                    .map(|rkey| WriteOp::Delete {
                        collection,
                        rkey: rkey.clone(),
                    })
                    .collect();
                self.apply(&space, &writes).await?;
            }
        }
        Ok(())
    }

    fn seed_writer_rev_floors(&self, floors: &BTreeMap<(String, String), String>) {
        self.floors.seed(floors);
    }

    fn replace_writer_rev_floors(&self, floors: &BTreeMap<(String, String), String>) {
        self.floors.replace(floors);
    }

    fn export_writer_rev_floors(&self) -> BTreeMap<(String, String), String> {
        self.floors.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;

    use super::*;
    use crate::store::space::SpaceError;

    struct GrantedRelay(u16);

    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    impl SpaceRpc for GrantedRelay {
        async fn query(
            &self,
            nsid: &str,
            _: &[(&str, String)],
        ) -> core::result::Result<Vec<u8>, SpaceError> {
            assert_eq!(nsid, endpoint::LIST_REPOS);
            Err(SpaceError::named(
                self.0,
                "SpaceNotFound",
                "unsigned refusal after credential grant",
            ))
        }

        async fn procedure(
            &self,
            nsid: &str,
            _: &[u8],
        ) -> core::result::Result<Vec<u8>, SpaceError> {
            assert_eq!(nsid, endpoint::APPLY_WRITES);
            Err(SpaceError::named(
                self.0,
                "SpaceNotFound",
                "unsigned refusal after credential grant",
            ))
        }
    }

    #[test]
    fn unsigned_space_not_found_is_not_member_repo_denial_at_read_or_write_boundary() {
        let space = SpaceRef::conversation("did:web:ds.example", "thread");
        for status in [400, 404] {
            let rpc: Arc<dyn SpaceRpc> = Arc::new(GrantedRelay(status));
            let store = SpaceThreadStore::new(rpc, "did:plc:alice");
            assert_eq!(
                block_on(store.list_repos(&space)).unwrap_err(),
                Error::NotFound("space")
            );
            assert_eq!(
                block_on(store.apply(
                    &space,
                    &[WriteOp::Delete {
                        collection: nsid::BATCH,
                        rkey: "pending".into(),
                    }],
                ))
                .unwrap_err(),
                Error::NotFound("space")
            );
        }
    }
}

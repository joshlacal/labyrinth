//! Memory-backed reference PDS / Space host for `com.atproto.space.*` and
//! Space-scoped encrypted attachment blobs (`atproto#5187`, Gates 1, 3, and 5).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{CONVERSATION_SPACE_TYPE, MAX_WRITES, SpaceError, SpaceRef, SpaceRpc, endpoint};
use crate::{Error, Result};

/// Largest JSON request body (reference `jsonLimit`).
pub const JSON_LIMIT: usize = 1_000_000;

type Reply = core::result::Result<Vec<u8>, SpaceError>;

/// Records of one repo in one Space, by record URI.
type Repo = BTreeMap<String, (String, String, Value)>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum BlobVisibility {
    Staged,
    SpaceScoped(BTreeSet<String>),
}

#[derive(Clone, Debug)]
struct StoredBlob {
    bytes: Vec<u8>,
    visibility: BlobVisibility,
}

#[derive(Default)]
struct State {
    /// `(space ref, author DID)` → records.
    repos: BTreeMap<(String, String), Repo>,
    /// Explicit member allowlists configured via [`MemorySpaceHost::grant_space_member`].
    members: HashMap<String, BTreeSet<String>>,
    /// Explicit revocations configured via [`MemorySpaceHost::revoke_space_member`].
    revoked_members: BTreeSet<(String, String)>,
    /// `(author DID, cid)` → blob + visibility.
    blobs: HashMap<(String, String), StoredBlob>,
    tid: u64,
}

impl State {
    fn next_tid(&mut self) -> String {
        const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
        self.tid += 1;
        let v = (1u64 << 62) | self.tid;
        (0..13)
            .rev()
            .map(|i| S32[((v >> (5 * i)) & 31) as usize] as char)
            .collect()
    }
}

/// Collects every `{"$type": "blob", "ref": {"$link": cid}}` CID referenced in `v`.
fn collect_blob_cids(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            if map.get("$type").and_then(Value::as_str) == Some("blob")
                && let Some(cid) = map
                    .get("ref")
                    .and_then(Value::as_object)
                    .and_then(|r| r.get("$link"))
                    .and_then(Value::as_str)
            {
                out.push(cid.to_owned());
            }
            for child in map.values() {
                collect_blob_cids(child, out);
            }
        }
        Value::Array(arr) => {
            for child in arr {
                collect_blob_cids(child, out);
            }
        }
        _ => {}
    }
}

/// The reference Space host. Cheap to clone; [`MemorySpaceHost::client`] gives
/// a transport authenticated as one account.
#[derive(Clone, Default)]
pub struct MemorySpaceHost {
    s: Arc<Mutex<State>>,
}

impl MemorySpaceHost {
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport whose session is `did`.
    pub fn client(&self, did: &str) -> SpaceClient {
        SpaceClient {
            host: self.clone(),
            did: did.to_owned(),
        }
    }

    /// Grants `did` membership read access on `space`.
    pub fn grant_space_member(&self, space: &SpaceRef, did: &str) {
        let mut s = self.s.lock().unwrap();
        let key = space.to_string();
        s.revoked_members.remove(&(key.clone(), did.to_owned()));
        s.members.entry(key).or_default().insert(did.to_owned());
    }

    /// Revokes `did`'s membership read/write access on `space`.
    pub fn revoke_space_member(&self, space: &SpaceRef, did: &str) {
        let mut s = self.s.lock().unwrap();
        let key = space.to_string();
        if let Some(m) = s.members.get_mut(&key) {
            m.remove(did);
        }
        s.revoked_members.insert((key, did.to_owned()));
    }

    /// Public unauthenticated `com.atproto.sync.getBlob` probe (`Gate 5`).
    /// Staged and Space-scoped blobs MUST NOT be served here (404).
    pub fn public_sync_get_blob(&self, did: &str, cid: &str) -> Result<Vec<u8>> {
        let _ = (did, cid);
        Err(Error::NotFound("blob"))
    }

    /// Fault-injection helper corrupting stored blob bytes in-place (`Gate 5`).
    pub fn tamper_blob(&self, did: &str, cid: &str, new_bytes: &[u8]) {
        let mut s = self.s.lock().unwrap();
        if let Some(blob) = s.blobs.get_mut(&(did.to_owned(), cid.to_owned())) {
            blob.bytes = new_bytes.to_vec();
        }
    }

    /// Records `did` holds in `space`, optionally of one collection.
    pub fn record_count(&self, space: &SpaceRef, did: &str, collection: Option<&str>) -> usize {
        let s = self.s.lock().unwrap();
        s.repos
            .get(&(space.to_string(), did.to_owned()))
            .map(|r| {
                r.values()
                    .filter(|(c, ..)| collection.is_none_or(|x| x == c))
                    .count()
            })
            .unwrap_or(0)
    }

    /// The raw JSON value of one record, for tamper/inspection tests.
    pub fn record(
        &self,
        space: &SpaceRef,
        did: &str,
        collection: &str,
        rkey: &str,
    ) -> Option<Value> {
        let s = self.s.lock().unwrap();
        s.repos
            .get(&(space.to_string(), did.to_owned()))
            .and_then(|r| r.get(&record_uri(&space.to_string(), did, collection, rkey)))
            .map(|(.., v)| v.clone())
    }

    /// Deletes one record, bypassing every check.
    pub fn remove(
        &self,
        space: &SpaceRef,
        did: &str,
        collection: &str,
        rkey: &str,
    ) -> Option<Value> {
        let mut s = self.s.lock().unwrap();
        let uri = record_uri(&space.to_string(), did, collection, rkey);
        s.repos
            .get_mut(&(space.to_string(), did.to_owned()))
            .and_then(|r| r.remove(&uri))
            .map(|(.., v)| v)
    }

    /// Overwrites one record's value, bypassing every check.
    pub fn tamper(&self, space: &SpaceRef, did: &str, collection: &str, rkey: &str, value: Value) {
        let mut s = self.s.lock().unwrap();
        let uri = record_uri(&space.to_string(), did, collection, rkey);
        s.repos
            .entry((space.to_string(), did.to_owned()))
            .or_default()
            .insert(uri, (collection.to_owned(), rkey.to_owned(), value));
    }
}

fn record_uri(space: &str, did: &str, collection: &str, rkey: &str) -> String {
    format!("{space}/{did}/{collection}/{rkey}")
}

fn cid(v: &Value) -> String {
    if v["$type"] == crate::records::nsid::BATCH
        && let Ok(batch) = serde_json::from_value::<crate::records::Batch>(v.clone())
        && let Ok(cid) = super::thread::batch_cid(&batch)
    {
        return cid;
    }
    format!(
        "bafyrei{}",
        &hex::encode(Sha256::digest(v.to_string().as_bytes()))[..40]
    )
}

fn err(status: u16, name: &str, msg: impl Into<String>) -> SpaceError {
    SpaceError::named(status, name, msg)
}

fn ok(v: Value) -> Reply {
    Ok(serde_json::to_vec(&v).expect("json"))
}

fn param<'a>(p: &'a [(&str, String)], k: &str) -> Option<&'a str> {
    p.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str())
}

fn required<'a>(p: &'a [(&str, String)], k: &str) -> core::result::Result<&'a str, SpaceError> {
    param(p, k).ok_or_else(|| err(400, "InvalidRequest", format!("missing {k}")))
}

#[derive(Deserialize)]
struct ApplyWritesIn {
    space: String,
    repo: String,
    #[serde(default)]
    writes: Vec<Value>,
}

#[derive(Deserialize)]
struct DeleteRecordIn {
    space: String,
    repo: String,
    collection: String,
    rkey: String,
}

/// One account's authenticated view of a [`MemorySpaceHost`].
#[derive(Clone)]
pub struct SpaceClient {
    host: MemorySpaceHost,
    did: String,
}

impl From<SpaceClient> for Arc<dyn SpaceRpc> {
    fn from(c: SpaceClient) -> Self {
        Arc::new(c)
    }
}

impl SpaceClient {
    fn check_space_access(
        &self,
        s: &State,
        space: &str,
        repo: Option<&str>,
    ) -> core::result::Result<(), SpaceError> {
        if s.revoked_members
            .contains(&(space.to_owned(), self.did.clone()))
        {
            return Err(err(403, "Forbidden", "member revoked from Space"));
        }
        let parsed = SpaceRef::parse(space).ok();
        let is_convo = parsed
            .as_ref()
            .is_some_and(|sr| sr.space_type == CONVERSATION_SPACE_TYPE);
        if is_convo {
            if let Some(allowed) = s.members.get(space)
                && !allowed.contains(&self.did)
            {
                return Err(err(403, "Forbidden", "caller is not a Space member"));
            }
            Ok(())
        } else {
            // Personal mailbox Space (`read_self` only).
            if let Some(r) = repo
                && r != self.did
            {
                return Err(err(400, "RepoNotFound", r));
            }
            Ok(())
        }
    }

    fn list_spaces(&self, p: &[(&str, String)]) -> Reply {
        let state = self.host.s.lock().unwrap();
        let cursor = param(p, "cursor");
        let limit: usize = param(p, "limit")
            .unwrap_or("50")
            .parse()
            .ok()
            .filter(|n| (1..=100).contains(n))
            .ok_or_else(|| err(400, "InvalidRequest", "limit"))?;
        let matching: Vec<_> = state
            .repos
            .keys()
            .filter(|(uri, did)| {
                did == &self.did
                    && cursor.is_none_or(|c| uri.as_str() > c)
                    && SpaceRef::parse(uri)
                        .is_ok_and(|s| param(p, "spaceType").is_none_or(|t| s.space_type == t))
            })
            .map(|(uri, _)| uri.clone())
            .take(limit)
            .collect();
        let cursor = (matching.len() == limit)
            .then(|| matching.last().cloned())
            .flatten();
        ok(
            json!({"spaces": matching.iter().map(|uri| json!({"uri": uri})).collect::<Vec<_>>(), "cursor": cursor}),
        )
    }

    fn list_repos(&self, p: &[(&str, String)]) -> Reply {
        let space = required(p, "space")?;
        let s = self.host.s.lock().unwrap();
        self.check_space_access(&s, space, None)?;
        let repos: Vec<Value> = s
            .repos
            .iter()
            .filter(|((sp, _), r)| sp == space && !r.is_empty())
            .map(|((_, did), _)| json!({ "did": did }))
            .collect();
        ok(json!({ "repos": repos }))
    }

    fn read_repo(
        &self,
        s: &State,
        space: &str,
        repo: &str,
    ) -> core::result::Result<Repo, SpaceError> {
        self.check_space_access(s, space, Some(repo))?;
        Ok(s.repos
            .get(&(space.to_owned(), repo.to_owned()))
            .cloned()
            .unwrap_or_default())
    }

    fn get_record(&self, p: &[(&str, String)]) -> Reply {
        let (space, repo) = (required(p, "space")?, required(p, "repo")?);
        let (collection, rkey) = (required(p, "collection")?, required(p, "rkey")?);
        let s = self.host.s.lock().unwrap();
        let r = self.read_repo(&s, space, repo)?;
        let uri = record_uri(space, repo, collection, rkey);
        let (.., v) = r
            .get(&uri)
            .ok_or_else(|| err(400, "RecordNotFound", &uri))?;
        ok(json!({ "uri": uri, "cid": cid(v), "value": v }))
    }

    fn list_records(&self, p: &[(&str, String)]) -> Reply {
        let (space, repo) = (required(p, "space")?, required(p, "repo")?);
        let limit: usize = match param(p, "limit") {
            None => 50,
            Some(l) => l
                .parse()
                .ok()
                .filter(|l| (1..=100).contains(l))
                .ok_or_else(|| err(400, "InvalidRequest", "limit"))?,
        };
        let reverse = param(p, "reverse") == Some("true");
        let exclude = param(p, "excludeValues") == Some("true");
        let collection = param(p, "collection");
        let cursor = param(p, "cursor");
        let s = self.host.s.lock().unwrap();
        let r = self.read_repo(&s, space, repo)?;
        let matching = r
            .iter()
            .filter(|(_, (c, ..))| collection.is_none_or(|x| x == c));
        let page: Vec<(&String, &(String, String, Value))> = if reverse {
            matching
                .filter(|(u, _)| cursor.is_none_or(|c| u.as_str() > c))
                .take(limit)
                .collect()
        } else {
            matching
                .rev()
                .filter(|(u, _)| cursor.is_none_or(|c| u.as_str() < c))
                .take(limit)
                .collect()
        };
        let next = (page.len() == limit).then(|| page.last().map(|(u, _)| (*u).clone()));
        let records: Vec<Value> = page
            .iter()
            .map(|(_, (c, k, v))| {
                let mut o = json!({ "collection": c, "rkey": k, "cid": cid(v) });
                if !exclude {
                    o["value"] = v.clone();
                }
                o
            })
            .collect();
        let mut out = json!({ "records": records });
        if let Some(Some(c)) = next {
            out["cursor"] = Value::from(c);
        }
        ok(out)
    }

    fn apply_writes(&self, payload: &[u8]) -> Reply {
        let input: ApplyWritesIn = serde_json::from_slice(payload)
            .map_err(|e| err(400, "InvalidRequest", e.to_string()))?;
        if input.repo != self.did {
            return Err(err(403, "Forbidden", "repo must match authenticated user"));
        }
        if input.writes.len() > MAX_WRITES {
            return Err(err(
                400,
                "InvalidRequest",
                format!("Too many writes. Max: {MAX_WRITES}"),
            ));
        }
        let mut s = self.host.s.lock().unwrap();
        self.check_space_access(&s, &input.space, Some(&self.did))?;
        let key = (input.space.clone(), self.did.clone());
        let mut repo = s.repos.get(&key).cloned().unwrap_or_default();
        let mut results = Vec::new();
        let mut promoted_cids = Vec::new();
        for w in &input.writes {
            let kind = w["$type"].as_str().unwrap_or("");
            let collection = w["collection"]
                .as_str()
                .ok_or_else(|| err(400, "InvalidRequest", "collection"))?
                .to_owned();
            let rkey = match w["rkey"].as_str() {
                Some(k) => k.to_owned(),
                None if kind.ends_with("#create") => s.next_tid(),
                None => return Err(err(400, "InvalidRequest", "rkey")),
            };
            let uri = record_uri(&input.space, &self.did, &collection, &rkey);
            match kind {
                "com.atproto.space.applyWrites#create" => {
                    if repo.contains_key(&uri) {
                        return Err(err(400, "RecordAlreadyExists", &uri));
                    }
                    let v = w["value"].clone();
                    collect_blob_cids(&v, &mut promoted_cids);
                    results.push(json!({
                        "$type": "com.atproto.space.applyWrites#createResult",
                        "uri": uri, "cid": cid(&v),
                    }));
                    repo.insert(uri, (collection, rkey, v));
                }
                "com.atproto.space.applyWrites#update" => {
                    let Some((_, _, existing)) = repo.get(&uri) else {
                        return Err(err(400, "RecordNotFound", &uri));
                    };
                    if let Some(expected_cid) = w["swapRecord"].as_str()
                        && cid(existing) != expected_cid
                    {
                        return Err(err(400, "InvalidSwap", &uri));
                    }
                    let v = w["value"].clone();
                    collect_blob_cids(&v, &mut promoted_cids);
                    results.push(json!({
                        "$type": "com.atproto.space.applyWrites#updateResult",
                        "uri": uri, "cid": cid(&v),
                    }));
                    repo.insert(uri, (collection, rkey, v));
                }
                "com.atproto.space.applyWrites#delete" => {
                    let Some((_, _, existing)) = repo.get(&uri) else {
                        return Err(err(400, "RecordNotFound", &uri));
                    };
                    if let Some(expected_cid) = w["swapRecord"].as_str()
                        && cid(existing) != expected_cid
                    {
                        return Err(err(400, "InvalidSwap", &uri));
                    }
                    repo.remove(&uri);
                    results.push(json!({
                        "$type": "com.atproto.space.applyWrites#deleteResult",
                    }));
                }
                other => {
                    return Err(err(
                        400,
                        "InvalidRequest",
                        format!("Action not supported: {other}"),
                    ));
                }
            }
        }
        // Promote any staged blobs referenced in the committed batch to `.space`!
        for blob_cid in promoted_cids {
            if let Some(blob) = s.blobs.get_mut(&(self.did.clone(), blob_cid)) {
                match &mut blob.visibility {
                    BlobVisibility::Staged => {
                        let mut set = BTreeSet::new();
                        set.insert(input.space.clone());
                        blob.visibility = BlobVisibility::SpaceScoped(set);
                    }
                    BlobVisibility::SpaceScoped(spaces) => {
                        spaces.insert(input.space.clone());
                    }
                }
            }
        }
        if !input.writes.is_empty() {
            s.repos.insert(key, repo);
        }
        ok(json!({ "results": results }))
    }

    fn delete_record(&self, payload: &[u8]) -> Reply {
        let input: DeleteRecordIn = serde_json::from_slice(payload)
            .map_err(|e| err(400, "InvalidRequest", e.to_string()))?;
        if input.repo != self.did {
            return Err(err(403, "Forbidden", "repo must match authenticated user"));
        }
        let mut s = self.host.s.lock().unwrap();
        let uri = record_uri(&input.space, &self.did, &input.collection, &input.rkey);
        if let Some(r) = s.repos.get_mut(&(input.space.clone(), self.did.clone())) {
            r.remove(&uri);
        }
        ok(json!({}))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SpaceRpc for SpaceClient {
    async fn query(&self, nsid: &str, params: &[(&str, String)]) -> Reply {
        match nsid {
            endpoint::GET_RECORD => self.get_record(params),
            endpoint::LIST_RECORDS => self.list_records(params),
            endpoint::LIST_REPOS => self.list_repos(params),
            endpoint::LIST_SPACES => self.list_spaces(params),
            _ => Err(err(404, "MethodNotImplemented", nsid)),
        }
    }

    async fn procedure(&self, nsid: &str, payload: &[u8]) -> Reply {
        if payload.len() > JSON_LIMIT {
            return Err(err(413, "PayloadTooLarge", "request entity too large"));
        }
        match nsid {
            endpoint::APPLY_WRITES => self.apply_writes(payload),
            endpoint::DELETE_RECORD => self.delete_record(payload),
            _ => Err(err(404, "MethodNotImplemented", nsid)),
        }
    }

    async fn upload_blob(
        &self,
        bytes: &[u8],
        _mime_type: &str,
    ) -> core::result::Result<String, SpaceError> {
        let mut s = self.host.s.lock().unwrap();
        let n = s.next_tid();
        let mut h = Sha256::new();
        h.update(bytes);
        h.update(n.as_bytes());
        let cid = format!("bafkrei{}", hex::encode(&h.finalize()[..20]));
        s.blobs.insert(
            (self.did.clone(), cid.clone()),
            StoredBlob {
                bytes: bytes.to_vec(),
                visibility: BlobVisibility::Staged,
            },
        );
        Ok(cid)
    }

    async fn get_blob(
        &self,
        space: &str,
        did: &str,
        cid: &str,
    ) -> core::result::Result<Vec<u8>, SpaceError> {
        let s = self.host.s.lock().unwrap();
        self.check_space_access(&s, space, Some(did))?;
        let blob = s
            .blobs
            .get(&(did.to_owned(), cid.to_owned()))
            .ok_or_else(|| err(404, "BlobNotFound", cid))?;
        match &blob.visibility {
            BlobVisibility::SpaceScoped(spaces) if spaces.contains(space) => Ok(blob.bytes.clone()),
            _ => Err(err(404, "BlobNotFound", cid)),
        }
    }
}

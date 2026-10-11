//! A memory-backed reference PDS for the `com.atproto.space` record
//! endpoints the Space store calls, for tests and as an executable
//! statement of the semantics it relies on (reference implementation
//! `packages/pds/src/api/com/atproto/space/*` and
//! `actor-store/space/{reader,transactor}.ts`, branch `permissioned-data`
//! at `5b95b2f2`, 2026-10-01).
//!
//! What it enforces:
//!
//! - writes only into the caller's own repo (`repo == auth.did`, else 403);
//! - `applyWrites`: at most [`super::MAX_WRITES`] ops, all-or-nothing;
//!   `#create` on an existing rkey is `RecordAlreadyExists`, `#update` or
//!   `#delete` of a missing one `RecordNotFound`; `#create` without an
//!   rkey gets a TID; JSON bodies over 1,000,000 bytes are refused (413);
//! - `deleteRecord` succeeds whether or not the record exists;
//! - reads are `read_self` only: another account's repo answers
//!   `RepoNotFound`; the caller's own repo with no writes lists as empty;
//! - no Space has to be created first: a member's PDS accepts writes to a
//!   Space no authority governs, and reads them back (checked against the
//!   live dev PDS, `tests/live_space_pds.rs`);
//! - `listRecords` orders by record URI, descending unless `reverse`,
//!   with the last URI as the cursor only when the page is full.
//!
//! It does not model space credentials, notifyWrite, rate limits, record
//! CIDs (a digest stands in) or lexicon validation.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{MAX_WRITES, SpaceRef, endpoint};
use crate::store::xrpc::{XrpcError, XrpcTransport};

/// Largest JSON request body (reference `jsonLimit`).
pub const JSON_LIMIT: usize = 1_000_000;

type Reply = core::result::Result<Vec<u8>, XrpcError>;

/// Records of one repo in one Space, by record URI.
type Repo = BTreeMap<String, (String, String, Value)>;

#[derive(Default)]
struct State {
    /// `(space ref, author DID)` → records.
    repos: BTreeMap<(String, String), Repo>,
    tid: u64,
}

impl State {
    fn next_tid(&mut self) -> String {
        const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
        self.tid += 1;
        // A fixed high timestamp keeps the leading character in TID range.
        let v = (1u64 << 62) | self.tid;
        (0..13)
            .rev()
            .map(|i| S32[((v >> (5 * i)) & 31) as usize] as char)
            .collect()
    }
}

/// The reference host. Cheap to clone; [`MemorySpaceHost::client`] gives a
/// transport authenticated as one account.
#[derive(Clone, Default)]
pub struct MemorySpaceHost {
    s: Arc<Mutex<State>>,
}

impl MemorySpaceHost {
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport whose OAuth session is `did`.
    pub fn client(&self, did: &str) -> SpaceClient {
        SpaceClient {
            host: self.clone(),
            did: did.to_owned(),
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

    /// The raw JSON value of one record, for tamper tests.
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

    /// Deletes one record, bypassing every check (a PDS hiding data).
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

    /// Overwrites one record's value, bypassing every check (a malicious
    /// PDS).
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
    format!(
        "bafyrei{}",
        &hex::encode(Sha256::digest(v.to_string().as_bytes()))[..40]
    )
}

fn err(status: u16, name: &str, msg: impl Into<String>) -> XrpcError {
    XrpcError::named(status, name, msg)
}

fn ok(v: Value) -> Reply {
    Ok(serde_json::to_vec(&v).expect("json"))
}

fn param<'a>(p: &'a [(&str, String)], k: &str) -> Option<&'a str> {
    p.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str())
}

fn required<'a>(p: &'a [(&str, String)], k: &str) -> core::result::Result<&'a str, XrpcError> {
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

impl SpaceClient {
    fn read_repo(
        &self,
        s: &State,
        space: &str,
        repo: &str,
    ) -> core::result::Result<Repo, XrpcError> {
        // read_self only: no space credentials are modeled.
        if repo != self.did {
            return Err(err(400, "RepoNotFound", repo));
        }
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
                .filter(|l| (1..=1000).contains(l))
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
        let key = (input.space.clone(), self.did.clone());
        let mut repo = s.repos.get(&key).cloned().unwrap_or_default();
        let mut results = Vec::new();
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
                    results.push(json!({
                        "$type": "com.atproto.space.applyWrites#createResult",
                        "uri": uri, "cid": cid(&v),
                    }));
                    repo.insert(uri, (collection, rkey, v));
                }
                "com.atproto.space.applyWrites#update" => {
                    if !repo.contains_key(&uri) {
                        return Err(err(400, "RecordNotFound", &uri));
                    }
                    let v = w["value"].clone();
                    results.push(json!({
                        "$type": "com.atproto.space.applyWrites#updateResult",
                        "uri": uri, "cid": cid(&v),
                    }));
                    repo.insert(uri, (collection, rkey, v));
                }
                "com.atproto.space.applyWrites#delete" => {
                    if repo.remove(&uri).is_none() {
                        return Err(err(400, "RecordNotFound", &uri));
                    }
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

impl XrpcTransport for SpaceClient {
    fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        _headers: &[(String, String)],
    ) -> Reply {
        match nsid {
            endpoint::GET_RECORD => self.get_record(params),
            endpoint::LIST_RECORDS => self.list_records(params),
            _ => Err(err(404, "MethodNotImplemented", nsid)),
        }
    }

    fn procedure(&self, nsid: &str, payload: &[u8], _operation_id: [u8; 16]) -> Reply {
        if payload.len() > JSON_LIMIT {
            return Err(err(413, "PayloadTooLarge", "request entity too large"));
        }
        match nsid {
            endpoint::APPLY_WRITES => self.apply_writes(payload),
            endpoint::DELETE_RECORD => self.delete_record(payload),
            _ => Err(err(404, "MethodNotImplemented", nsid)),
        }
    }
}

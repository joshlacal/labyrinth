//! Memory-backed reference PDS / Space host for `com.atproto.space.*`,
//! `com.atproto.memberspace.*`, RFC 9421 + HPKE `0xFFFF` Export MACs, `STAR`
//! v0.2 repository archives, and Space-scoped encrypted attachment blobs
//! (`atproto#5187` November 12 alpha, Gates 1, 3, and 5).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    CONVERSATION_SPACE_TYPE, MAX_WRITES, MemberAccess, SpaceError, SpaceRef, SpaceRpc, endpoint,
};
use crate::records::Bytes;
use crate::{Error, Result};

/// Largest JSON request body (reference `jsonLimit`).
pub const JSON_LIMIT: usize = 1_000_000;

type Reply = core::result::Result<Vec<u8>, SpaceError>;
type HeaderReply = core::result::Result<(Vec<(String, String)>, Vec<u8>), SpaceError>;

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

#[derive(Clone, Debug)]
struct WriterMeta {
    repo_rev: String,
    space_rev: String,
}

#[derive(Clone, Debug)]
enum WriterSeqEntry {
    Write {
        repo: String,
        repo_rev: String,
        data: [u8; 32],
    },
    Removed {
        repo: String,
    },
}

struct State {
    /// `(space ref, author DID)` → records.
    repos: BTreeMap<(String, String), Repo>,
    /// `(space ref, author DID)` → latest `(repo_rev, space_rev)`.
    writer_meta: BTreeMap<(String, String), WriterMeta>,
    /// `space ref` → latest per-writer sequenced state keyed by `space_rev`.
    space_events: BTreeMap<String, BTreeMap<String, WriterSeqEntry>>,
    /// Explicit member allowlists (`space ref` → `did` → `(read, write)`).
    members: HashMap<String, BTreeMap<String, (bool, bool)>>,
    /// Explicit revocations configured via [`MemorySpaceHost::revoke_space_member`] or `removeMembers`.
    revoked_members: BTreeSet<(String, String)>,
    /// `(author DID, cid)` → blob + visibility.
    blobs: HashMap<(String, String), StoredBlob>,
    /// Injected `409 ConcurrentWrite` conflict count per `(space, did)`.
    injected_conflicts: HashMap<(String, String), usize>,
    /// Host P-256 KEM secret key for HPKE `0xFFFF` Export MAC negotiation.
    kem_secret: atproto_spaces::kem::P256SecretKey,
    tid: u64,
}

impl Default for State {
    fn default() -> Self {
        let kem_secret = atproto_spaces::kem::P256SecretKey::from_slice(&[0x42; 32])
            .expect("valid fixed test P-256 scalar");
        Self {
            repos: BTreeMap::new(),
            writer_meta: BTreeMap::new(),
            space_events: BTreeMap::new(),
            members: HashMap::new(),
            revoked_members: BTreeSet::new(),
            blobs: HashMap::new(),
            injected_conflicts: HashMap::new(),
            kem_secret,
            tid: 0,
        }
    }
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

    fn record_writer_commit(&mut self, space: &str, did: &str) {
        let repo_rev = self.next_tid();
        let space_rev = self.next_tid();
        let data = self.repo_lthash_digest(space, did);
        if let Some(prev) = self.writer_meta.insert(
            (space.to_owned(), did.to_owned()),
            WriterMeta {
                repo_rev: repo_rev.clone(),
                space_rev: space_rev.clone(),
            },
        ) && let Some(events) = self.space_events.get_mut(space)
        {
            events.remove(&prev.space_rev);
        }
        // Remove any prior `#repoRemoved` entry for this DID in `space`.
        if let Some(events) = self.space_events.get_mut(space) {
            events.retain(|_, ev| match ev {
                WriterSeqEntry::Removed { repo } => repo != did,
                WriterSeqEntry::Write { repo, .. } => repo != did,
            });
        }
        self.space_events
            .entry(space.to_owned())
            .or_default()
            .insert(
                space_rev,
                WriterSeqEntry::Write {
                    repo: did.to_owned(),
                    repo_rev,
                    data,
                },
            );
    }

    fn record_writer_removed(&mut self, space: &str, did: &str) {
        let space_rev = self.next_tid();
        self.writer_meta.remove(&(space.to_owned(), did.to_owned()));
        let events = self.space_events.entry(space.to_owned()).or_default();
        events.retain(|_, ev| match ev {
            WriterSeqEntry::Removed { repo } | WriterSeqEntry::Write { repo, .. } => repo != did,
        });
        events.insert(
            space_rev,
            WriterSeqEntry::Removed {
                repo: did.to_owned(),
            },
        );
    }

    fn repo_lthash_digest(&self, space: &str, did: &str) -> [u8; 32] {
        let mut lt = atproto_spaces::lthash::LtHash::empty();
        if let Some(repo) = self.repos.get(&(space.to_owned(), did.to_owned())) {
            for (collection, rkey, val) in repo.values() {
                let dagcbor = json_to_canonical_dagcbor(val);
                let rec_cid = atproto_spaces::lthash::compute_dagcbor_cid(&dagcbor);
                lt.add(&atproto_spaces::lthash::compute_record_element_hash(
                    collection, rkey, &rec_cid,
                ));
            }
        }
        lt.commitment()
    }
}

/// Converts an ATProto JSON `Value` (`$bytes`, `$link`, maps, arrays, scalars)
/// into canonical DAG-CBOR bytes matching `atproto_spaces::star` rules.
fn json_to_canonical_dagcbor(v: &Value) -> Vec<u8> {
    struct Canonical<'a>(&'a Value);

    impl serde::Serialize for Canonical<'_> {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> core::result::Result<S::Ok, S::Error> {
            use serde::ser::{SerializeMap, SerializeSeq};
            match self.0 {
                Value::Null => serializer.serialize_none(),
                Value::Bool(b) => serializer.serialize_bool(*b),
                Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        serializer.serialize_i64(i)
                    } else if let Some(u) = n.as_u64() {
                        serializer.serialize_u64(u)
                    } else {
                        Err(serde::ser::Error::custom("floats forbidden in DAG-CBOR"))
                    }
                }
                Value::String(s) => serializer.serialize_str(s),
                Value::Array(arr) => {
                    let mut seq = serializer.serialize_seq(Some(arr.len()))?;
                    for item in arr {
                        seq.serialize_element(&Canonical(item))?;
                    }
                    seq.end()
                }
                Value::Object(map) => {
                    if map.len() == 1 {
                        if let Some(b64) = map.get("$bytes").and_then(Value::as_str)
                            && let Ok(raw) =
                                STANDARD_NO_PAD.decode(b64.trim_end_matches('=').as_bytes())
                        {
                            return serializer.serialize_bytes(&raw);
                        }
                        if let Some(link) = map.get("$link").and_then(Value::as_str)
                            && let Ok(parsed_cid) = link.parse::<cid::Cid>()
                        {
                            return parsed_cid.serialize(serializer);
                        }
                    }
                    let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                    entries.sort_by(|(a, _), (b, _)| {
                        (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes()))
                    });
                    let mut m = serializer.serialize_map(Some(entries.len()))?;
                    for (k, val) in entries {
                        m.serialize_entry(k, &Canonical(val))?;
                    }
                    m.end()
                }
            }
        }
    }

    serde_ipld_dagcbor::to_vec(&Canonical(v)).expect("canonical ATProto DAG-CBOR")
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

    /// Host P-256 `#atproto_kem` `did:key:zDn...` for HPKE `0xFFFF` Export MAC negotiation.
    pub fn kem_did_key(&self) -> String {
        let s = self.s.lock().unwrap();
        atproto_spaces::kem::encode_p256_did_key(&s.kem_secret.public_key())
    }

    /// Grants `did` membership read/write access on `space`.
    pub fn grant_space_member(&self, space: &SpaceRef, did: &str) {
        let mut s = self.s.lock().unwrap();
        let key = space.to_string();
        s.revoked_members.remove(&(key.clone(), did.to_owned()));
        s.members
            .entry(key)
            .or_default()
            .insert(did.to_owned(), (true, true));
    }

    /// Revokes `did`'s membership read/write access on `space` and sequences `#repoRemoved`.
    pub fn revoke_space_member(&self, space: &SpaceRef, did: &str) {
        let mut s = self.s.lock().unwrap();
        let key = space.to_string();
        if let Some(m) = s.members.get_mut(&key) {
            m.remove(did);
        }
        s.revoked_members.insert((key.clone(), did.to_owned()));
        s.record_writer_removed(&key, did);
    }

    /// Fault-injection helper rolling back `(space, did)`'s advertised `repoRev` to `older_rev`.
    pub fn rollback_writer_rev(&self, space: &SpaceRef, did: &str, older_rev: &str) {
        let mut s = self.s.lock().unwrap();
        let space_str = space.to_string();
        let data = s.repo_lthash_digest(&space_str, did);
        let space_rev =
            if let Some(meta) = s.writer_meta.get_mut(&(space_str.clone(), did.to_owned())) {
                meta.repo_rev = older_rev.to_owned();
                meta.space_rev.clone()
            } else {
                let sr = s.next_tid();
                s.writer_meta.insert(
                    (space_str.clone(), did.to_owned()),
                    WriterMeta {
                        repo_rev: older_rev.to_owned(),
                        space_rev: sr.clone(),
                    },
                );
                sr
            };
        s.space_events.entry(space_str).or_default().insert(
            space_rev,
            WriterSeqEntry::Write {
                repo: did.to_owned(),
                repo_rev: older_rev.to_owned(),
                data,
            },
        );
    }

    /// Fault-injection helper causing the next `count` `applyWrites` calls for `(space, did)`
    /// to fail with HTTP `409 ConcurrentWrite`.
    pub fn inject_concurrent_write_conflicts(&self, space: &SpaceRef, did: &str, count: usize) {
        let mut s = self.s.lock().unwrap();
        s.injected_conflicts
            .insert((space.to_string(), did.to_owned()), count);
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
        let space_str = space.to_string();
        let uri = record_uri(&space_str, did, collection, rkey);
        let out = s
            .repos
            .get_mut(&(space_str.clone(), did.to_owned()))
            .and_then(|r| r.remove(&uri))
            .map(|(.., v)| v);
        if out.is_some() {
            s.record_writer_commit(&space_str, did);
        }
        out
    }

    /// Overwrites one record's value, bypassing every check.
    pub fn tamper(&self, space: &SpaceRef, did: &str, collection: &str, rkey: &str, value: Value) {
        let mut s = self.s.lock().unwrap();
        let space_str = space.to_string();
        let uri = record_uri(&space_str, did, collection, rkey);
        s.repos
            .entry((space_str.clone(), did.to_owned()))
            .or_default()
            .insert(uri, (collection.to_owned(), rkey.to_owned(), value));
        s.record_writer_commit(&space_str, did);
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
    let dagcbor = json_to_canonical_dagcbor(v);
    atproto_spaces::lthash::compute_dagcbor_cid(&dagcbor).to_string()
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizeSpaceSyncIn {
    space: String,
    credential_key: String,
}

#[derive(Deserialize)]
struct PutMembersIn {
    space: String,
    members: Vec<MemberAccess>,
}

#[derive(Deserialize)]
struct RemoveMembersIn {
    space: String,
    dids: Vec<String>,
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
        write: bool,
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
            let is_authority = parsed.as_ref().is_some_and(|sr| sr.space_did == self.did);
            if !is_authority && let Some(allowed) = s.members.get(space) {
                match allowed.get(&self.did) {
                    Some(&(can_read, can_write))
                        if (write && can_write) || (!write && can_read) => {}
                    _ => return Err(err(403, "Forbidden", "caller is not a Space member")),
                }
            }
            Ok(())
        } else {
            if let Some(r) = repo
                && r != self.did
            {
                return Err(err(400, "RepoNotFound", r));
            }
            Ok(())
        }
    }

    fn check_space_authority(&self, space: &str) -> core::result::Result<SpaceRef, SpaceError> {
        let parsed =
            SpaceRef::parse(space).map_err(|_| err(400, "InvalidRequest", "invalid space ref"))?;
        if parsed.space_did != self.did {
            return Err(err(403, "NotAuthorized", "caller is not space authority"));
        }
        Ok(parsed)
    }

    fn list_spaces(&self, p: &[(&str, String)]) -> Reply {
        let state = self.host.s.lock().unwrap();
        let cursor = param(p, "cursor");
        if let Some(c) = cursor
            && SpaceRef::parse(c).is_err()
        {
            return Err(err(400, "InvalidCursor", "cursor must be a space ref"));
        }
        let limit: usize = param(p, "limit")
            .unwrap_or("50")
            .parse()
            .ok()
            .filter(|n| (1..=100).contains(n))
            .ok_or_else(|| err(400, "InvalidRequest", "limit"))?;
        let matching: Vec<String> = state
            .repos
            .keys()
            .filter(|(uri, did)| {
                did == &self.did
                    && cursor.is_none_or(|c| uri.as_str() > c)
                    && SpaceRef::parse(uri).is_ok_and(|s| {
                        param(p, "spaceDid").is_none_or(|d| s.space_did == d)
                            && param(p, "spaceType").is_none_or(|t| s.space_type == t)
                    })
            })
            .map(|(uri, _)| uri.clone())
            .take(limit)
            .collect();
        let next_cursor = (matching.len() == limit)
            .then(|| matching.last().cloned())
            .flatten();
        let spaces: Vec<Value> = matching
            .iter()
            .map(|space_uri| {
                let mut view = json!({ "space": space_uri });
                if let Some(meta) = state
                    .writer_meta
                    .get(&(space_uri.clone(), self.did.clone()))
                {
                    let digest = state.repo_lthash_digest(space_uri, &self.did);
                    view["repoRev"] = Value::from(meta.repo_rev.clone());
                    view["data"] = serde_json::to_value(Bytes(digest.to_vec())).expect("bytes");
                }
                if SpaceRef::parse(space_uri).is_ok_and(|sr| sr.space_did == self.did)
                    && let Some(events) = state.space_events.get(space_uri)
                    && let Some((last_rev, _)) = events.iter().next_back()
                {
                    view["spaceRev"] = Value::from(last_rev.clone());
                }
                view
            })
            .collect();
        let mut out = json!({ "spaces": spaces });
        if let Some(c) = next_cursor {
            out["cursor"] = Value::from(c);
        }
        ok(out)
    }

    fn list_writers(&self, p: &[(&str, String)]) -> Reply {
        let space = required(p, "space")?;
        let cursor = param(p, "cursor");
        let limit: usize = param(p, "limit")
            .unwrap_or("100")
            .parse()
            .ok()
            .filter(|n| (1..=1_000).contains(n))
            .ok_or_else(|| err(400, "InvalidRequest", "limit"))?;
        let s = self.host.s.lock().unwrap();
        self.check_space_access(&s, space, None, false)?;

        let mut items: Vec<(String, Value)> = Vec::new();
        if let Some(events) = s.space_events.get(space) {
            for (space_rev, ev) in events {
                if cursor.is_some_and(|c| space_rev.as_str() <= c) {
                    continue;
                }
                let val = match ev {
                    WriterSeqEntry::Write {
                        repo,
                        repo_rev,
                        data,
                    } => json!({
                        "$type": "com.atproto.space.defs#repoWrite",
                        "repo": repo,
                        "repoRev": repo_rev,
                        "data": Bytes(data.to_vec()),
                        "spaceRev": space_rev,
                    }),
                    WriterSeqEntry::Removed { repo } => json!({
                        "$type": "com.atproto.space.defs#repoRemoved",
                        "repo": repo,
                        "spaceRev": space_rev,
                    }),
                };
                items.push((space_rev.clone(), val));
                if items.len() == limit {
                    break;
                }
            }
        }
        let next_cursor = (items.len() == limit).then(|| items.last().map(|(sr, _)| sr.clone()));
        let repos: Vec<Value> = items.into_iter().map(|(_, v)| v).collect();
        let mut out = json!({ "repos": repos });
        if let Some(Some(c)) = next_cursor {
            out["cursor"] = Value::from(c);
        }
        ok(out)
    }

    fn authorize_space_sync(&self, payload: &[u8]) -> Reply {
        let input: AuthorizeSpaceSyncIn = serde_json::from_slice(payload)
            .map_err(|e| err(400, "InvalidRequest", e.to_string()))?;
        atproto_spaces::kem::decode_p256_did_key(&input.credential_key)
            .map_err(|e| err(400, "InvalidRequest", e.to_string()))?;
        let mut s = self.host.s.lock().unwrap();
        if s.revoked_members
            .contains(&(input.space.clone(), self.did.clone()))
        {
            return Err(err(
                403,
                "AccountNotAuthorized",
                "member revoked from Space",
            ));
        }
        self.check_space_access(&s, &input.space, None, false)?;
        let token_id = s.next_tid();
        let space_rev = s
            .space_events
            .get(&input.space)
            .and_then(|ev| ev.keys().next_back().cloned());
        let mut out = json!({
            "credential": format!("space-cred-{token_id}"),
        });
        if let Some(sr) = space_rev {
            out["spaceRev"] = Value::from(sr);
        }
        ok(out)
    }

    fn put_members(&self, payload: &[u8]) -> Reply {
        let input: PutMembersIn = serde_json::from_slice(payload)
            .map_err(|e| err(400, "InvalidRequest", e.to_string()))?;
        if input.members.len() > 100 {
            return Err(err(400, "InvalidRequest", "members exceeds 100"));
        }
        self.check_space_authority(&input.space)?;
        let mut s = self.host.s.lock().unwrap();
        for m in input.members {
            s.revoked_members
                .remove(&(input.space.clone(), m.did.clone()));
            s.members
                .entry(input.space.clone())
                .or_default()
                .insert(m.did, (m.read, m.write));
        }
        Ok(Vec::new())
    }

    fn remove_members(&self, payload: &[u8]) -> Reply {
        let input: RemoveMembersIn = serde_json::from_slice(payload)
            .map_err(|e| err(400, "InvalidRequest", e.to_string()))?;
        if input.dids.len() > 100 {
            return Err(err(400, "InvalidRequest", "dids exceeds 100"));
        }
        self.check_space_authority(&input.space)?;
        let mut s = self.host.s.lock().unwrap();
        for did in input.dids {
            if let Some(map) = s.members.get_mut(&input.space) {
                map.remove(&did);
            }
            s.revoked_members.insert((input.space.clone(), did.clone()));
            s.record_writer_removed(&input.space, &did);
        }
        Ok(Vec::new())
    }

    fn list_members(&self, p: &[(&str, String)]) -> Reply {
        let space = required(p, "space")?;
        self.check_space_authority(space)?;
        let cursor = param(p, "cursor");
        let limit: usize = param(p, "limit")
            .unwrap_or("100")
            .parse()
            .ok()
            .filter(|n| (1..=1_000).contains(n))
            .ok_or_else(|| err(400, "InvalidRequest", "limit"))?;
        let s = self.host.s.lock().unwrap();
        let mut members = Vec::new();
        if let Some(map) = s.members.get(space) {
            for (did, &(read, write)) in map {
                if cursor.is_some_and(|c| did.as_str() <= c) {
                    continue;
                }
                members.push(MemberAccess {
                    did: did.clone(),
                    read,
                    write,
                });
                if members.len() == limit {
                    break;
                }
            }
        }
        let next_cursor = (members.len() == limit).then(|| members.last().map(|m| m.did.clone()));
        let mut out = json!({ "members": members });
        if let Some(Some(c)) = next_cursor {
            out["cursor"] = Value::from(c);
        }
        ok(out)
    }

    fn read_repo(
        &self,
        s: &State,
        space: &str,
        repo: &str,
    ) -> core::result::Result<Repo, SpaceError> {
        self.check_space_access(s, space, Some(repo), false)?;
        Ok(s.repos
            .get(&(space.to_owned(), repo.to_owned()))
            .cloned()
            .unwrap_or_default())
    }

    fn get_record_with_headers(
        &self,
        p: &[(&str, String)],
        req_headers: &[(String, String)],
    ) -> HeaderReply {
        let (space, repo) = (required(p, "space")?, required(p, "repo")?);
        let (collection, rkey) = (required(p, "collection")?, required(p, "rkey")?);
        let s = self.host.s.lock().unwrap();
        let r = self.read_repo(&s, space, repo)?;
        let uri = record_uri(space, repo, collection, rkey);
        let (.., v) = r
            .get(&uri)
            .ok_or_else(|| err(400, "RecordNotFound", &uri))?;
        let cid_str = cid(v);
        let mut resp_headers = Vec::new();
        if let Some(accept) = req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(atproto_spaces::mac::ACCEPT_SIGNATURE_HEADER))
            .map(|(_, val)| val.as_str())
        {
            let (label, key_share) = atproto_spaces::mac::parse_accept_signature(
                accept,
                atproto_spaces::mac::MacProfile::Record,
            )
            .map_err(|e| err(400, "InvalidSpaceMac", e.to_string()))?;
            let shared = atproto_spaces::kem::decapsulate_p256(&s.kem_secret, &key_share)
                .map_err(|e| err(400, "InvalidSpaceMac", e.to_string()))?;
            let (mac_headers, _) =
                atproto_spaces::mac::sign_record_mac(&shared, &key_share, &label, &uri, &cid_str)
                    .map_err(|e| err(400, "InvalidSpaceMac", e.to_string()))?;
            resp_headers.push((
                mac_headers.covered_header_name.to_owned(),
                mac_headers.covered_header,
            ));
            resp_headers.push((
                atproto_spaces::mac::SIGNATURE_INPUT_HEADER.to_owned(),
                mac_headers.signature_input,
            ));
            resp_headers.push((
                atproto_spaces::mac::SIGNATURE_HEADER.to_owned(),
                mac_headers.signature,
            ));
        }
        let body =
            serde_json::to_vec(&json!({ "uri": uri, "cid": cid_str, "value": v })).expect("json");
        Ok((resp_headers, body))
    }

    fn get_repo_with_headers(
        &self,
        p: &[(&str, String)],
        req_headers: &[(String, String)],
    ) -> HeaderReply {
        let (space, repo) = (required(p, "space")?, required(p, "repo")?);
        let mut s = self.host.s.lock().unwrap();
        let r = self.read_repo(&s, space, repo)?;
        let rev = match s.writer_meta.get(&(space.to_owned(), repo.to_owned())) {
            Some(meta) => meta.repo_rev.clone(),
            None if r.is_empty() => return Err(err(404, "RepoNotFound", repo)),
            None => s.next_tid(),
        };
        let data = s.repo_lthash_digest(space, repo);
        let mut entries: Vec<atproto_spaces::star::StarRecordEntry> = r
            .values()
            .map(
                |(collection, rkey, val)| atproto_spaces::star::StarRecordEntry {
                    path: format!("{collection}/{rkey}"),
                    record_dagcbor: json_to_canonical_dagcbor(val),
                },
            )
            .collect();
        entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        let star_bytes = atproto_spaces::star::write_star_repo(space, repo, &rev, &data, &entries)
            .map_err(|e| err(500, "InternalServerError", e.to_string()))?;

        let mut resp_headers = Vec::new();
        if let Some(accept) = req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(atproto_spaces::mac::ACCEPT_SIGNATURE_HEADER))
            .map(|(_, val)| val.as_str())
        {
            let (label, key_share) = atproto_spaces::mac::parse_accept_signature(
                accept,
                atproto_spaces::mac::MacProfile::Commit,
            )
            .map_err(|e| err(400, "InvalidSpaceMac", e.to_string()))?;
            let shared = atproto_spaces::kem::decapsulate_p256(&s.kem_secret, &key_share)
                .map_err(|e| err(400, "InvalidSpaceMac", e.to_string()))?;
            let (mac_headers, _) = atproto_spaces::mac::sign_commit_mac(
                &shared, &key_share, &label, space, repo, &rev, &data,
            )
            .map_err(|e| err(400, "InvalidSpaceMac", e.to_string()))?;
            resp_headers.push((
                mac_headers.covered_header_name.to_owned(),
                mac_headers.covered_header,
            ));
            resp_headers.push((
                atproto_spaces::mac::SIGNATURE_INPUT_HEADER.to_owned(),
                mac_headers.signature_input,
            ));
            resp_headers.push((
                atproto_spaces::mac::SIGNATURE_HEADER.to_owned(),
                mac_headers.signature,
            ));
        }
        Ok((resp_headers, star_bytes))
    }

    fn list_records(&self, p: &[(&str, String)]) -> Reply {
        let (space, repo) = (required(p, "space")?, required(p, "repo")?);
        if param(p, "reverse").is_some() {
            return Err(err(400, "InvalidRequest", "reverse parameter is retired"));
        }
        let limit: usize = match param(p, "limit") {
            None => 50,
            Some(l) => l
                .parse()
                .ok()
                .filter(|l| (1..=1_000).contains(l))
                .ok_or_else(|| err(400, "InvalidRequest", "limit"))?,
        };
        let exclude = param(p, "excludeValues") == Some("true");
        let collection = param(p, "collection");
        let cursor = param(p, "cursor");
        let s = self.host.s.lock().unwrap();
        let r = self.read_repo(&s, space, repo)?;
        let page: Vec<(&String, &(String, String, Value))> = r
            .iter()
            .filter(|(_, (c, ..))| collection.is_none_or(|x| x == c))
            .rev()
            .filter(|(u, _)| cursor.is_none_or(|c| u.as_str() < c))
            .take(limit)
            .collect();
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
        self.check_space_access(&s, &input.space, Some(&self.did), true)?;
        let key = (input.space.clone(), self.did.clone());
        if let Some(rem) = s.injected_conflicts.get_mut(&key)
            && *rem > 0
        {
            *rem -= 1;
            return Err(err(409, "ConcurrentWrite", "concurrent repository write"));
        }
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
            let space_str = input.space.clone();
            s.repos.insert(key, repo);
            s.record_writer_commit(&space_str, &self.did);
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
        self.check_space_access(&s, &input.space, Some(&self.did), true)?;
        let uri = record_uri(&input.space, &self.did, &input.collection, &input.rkey);
        let removed = s
            .repos
            .get_mut(&(input.space.clone(), self.did.clone()))
            .and_then(|r| r.remove(&uri))
            .is_some();
        if removed {
            s.record_writer_commit(&input.space, &self.did);
        }
        ok(json!({}))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SpaceRpc for SpaceClient {
    async fn query(&self, nsid: &str, params: &[(&str, String)]) -> Reply {
        let (_, body) = self.query_with_headers(nsid, params, &[]).await?;
        Ok(body)
    }

    async fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> HeaderReply {
        match nsid {
            endpoint::GET_RECORD => self.get_record_with_headers(params, headers),
            endpoint::GET_REPO => self.get_repo_with_headers(params, headers),
            endpoint::LIST_RECORDS => Ok((Vec::new(), self.list_records(params)?)),
            endpoint::LIST_WRITERS => Ok((Vec::new(), self.list_writers(params)?)),
            endpoint::LIST_SPACES => Ok((Vec::new(), self.list_spaces(params)?)),
            endpoint::LIST_MEMBERS => Ok((Vec::new(), self.list_members(params)?)),
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
            endpoint::AUTHORIZE_SPACE_SYNC => self.authorize_space_sync(payload),
            endpoint::PUT_MEMBERS => self.put_members(payload),
            endpoint::REMOVE_MEMBERS => self.remove_members(payload),
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
        self.check_space_access(&s, space, Some(did), false)?;
        let blob = s
            .blobs
            .get(&(did.to_owned(), cid.to_owned()))
            .ok_or_else(|| err(404, "BlobNotFound", cid))?;
        match &blob.visibility {
            BlobVisibility::SpaceScoped(spaces) if spaces.contains(space) => Ok(blob.bytes.clone()),
            _ => Err(err(404, "BlobNotFound", cid)),
        }
    }

    async fn host_kem_did_key(
        &self,
        _space: &str,
    ) -> core::result::Result<Option<String>, SpaceError> {
        Ok(Some(self.host.kem_did_key()))
    }
}

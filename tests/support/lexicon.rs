//! A small structural validator for atproto lexicon records: required
//! fields, unknown fields, types, string/bytes/array length limits,
//! integer bounds, refs and closed unions. It is not a full lexicon
//! implementation; it covers the features our lexicons use.

use std::collections::HashMap;
use std::path::Path;

use base64::Engine as _;
use serde_json::Value;

pub struct Lexicons {
    docs: HashMap<String, Value>,
}

type R = Result<(), String>;

impl Lexicons {
    pub fn load(dir: &Path) -> Self {
        let mut docs = HashMap::new();
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "json") {
                let v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
                docs.insert(v["id"].as_str().unwrap().to_owned(), v);
            }
        }
        Self { docs }
    }

    pub fn docs(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.docs.iter()
    }

    /// Validate `v` as a record of collection `nsid`.
    pub fn validate_record(&self, nsid: &str, v: &Value) -> R {
        let main = self.def(nsid, "main")?;
        if main["type"] != "record" {
            return Err(format!("{nsid}#main is not a record"));
        }
        if v.get("$type").and_then(Value::as_str) != Some(nsid) {
            return Err(format!("$type must be {nsid}"));
        }
        self.object(nsid, &main["record"], v, "", true)
    }

    fn def(&self, nsid: &str, name: &str) -> Result<&Value, String> {
        self.docs
            .get(nsid)
            .and_then(|d| d["defs"].get(name))
            .ok_or_else(|| format!("unknown def {nsid}#{name}"))
    }

    /// Resolve a ref string relative to `cur`: `(nsid, name)`.
    pub fn resolve(cur: &str, r: &str) -> (String, String) {
        match r.split_once('#') {
            Some(("", name)) => (cur.to_owned(), name.to_owned()),
            Some((n, name)) => (n.to_owned(), name.to_owned()),
            None => (r.to_owned(), "main".to_owned()),
        }
    }

    fn object(&self, nsid: &str, def: &Value, v: &Value, path: &str, allow_type: bool) -> R {
        let obj = v.as_object().ok_or(format!("{path}: expected object"))?;
        let props = def["properties"].as_object().cloned().unwrap_or_default();
        for req in def["required"].as_array().into_iter().flatten() {
            let k = req.as_str().unwrap();
            if !obj.contains_key(k) {
                return Err(format!("{path}: missing required {k}"));
            }
        }
        for (k, val) in obj {
            if k == "$type" && allow_type {
                continue;
            }
            let pdef = props.get(k).ok_or(format!("{path}: unknown field {k}"))?;
            self.value(nsid, pdef, val, &format!("{path}.{k}"))?;
        }
        Ok(())
    }

    fn value(&self, nsid: &str, def: &Value, v: &Value, path: &str) -> R {
        let min = |k: &str| def.get(k).and_then(Value::as_u64);
        let len_ok = |n: usize, what: &str| -> R {
            if min("maxLength").is_some_and(|m| n as u64 > m) {
                return Err(format!("{path}: {what} length {n} > maxLength"));
            }
            if min("minLength").is_some_and(|m| (n as u64) < m) {
                return Err(format!("{path}: {what} length {n} < minLength"));
            }
            Ok(())
        };
        match def["type"].as_str().unwrap_or("") {
            "string" => {
                let s = v.as_str().ok_or(format!("{path}: expected string"))?;
                len_ok(s.len(), "string")?;
                match def.get("format").and_then(Value::as_str) {
                    Some("datetime") if !is_rfc3339(s) => {
                        Err(format!("{path}: not an RFC 3339 datetime: {s}"))
                    }
                    Some("did") if !s.starts_with("did:") || s.len() < 8 => {
                        Err(format!("{path}: not a DID: {s}"))
                    }
                    _ => Ok(()),
                }
            }
            "integer" => {
                let n = v.as_i64().ok_or(format!("{path}: expected integer"))?;
                if def
                    .get("minimum")
                    .and_then(Value::as_i64)
                    .is_some_and(|m| n < m)
                    || def
                        .get("maximum")
                        .and_then(Value::as_i64)
                        .is_some_and(|m| n > m)
                {
                    return Err(format!("{path}: integer {n} out of range"));
                }
                Ok(())
            }
            "boolean" => v
                .as_bool()
                .map(|_| ())
                .ok_or(format!("{path}: expected boolean")),
            "bytes" => {
                let o = v.as_object().ok_or(format!("{path}: expected $bytes"))?;
                let b64 = o
                    .get("$bytes")
                    .and_then(Value::as_str)
                    .filter(|_| o.len() == 1)
                    .ok_or(format!("{path}: expected {{\"$bytes\"}}"))?;
                let raw = base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(b64)
                    .map_err(|_| format!("{path}: bad base64"))?;
                len_ok(raw.len(), "bytes")
            }
            "array" => {
                let a = v.as_array().ok_or(format!("{path}: expected array"))?;
                len_ok(a.len(), "array")?;
                for (i, item) in a.iter().enumerate() {
                    self.value(nsid, &def["items"], item, &format!("{path}[{i}]"))?;
                }
                Ok(())
            }
            "ref" => {
                let (n, name) = Self::resolve(nsid, def["ref"].as_str().unwrap());
                let target = self.def(&n, &name)?;
                self.value(&n, target, v, path)
            }
            "object" => self.object(nsid, def, v, path, false),
            "union" => {
                let t = v
                    .get("$type")
                    .and_then(Value::as_str)
                    .ok_or(format!("{path}: union member needs $type"))?;
                let hit = def["refs"].as_array().unwrap().iter().find(|r| {
                    let (n, name) = Self::resolve(nsid, r.as_str().unwrap());
                    format!("{n}#{name}") == t
                });
                let Some(r) = hit else {
                    return Err(format!("{path}: $type {t} not in closed union"));
                };
                let (n, name) = Self::resolve(nsid, r.as_str().unwrap());
                self.object(&n, self.def(&n, &name)?, v, path, true)
            }
            other => Err(format!("{path}: unsupported lexicon type {other:?}")),
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`.
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|x| x.iter().all(u8::is_ascii_digit));
    if b.len() < 20
        || !digits(0..4)
        || b[4] != b'-'
        || !digits(5..7)
        || b[7] != b'-'
        || !digits(8..10)
        || b[10] != b'T'
        || !digits(11..13)
        || b[13] != b':'
        || !digits(14..16)
        || b[16] != b':'
        || !digits(17..19)
    {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match &b[i..] {
        b"Z" => true,
        [s, h1, h2, b':', m1, m2] if (*s == b'+' || *s == b'-') => {
            [h1, h2, m1, m2].iter().all(|c| c.is_ascii_digit())
        }
        _ => false,
    }
}

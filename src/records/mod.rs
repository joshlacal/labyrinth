//! atproto record shapes for every `blue.catbird.labyrinth.*` lexicon
//! (SPEC §9), with lossless conversions to and from the protocol structs.
//!
//! These types serialize (with `serde_json`) to the exact atproto JSON data
//! model: camelCase field names, `$type` set to the record NSID, byte
//! fields as `{"$bytes": "<base64, no padding>"}`, datetimes as RFC 3339
//! strings. Non-human-readable serializers (DAG-CBOR) get raw bytes.
//!
//! Each record type has a `from_*` constructor that takes the protocol
//! struct plus the record-only fields (`createdAt`, …) and a `to_*`
//! method that checks `$type`, byte lengths and key encodings and returns
//! the protocol struct. Nothing here verifies signatures or MACs; that is
//! the protocol layer's job.

pub mod defs;
pub mod mailbox;
pub mod thread;

pub use defs::{
    EpochPublicDef, MekRecipientDef, OwnerMessageDef, RedactionDef, SealedMessageDef,
    TransportAttestationDef,
};
pub use mailbox::{Device, Epoch, EpochMember, MailboxKeysRecord, OwnerBatch, VirtualDevice};
pub use thread::{
    Batch, BatchEntry, LabyrinthSenderDef, MekDistribution, MekSenderDef, TransportSenderDef,
};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::de::Error as _;

use crate::{Error, Result};

/// Record NSIDs.
pub mod nsid {
    pub const DEVICE: &str = "blue.catbird.labyrinth.device";
    pub const EPOCH: &str = "blue.catbird.labyrinth.epoch";
    pub const EPOCH_MEMBER: &str = "blue.catbird.labyrinth.epochMember";
    pub const VIRTUAL_DEVICE: &str = "blue.catbird.labyrinth.virtualDevice";
    pub const OWNER_BATCH: &str = "blue.catbird.labyrinth.ownerBatch";
    pub const MAILBOX_KEYS: &str = "blue.catbird.labyrinth.mailboxKeys";
    pub const MEK: &str = "blue.catbird.labyrinth.mek";
    pub const BATCH: &str = "blue.catbird.labyrinth.batch";
}

/// Most messages per `batch` / `ownerBatch` record ([CB-20]).
pub const MAX_BATCH_ITEMS: usize = 256;

/// Byte budget a client keeps a batch under before flushing, leaving
/// headroom under the PDS's 1 MB record cap after base64 expansion.
pub const BATCH_BYTE_BUDGET: usize = 900_000;

/// Largest `epochNumber` any record may carry (2^40). Epoch numbers come
/// from the store, so they are bounded here, well below `u64::MAX`, to
/// keep every `seq + 1` in the protocol layers far from overflow. The
/// lexicons carry the same `maximum`.
pub const MAX_EPOCH_NUMBER: u64 = 1 << 40;

/// Rejects an `epochNumber` above [`MAX_EPOCH_NUMBER`].
pub fn check_epoch_number(n: u64) -> Result<u64> {
    if n > MAX_EPOCH_NUMBER {
        return Err(Error::Malformed("epochNumber out of range"));
    }
    Ok(n)
}

/// An atproto `bytes` value: `{"$bytes": "<base64 no padding>"}` in JSON.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Bytes(pub Vec<u8>);

impl Bytes {
    pub fn from_slice(b: &[u8]) -> Self {
        Self(b.to_vec())
    }

    /// The bytes as a fixed-size array; `what` names the field on error.
    pub fn array<const N: usize>(&self, what: &'static str) -> Result<[u8; N]> {
        self.0
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed(what))
    }
}

impl serde::Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        if !s.is_human_readable() {
            return s.serialize_bytes(&self.0);
        }
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry("$bytes", &STANDARD_NO_PAD.encode(&self.0))?;
        m.end()
    }
}

impl<'de> serde::Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        if !d.is_human_readable() {
            return Ok(Self(
                serde::de::Deserialize::deserialize(d).map(|b: serde_bytes_shim::ByteBuf| b.0)?,
            ));
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(rename = "$bytes")]
            bytes: String,
        }
        let w = Wire::deserialize(d)?;
        STANDARD_NO_PAD
            .decode(w.bytes.as_bytes())
            .map(Self)
            .map_err(|_| D::Error::custom("$bytes is not unpadded base64"))
    }
}

/// Minimal byte-buffer visitor so binary formats need no extra crate.
mod serde_bytes_shim {
    pub struct ByteBuf(pub Vec<u8>);

    impl<'de> serde::Deserialize<'de> for ByteBuf {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = ByteBuf;
                fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E>(self, v: &[u8]) -> Result<ByteBuf, E> {
                    Ok(ByteBuf(v.to_vec()))
                }
                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<ByteBuf, E> {
                    Ok(ByteBuf(v))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> Result<ByteBuf, A::Error> {
                    let mut out = Vec::new();
                    while let Some(b) = a.next_element::<u8>()? {
                        out.push(b);
                    }
                    Ok(ByteBuf(out))
                }
            }
            d.deserialize_byte_buf(V)
        }
    }
}

/// Fails unless a record's `$type` is `expected`.
pub(crate) fn check_type(found: &str, expected: &'static str) -> Result<()> {
    if found == expected {
        Ok(())
    } else {
        Err(Error::Malformed("record $type mismatch"))
    }
}

/// RFC 3339 UTC datetime with millisecond precision for Unix time `ms`,
/// e.g. `2026-10-04T06:15:27.000Z`.
pub fn datetime_from_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        ms % 1000
    )
}

/// Unix time in ms for an RFC 3339 datetime
/// (`YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`), truncated to milliseconds.
/// The inverse of [`datetime_from_ms`]; times before 1970 are rejected.
pub fn ms_from_datetime(s: &str) -> Result<u64> {
    let bad = Error::Malformed("not an RFC 3339 datetime");
    let b = s.as_bytes();
    let num = |r: core::ops::Range<usize>| -> Result<i64> {
        let d = b
            .get(r)
            .ok_or(Error::Malformed("not an RFC 3339 datetime"))?;
        if d.is_empty() || !d.iter().all(u8::is_ascii_digit) {
            return Err(Error::Malformed("not an RFC 3339 datetime"));
        }
        Ok(d.iter().fold(0i64, |a, c| a * 10 + i64::from(c - b'0')))
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') {
        return Err(bad);
    }
    if b[13] != b':' || b[16] != b':' {
        return Err(bad);
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return Err(bad);
    }
    let mut i = 19;
    let mut ms = 0i64;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err(bad);
        }
        let frac = &b[start..i.min(start + 3)];
        ms = frac.iter().fold(0, |a, c| a * 10 + i64::from(c - b'0'))
            * 10i64.pow(3 - frac.len() as u32);
    }
    let offset_min = match &b[i..] {
        b"Z" | b"z" => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let m = num(i + 1..i + 3)? * 60 + num(i + 4..i + 6)?;
            if *sign == b'+' { m } else { -m }
        }
        _ => return Err(bad),
    };
    let days = days_from_civil(y, mo as u32, d as u32);
    let total = ((days * 86_400 + h * 3600 + mi * 60 + sec - offset_min * 60) * 1000) + ms;
    u64::try_from(total).map_err(|_| bad)
}

/// (year, month, day) to days since 1970-01-01; H. Hinnant's algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Days since 1970-01-01 to (year, month, day); H. Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datetimes() {
        assert_eq!(datetime_from_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            datetime_from_ms(1_791_181_727_123),
            "2026-10-05T06:28:47.123Z"
        );
        assert_eq!(
            datetime_from_ms(951_782_400_000),
            "2000-02-29T00:00:00.000Z"
        );
    }

    #[test]
    fn datetimes_parse_back() {
        for ms in [0, 951_782_400_000, 1_791_181_727_123, 4_102_444_799_999] {
            assert_eq!(ms_from_datetime(&datetime_from_ms(ms)).unwrap(), ms);
        }
        assert_eq!(
            ms_from_datetime("2026-10-05T08:28:47.1239+02:00").unwrap(),
            1_791_181_727_123
        );
        assert_eq!(ms_from_datetime("1970-01-01T00:00:01Z").unwrap(), 1000);
        for bad in [
            "1969-12-31T23:59:59Z",
            "2026-13-01T00:00:00Z",
            "2026-10-05 08:28:47Z",
            "2026-10-05T08:28:47",
            "2026-10-05T08:28:47.Z",
        ] {
            assert!(ms_from_datetime(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bytes_json_shape() {
        let b = Bytes(vec![1, 2, 3, 4]);
        let j = serde_json::to_string(&b).unwrap();
        assert_eq!(j, r#"{"$bytes":"AQIDBA"}"#);
        assert_eq!(serde_json::from_str::<Bytes>(&j).unwrap(), b);
        assert!(serde_json::from_str::<Bytes>(r#"{"$bytes":"AQIDBA=="}"#).is_err());
        assert!(serde_json::from_str::<Bytes>(r#"{"$bytes":"AQ","x":1}"#).is_err());
        assert_eq!(b.array::<4>("x").unwrap(), [1, 2, 3, 4]);
        assert!(b.array::<3>("x").is_err());
    }
}

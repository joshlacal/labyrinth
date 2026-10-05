//! Lookup endpoints of the reference server (mls-ds
//! `labyrinth/repo/lookup.rs`): `getMessages`, `listThreads` and
//! `listOwnerThreads`.
//!
//! - `getMessages`: the readable batches of one thread holding any of
//!   1..=100 `messageIds` (repeated query keys), in server seq order,
//!   redacted items as stored.
//! - `listThreads`: conversations where the caller wrote a MEK or is a MEK
//!   recipient, ascending by id, as `{items: [{threadId}]}`.
//! - `listOwnerThreads`: the caller's owner-archive threads, by the seq of
//!   each thread's first owner batch.

use super::thread::{readable, seq_order};
use super::{Caller, Input, MemoryXrpcServer, Reply, bad, err, req};
use crate::store::xrpc::wire::ThreadView;
use crate::store::{MailboxStore, ThreadStore, TimeRange};

fn message_ids<'a>(input: &'a Input<'_>) -> core::result::Result<Vec<&'a str>, super::XrpcError> {
    let ids: Vec<&str> = match input {
        Input::Params(p) => p
            .iter()
            .filter(|(k, _)| *k == "messageIds")
            .map(|(_, v)| v.as_str())
            .collect(),
        Input::Body(_) => Vec::new(),
    };
    if ids.is_empty() || ids.len() > 100 || ids.iter().any(|i| i.is_empty() || i.len() > 128) {
        return Err(bad("messageIds must name 1..=100 ids"));
    }
    Ok(ids)
}

pub(super) fn handle(
    s: &MemoryXrpcServer,
    c: &Caller,
    name: &str,
    input: &Input<'_>,
) -> Option<Reply> {
    let th = s.net.threads(&c.did);
    let r = match name {
        "getMessages" => (|| {
            let thread = req(input, "threadId")?;
            let ids = message_ids(input)?;
            let v = th.get_messages(thread, &ids).map_err(err)?;
            s.page(seq_order(readable(&th, &c.did, thread, v)?, false), input)
        })(),
        "listThreads" => (|| {
            let v: Vec<ThreadView> = th
                .list_threads()
                .map_err(err)?
                .into_iter()
                .map(|thread_id| ThreadView { thread_id })
                .collect();
            s.page(v, input)
        })(),
        "listOwnerThreads" => (|| {
            let mb = s.net.mailbox(&c.did);
            let mut v = Vec::new();
            for t in mb.list_owner_threads().map_err(err)? {
                let first = mb
                    .list_owner_batches(&t, TimeRange::ALL)
                    .map_err(err)?
                    .iter()
                    .filter_map(|b| b.order.map(|o| o.labyrinth_seq))
                    .min();
                v.push((first, t));
            }
            v.sort();
            let v: Vec<ThreadView> = v
                .into_iter()
                .map(|(_, thread_id)| ThreadView { thread_id })
                .collect();
            s.page(v, input)
        })(),
        _ => return None,
    };
    Some(r)
}

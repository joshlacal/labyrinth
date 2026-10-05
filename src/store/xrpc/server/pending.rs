//! Endpoints the crate proposes but mls-ds has not built (no lexicon in
//! `lexicons/`): `listThreads` and `listOwnerThreads`, each →
//! `{threads: [threadId]}`. The XRPC stores do not call them (their trait
//! methods return [`crate::Error::NotSupported`], and
//! [`crate::client::Labyrinth::purge_account`] falls back to the
//! server-side `deleteAccountData`); the handlers pin the proposed shape.
//!
//! Everything the gap lane left here earlier is now served by
//! [`super::retention`] and [`super::attachments`] against the mls-ds
//! lexicons.

use super::{Caller, Input, MemoryXrpcServer, Reply, err, json};
use crate::store::xrpc::wire::ThreadsOut;
use crate::store::{MailboxStore, ThreadStore};

pub(super) fn handle(
    s: &MemoryXrpcServer,
    c: &Caller,
    name: &str,
    _input: &Input<'_>,
) -> Option<Reply> {
    let r = match name {
        "listThreads" => s.net.threads(&c.did).list_threads(),
        "listOwnerThreads" => s.net.mailbox(&c.did).list_owner_threads(),
        _ => return None,
    };
    Some(
        r.map_err(err)
            .and_then(|threads| json(&ThreadsOut { threads })),
    )
}

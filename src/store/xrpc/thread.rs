//! [`ThreadStore`] over the mls-ds thread endpoints (design §2, "Thread").
//! `threadId` is the chat conversation id; the server stamps every MEK and
//! batch with a [`crate::store::ServerOrder`].

use std::sync::Arc;

use super::mailbox::range_params;
use super::wire::{AuthoredView, RecordBody, RkeyOrderOut};
use super::{Xrpc, XrpcTransport};
use crate::Result;
use crate::records::{Batch, MekDistribution};
use crate::store::{Stored, ThreadStore, TimeRange};

/// The conversation records on the sequencer DS, writing as one DID.
pub struct XrpcThreadStore {
    did: String,
    x: Xrpc,
}

impl XrpcThreadStore {
    pub fn new(did: &str, transport: Arc<dyn XrpcTransport>) -> Self {
        Self {
            did: did.to_owned(),
            x: Xrpc::new(transport),
        }
    }
}

fn stored<T>(v: AuthoredView<T>) -> Result<Stored<T>> {
    Ok(Stored {
        order: Some(v.order.to_order()?),
        author: v.author,
        rkey: v.rkey,
        value: v.record,
    })
}

impl ThreadStore for XrpcThreadStore {
    fn author(&self) -> &str {
        &self.did
    }

    fn create_mek(&self, mek: &MekDistribution) -> Result<()> {
        let _: RkeyOrderOut = self.x.post("createMek", &RecordBody { record: mek })?;
        Ok(())
    }

    fn find_meks(
        &self,
        thread_id: &str,
        mek_id: &[u8; 12],
    ) -> Result<Vec<Stored<MekDistribution>>> {
        let p = [
            ("threadId", thread_id.to_owned()),
            ("mekId", hex::encode(mek_id)),
        ];
        let v: Vec<AuthoredView<MekDistribution>> = self.x.list_all("findMeks", &p)?;
        v.into_iter().map(stored).collect()
    }

    fn append_batch(&self, batch: &Batch) -> Result<String> {
        let out: RkeyOrderOut = self.x.post("appendBatch", &RecordBody { record: batch })?;
        Ok(out.rkey)
    }

    fn list_batches(
        &self,
        thread_id: &str,
        sender: Option<&str>,
        range: TimeRange,
    ) -> Result<Vec<Stored<Batch>>> {
        let mut p = vec![("threadId", thread_id.to_owned())];
        if let Some(s) = sender {
            p.push(("sender", s.to_owned()));
        }
        range_params(range, &mut p);
        let v: Vec<AuthoredView<Batch>> = self.x.list_all("listBatches", &p)?;
        v.into_iter().map(stored).collect()
    }
}

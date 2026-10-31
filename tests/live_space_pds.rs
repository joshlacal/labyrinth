//! The Space mailbox store against a real atproto PDS from the upstream
//! `permissioned-data` branch (`Swan`). Opt-in: runs only when
//! `LABYRINTH_SPACE_PDS` names the session file written by
//! `scripts/space-pds/start.mjs`. Explicitly ignored without a live test run.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::executor::block_on;
use labyrinth::Error;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth, MessageSource};
use labyrinth::records::nsid;
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::pds::{PdsDirectory, PdsPublisher, PublicRepoBackend};
use labyrinth::store::space::{SpaceError, SpaceMailboxStore, SpaceRef, SpaceRpc};
use labyrinth::store::{MailboxDirectory, MailboxStore, TimeRange};
use labyrinth::virtual_device::Mechanism;
use serde_json::{Value, json};

const THREAD: &str = "conv-live";

#[derive(Clone, Debug)]
struct Account {
    did: String,
    jwt: String,
    space: String,
}

fn session() -> Option<(String, Vec<Account>)> {
    let path = std::env::var("LABYRINTH_SPACE_PDS").ok()?;
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let acct = |n: &str| Account {
        did: v["accounts"][n]["did"].as_str().unwrap().to_owned(),
        jwt: v["accounts"][n]["accessJwt"].as_str().unwrap().to_owned(),
        space: v["accounts"][n]["space"].as_str().unwrap().to_owned(),
    };
    Some((
        v["pds"].as_str().unwrap().to_owned(),
        ["alice", "bob", "carol", "dave"].map(acct).to_vec(),
    ))
}

/// Plain HTTP XRPC as one account (the dev PDS's session JWT).
struct Http {
    base: String,
    jwt: String,
    agent: ureq::Agent,
}

impl Http {
    fn new(base: &str, jwt: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .proxy(None)
            .build()
            .into();
        Self {
            base: base.to_owned(),
            jwt: jwt.to_owned(),
            agent,
        }
    }

    fn finish(
        res: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<Vec<u8>, SpaceError> {
        let mut res = res.map_err(|e| SpaceError {
            status: 0,
            error: None,
            message: Some(e.to_string()),
        })?;
        let status = res.status().as_u16();
        let body = res.body_mut().read_to_vec().unwrap_or_default();
        if status < 300 {
            return Ok(body);
        }
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        Err(SpaceError {
            status,
            error: v["error"].as_str().map(str::to_owned),
            message: v["message"].as_str().map(str::to_owned),
        })
    }

    fn query_sync(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, SpaceError> {
        let mut req = self
            .agent
            .get(format!("{}/xrpc/{nsid}", self.base))
            .header("authorization", format!("Bearer {}", self.jwt));
        for (k, v) in params {
            req = req.query(*k, v);
        }
        Self::finish(req.call())
    }

    fn procedure_sync(&self, nsid: &str, payload: &[u8]) -> Result<Vec<u8>, SpaceError> {
        Self::finish(
            self.agent
                .post(format!("{}/xrpc/{nsid}", self.base))
                .header("authorization", format!("Bearer {}", self.jwt))
                .header("content-type", "application/json")
                .send(payload),
        )
    }
}

#[async_trait::async_trait]
impl SpaceRpc for Http {
    async fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>, SpaceError> {
        self.query_sync(nsid, params)
    }

    async fn procedure(&self, nsid: &str, payload: &[u8]) -> Result<Vec<u8>, SpaceError> {
        self.procedure_sync(nsid, payload)
    }
}

/// `mailboxKeys` in the public repo, over `com.atproto.repo.*` with `swapRecord` CAS.
struct PublicRepo {
    did: String,
    http: Http,
}

#[async_trait::async_trait]
impl PublicRepoBackend for PublicRepo {
    async fn put_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
        record: &[u8],
        swap_cid: Option<&str>,
    ) -> labyrinth::Result<String> {
        if did != self.did {
            return Err(Error::Forbidden);
        }
        let record: Value =
            serde_json::from_slice(record).map_err(|e| Error::Backend(e.to_string()))?;
        let mut body = json!({
            "repo": self.did,
            "collection": nsid::MAILBOX_KEYS,
            "rkey": rkey,
            "record": record,
            "validate": false,
        });
        if let Some(cid) = swap_cid {
            body["swapRecord"] = Value::String(cid.to_owned());
        }
        let out = self
            .http
            .procedure_sync(
                "com.atproto.repo.putRecord",
                &serde_json::to_vec(&body).unwrap(),
            )
            .map_err(|e| {
                if e.error.as_deref() == Some("InvalidSwap") {
                    Error::Conflict
                } else {
                    Error::Backend(format!("{e:?}"))
                }
            })?;
        let v: Value = serde_json::from_slice(&out).map_err(|e| Error::Backend(e.to_string()))?;
        Ok(v["cid"].as_str().unwrap_or_default().to_owned())
    }

    async fn get_mailbox_keys(
        &self,
        did: &str,
        rkey: &str,
    ) -> labyrinth::Result<Option<(Vec<u8>, String)>> {
        let p = [
            ("repo", did.to_owned()),
            ("collection", nsid::MAILBOX_KEYS.to_owned()),
            ("rkey", rkey.to_owned()),
        ];
        match self.http.query_sync("com.atproto.repo.getRecord", &p) {
            Ok(b) => {
                let v: Value =
                    serde_json::from_slice(&b).map_err(|e| Error::Backend(e.to_string()))?;
                let cid = v["cid"].as_str().unwrap_or_default().to_owned();
                Ok(Some((serde_json::to_vec(&v["value"]).unwrap(), cid)))
            }
            Err(e) if e.error.as_deref() == Some("RecordNotFound") => Ok(None),
            Err(e) => Err(Error::Backend(format!("{e:?}"))),
        }
    }

    async fn delete_all_mailbox_keys(&self, did: &str) -> labyrinth::Result<()> {
        if did != self.did {
            return Err(Error::Forbidden);
        }
        let p = [
            ("repo", self.did.clone()),
            ("collection", nsid::MAILBOX_KEYS.to_owned()),
            ("limit", "100".to_owned()),
        ];
        let b = self
            .http
            .query_sync("com.atproto.repo.listRecords", &p)
            .map_err(|e| Error::Backend(format!("{e:?}")))?;
        let v: Value = serde_json::from_slice(&b).map_err(|e| Error::Backend(e.to_string()))?;
        for r in v["records"].as_array().into_iter().flatten() {
            let rkey = r["uri"].as_str().unwrap().rsplit('/').next().unwrap();
            let body = json!({ "repo": self.did, "collection": nsid::MAILBOX_KEYS, "rkey": rkey });
            self.http
                .procedure_sync(
                    "com.atproto.repo.deleteRecord",
                    &serde_json::to_vec(&body).unwrap(),
                )
                .map_err(|e| Error::Backend(format!("{e:?}")))?;
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        1_791_000_000_000 + self.0.fetch_add(1, Ordering::Relaxed)
    }
}

fn signer(seed: u8) -> Ed25519Transport {
    Ed25519Transport(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
}

struct World {
    pds: String,
    net: MemoryBackend,
    clock: TestClock,
    sent: Vec<(String, String, Vec<u8>)>,
    ts: u64,
}

impl World {
    fn transport(&self, a: &Account) -> Arc<dyn SpaceRpc> {
        Arc::new(Http::new(&self.pds, &a.jwt))
    }

    fn public(&self, a: &Account) -> Arc<dyn PublicRepoBackend> {
        Arc::new(PublicRepo {
            did: a.did.clone(),
            http: Http::new(&self.pds, &a.jwt),
        })
    }

    fn mailbox(&self, a: &Account) -> SpaceMailboxStore {
        let store = SpaceMailboxStore::for_owner(
            &a.did,
            self.transport(a),
            Box::new(PdsPublisher::new(self.public(a), &a.did)),
        )
        .with_page_size(3);
        assert_eq!(store.space().to_string(), a.space);
        store
    }

    fn directory(&self, a: &Account) -> CompositeDirectory {
        CompositeDirectory::new(
            Box::new(PdsDirectory::new(self.public(a))),
            Box::new(self.net.ds_directory()),
        )
    }

    fn backends(&self, a: &Account) -> Backends {
        Backends {
            mailbox: Box::new(self.mailbox(a)),
            threads: Box::new(self.net.threads(&a.did)),
            directory: Box::new(self.directory(a)),
            publishers: vec![Box::new(self.net.ds_publisher(&a.did))],
            clock: Box::new(self.clock.clone()),
        }
    }

    fn chat_device(&self, a: &Account, seed: u8) -> Box<Ed25519Transport> {
        self.net
            .register_chat_device(&a.did, signer(seed).0.verifying_key().to_bytes());
        Box::new(signer(seed))
    }

    fn send(&mut self, lab: &mut Labyrinth, members: &[&str], id: &str) {
        self.ts += 10;
        let frame = format!("frame {id}").into_bytes();
        let roster = block_on(lab.resolve_roster(members)).unwrap();
        block_on(lab.archive_outgoing(THREAD, &roster, id, self.ts, &frame)).unwrap();
        self.sent.push((id.to_owned(), lab.did().to_owned(), frame));
    }

    fn expected(&self, ids: &[&str]) -> Vec<(String, Option<String>, Vec<u8>)> {
        ids.iter()
            .map(|id| {
                let (i, s, f) = self.sent.iter().find(|(i, ..)| i == id).unwrap();
                (i.clone(), Some(s.clone()), f.clone())
            })
            .collect()
    }
}

fn got(h: &labyrinth::client::ThreadHistory) -> Vec<(String, Option<String>, Vec<u8>)> {
    h.messages
        .iter()
        .map(|m| (m.message_id.clone(), m.sender.clone(), m.frame.clone()))
        .collect()
}

#[test]
#[ignore = "requires an explicitly provisioned local PDS and LABYRINTH_SPACE_PDS session file"]
fn lifecycle_on_a_live_space_pds() {
    let (pds, accts) =
        session().expect("LABYRINTH_SPACE_PDS must name the local test session file");
    let [alice_a, bob_a, carol_a, dave_a] = <[Account; 4]>::try_from(accts).unwrap();
    let mut w = World {
        pds,
        net: MemoryBackend::new(),
        clock: TestClock::default(),
        sent: Vec::new(),
        ts: 1_000,
    };

    // Enrollment writes the mailbox into Alice's Space on the PDS.
    let mut phone = block_on(Labyrinth::initialize(
        &alice_a.did,
        w.chat_device(&alice_a, 1),
        w.backends(&alice_a),
    ))
    .unwrap();
    let mut responder = phone.otc_offer().unwrap();
    let typed = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(&alice_a.did, &typed).unwrap();
    let reply = block_on(phone.otc_respond(&mut responder, &hello)).unwrap();
    let (mut laptop, _) = block_on(Labyrinth::enroll_via_otc(
        &alice_a.did,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        w.chat_device(&alice_a, 2),
        w.backends(&alice_a),
    ))
    .unwrap();
    let recovery = block_on(phone.create_recovery_code(Mechanism::Code)).unwrap();
    let mb = w.mailbox(&alice_a);
    assert_eq!(block_on(mb.list_devices()).unwrap().len(), 3);
    assert_eq!(block_on(mb.list_epochs()).unwrap().len(), 2);
    assert_eq!(block_on(mb.list_epoch_members(1)).unwrap().len(), 3);
    assert!(
        block_on(mb.get_virtual_device(&recovery.vdevice_id))
            .unwrap()
            .is_some()
    );
    // Create-if-absent on the real PDS.
    let dev = block_on(mb.list_devices()).unwrap().remove(0);
    assert_eq!(
        block_on(mb.create_device(&dev)).unwrap_err(),
        Error::Conflict
    );
    // mailboxKeys reached the public repo (Gate 3 rotated to epoch 1 on laptop enrollment).
    let pds_dir = PdsDirectory::new(w.public(&alice_a));
    assert_eq!(
        block_on(pds_dir.latest(&alice_a.did)).unwrap().unwrap().seq,
        1
    );

    let mut bob = block_on(Labyrinth::initialize(
        &bob_a.did,
        w.chat_device(&bob_a, 3),
        w.backends(&bob_a),
    ))
    .unwrap();
    let mut carol = block_on(Labyrinth::initialize(
        &carol_a.did,
        w.chat_device(&carol_a, 4),
        w.backends(&carol_a),
    ))
    .unwrap();
    let group = [
        alice_a.did.as_str(),
        bob_a.did.as_str(),
        carol_a.did.as_str(),
    ];
    w.send(&mut phone, &group, "a1");
    w.send(&mut bob, &group, "b1");
    w.send(&mut carol, &group, "c1");
    w.send(&mut laptop, &group, "a2");
    for lab in [&mut phone, &mut laptop, &mut bob, &mut carol] {
        block_on(lab.flush()).unwrap();
    }

    // Revocation (`#update` on the device record) opens epoch 2.
    w.net.remove_chat_device(
        &alice_a.did,
        signer(1).0.verifying_key().to_bytes(),
        w.ts + 1,
    );
    let phone_key = phone.device_public().device_key_pub;
    assert_eq!(
        block_on(laptop.revoke_device(&phone_key))
            .unwrap()
            .new_epoch,
        2
    );
    assert!(
        block_on(mb.get_device(&phone_key))
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert_eq!(
        block_on(pds_dir.latest(&alice_a.did)).unwrap().unwrap().seq,
        2
    );
    w.send(&mut laptop, &group, "a3");
    block_on(laptop.flush()).unwrap();

    // Restore from the code through the PDS (rotates to epoch 3) and read everything.
    let (mut alice, _) = block_on(Labyrinth::restore_with_recovery_code(
        &alice_a.did,
        recovery.code.as_str(),
        w.chat_device(&alice_a, 5),
        w.backends(&alice_a),
    ))
    .unwrap();
    let all = ["a1", "b1", "c1", "a2", "a3"];
    let h = block_on(alice.load_thread(THREAD, TimeRange::ALL)).unwrap();
    assert_eq!(got(&h), w.expected(&all));
    assert!(
        block_on(mb.get_virtual_device(&recovery.vdevice_id))
            .unwrap()
            .unwrap()
            .last_used_at
            .is_some()
    );

    // Carol's owner archive goes into her Space with PDS-assigned TIDs.
    assert_eq!(
        block_on(carol.rearchive_thread_before_leave(THREAD)).unwrap(),
        all.len()
    );
    assert_eq!(
        block_on(w.mailbox(&carol_a).list_owner_threads()).unwrap(),
        vec![THREAD.to_owned()]
    );
    w.net.revoke_thread_access(THREAD, &carol_a.did);
    let h = block_on(carol.load_thread(THREAD, TimeRange::ALL)).unwrap();
    assert!(h.messages.iter().all(|m| m.source == MessageSource::Owner));
    let frames: Vec<_> = h.messages.iter().map(|m| m.frame.clone()).collect();
    let want: Vec<_> = w.expected(&all).into_iter().map(|x| x.2).collect();
    assert_eq!(frames, want);

    // read_self only: Bob's session cannot read Alice's mailbox.
    let as_bob = SpaceMailboxStore::in_space_unchecked_for_test(
        SpaceRef::mailbox(&alice_a.did),
        w.transport(&bob_a),
        Box::new(PdsPublisher::new(w.public(&bob_a), &bob_a.did)),
    );
    assert!(block_on(as_bob.list_devices()).unwrap().is_empty());
    assert_eq!(
        block_on(as_bob.create_device(&dev)).unwrap_err(),
        Error::Forbidden
    );

    // Dave's Space exists but holds nothing.
    assert!(
        block_on(w.mailbox(&dave_a).list_devices())
            .unwrap()
            .is_empty()
    );

    // Removing the recovery method deletes its bundle; purge empties the
    // Space and the public mailboxKeys.
    block_on(alice.remove_recovery_method(&recovery.vdevice_id)).unwrap();
    assert!(
        block_on(mb.get_virtual_device(&recovery.vdevice_id))
            .unwrap()
            .is_none()
    );
    let report = block_on(alice.purge_account()).unwrap();
    assert!(report.remote_pending.is_none(), "{report:?}");
    assert!(block_on(mb.list_devices()).unwrap().is_empty());
    assert!(block_on(mb.list_epochs()).unwrap().is_empty());
    assert!(block_on(pds_dir.latest(&alice_a.did)).unwrap().is_none());
}

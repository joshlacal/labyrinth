//! The Space mailbox store against a real atproto PDS from the upstream
//! `permissioned-data` branch. Opt-in: it runs only when
//! `LABYRINTH_SPACE_PDS` names the session file written by
//! `scripts/space-pds/start.mjs`. Explicitly ignored without a live test run.
//!
//! ```bash
//! node scripts/space-pds/start.mjs ../atproto /tmp/space-pds.json &
//! LABYRINTH_SPACE_PDS=/tmp/space-pds.json \
//!   cargo test --release --features space --test live_space_pds -- --ignored --test-threads=1
//! ```
//!
//! Each run uses a fresh network (the accounts' mailboxes must start
//! empty). Mailboxes live in each account's personal Space and
//! `mailboxKeys` in its public repo, both on the PDS; threads, the ORF and
//! the mls-ds head directory stay on the memory backend.

#![cfg(feature = "space")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use labyrinth::Error;
use labyrinth::client::{Backends, Clock, CompositeDirectory, Labyrinth, MessageSource};
use labyrinth::records::nsid;
use labyrinth::sign::Ed25519Transport;
use labyrinth::store::memory::MemoryBackend;
use labyrinth::store::pds::{PdsDirectory, PdsPublisher, PdsRecords};
use labyrinth::store::space::{SpaceMailboxStore, SpaceRef};
use labyrinth::store::xrpc::{XrpcError, XrpcTransport};
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
    ) -> Result<Vec<u8>, XrpcError> {
        let mut res = res.map_err(|e| XrpcError {
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
        Err(XrpcError {
            status,
            error: v["error"].as_str().map(str::to_owned),
            message: v["message"].as_str().map(str::to_owned),
        })
    }
}

impl XrpcTransport for Http {
    fn query_with_headers(
        &self,
        nsid: &str,
        params: &[(&str, String)],
        headers: &[(String, String)],
    ) -> Result<Vec<u8>, XrpcError> {
        let mut req = self
            .agent
            .get(format!("{}/xrpc/{nsid}", self.base))
            .header("authorization", format!("Bearer {}", self.jwt));
        for (k, v) in params {
            req = req.query(*k, v);
        }
        for (k, v) in headers {
            req = req.header(k, v);
        }
        Self::finish(req.call())
    }

    fn procedure(&self, nsid: &str, payload: &[u8], _op: [u8; 16]) -> Result<Vec<u8>, XrpcError> {
        Self::finish(
            self.agent
                .post(format!("{}/xrpc/{nsid}", self.base))
                .header("authorization", format!("Bearer {}", self.jwt))
                .header("content-type", "application/json")
                .send(payload),
        )
    }
}

/// `mailboxKeys` in the public repo, over `com.atproto.repo.*`.
struct PublicRepo {
    did: String,
    http: Http,
}

impl PdsRecords for PublicRepo {
    fn put_mailbox_keys(&self, rkey: &str, record: &[u8]) -> Result<(), String> {
        let record: Value = serde_json::from_slice(record).map_err(|e| e.to_string())?;
        let body = json!({
            "repo": self.did, "collection": nsid::MAILBOX_KEYS, "rkey": rkey,
            "record": record, "validate": false,
        });
        self.http
            .procedure(
                "com.atproto.repo.putRecord",
                &serde_json::to_vec(&body).unwrap(),
                [0; 16],
            )
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }

    fn get_mailbox_keys(&self, did: &str, rkey: &str) -> Result<Option<Vec<u8>>, String> {
        let p = [
            ("repo", did.to_owned()),
            ("collection", nsid::MAILBOX_KEYS.to_owned()),
            ("rkey", rkey.to_owned()),
        ];
        match self.http.query("com.atproto.repo.getRecord", &p) {
            Ok(b) => {
                let v: Value = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
                Ok(Some(serde_json::to_vec(&v["value"]).unwrap()))
            }
            Err(e) if e.error.as_deref() == Some("RecordNotFound") => Ok(None),
            Err(e) => Err(format!("{e:?}")),
        }
    }

    fn delete_all_mailbox_keys(&self) -> Result<(), String> {
        let p = [
            ("repo", self.did.clone()),
            ("collection", nsid::MAILBOX_KEYS.to_owned()),
            ("limit", "100".to_owned()),
        ];
        let b = self
            .http
            .query("com.atproto.repo.listRecords", &p)
            .map_err(|e| format!("{e:?}"))?;
        let v: Value = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
        for r in v["records"].as_array().into_iter().flatten() {
            let rkey = r["uri"].as_str().unwrap().rsplit('/').next().unwrap();
            let body = json!({ "repo": self.did, "collection": nsid::MAILBOX_KEYS, "rkey": rkey });
            self.http
                .procedure(
                    "com.atproto.repo.deleteRecord",
                    &serde_json::to_vec(&body).unwrap(),
                    [0; 16],
                )
                .map_err(|e| format!("{e:?}"))?;
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
    fn transport(&self, a: &Account) -> Arc<dyn XrpcTransport> {
        Arc::new(Http::new(&self.pds, &a.jwt))
    }

    fn public(&self, a: &Account) -> Arc<dyn PdsRecords> {
        Arc::new(PublicRepo {
            did: a.did.clone(),
            http: Http::new(&self.pds, &a.jwt),
        })
    }

    fn mailbox(&self, a: &Account) -> SpaceMailboxStore {
        let store = SpaceMailboxStore::new(
            &a.did,
            self.transport(a),
            Box::new(PdsPublisher::new(&a.did, self.public(a))),
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
            orf: Box::new(self.net.orf(&a.did)),
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
        let roster = lab.resolve_roster(members).unwrap();
        lab.archive_outgoing(THREAD, &roster, id, self.ts, &frame)
            .unwrap();
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
    let mut phone = Labyrinth::initialize(
        &alice_a.did,
        w.chat_device(&alice_a, 1),
        w.backends(&alice_a),
    )
    .unwrap();
    let mut responder = phone.otc_offer().unwrap();
    let typed = responder.code().as_str().to_owned();
    let (initiator, hello) = Labyrinth::otc_start(&alice_a.did, &typed).unwrap();
    let reply = phone.otc_respond(&mut responder, &hello).unwrap();
    let (mut laptop, _) = Labyrinth::enroll_via_otc(
        &alice_a.did,
        initiator,
        &reply.message,
        &reply.sealed_payload,
        w.chat_device(&alice_a, 2),
        w.backends(&alice_a),
    )
    .unwrap();
    let recovery = phone.create_recovery_code(Mechanism::Code).unwrap();
    let mb = w.mailbox(&alice_a);
    assert_eq!(mb.list_devices().unwrap().len(), 3);
    assert_eq!(mb.list_epochs().unwrap().len(), 1);
    assert_eq!(mb.list_epoch_members(0).unwrap().len(), 3);
    assert!(
        mb.get_virtual_device(&recovery.vdevice_id)
            .unwrap()
            .is_some()
    );
    // Create-if-absent on the real PDS.
    let dev = mb.list_devices().unwrap().remove(0);
    assert_eq!(mb.create_device(&dev).unwrap_err(), Error::Conflict);
    // mailboxKeys reached the public repo.
    let pds_dir = PdsDirectory::new(w.public(&alice_a));
    assert_eq!(pds_dir.latest(&alice_a.did).unwrap().unwrap().seq, 0);

    let mut bob =
        Labyrinth::initialize(&bob_a.did, w.chat_device(&bob_a, 3), w.backends(&bob_a)).unwrap();
    let mut carol = Labyrinth::initialize(
        &carol_a.did,
        w.chat_device(&carol_a, 4),
        w.backends(&carol_a),
    )
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
        lab.flush().unwrap();
    }

    // Revocation (`#update` on the device record) and a new epoch.
    w.net.remove_chat_device(
        &alice_a.did,
        signer(1).0.verifying_key().to_bytes(),
        w.ts + 1,
    );
    let phone_key = phone.device_public().device_key_pub;
    assert_eq!(laptop.revoke_device(&phone_key).unwrap().new_epoch, 1);
    assert!(
        mb.get_device(&phone_key)
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert_eq!(pds_dir.latest(&alice_a.did).unwrap().unwrap().seq, 1);
    w.send(&mut laptop, &group, "a3");
    laptop.flush().unwrap();

    // Restore from the code through the PDS and read everything.
    let (mut alice, _) = Labyrinth::restore_with_recovery_code(
        &alice_a.did,
        recovery.code.as_str(),
        w.chat_device(&alice_a, 5),
        w.backends(&alice_a),
    )
    .unwrap();
    let all = ["a1", "b1", "c1", "a2", "a3"];
    let h = alice.load_thread(THREAD, TimeRange::ALL).unwrap();
    assert_eq!(got(&h), w.expected(&all));
    assert!(
        mb.get_virtual_device(&recovery.vdevice_id)
            .unwrap()
            .unwrap()
            .last_used_at
            .is_some()
    );

    // Carol's owner archive goes into her Space with PDS-assigned TIDs.
    assert_eq!(
        carol.rearchive_thread_before_leave(THREAD).unwrap(),
        all.len()
    );
    assert_eq!(
        w.mailbox(&carol_a).list_owner_threads().unwrap(),
        vec![THREAD.to_owned()]
    );
    w.net.revoke_thread_access(THREAD, &carol_a.did);
    let h = carol.load_thread(THREAD, TimeRange::ALL).unwrap();
    assert!(h.messages.iter().all(|m| m.source == MessageSource::Owner));
    // Owner copies carry no sender DID (README, owner-mode records).
    let frames: Vec<_> = h.messages.iter().map(|m| m.frame.clone()).collect();
    let want: Vec<_> = w.expected(&all).into_iter().map(|x| x.2).collect();
    assert_eq!(frames, want);

    // read_self only: Bob's session cannot read Alice's mailbox.
    let as_bob = SpaceMailboxStore::in_space(
        SpaceRef::mailbox(&alice_a.did),
        w.transport(&bob_a),
        Box::new(PdsPublisher::new(&bob_a.did, w.public(&bob_a))),
    );
    assert!(as_bob.list_devices().unwrap().is_empty());
    assert_eq!(as_bob.create_device(&dev).unwrap_err(), Error::Forbidden);

    // Dave's Space exists but holds nothing.
    assert!(w.mailbox(&dave_a).list_devices().unwrap().is_empty());

    // Removing the recovery method deletes its bundle; purge empties the
    // Space and the public mailboxKeys.
    alice.remove_recovery_method(&recovery.vdevice_id).unwrap();
    assert!(
        mb.get_virtual_device(&recovery.vdevice_id)
            .unwrap()
            .is_none()
    );
    let report = alice.purge_account().unwrap();
    assert!(report.remote_pending.is_none(), "{report:?}");
    assert!(mb.list_devices().unwrap().is_empty());
    assert!(mb.list_epochs().unwrap().is_empty());
    assert!(pds_dir.latest(&alice_a.did).unwrap().is_none());
}

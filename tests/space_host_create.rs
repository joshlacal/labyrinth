//! The in-memory Space host answers `com.atproto.space.createSpace` the way a PDS does,
//! so a client that creates its mailbox Space can be tested against it.

use futures::executor::block_on;
use labyrinth::store::space::host::MemorySpaceHost;
use labyrinth::store::space::{MAILBOX_SKEY, MAILBOX_SPACE_TYPE, SpaceRpc, endpoint};
use serde_json::{Value, json};

const ALICE: &str = "did:plc:alice";

fn create(host: &MemorySpaceHost, body: Value) -> Result<Value, (u16, Option<String>)> {
    let client = host.client(ALICE);
    block_on(client.procedure(endpoint::CREATE_SPACE, &serde_json::to_vec(&body).unwrap()))
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .map_err(|e| (e.status, e.error))
}

fn personal_mailbox() -> Value {
    json!({
        "spaceType": MAILBOX_SPACE_TYPE,
        "skey": MAILBOX_SKEY,
        "policy": { "$type": "com.atproto.personalspace.policy" },
    })
}

#[test]
fn create_space_makes_the_caller_the_authority_and_refuses_a_second_create() {
    let host = MemorySpaceHost::default();

    let created = create(&host, personal_mailbox()).expect("first create succeeds");
    assert_eq!(
        created,
        json!({ "space": format!("at:space/{ALICE}/{MAILBOX_SPACE_TYPE}/{MAILBOX_SKEY}") })
    );

    assert_eq!(
        create(&host, personal_mailbox()),
        Err((400, Some("SpaceAlreadyExists".to_owned())))
    );
}

#[test]
fn create_space_without_a_key_generates_one() {
    let host = MemorySpaceHost::default();
    let body = json!({
        "spaceType": MAILBOX_SPACE_TYPE,
        "policy": { "$type": "com.atproto.memberspace.policy" },
    });

    let first = create(&host, body.clone()).expect("create without skey");
    let second = create(&host, body).expect("each keyless create is a new Space");

    assert_ne!(first["space"], second["space"]);
}

#[test]
fn create_space_refuses_a_policy_it_does_not_know() {
    let host = MemorySpaceHost::default();
    let body = json!({
        "spaceType": MAILBOX_SPACE_TYPE,
        "skey": MAILBOX_SKEY,
        "policy": { "$type": "com.example.policy" },
    });

    assert_eq!(
        create(&host, body),
        Err((400, Some("UnsupportedPolicy".to_owned())))
    );
}

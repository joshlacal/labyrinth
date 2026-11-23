# Integrating Labyrinth

This chapter walks through using the `labyrinth` crate from an MLS chat client. Catbird's own integration, in [`catbird-mls`](https://github.com/joshlacal/catbird-mls), is the reference: it wires Labyrinth into the MLS send and receive paths and exposes it to Swift, Kotlin and the web.

## What you provide

`Labyrinth` is generic over storage and identity. You give it:

| Input | Type | What it is |
|---|---|---|
| The account's DID | `&str` | `did:plc:…` or `did:web:…` |
| A transport signer | `Box<dyn TransportSigner>` | The device's MLS chat key: an Ed25519 key already registered with the delivery service. It signs archived messages and epoch-head attestations. |
| Backends | `Backends` | Where the mailbox, conversation archives and directory live, and a clock |

```rust
pub trait TransportSigner {
    fn transport_public_key(&self) -> [u8; 32];
    fn sign_transport(&self, msg: &[u8]) -> [u8; 64];
}

pub struct Backends {
    pub mailbox: Box<dyn MailboxStore>,       // the account's personal mailbox Space
    pub threads: Box<dyn ThreadStore>,        // conversation Spaces
    pub directory: Box<dyn MailboxDirectory>, // peers' epoch heads and chat-device keys
    pub publishers: Vec<Box<dyn KeyPublisher>>, // where this account's heads are published
    pub clock: Box<dyn Clock>,
}
```

See [Storage backends](storage-backends.md) for each trait and the implementations that ship with the crate.

## A first run on the memory backend

`MemoryBackend` is an in-process network of mailboxes, conversations and a directory. It is meant for tests and for learning the API.

```rust
use labyrinth::client::{Backends, Labyrinth, SystemClock};
use labyrinth::store::{memory::MemoryBackend, TimeRange};

let net = MemoryBackend::new();
let backends = |did: &str| Backends {
    mailbox: Box::new(net.mailbox(did)),
    threads: Box::new(net.threads(did)),
    directory: Box::new(net.directory()),
    publishers: vec![],
    clock: Box::new(SystemClock),
};

// Inside an async fn. `transport` is the device's MLS chat key, registered with the directory.
let mut alice = Labyrinth::initialize("did:plc:alice", Box::new(transport), backends("did:plc:alice")).await?;
let roster = alice.resolve_roster(&["did:plc:alice", "did:plc:bob"]).await?;
alice.archive_outgoing("conv-1", &roster, "msg-1", now_ms, frame).await?;
alice.flush().await?;
let history = alice.load_thread("conv-1", TimeRange::ALL).await?;
```

`tests/e2e_memory.rs` is the complete worked example, with several accounts and devices.

## The client lifecycle

### Start a session

- `Labyrinth::initialize(did, transport, backends)` creates a new mailbox for an account that has none: a genesis device, epoch 0 and the public `mailboxKeys` record. It fails with `Conflict` if the mailbox already has an epoch 0. An account's later devices join through a one-time code or a recovery method instead (see below).
- Creating epoch 0 is the point of no return, so a failure to publish afterwards does not fail `initialize`. Use `initialize_with_report` to see such a failure, and retry with `finish_initialize`.
- `Labyrinth::from_state(bytes, did, transport, backends)` resumes from a saved state.
- `export_state()` returns that state. **It contains private keys, epoch roots and MEKs** ([CB-30]). Store it only in the platform keychain or an encrypted database. A `StateSink` (`save_state(&self, &[u8])`) lets the client checkpoint itself before operations that must not be lost, such as revocation.

Call `sync_epochs()` when a session opens. It forward-chains to the newest epoch this device belongs to, retries publication of any pending head ([CB-19]) and reports a squatted next epoch rather than looping.

### Send

For each outgoing MLS application message:

1. `resolve_roster(&member_dids)` resolves the Labyrinth-enrolled members of the MLS group to verified epoch heads. Pass every member DID, including your own. Accounts that haven't enrolled are left out.
2. `archive_outgoing(...)`, or `archive_outgoing_committed(...)` when the message carries an `I13` archive commitment and sequencer receipt, queues the frame. A changed roster mints a new MEK.
3. `flush()` writes queued batches. Flush on a timer and before the app is suspended.

### Read

- `list_threads()` lists the conversations this account has history in.
- `load_thread_page(thread_id, cursor)` returns history newest-first, one page at a time; `load_thread(thread_id, range)` loads a time range; `load_message(thread_id, message_id)` loads one.
- Each result is a `ThreadHistory`. `messages` are verified and safe to show. `rejected` holds witness copies that contradict an accepted copy, and `quarantined` names authors whose records failed checks; never show either to the user. `space_readable` is false when the conversation Space refused the read, in which case only owner-archived copies are included.

### Devices

- `rotate_epoch()` opens a new epoch with the current members.
- `revoke_device(&device_key)` opens a new epoch without that device. The returned `RotationReport` lists any members excluded by the audit ([Devices, epochs and revocation](../overview/keys-and-epochs.md)).
- `safety_number_with(did)` returns a fingerprint to compare out of band.

### Recovery and new devices

| Call | When |
|---|---|
| `create_recovery_code(mechanism)` | Show the user a recovery code |
| `create_passkey_recovery(...)` | Store the code under a passkey's PRF output |
| `restore_with_recovery_code(...)`, `restore_with_recovery_code_shared(...)` | Restore on a device with no state; the `_shared` form takes the server-held share for version-3 codes |
| `restore_with_passkey(...)` | Restore with a passkey |
| `otc_offer`, `otc_respond`, `otc_start`, `enroll_via_otc` | Add a device with a one-time code shown on the new device |
| `list_recovery_methods`, `touch_recovery_method`, `remove_recovery_method` | Manage virtual devices and their staleness |

See [Recovery](../overview/recovery.md) for what each method guarantees.

### Deletion

- `delete_for_me(...)` hides a message on this account's devices.
- `unsend(thread_id, message_id)` writes an author redaction that every honest reader applies.
- `purge_account()` deletes the account's own conversation records, retracts its published heads and purges its mailbox.

See [Deletion](../overview/deletion.md) for the limits.

## Errors you should handle

| Error | Meaning | What to do |
|---|---|---|
| `DirectoryIncomplete`, `DirectoryFork` | The PDS and mls-ds disagree on a peer's epoch head | Don't archive to that peer; retry later. A persistent fork is worth surfacing. |
| `EpochRollback` | A directory served an older head than this device pinned | Treat as an attack or a stale cache; don't accept it. |
| `EpochSquatted { seq, reason }` | A record blocks the next epoch number | Call `clear_squatted_epoch` from an active device if the reason allows. |
| `MemberTampered`, `Unattested` | A rotation audit failed | Stop and surface the error. |
| `WriterRollback` | A Space served an older revision of a writer's repo than this device saw | Retry; don't accept the older data. |
| `RecoveryShareUnavailable` | A version-3 code's server share is gone | The code can't restore; there is no fallback. |
| `Forbidden` (from a `ThreadStore`) | The Space refused this account | The client falls back to owner archiving automatically. |

The full list is the `Error` enum in the [API reference](../reference/api.md).

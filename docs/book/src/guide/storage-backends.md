# Storage backends

`Labyrinth` reaches storage only through five traits, gathered in `Backends`. Each is an `async_trait`; on `wasm32` they are `?Send`.

| Trait | Holds | Shipped implementations |
|---|---|---|
| `MailboxStore` | The account's personal mailbox: devices, epochs and their members, virtual devices (recovery bundles), one-time-code sessions, owner batches, read state, circle owner state | `SpaceMailboxStore` (a personal Space on the owner's PDS); `MemoryBackend::mailbox` |
| `ThreadStore` | Conversation archives: MEKs, sender and witness batches, author redactions, attachment manifests | `SpaceThreadStore` (conversation Spaces); `MemoryBackend::threads` |
| `MailboxDirectory` | Peers' public epoch heads, chat-device key history, per-conversation leaf history, sequencer receipt keys | `CompositeDirectory` (PDS × mls-ds), `PdsDirectory`; memory directories for tests |
| `KeyPublisher` | Where this account publishes its own heads | `PdsPublisher` (the public `mailboxKeys` record); memory publishers for tests |
| `Clock` | Milliseconds since the Unix epoch | `SystemClock` |

The mls-ds side of the directory, and the XRPC transport for Spaces, are implemented by the application. Catbird's are in `catbird-mls` (`src/labyrinth/`).

## `MailboxStore`

The required methods cover devices (`create_device`, `get_device`, `list_devices`, `set_device_revoked`), epochs (`create_epoch`, `get_epoch`, `list_epochs`, `create_epoch_member`, `list_epoch_members`), the single-write enrollment bundle (`atomic_enroll`), virtual devices, owner batches (`append_owner_batch`, `list_owner_batches`) and `publish_mailbox_keys`. Methods with default bodies (one-time-code sessions, read and circle state, attachments in the owner archive, `delete_squatted_epoch`, `purge_mailbox`, `delete_account_data`) return `NotSupported` unless the backend implements them.

**Requirements an implementation must meet:**

- `create_epoch` and `create_device` are **create-if-absent**: writing an existing record key fails with `Conflict`. Epoch numbers are claimed this way.
- `atomic_enroll` writes the device, epoch, members and bundle update in one transaction. `SpaceMailboxStore` uses a single `com.atproto.space.applyWrites`.
- Reads return bytes as stored. The client verifies signatures, MACs and CIDs itself, so a backend must not re-encode records.

## `ThreadStore`

Required: `create_mek`, `find_meks`, `append_batch`, `list_batches`, `get_messages`. Optional, with defaults: `list_threads`, `redact_item` (author redactions), `upload_and_commit_attachment` and `get_attachment_verified`, `list_own_attachment_manifests`, `clear_records`.

A `ThreadStore` returns `Forbidden` **only** when the Space really refused the account. The client treats `Forbidden` as removal and switches to owner archiving, so mapping a network error or a missing Space to `Forbidden` would wrongly divert history.

The `*_quarantined` variants return records that failed to parse instead of dropping them, so readers can report tampering.

## `MailboxDirectory`

```rust
async fn latest(&self, did: &str) -> Result<Option<EpochPublic>>;
async fn epoch(&self, did: &str, seq: u64) -> Result<Option<EpochPublic>>;
async fn device_transport_keys(&self, did: &str) -> Result<Vec<ChatDeviceKey>>;
// plus epoch_chain, member_device_keys and the sequencer_receipt_key_* lookups
```

Production clients should use **`CompositeDirectory::new(pds, ds)`**, which requires the public PDS and mls-ds to return identical heads. `CompositeDirectory::new_allowing_single_source` accepts a head from one source when the other has none; it is a trust-on-first-use fallback that lets the single source choose a peer's first-contact epoch, and is not recommended.

Chat-device and member-device key lists must be **complete histories, including revoked keys**. The client uses them to decide whether a device was a member when an old message was sent ([CB-27]).

## The Space stores

```rust
let mailbox = SpaceMailboxStore::new(transport.clone(), SpaceRef::mailbox(did), did)
    .with_key_publisher(Box::new(PdsPublisher::new(public_repo, did)));
let threads = SpaceThreadStore::new(transport, did);
```

`transport` implements `SpaceRpc`: `query`, `query_with_headers` and `procedure` for `com.atproto.space.*`, plus Space-scoped blob upload and download. The store handles record keys, writer-revision floors (`WriterRollback`), CID checks and pagination.

`SpaceRef::mailbox(did)` names `at:space/<did>/blue.catbird.labyrinth.mailbox/self`. `SpaceRef::conversation(authority_did, skey)` names a conversation Space, `{conversationId}-{generation}` under the sequencer's DID.

## The memory backend

`MemoryBackend` keeps everything in process. Besides tests, it is useful for fault injection: `tests/fault_lines.rs` and `tests/mek_tamper.rs` show a backend that tampers with, withholds and replays records. `MemorySpaceHost` (`src/store/space/host.rs`) is a reference Space host that `tests/e2e_space.rs` drives through `SpaceRpc`, validating each call against the vendored upstream `com.atproto.space.*` lexicons.

# The mls-ds backend for Labyrinth (design)

**What this is.** This crate implements Labyrinth 1.1, Meta's protocol for encrypted chat *history*, in a Catbird profile (see `docs/SPEC.md`). It talks to storage only through three synchronous traits: `MailboxStore`, `ThreadStore` and `MailboxDirectory` (`src/store/mod.rs`). Today the only implementation is in memory. This document designs a second backend inside `mls-ds`, Catbird's Rust/Axum MLS delivery service (DS), along with the client store that talks to it. The design also closes the three residual risks left after the 2026-10-04 security review (SPEC §10; DECISIONS "security review fixes"). **Status:** the crate side (the trait changes in §6, `CompositeDirectory`, and the `xrpc` feature with a memory-backed reference server) is built; see DECISIONS "mls-ds backend (design Y1–Y8)" for where it deviates. The mls-ds server side is not built. The decisions in §6 are provisional (Yellow tier) and can be overridden before the `labyrinth-1.1` bookmark merges.

All mls-ds references point at the merged line in `/Users/joshlacalamito/Developer/.workspaces/mls-ds-line-merge-20261004/mls-ds/`. Paths are relative to its `server/` directory.

Glossary:
- **MEK** (message encryption key): the per-roster key that senders use to encrypt history.
- **Epoch head**: the hash that commits to a mailbox's public keys for one epoch.
- **Sequencer DS**: the delivery service that orders a conversation's entries.
- **Chat device key**: the Ed25519 key that mls-ds registers per device in `chat.device_keys`. It is Labyrinth's "transport key" ([CB-3]).

---

## 1. Goal, and the three residuals it closes

mls-ds becomes a full Labyrinth storage backend:
- a personal mailbox per DID;
- one sender-record store per conversation ([CB-15], [CB-21]);
- the ORF server role ([CB-17]; ORF is the oblivious function that indexes attachments);
- an **independent, verifying directory** of every enrolled DID's epoch heads.

The directory and the server-assigned ordering are what fix the residuals. Atproto Spaces cannot provide either.

### 1a. [CB-29] first-contact TOFU becomes an mls-ds-verified head with a cross-check

Today a sender who has never addressed a DID accepts any epoch attested by one of that DID's current chat devices. A PDS that replays an old `mailboxKeys` record goes undetected.

**Design.** mls-ds keeps an append-only table `labyrinth.epoch_heads` (§4) with one row per `(did, epochNumber)`. On `publishEpochHead`, and implicitly inside `createEpoch`, mls-ds accepts an `epochPublic` only if all of these hold:

1. `epochNumber` is 0 with no prior row, or exactly the stored latest + 1. Contiguity guarantees that `getEpochHead(did, n)` can serve every step of a client's `prev_sig` walk (`src/client/pins.rs:57`).
2. `previousEpochHead` equals the stored head of `n-1`.
3. Recomputing `epochHash`/`epochHead` per SPEC §5.3 yields `epochHead`. This needs only sha256 and hex.
4. The [CB-18] attestation verifies as Ed25519 over `"catbird.labyrinth.epoch_head_attest:" || did || ":" || epochHead`.
5. The attesting key is the `signing_public_key` of a `chat.device_keys` row for `did` with `revoked_at IS NULL` and `chat.devices.status='active'`. Those tables are at `migrations/20260722000001_chat_protocol_core.sql:305` and `:337`.
6. The caller is a chat device of `did`, and the attesting key is the caller's own key.

Who may publish depends on where the DID's mailbox lives:
- **Mailbox in mls-ds** (the DID has a `labyrinth.mailboxes` row): the caller must be a bound device, and the head must be an epoch the mailbox already holds. `publishEpochHead` only re-publishes.
- **Mailbox in a Space** (no row): mls-ds holds nothing to compare against, so it records the head itself under checks 1–6. No binding is needed, and `deleteOrfState` likewise needs none. A compromised chat device of the DID could publish the next head first, but that is the same reach it already has over the DID's chat, and the client sees it as a `DirectoryFork` against the PDS head.

Re-sending identical bytes for an existing `(did, n)` succeeds. Different bytes fail with `EpochHeadConflict`. mls-ds does **not** verify the XEdDSA `selfSig`/`prevSig`, because clients already verify them (`src/client/pins.rs:79-92`). Checks 1–5 are enough to make the server-side head chain monotone and anchored to live MLS identity.

**How it is served.** Each `participantView` in `blue.catbird.chat.getConversationState` gains an optional `labyrinthHead` field: `{epochNumber, epochHead, attestationKeyId}`. The participant view is defined at `lexicon/blue/catbird/chat/blue.catbird.chat.defs.json:765` and projected through `load_conversation_state_source` (`src/chat_protocol/repository/inventory.rs:5819`, participants query at `:5883`). The full record comes from `blue.catbird.labyrinth.getEpochHead`.

**How clients verify.** When a client resolves a roster, it first runs the usual [CB-18] check: the head verifies, and its attestation key is a current chat device of the DID according to `getChatDeviceKeys`. Then it compares the mls-ds head with the PDS `mailboxKeys/self` head:
- if they are equal, accept;
- if one is newer, accept the newer one only if the `prev_sig` chain from the older one verifies;
- if they fork, fail with a new `Error::DirectoryFork`.

The client pins whatever it accepted, as it does today.

**What remains.** First contact is now protected unless mls-ds and the peer's PDS collude. mls-ds alone cannot roll a DID back, because the chain is append-only and enforced by the server. A PDS alone cannot roll it back either, because the client cross-checks. Fully MLS-authenticated heads, carried in the group context, stay future work (SPEC §5.3 "long-term plan").

### 1b. [CB-27] sender-chosen timestamps become server-assigned order

**Design.** Every `mek` and `batch` row gets a server stamp `{seq, chatSeq, receivedAt}` when it is written:
- `seq` is a per-conversation Labyrinth counter.
- `receivedAt` is the request's `TrustedRequestInstant`. That is the single server-clock instant captured once per request (`src/chat_protocol/validation.rs:283-286`, captured in `src/handlers/chat/context.rs:62-67`).
- `chatSeq` is the conversation's last chat entry seq. It is read under `SELECT next_entry_seq FROM chat.conversations … FOR SHARE`. The chat append path takes `FOR UPDATE` on the same row (`src/chat_protocol/repository/delivery.rs:113-194`), so Labyrinth writes are linearized against MLS entries.

**Write-time guards.** mls-ds already refuses requests from revoked devices: `lock_device_and_key` requires `devices.status='active'` and `device_keys.revoked_at IS NULL` (`src/chat_protocol/repository/auth.rs:3364`). On top of that, mls-ds requires:
- every item's `senderTransportPubkey` equals the writing device's own chat key;
- the writing device has an active leaf in the conversation (`chat.member_devices.active`, `core.sql:1013`);
- for a Labyrinth MEK, `senderEpoch.attestation.transportPubkey` is a current key of the sender DID;
- for a transport MEK, `transportPubkey` is the writer's own key.

**How readers use the stamp.** The reader replaces the sender timestamp with the stamp when it applies the removed-key bound:
- **Account-wide revocation:** a key revoked at `revokedAt` vouches for a record only if `record.receivedAt < revokedAt`. Both times come from the same DS clock when the device's home DS is also the sequencer.
- **Removal from this conversation's group:** a key whose leaf was removed at `removed_seq` vouches only if `record.chatSeq < removed_seq`. The per-leaf `joined_seq`/`removed_seq` values are in `chat.member_devices` (`core.sql:1013`). These are needed because `revokeDevice` does **not** remove leaves (`apply_device_revocation`, `src/chat_protocol/state_machine/executor.rs:4735-4747`).

A backdated message from a stolen device now fails the check, because the server stamped it after the revocation or removal. Records without a stamp (the Space backend) keep the current behaviour, which uses the sender timestamp.

**What remains.** Readers trust mls-ds's stamps. mls-ds is already trusted to sequence MLS, so this adds no new trust party. Under federation, account revocation and receipt can come from two DSes' clocks. Leaf removal by `chatSeq` has no clock problem.

### 1c. [CB-28] epoch truncation is checked against an independent directory

`check_integrity` (`src/client/epochs.rs:107`) is only as strong as the independence of the directory from the mailbox. The client gets a `CompositeDirectory` that reports the verified newest head across two sources: the PDS `mailboxKeys/self` record and mls-ds `epoch_heads`. Which source supplies the independence depends on where the mailbox lives:
- **Mailbox in a Space:** mls-ds is the independent source, because a PDS cannot truncate what mls-ds has recorded.
- **Mailbox in mls-ds:** `createEpoch` writes `epoch_heads` in the same transaction, so mls-ds is *not* independent of itself. The PDS record ([CB-19]) is the independent source, and the client **must keep publishing it**.

Either way, truncation now requires both parties to collude, which is the paper's stated limit.

## 2. XRPC surface: `blue.catbird.labyrinth.*`

Stored payloads reuse the existing record lexicons in `lexicons/blue/catbird/labyrinth/`. New query and procedure lexicons sit beside them. Every list returns `{items, cursor?}` with at most 100 items per page. Server stamps use one new def: `defs#serverOrder {seq, chatSeq?, receivedAt}`.

Errors common to every endpoint: `NotAuthorized`, `AccountSessionExpired`, `DeviceRevoked`, `RateLimited`, `InvalidRequest`, `PayloadTooLarge`, `QuotaExceeded`. The store maps `RecordAlreadyExists` to `Error::Conflict`, `NotAuthorized`/`NotRecipient` to `Error::Forbidden`, and everything else to `Error::Backend`.

### Mailbox (`MailboxStore`; caller = a chat device of the mailbox owner)

| NSID | Kind | Input → output | Extra errors |
|---|---|---|---|
| `createDevice` | proc | `{record: device}` → `{rkey}` (hex deviceKey) | `RecordAlreadyExists` |
| `markDeviceRevoked` | proc | `{deviceKeyPubkey, revokedAt}` → `{}`; idempotent; deletes that device's ORF state in the same transaction | `DeviceNotFound` |
| `getDevice` / `listDevices` | query | `deviceKeyPubkey` / cursor → `device` records | — |
| `createEpoch` | proc | `{epoch, members: epochMember[] (≤256)}` → `{epochId, epochNumber}`, atomic; also records the head (§1a) | `RecordAlreadyExists` (epoch number taken: the [CB-9] race guard), `InvalidEpochChain`, `AttestationNotCurrent` |
| `getEpoch` / `listEpochs` | query | `epochNumber` / cursor → `{epochId, record}` ascending | — |
| `createEpochMember` / `listEpochMembers` | proc / query | `epochMember` / `epochNumber` | `RecordAlreadyExists`, `EpochNotFound` |
| `createVirtualDevice` | proc | `{record: virtualDevice, member: epochMember, orf: {parentDeviceKey, evolveToken}}` → `{}`; also registers the ORF state | `RecordAlreadyExists` |
| `getVirtualDevice` / `listVirtualDevices` | query | `vdeviceId` / cursor | — |
| `appendOwnerBatch` | proc | `{record: ownerBatch}` → `{rkey (TID), order}` | — |
| `listOwnerBatches` | query | `threadId, fromMs?, untilMs?, cursor` → `{rkey, record, order}[]` | — |

`epochId` is the decimal value of a `bigserial` row id ([CB-9], SPEC §5.1).

**Restore auth.** Before restoring, a new install enrolls as a chat device of the DID through the normal `blue.catbird.chat.enrollDevice` flow. Its owner credential then reads the bundle by `vdeviceId`. The bundle is sealed under the recovery code (about 170 bits of entropy), so owner-only reads plus per-DID rate limits are enough. The client sends the evolve token from `Enrollment` (`src/client/enroll.rs:28`) through `registerOrfState`.

### Thread (`ThreadStore`; `threadId` = `chat.conversations.conversation_id`, a UUID, [CB-2])

| NSID | Kind | Input → output | Extra errors |
|---|---|---|---|
| `createMek` | proc | `{record: mek}` → `{rkey, order}` | `RecordAlreadyExists`, `NotParticipant`, `RecipientNotParticipant`, `SenderMismatch`, `AttestationNotCurrent` |
| `findMeks` | query | `threadId, mekId` → `{author, rkey, record, order}[]`; returns only MEKs the caller wrote or is a recipient of | `NotRecipient` |
| `appendBatch` | proc | `{record: batch}` → `{rkey, order}` | `NotParticipant`, `UnknownMek`, `MixedMekBatch`, `SenderKeyMismatch` |
| `listBatches` | query | `threadId, sender?, fromMs?, untilMs?, cursor` → `{author, rkey, record, order}[]` in `seq` order | `NotRecipient` |

### Directory (`MailboxDirectory`; caller = any authenticated chat device)

| NSID | Kind | Input → output | Extra errors |
|---|---|---|---|
| `publishEpochHead` | proc | `{epoch: defs#epochPublic}` → `{}` (the §1a checks) | `InvalidEpochChain`, `EpochHeadConflict`, `AttestationNotCurrent`, `AttestationNotCaller`; for an mls-ds mailbox also `EpochNotFound`, `LabyrinthDeviceNotBound` |
| `getEpochHead` | query | `did, epochNumber?` (absent means latest) → `{epoch, receivedAt}` | `EpochNotFound` |
| `getChatDeviceKeys` | query | `did` → `{keyId, signingPublicKey, createdAt, revokedAt?}[]` | — |

`getChatDeviceKeys` returns revoked keys too. The existing views either hide them (`getDevices` filters on `revoked_at IS NULL`, `inventory.rs:1460-1495`) or omit the revocation time (`getDeviceKey`, `src/chat_protocol/repository/device_directory.rs:708-716`).

### ORF and attachments (SPEC §8, [CB-17])

| NSID | Kind | Input → output |
|---|---|---|
| `registerOrfState` | proc | `{deviceKeyPubkey, parent?: {deviceKeyPubkey, evolveToken}}` → `{}`. Without a parent this is the genesis `orf_server_init`; with one, `state = orf_server_evolve(parent, token)` (`src/orf.rs:94`, `:131`) |
| `putAttachmentRef` | proc | `{deviceKeyPubkey, blindedIndex, blindedToken, conversationId, blobId, messageId}` → `{}` |
| `getAttachmentRef` | query | `{deviceKeyPubkey, blindedIndex}` → `{conversationId, blobId, messageId, tokenMac}` |
| `getAttachmentBlob` | query | `{deviceKeyPubkey, blindedIndex, blindedToken}` → blob bytes |

The server applies `orf_server_map` itself, using the caller device's state. It exposes **no raw `orfMap` oracle**.

**Why `getAttachmentBlob` exists.** A restored device has no `chat.application_intervals` row at the attachment's `entry_seq`, so `authorize_blob_read` (`src/chat_protocol/repository/blobs.rs:1090`) refuses it. The token lets that device read the blob anyway. An attachment ref also pins the blob against object GC (§4).

## 3. Authorization

**Transport auth.** Labyrinth reuses the clean-chat admission spine instead of building its own. Note that the v2 chat routes are not DPoP-bound now: they use standard atproto service auth plus an `actorDeviceId`.
- **Reads** call the pattern in `admit_unsigned_read` (`src/handlers/chat/context.rs:140-161`): a service-auth JWT whose `lxm` is the Labyrinth NSID (`verify_mls_service_principal`, `src/auth.rs:1512`), plus `actorDeviceId`. That locks the device and key and yields a `VerifiedReadAdmission`.
  - **Amended 2026-10-05 (review 2):** every Labyrinth query also carries the device-signed read headers `catbird-labyrinth-read` (base64url-nopad canonical JSON `{"v":1,"nsid","query","did","deviceId","issuedAt"}`, `query` = all wire params incl. `actorDeviceId`, sorted by decoded (key, value) bytes, RFC 3986 percent-encoded) and `catbird-labyrinth-read-signature` (Ed25519 by the chat device key over `CATBIRD-LABYRINTH-READ\0` || claim bytes). `deviceId` = `actorDeviceId`, window ±300 s. Crate: `src/store/xrpc/read_auth.rs`; golden vector `tests/vectors/labyrinth_read_header.json`.
- **Writes** call the pattern in `admit_signed_operation_only` (`context.rs:166-188`). There is one new signed-mutation kind, `labyrinthWriteBody`, with domain `"CATBIRD-LABYRINTH-WRITE\0"`. It goes in the `signed_mutation_kinds!` list (`src/chat_protocol/transcript.rs:947`). Its type id is fixed under `blue.catbird.chat.defs#` (`:927`).
  - The body is `{operationId, actorDeviceId, endpointNsid, payloadSha256, signedAt}`, and the Labyrinth payload travels next to it.
  - Idempotency uses the existing `chat.operation_claims`/`chat.idempotency_records` prelude (`src/chat_protocol/repository/prelude.rs:2412`, `:3149`). A retry with the same `operationId` replays byte-identical output. A *new* operation on an existing rkey gets `RecordAlreadyExists`, which is what the traits expect.

**Who may do what:**
- **Mailbox ops:** the caller DID must equal the owner. Any active chat device of that DID qualifies. There is no Labyrinth-level device check, because Labyrinth membership is enforced cryptographically by epoch MACs (SPEC §5.4).
- **Thread writes:** the author DID is always the authenticated DID, and the writer must be a current participant with an active leaf (§1b). For `appendBatch`, every item's `mekId` must name a MEK in the conversation, and all items must share **one** `mekId` (see Y4). The writer must be that MEK's author or one of its recipients. Since [CB-42] this crate reuses only MEKs its own account minted (another device of the same DID may write under it); the recipient allowance is kept for clients that reuse an opened MEK under the paper's rules (SPEC §7.3).
- **Thread reads:** authorized **per MEK** through the index `labyrinth.mek_recipients (conversation_id, recipient_did, mek_id)`. A caller sees MEKs it wrote or was addressed in, and the batches sealed under those MEKs. Current membership is **not** required, so:
  - a member who leaves keeps the history it was addressed in, and no re-archive is needed ([CB-22]; `rearchive_thread_before_leave` stays for the Space backend);
  - a member who joins later sees nothing from before it joined, which matches [CB-16].
- **Directory reads:** any authenticated chat device.
- **Federation (recommended):**
  - **Thread records** live on the conversation's **sequencer DS**, recorded in `chat.conversations.sequencer_ds`/`is_remote` (`migrations/20260824000003_chat_federation_routing.sql:4-22`). That is the only place where `chatSeq` and `receivedAt` share a clock with MLS ordering.
  - **Mailbox, ORF and directory** live on the DID's **home DS**.
  - **Remote thread ops:** a non-sequencer DS authenticates its own device and relays to the sequencer through a new server-to-server procedure, `blue.catbird.mlsDS.labyrinthRelay`. It is signed with `ServiceAuthClient::sign_request` (`src/federation/service_auth.rs:78-103`) and checked by `enforce_ds_request_security` (`src/handlers/ds/deliver_message.rs:103-169`). The sequencer re-verifies the device's `labyrinthWriteBody` signature against its replicated `chat.device_keys`.
  - **Rejected:** replicating thread records to every participant's DS. Each DS would stamp its own order.

## 4. Storage schema (new migrations only)

**Conventions.** New migrations go in `server/migrations/` with 14-digit `YYYYMMDDNNNNNN_desc.sql` names, starting after `20261004000001_reconcile_conversation_identity_whitelist.sql`. Applied migrations are never edited. The new tables live in a separate `labyrinth` schema. Immutability reuses `chat.enforce_immutable_identity(mutable_cols…)` (`core.sql:124-145`; current body in `20260828000005_fix_inventory_session_gc_scoping.sql`), which blocks DELETE and allows only the whitelisted columns to change on UPDATE.

| Table | Key | Main columns | Mutability |
|---|---|---|---|
| `labyrinth.mailboxes` | `owner_did` | `bytes_used`, `record_count`, `created_at` | counters only |
| `labyrinth.devices` | `(owner_did, device_key)` | `record_bytes`, `is_virtual`, `revoked_at`, `created_at` | `revoked_at`, set once (a trigger rejects NULL→X→Y) |
| `labyrinth.epochs` | `epoch_id bigserial`; UNIQUE `(owner_did, epoch_number)` | `epoch_head`, `previous_epoch_head`, `opened_by`, `record_bytes` | immutable |
| `labyrinth.epoch_members` | `(owner_did, epoch_number, device_key)` | `record_bytes` | immutable |
| `labyrinth.virtual_devices` | `(owner_did, vdevice_id)` | `device_key`, `record_bytes` | immutable |
| `labyrinth.owner_batches` | `(owner_did, rkey)`; index `(owner_did, thread_id, max_ts)` | `thread_id`, `min_ts`, `max_ts`, `record_bytes`, `received_at` | immutable |
| `labyrinth.epoch_heads` | `(did, epoch_number)` | `epoch_head`, `previous_epoch_head`, `epoch_public_bytes`, `attestation_key_id` FK `chat.device_keys(key_id)`, `received_at` | immutable |
| `labyrinth.thread_counters` | `conversation_id` FK `chat.conversations` | `next_seq` | counter only |
| `labyrinth.meks` | `(conversation_id, author_did, mek_id)` | `sender_kind`, `attestation_key_id`, `record_bytes`, `seq`, `chat_seq`, `received_at` | immutable |
| `labyrinth.mek_recipients` | `(conversation_id, mek_id, author_did, recipient_did)`; index `(conversation_id, recipient_did, mek_id)` | — | immutable |
| `labyrinth.batches` | `(conversation_id, author_did, rkey)`; UNIQUE `(conversation_id, seq)`; index `(conversation_id, mek_id, seq)` | `mek_id`, `writer_device_id`, `min_ts`, `max_ts`, `record_bytes`, `seq`, `chat_seq`, `received_at` | immutable |
| `labyrinth.orf_states` | `(owner_did, device_key)` | `server_state` (32 bytes), `created_at` | DELETE allowed (revocation is the point) |
| `labyrinth.attachment_refs` | `(owner_did, orf_index)` | `conversation_id`, `blob_id` FK `chat.blobs`, `token_mac`, `created_at` | immutable |

**Size limits.** Body limits follow the `DefaultBodyLimit` pattern in `src/handlers/chat/mod.rs:153-369`:
- 1 MiB for `appendBatch`, `appendOwnerBatch` and `createMek`. This matches [CB-20]'s 900 KB client budget and the 512-recipient MEK cap.
- 512 KiB for `createEpoch`.
- 64 KiB for everything else.

Each `record_bytes` column carries a CHECK that mirrors the lexicon maxima.

**Quotas (Yellow, Y6):**
- 256 MiB per mailbox, counted in `labyrinth.mailboxes`;
- 1 GiB of thread records per author DID across all conversations;
- 4096 epochs per DID;
- 64 virtual devices per DID.

**Retention.**
- Mailbox rows live until the account is deleted, through a SECURITY DEFINER purge function. That function is the only DELETE path, and it is gated by a session GUC that the immutability trigger checks.
- Thread rows live until every recipient DID of their MEK has left the conversation and the conversation is closed, plus a grace period.
- Attachment refs pin their blob: a new migration replaces the blob object-GC claim so that it skips blobs that have a live `attachment_refs` row.

**Bounding `chat.entries` later.** `chat.entries` currently has no retention: `entries_immutable` blocks DELETE (`migrations/20260722000002_chat_protocol_delivery.sql:4327`). Once Labyrinth is the durable archive, a later chat migration can cap application entries at a horizon of days, not forever, because new or restored devices rebuild history from Labyrinth instead of replaying entries. The precondition is that the horizon exceeds the longest supported offline period, so senders can flush their batches. The existing `chat.event_retention.retained_floor` mechanism (delivery.sql:1976) is the model for that change.

**Events.** v1 adds no new kind to `chat.events`. Its `event_kind` CHECK is closed (delivery.sql:1555-1558). Clients pull Labyrinth data on sync and restore, because history is not latency-sensitive.

## 5. Client side

**Placement (recommended):** a `xrpc` cargo feature inside the labyrinth crate (`src/store/xrpc.rs`). It is generic over a small synchronous transport trait:

```rust
pub trait XrpcTransport: Send + Sync {
    fn query(&self, nsid: &str, params: &[(&str, String)]) -> Result<Vec<u8>>;
    /// The transport signs `labyrinthWriteBody` over sha256(payload) with the chat device key.
    fn procedure(&self, nsid: &str, payload: &[u8], operation_id: [u8; 16]) -> Result<Vec<u8>>;
}
```

catbird-mls implements the trait. It already owns the HTTP client, service-auth token minting, the device signing key and the async runtime, which it blocks on.

With this split, the request and response shapes, the error mapping and the stamp handling are tested once, in the crate, against the in-memory server fixtures. The crate stays free of chat signing and auth details.

Rejected: putting the store inside catbird-mls. That would duplicate record knowledge and keep the store out of this crate's test suite.

## 6. Plan, tests, decisions, trait changes

### Trait changes

1. `Stored<T>` gains `order: Option<ServerOrder { seq, chat_seq: Option<u64>, received_at_ms }>`.
2. `ChatDeviceKey` gains `removed_chat_seq: Option<u64>`. A new `ThreadStore::member_device_keys(thread_id, did)` returns the per-leaf join and removal seqs.
3. `keys_valid_at` becomes `keys_valid_for(keys, &Stored order or timestamp)`. `open_sealed`/`mek_for` (`src/client/read.rs:175-183`) use the stamp when it is present.
4. `client::CompositeDirectory` gets a new `Error::DirectoryFork`.
5. `Backends` gains `orf: Box<dyn OrfServer>` and `publishers: Vec<Box<dyn KeyPublisher>>`. The client then registers evolve tokens itself and publishes heads to both the PDS and mls-ds.
6. The `flush` path (`src/client/send.rs:120-125`) also starts a new batch whenever the `mekId` changes.

### Phases

| Phase | Work | Closes |
|---|---|---|
| P0 | Copy `lexicons/blue/catbird/labyrinth/` plus the new query/procedure lexicons into `PetrelCatbird/lexicons/blue/catbird/labyrinth/`. Add `labyrinthWriteBody` and `participantView.labyrinthHead` to chat defs. Regenerate with `./scripts/regenerate-atproto-types.sh` after `jj new` checkpoints, and expect `lib.rs` fallout. Add a test that the two lexicon directories match byte for byte | — |
| P1 | `epoch_heads`, `publishEpochHead`, `getEpochHead`, `getChatDeviceKeys`, the `labyrinthHead` projection. Client: `CompositeDirectory`, the `xrpc` feature with directory only | [CB-29], [CB-28] for Space mailboxes |
| P2 | Mailbox tables and endpoints, `LabyrinthEndpoint` registry (mirroring `define_endpoint_contracts!`, `src/chat_protocol/error.rs:210-252`), `labyrinth_router` merged next to `chat_router` (`src/main.rs:1335-1337`) behind `LABYRINTH_ENABLED` plus the chat cutover gate | mls-ds as a mailbox |
| P3 | Thread tables, stamps, per-MEK authorization, trait changes 1–3 and 6 | [CB-27] |
| P4 | ORF states and attachment refs, the blob GC pin | SPEC §8 |
| P5 | `labyrinthRelay` federation | remote conversations |
| P6 | Retention purge and the `chat.entries` horizon proposal | — |

### Tests

**Server**, as sqlx integration tests in the existing repository style:
- every immutability trigger rejects UPDATE and DELETE;
- two concurrent `createEpoch` calls for one number give exactly one `RecordAlreadyExists`;
- an operation-id replay returns identical bytes;
- an authorization matrix: non-owner, revoked device, a member who left reading an old MEK (allowed) and a new MEK (denied), a joiner reading pre-join history (denied), a mixed-MEK batch, a mismatched sender key;
- `publishEpochHead` against golden `epochPublic` vectors exported from this crate's tests as JSON fixtures, since mls-ds takes no dependency on this crate;
- a `chatSeq` linearization test against a concurrent `sendMessage`.

**Client:**
- run `tests/e2e_memory.rs` and `tests/review_regressions.rs` against the `xrpc` store through a fake transport;
- a new regression where a removed device backdates a message, which must fail when stamps are present.

**Cross-stack:** one scenario in `mls-ds/e2e-tests`.

### Yellow decisions (recommended defaults; overridable before merge)

These should be appended to `docs/DECISIONS.md` when the design is accepted.

- **Y1.** labyrinth stays private for now. mls-ds re-implements the small sha256 head recomputation and the Ed25519 attestation check itself, and leaves XEdDSA to clients. *Override:* make labyrinth public and depend on its verifier.
- **Y2.** No client-claimed "last seen seq" bound into batches or messages in v1. Server stamps are enough, and the seq can't be bound into the signature because it is assigned after signing. Revisit with MLS-authenticated heads.
- **Y3.** Thread records live on the sequencer DS, with a home-DS relay for remote devices.
- **Y4.** Batches are single-MEK (`MixedMekBatch`). That makes per-MEK read authorization a row filter, not item surgery. *Cost:* more batch records when the roster churns.
- **Y5.** `labyrinthHead` is an optional field on `participantView`, not a new endpoint.
- **Y6.** The quota numbers in §4.
- **Y7.** No `chat.events` kind for Labyrinth in v1.
- **Y8.** ORF server state is stored raw, relying on database at-rest encryption. Revocation deletes the row.

### Open items with no default yet

- **One-time-code CPace relay:** how the two devices exchange messages. Out of scope here; the chat channel is a candidate.
- **The removal bound under federation:** cross-DS clock skew still affects account revocations that are not followed by a Remove.

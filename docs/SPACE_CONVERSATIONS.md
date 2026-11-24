# Conversation history in Spaces

Labyrinth encrypts chat history before storage. Each conversation has one atproto Space, and every member writes its MEK distributions, immutable sender batches, redactions and attachment manifests into **its own repo** in that Space. mls-ds stores no history and no index of it. It sequences MLS entries and signs the `I13` receipts that order archived frames; the original sender separately attests archive identity ([MLSDS_BACKEND.md](MLSDS_BACKEND.md)). The decisions behind this file are in [DECISIONS.md](DECISIONS.md).

**Status (2026-11-07).** Stress Fix Round 3 is provisional on `clean-slate-2026-10-31`; Task 4 is not sealed. Its independent R3 review failed, and Fix Round 4 is in progress. G1–G16 are not complete (see "Stress-gate status" below). Source review and deterministic tests are useful evidence but do not mark a gate done. The opt-in G5 live fault fixture is defined below and remains pending until its production-gateway run is recorded.

## Storage and identity

A conversation's Space is `at://{sequencerDid}/space/blue.catbird.labyrinth.conversation/{conversationId}-{generation}`. In production the sequencer creates it under the membership policy derived from authenticated MLS membership; only current members receive conversation-Space credentials. An open-app or owner-only policy is a development fixture, never the production membership contract. Clients do not infer membership from repository visibility and never create an open production conversation Space.

catbird-mls pins the Space per account as a `ThreadPlacement` (`{space, generation}`) under `native.placements:threads:{did}` in the encrypted account database:
- Before every flush, rescue or restore, `pin_native_conversation` re-derives the pin from the authenticated local conversation row. It refuses a Space whose authority differs from the conversation's pinned `sequencerDid`.
- `blue.catbird.chat.getConversationState` (`conversationSpace`, or `sequencerDid` plus the generation) fills a missing pin. It never replaces an existing one.
Writes go through the account's PDS OAuth session as `com.atproto.space.applyWrites` into the writer's own repo (`SpaceThreadStore`, `src/store/space/thread.rs`):

| Record | rkey |
|---|---|
| `blue.catbird.labyrinth.mek` | `hex(mekId)` ([CB-21]) |
| `blue.catbird.labyrinth.batch` | `<16-hex first receipt seq>-<8-hex device tag>-<TID>` |
| `blue.catbird.labyrinth.authorRedaction` | deterministic original-sender/message key |
| `blue.catbird.labyrinth.attachmentManifest` | deterministic manifest key (SPEC §8) |

Readers list the Space's writers via paginated `com.atproto.space.listWriters` (`#repoWrite` active entries, `#repoRemoved` tombstones) and each active repo's records (`com.atproto.space.listRecords`, sorted ascending by `rkey` client-side). Each device also pins the highest observed `repoRev` per `(spaceUri, authorDid)` in `LBYS` v4 state and fails closed with `Error::WriterRollback` if a Space host ever serves an older writer revision on `listWriters`, `listSpaces`, or `getRepo`. The production store attaches no server order, so the history merge sees batches in listing order: by writer DID, then by rkey.

### Personal mailbox Space state records

In addition to `device`, `epoch`, `epochMember`, `virtualDevice`, `otcSession`, `ownerBatch`, and `attachmentManifest`, the personal mailbox Space (`at://<did>/space/blue.catbird.labyrinth.mailbox/self`) stores two encrypted multi-device state collections sealed with PADMÉ + `AES-256-DNDK-GCM` under domain-separated keys derived from the mailbox epoch root and AAD-bound to `(did, collection, rkey, epoch)`:
- `blue.catbird.labyrinth.readState` (`rkey = <conversationId>`): `{ conversationId, readThroughSeq, updatedAt }`, synchronized monotonically across sibling devices via `MAX(readThroughSeq)` CRDT + optimistic CAS (`Labyrinth::advance_read_state`).
- `blue.catbird.labyrinth.circleOwnerState` (`rkey = <circleId>`): `{ circleId, spaceUri, currentKeyVersion, joinedAtVersionByDid, pendingOps, updatedAt }`, updated via `#create` / CID-checked CAS (`Labyrinth::merge_circle_owner_state`), enforcing `joinedAtVersion = MAX` and `__acl__:<did>` removal-tombstone dominance until ACL removal completes (`Labyrinth::clear_circle_acl_tombstone`).

## Reading a conversation Space

The crate trusts its `SpaceRpc` transport for Space authentication. catbird-mls's native transport (`src/client/native_archive_space.rs`) checks every read before Labyrinth sees any bytes:
- **Scope.** Only `getRecord`, `listRecords`, `listRepoOps`, `getRepo`, `getLatestCommit` and `getBlob` (which need `repo`), plus `getSpace` and `listRepos`, are allowed. Caller-supplied auth headers are refused. The Space must be this account's own mailbox (`…mailbox/self`) or a conversation Space. Writes and `listSpaces` keep the platform's OAuth session unchanged.
- **Identity.** DID documents are resolved only through the account PDS (`com.atproto.identity.resolveDid`), so a Space read never reveals interest to a foreign host.
- **Credential and proof of possession.** Each request mints a fresh P-256 key and gets a delegation token from the account PDS (`getDelegationToken`). That is exchanged for a Space credential at the PDS for the mailbox (`getSpaceCredential`), or through the home DS for a conversation (`blue.catbird.chat.relaySpaceCredential`). The credential must verify under the authority's `#atproto` key, name the authority as `iss`, the Space as `sub` and the fresh key as `cnf`, and be strictly unexpired before and after each read. Each read carries an HTTP-signature proof of possession over the writer.
- **KEM and MAC.** Each read encapsulates a fresh share to the writer's `atproto_kem` key (`Atproto-Space-Want-Mac`). A record read (`getRecord`, including the re-fetches behind `listRecords`) must return exactly one `Atproto-Space-Mac` record MAC. A commit read (`listRepoOps`, `getRepo`, `getLatestCommit`) must return a commit MAC. `getBlob` is checked by content hash instead, and `getSpace` and `listRepos` carry no MAC.
- **Content.** `getRecord` must match the exact URI, record MAC, canonical DAG-CBOR and recomputed CID. `listRecords` re-fetches every listed record through that `getRecord` check before releasing inline values. `listRepoOps` replays the op log into an LtHash that must equal the MAC'd head commit. `getRepo` checks the STAR commitment. `getBlob` sends the lexicon's `space`, `repo` and `cid` parameters, and the body must hash to its CIDv1 (raw, SHA-256).
- **Released bytes.** Verified record JSON is released exactly as served, because re-rendered `$bytes` would not open in Labyrinth's strict codec.

Conversation reads go through the home DS (`blue.catbird.chat.relaySpaceRead`). Mailbox reads go straight to the account PDS.

**Failure semantics.**
- An HTTP 401 or 403 from the credential exchange or the read is the Space's answer and maps to `Forbidden`. A removed member reads that way. After a refused exchange, no read is sent.
- Every other failure, including a missing OAuth grant, a binding, MAC or CID mismatch, or an expired credential, is an error (`native_space_*`), not `Forbidden`. The operation fails closed, and queued archive rows stay queued.
- In `map_space_error`, `SpaceNotFound` is `NotFound("space")`, and `SpaceDeleted`, 401 and 403 are `Forbidden`.

Labyrinth then checks, per committed item:
- the batch's thread and message ID;
- the receipt under the exact versioned conversation key it names;
- the archive commitment and MEK;
- the writer's sealing key for the archive act;
- the independent original-sender attestation and its historical sender device/leaf interval at the receipt's order.

## Committed frames (`I13`)

The archived frame is the canonical `MLSMessagePayload` JSON that the sender put inside the MLS plaintext envelope together with a random 32-byte `frameNonce`. The MLS AAD and sequencer receipt bind `archiveCommitment = HMAC-SHA256(frameNonce, frame)`. The nonce travels only inside encrypted payloads, so the commitment stays hiding.

The original sender also signs `OriginalSenderAttestation { senderDid, senderDeviceId, senderTransportPubkey, signature }`. Its Ed25519 transcript is `catbird.labyrinth.original_sender_archive.v1\0`, then the length-prefixed thread and message IDs and the 32-byte archive commitment. The attestation is outside the commitment input, but its exact bytes are bound into the encrypted MLS envelope and application AAD. Sender, witness and owner evidence retain it beside the receipt.

`archive_outgoing_committed` and `archive_owner_committed` take the archived receipt and original-sender attestation, so re-archiving keeps both. Before sealing, they check the thread, message ID, commitment and sender coordinates.

Verified committed `LoadedMessage`s keep the archived receipt, attestation and frame nonce, so import and later rescue preserve the same evidence.

Committed owner records bind the **full** receipt and attestation into owner AEAD. Changing or removing either fails before authority lookup:
- Every receipt names `{sequencerDid}#mls-receipt-N`, with canonical positive-decimal `N`. The first valid receipt durably sets `receipts_required` and stores authority plus P-256 SEC1 bytes by key ID.
- Rotation retains every prior method. A key ID is immutable, never reused, and the same ID with other bytes fails closed.
- Removing the method from the current DID document never restores receiptless/timestamp fallback. Without the named historical key and valid sender attestation, the owner record is undecryptable.

## Active members and the owner fallback

`Labyrinth::load_thread` returns the conversation Space's copies together with this account's owner copies. It clears `space_readable` only when the Space answers `Forbidden`. On that basis catbird-mls treats the conversation Space as authoritative for active members: they recover from sender and witness copies (and MEKs), never from personal owner copies. Only these cases permit the owner-mailbox fallback:
- `Forbidden`;
- an authenticated local kick or leave: a verified MLS Commit removed this device, or the local MLS roster no longer contains this account.

A missing active Space is an error (`NotFound("space")`), not a fallback.

The rules in catbird-mls (`src/client/native_archive.rs`):

| Operation | Behavior |
|---|---|
| `flush_labyrinth_queue` | For each conversation, a `getConversationState` read with the local roster still holding this account writes sender copies. If the sender write returns `Forbidden`, that chunk is sealed into owner batches instead. The flush goes owner-only when the state read is `Forbidden`, or when the local roster lacks this account (on a successful read, or on `ConversationNotFound`). `ConversationNotFound` while the local roster still holds this account, or any other error, fails that conversation and keeps its rows. |
| `rescue_conversation_on_kick` | Seals each local message of the conversation from its retained evidence, plus any queued rows, into owner batches. A message whose own evidence fails validation (missing or malformed evidence, a frame or receipt commitment mismatch, a bad attestation or signature) is skipped; its ID is recorded in `native.rescue-report:{cid}` (`skippedEvidenceIds`), and the other messages are still rescued. A transport, directory or Space failure is not invalid evidence: it fails the rescue and keeps the rows for retry. Live sync calls it after a verified Commit removed this device, and platforms can also call it. |
| `restore_conversation_from_owner_mailbox` | Despite its name, an active member restores from the conversation Space. Owner copies are dropped whenever the Space was readable. It reads only the owner archive when the verified local roster lacks this account, or when the authenticated Space authority denies access. A fresh device with no local group treats a home-DS `NotEntitled` or `ConversationNotFound` only as a lead. It must open authenticated owner evidence, derive the receipt-pinned Space, and get the denial from that Space. An unsigned home-DS 4xx is never denial evidence. |

Owner batches always use the same canonical frame bytes and `I13` evidence as sender batches. Open a whole owner batch before applying its delete-for-me tombstones; finalizing each item separately can resurrect an earlier tombstoned message.

## Witness copies

A member that authenticated and decrypted another member's application entry archives the same canonical frame, nonce, `I13` receipt and `OriginalSenderAttestation` in its own repo. Pre-removal history therefore survives a sender that an admin removes before it flushes, with no flush needed before removal. The removed sender's own fallback remains its owner batch.

catbird-mls queues a witness copy only after verifying both the receipt and the original sender's attestation. An own-account message remains the sending device's duty.

A reader accepts a witness item only after:
- the receipt verifies under its pinned versioned key ID and names this thread;
- the archive commitment matches;
- the original sender's Ed25519 attestation binds this thread, message ID and commitment;
- that attestation's exact sender device key and conversation leaf were active at the receipt's order;
- the MEK opens, and any freshly decrypted MLS sender equals the attested sender/device.

The witness's repo and sealing key authenticate who stored the copy; they never establish original sender identity. The sequencer receipt supplies order, not sender attestation.

Sender and owner copies are accepted first. Witness copies follow in deterministic store order. Equal copies merge only when the original-sender attestation, frame, nonce, receipt and commitment all match. A contradiction or receipt reuse goes to `ThreadHistory::rejected`; it never re-attributes or taints an accepted copy. Other authenticated sender/owner collisions remain visible with `conflict = true`.

**Restore.** Native restore imports one authenticated copy per message ID. It never resolves ambiguity by trusting a witness or sequencer over the sender attestation.

**Pages.** `load_thread_page` positions each message once, using all accepted copies. A message appears on exactly one page, together with every equal copy. A page can come back short when its window holds copies positioned on other pages.

## Account deletion

A verified author redaction (unsend) for `(messageId, original sender)` hides every sender, witness and owner copy carrying that authenticated sender identity. So does a verified `accountDeletedEntry` for that sender (below). A delete-for-me tombstone also hides them. mls-ds writes no DS redaction records; the sequenced `accountDeletedEntry` is the only account-deletion authority.

The sequencer's account-deletion evidence names its exact `{sequencerDid}#mls-receipt-N` method. The conversation's durable authority/P-256 SEC1 history survives current-method removal; canonical key IDs are immutable and never reused.

mls-ds's `deleteAccountData` sequences a signed `accountDeletedEntry`, and catbird-mls:
- verifies the conversation, pinned sequencer, key ID and low-S ES256 signature over the account-deletion transcript;
- records its sequence, drops that account's queued witness copies and retained evidence, and purges local messages;
- hides every copy attributed to the deleted account unless its receipt orders it after the deletion entry; a copy without a receipt is hidden;
- restores only from account-deletion entries whose historical key ID verifies under the pinned sequencer.

Peer epoch pins are per-device, not recovered account state. A restored device repeats strict public-PDS + mls-ds exact agreement before caching a first-contact pin. Missing/stale one-source data and forks fail closed and are not cached. Pending local epoch-head publication is retried on session open and sync until both sources match; native status exposes the pending epoch, stalled/error and retry count, and archive rows remain queued.

## Deletion and cleanup

- **Unsend** writes a separate immutable `blue.catbird.labyrinth.authorRedaction` record under the author's deterministic message key. It never rewrites or empties the source batch. Listing, leave and account-cleanup inventory retain the redaction, so concurrent writes and retries cannot resurrect the ciphertext.
- **Leave** (`rearchive_before_leave`) copies what reading accepts, including the original-sender attestation and applied redactions, into owner batches, and copies the account's attachment manifests into the personal mailbox Space. For each message already in the account's owner archive that a verified author redaction now hides, it writes an owner tombstone. Leave deletes nothing from the conversation Space: the account's MEK, batch, redaction and attachment-manifest records stay, because they may be the only copy that remaining members can restore from.
- **Account cleanup** inventories conversation Spaces from saved pins and the owner's paginated `listSpaces`, including more than one page, records written by other devices and conversations already left. It deletes only the signed-in account's erasable records and retains redaction evidence required by peers. Before local erasure, the app saves placement, pins and required cleanup in a durable deletion journal. An unreachable required host leaves cleanup pending.
- **Close.** catbird-mls's terminal close erases the conversation's archive queue, retained evidence and staged C33 opening with its MLS state. Nothing is archived or rescued afterwards; local message rows stay unsendable.

## Stress-gate status and live boundary

Stress Fix Round 3 gates G1–G16 are **not complete**. The independent R3 review (2026-11-07) failed, and Fix Round 4 is in progress. The per-finding status (confirmed fixed, partially fixed or open, with the covering test) is the authoritative table in `Labyrinth doc review — handoff for MLS stress testing.md` at the workspace root. No source review, deterministic unit test or earlier dated run closes a gate by itself.

G5's opt-in live fault test is `catbird-mls/tests/live_native_archive_g5.rs`. It uses the production `CatbirdMlsClient` path that constructs `NativeArchiveGateway`, plus an explicitly provisioned real conversation Space named by `LABYRINTH_G5_LIVE_FIXTURE`. Its loopback fault proxy keeps fixture credentials away from accidental direct-host requests. The fixture must exercise:
- expiry after one verified record but before the next read;
- replay of a valid record MAC under the wrong URI and under the wrong CID;
- a `listRecords` inline value that differs from the verified `getRecord`;
- complete paginated inventory with more than 100 records.

Each injected fault must make the operation fail closed; the inventory case must return every fixture record. A missing explicit fixture is the only permitted skip. The test never substitutes `MemorySpaceHost`, a fake gateway or a successful no-op. G5 remains pending until the live result is recorded.

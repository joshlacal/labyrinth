# mls-ds and Labyrinth

**What this is.** The contract between Labyrinth clients and `mls-ds`, Catbird's MLS delivery service, in the clean-slate Spaces-only profile. mls-ds is Labyrinth's **directory and sequencer**. It stores no Labyrinth content: no mailboxes, sender batches, MEKs, owner batches, virtual devices, attachment references or ORF state. Each account's mailbox lives in its personal Space on its own PDS, and conversation history lives in the conversation's Space (SPEC §9, [SPACE_CONVERSATIONS.md](SPACE_CONVERSATIONS.md)).

The client side is catbird-mls `src/labyrinth/transport.rs` (`GatewayXrpcTransport`, `DsDirectoryStore`). The server side is mls-ds `server/src/handlers/labyrinth/` and `server/src/labyrinth/`.

**Status (2026-11-07).** Stress Fix Round 3 is provisional on `clean-slate-2026-10-31`. Its independent R3 review failed, and Fix Round 4 is in progress. G1–G16 are not complete, including the G5 production-gateway live faults; none is marked complete by source review alone.

**Retired design.** This file used to hold the 2026-10-04 design that made mls-ds a full Labyrinth storage backend (`createDevice`, `createEpoch`, `getEpoch`, `appendOwnerBatch`, `createMek`, `appendBatch`, `listBatches`, `registerOrfState`, `putAttachmentRef`, the `labyrinthRelay` federation relay) and the October 23 Space-reference endpoints (`getThreadStorage`, `appendSpaceBatch`, `listSpaceBatches`). mls-ds serves none of them. Their lexicons are still in `lexicons/blue/catbird/labyrinth/`, but they are not a contract. The old design is in VCS history, and [DECISIONS.md](DECISIONS.md) records why it was chosen.

## 1. What mls-ds provides

### 1a. [CB-29] First contact is cross-checked

mls-ds keeps an append-only chain of `EpochPublic` heads per DID. `publishEpochHead` accepts a head only if all of these hold:
- the recomputed `epochHead` (including `membersHash`) matches, and the XEdDSA `selfSig` verifies;
- the [CB-18] attestation is signed by the **calling** chat device (`AttestationNotCaller` otherwise);
- the epoch extends the stored chain, is above the account's rollback floor (`labyrinth.epoch_head_floors`, `L-F01`), and its `prevSig` verifies under the previous epoch's signing key.

Re-sending identical bytes succeeds. A different head at a stored epoch number fails with `409 EpochHeadConflict`.

Each account publishes every head to its public PDS (`mailboxKeys/<12-digit epoch>` then `self`) and mls-ds. A locally opened epoch is durably pending until both sources contain the exact same head. Session open and sync retry publication. Native status exposes pending epoch, stalled/error and retry count; archive work stays queued rather than being discarded or allowed to bypass a mismatch.

catbird-mls reads peers through strict `CompositeDirectory`. Pins deliberately remain per-device, so restore inherits no peer pins and repeats first contact:
- both sources must provide the exact same head and intermediate chain;
- missing or stale one-source data fails `DirectoryIncomplete`;
- a same-sequence mismatch fails `DirectoryFork`;
- failures are not cached, and no production or restored-device path silently selects TOFU.

`new_allowing_single_source` is an explicit non-production TOFU opt-in.

### 1b. [CB-27] Order comes from signed receipts

mls-ds does not stamp Labyrinth records. Each `I13` receipt carries the exact verification method `{sequencerDid}#mls-receipt-N`, where `N` is canonical positive decimal, and binds conversation, group, epoch, sender device DID URL, entry ID, blinded archive commitment, `seq` and `issuedAtMs`.

The receipt supplies sequencer order, not original-sender attestation. Readers separately verify `OriginalSenderAttestation`, historical device-key inventory and the sender's conversation-leaf interval.

After the first valid receipt, the conversation durably latches `receipts_required` and stores its authority plus P-256 SEC1 public bytes by key ID. Rotation retains every prior method. A key ID is immutable and never reused; the same ID with changed bytes fails closed. Removing a method from the current DID document never restores receiptless/timestamp fallback.

### 1c. [CB-28] Truncation needs the PDS and mls-ds to collude

`check_epoch_integrity` compares the mailbox's newest epoch with the newest head both directories anchor. The strict two-source rule applies after restore even when the device has no local pin. A missing source is `DirectoryIncomplete`, a directory ahead of the mailbox is `EpochTruncated`, and a fork fails closed. `purgeMailbox` and `deleteAccountData` delete the head chain but raise the floor, so a re-enrolled mailbox restarts strictly above deleted epochs.

## 2. XRPC surface: `blue.catbird.labyrinth.*`

Exactly six endpoints remain (`PROCEDURES` and `QUERIES` in mls-ds `server/src/handlers/labyrinth/mod.rs`):

| NSID | Kind | Input → output | Notes |
|---|---|---|---|
| `publishEpochHead` | procedure | `{epoch}` → `{}` | The checks in §1a. The caller's DID is the epoch's DID. |
| `getEpochHead` | query | `did, epochNumber?` → `{epoch, chain, floorSeq, receivedAt}` | Latest head when `epochNumber` is absent. `EpochNotFound` when none. Relayed to the DID's home DS under federation. |
| `getChatDeviceKeys` | query | `did, cursor?, limit?` → `{keyId, signingPublicKey, createdAt, revokedAt?}[]` | Complete historical key inventory, including revoked keys. A `keyId` is immutable: the same ID may never name different bytes. Relayed to the DID's home DS. |
| `getMemberDevices` | query | `threadId, did, cursor?, limit?` → `{keyId, signingPublicKey, joinedSeq, removedSeq?}[]` | Complete per-leaf history for one conversation, keyed by the same immutable device key IDs. |
| `purgeMailbox` | procedure | `{}` → `{}` | Deletes the caller's head chain and raises its floor to the newest deleted epoch. |
| `deleteAccountData` | procedure | `{}` → `{}` | Account deletion on this DS. It sequences a signed `accountDeletedEntry` in every active conversation this DS sequences for the account, relays the deletion to remote sequencers, prunes the account's application and C33 opening ciphertext, deletes push bindings, and purges the head chain. A DS that cannot sign or relay an owed entry refuses the whole deletion (`SignerUnavailable`, `PeerHomeUnavailable`). |

**Authentication.** Every call is made by an enrolled chat device. Queries carry `actorDeviceId` plus `catbird-labyrinth-read` and `catbird-labyrinth-read-signature`. The signature is Ed25519 by the chat device key over `CATBIRD-LABYRINTH-READ\0` followed by the claim, and the claim covers every wire parameter. Procedures carry `catbird-labyrinth-write` and `catbird-labyrinth-write-signature`, signed over `CATBIRD-LABYRINTH-WRITE\0` (catbird-mls `src/labyrinth/write_auth.rs`). Operation ids are idempotent for 7 days (`labyrinth.operations`). The read-header golden vector `tests/vectors/labyrinth_read_header.json` is byte-identical to the copy mls-ds pins (`server/tests/fixtures/labyrinth_read_header.json`, tested in `server/src/labyrinth/read_auth.rs`); no test in this crate reads it.

**Errors.** Failures are XRPC error bodies `{"error", "message"}`. catbird-mls maps them in `src/labyrinth/transport.rs` `map_xrpc_error`:

| Wire error | Client error |
|---|---|
| `EpochNotFound` (400/404) | `NotFound("epoch")` |
| `ConversationNotFound` (400/404) | `NotFound("conversation")` |
| `EpochHeadConflict`, `RecordAlreadyExists`, `InvalidSwap`; `InvalidEpochChain` (400/409) | `Conflict` |
| `NotEntitled`, `AccessOutsideMembershipInterval` (HTTP 400 only) | `Forbidden` |
| any 401 or 403 | `Forbidden` |
| everything else | `Backend` |

Storage failures cross the wire as `InternalServerError`.

## 3. Calls outside `blue.catbird.labyrinth.*`

- `blue.catbird.chat.getConversationState` gives the pinned `sequencerDid`, production conversation Space/generation and sequenced account deletions. It may fill an empty Space pin but never replace one. It does not replace durable receipt-key history or per-device peer epoch pins.
- Receipt/redaction verification resolves the exact `{sequencerDid}#mls-receipt-N` named by the signed object. Canonical positive-decimal `N`, `receipts_required`, authority and P-256 SEC1 bytes are durable conversation state; prior methods survive rotation/current-document removal and IDs are never reused.
- `blue.catbird.chat.relaySpaceCredential` and `blue.catbird.chat.relaySpaceRead` carry a current member's conversation-Space credential exchange and reads through its home DS. The home DS forwards only the closed read-only allowlist; the client still verifies credential expiry before and after each read, proof of possession, record/commit MACs, exact URI/CID and complete paginated inventory.

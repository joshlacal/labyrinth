# mls-ds and Labyrinth

**What this is.** The contract between Labyrinth clients and `mls-ds`, Catbird's MLS delivery service, in the clean-slate Spaces-only profile. mls-ds is Labyrinth's **directory and sequencer**. It stores no Labyrinth content: no mailboxes, sender batches, MEKs, owner batches, virtual devices, attachment references or ORF state. Each account's mailbox lives in its personal Space on its own PDS, and conversation history lives in the conversation's Space (SPEC §9, [SPACE_CONVERSATIONS.md](SPACE_CONVERSATIONS.md)).

The client side is catbird-mls `src/labyrinth/transport.rs` (`GatewayXrpcTransport`, `DsDirectoryStore`). The server side is mls-ds `server/src/handlers/labyrinth/` and `server/src/labyrinth/`.

**Retired design.** This file used to hold the 2026-10-04 design that made mls-ds a full Labyrinth storage backend (`createDevice`, `createEpoch`, `getEpoch`, `appendOwnerBatch`, `createMek`, `appendBatch`, `listBatches`, `registerOrfState`, `putAttachmentRef`, the `labyrinthRelay` federation relay) and the October 23 Space-reference endpoints (`getThreadStorage`, `appendSpaceBatch`, `listSpaceBatches`). mls-ds serves none of them. Their lexicons are still in `lexicons/blue/catbird/labyrinth/`, but they are not a contract. The old design is in VCS history, and [DECISIONS.md](DECISIONS.md) records why it was chosen.

## 1. What mls-ds provides

### 1a. [CB-29] First contact is cross-checked

mls-ds keeps an append-only chain of `EpochPublic` heads per DID. `publishEpochHead` accepts a head only if all of these hold:
- the recomputed `epochHead` (including `membersHash`) matches, and the XEdDSA `selfSig` verifies;
- the [CB-18] attestation is signed by the **calling** chat device (`AttestationNotCaller` otherwise);
- the epoch extends the stored chain, is above the account's rollback floor (`labyrinth.epoch_head_floors`, `L-F01`), and its `prevSig` verifies under the previous epoch's signing key.

Re-sending identical bytes succeeds. A different head at a stored epoch number fails with `409 EpochHeadConflict`.

Each account also publishes its head in its **public** PDS repo as `blue.catbird.labyrinth.mailboxKeys`: an immutable `<12-digit epoch>` copy first, then `self` under `swapRecord` (`PdsPublisher`, `src/store/pds.rs`).

catbird-mls reads peers through `CompositeDirectory::new(PdsDirectory, DsDirectoryStore)` (`src/client/composite.rs`). It reports a head only when both sources agree:
- equal heads: accepted;
- one source newer: accepted only through a verified `prev_sig` chain, with both sources agreeing on every intermediate epoch;
- two different heads for one epoch number: `Error::DirectoryFork`;
- a head in only one source: `Error::DirectoryIncomplete`. The flush that needed it fails and keeps its rows queued. It never falls back to trust-on-first-use;
- no head in either source: the DID is not enrolled, and senders do not address it.

`CompositeDirectory::new_allowing_single_source` accepts one source on first contact (trust-on-first-use). catbird-mls does not use it.

### 1b. [CB-27] Order comes from signed receipts

mls-ds does not stamp Labyrinth records. Order comes from the `I13` sequencer receipt that each application entry carries. The conversation's sequencer signs it with ES256 under `{sequencerDid}#mls-receipt-1`, over the domain `catbird-mls-sequencer-receipt-v2\0` (`labyrinth-protocol/src/receipt.rs`). The receipt binds:
- the conversation, group and epoch;
- the sender device;
- the entry id;
- the blinded archive commitment `HMAC-SHA256(frameNonce, canonical frame)`;
- `seq` and `issuedAtMs`.

Each sealed item stores its receipt. Readers check the sealing chat key against the sender's devices at the receipt's order: `getMemberDevices` reports each leaf's `joinedSeq`/`removedSeq`, and `getChatDeviceKeys` reports revocation times. Sender batch rkeys start with the first item's receipt seq (`<16-hex-seq>-<tid>`).

A conversation whose receipt key resolves rejects unreceipted sender items (`ReceiptCommitmentMismatch`). Only a conversation with no resolvable receipt key falls back to sender timestamps bounded by key removal.

### 1c. [CB-28] Truncation needs the PDS and mls-ds to collude

`check_epoch_integrity` compares the mailbox's newest epoch with the newest head both directories anchor. The personal mailbox Space and the public `mailboxKeys` both live on the account's PDS, so mls-ds's head chain is the independent source. A host that drops newer epochs from the mailbox is caught unless mls-ds colludes with it. `purgeMailbox` and `deleteAccountData` delete the head chain but raise the floor, so a re-enrolled mailbox restarts strictly above the deleted epochs.

## 2. XRPC surface: `blue.catbird.labyrinth.*`

Exactly six endpoints remain (`PROCEDURES` and `QUERIES` in mls-ds `server/src/handlers/labyrinth/mod.rs`):

| NSID | Kind | Input → output | Notes |
|---|---|---|---|
| `publishEpochHead` | procedure | `{epoch}` → `{}` | The checks in §1a. The caller's DID is the epoch's DID. |
| `getEpochHead` | query | `did, epochNumber?` → `{epoch, chain, floorSeq, receivedAt}` | Latest head when `epochNumber` is absent. `EpochNotFound` when none. Relayed to the DID's home DS under federation. |
| `getChatDeviceKeys` | query | `did, cursor?, limit?` → `{keyId, signingPublicKey, createdAt, revokedAt?}[]` | Includes revoked keys, with their revocation time. Relayed to the DID's home DS under federation. |
| `getMemberDevices` | query | `threadId, did, cursor?, limit?` → `{keyId, signingPublicKey, joinedSeq, removedSeq?}[]` | The per-leaf view of one conversation. |
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

- `blue.catbird.chat.getConversationState` gives a conversation's `sequencerDid`, its `conversationSpace` URI and coordinates, and the sequenced `accountDeletions`. The state may fill an empty sequencer pin. It never replaces a saved pin and never supplies key bytes: receipt and redaction keys come from a trusted resolver, which in the native client is the sequencer's DID document (`#mls-receipt-1`, `#labyrinth-redaction-1`).
- `blue.catbird.chat.relaySpaceCredential` and `blue.catbird.chat.relaySpaceRead` carry a member's conversation-Space credential exchange and reads through its home DS, so conversation-Space reads never go to a foreign sequencer directly. The home DS forwards only the closed allowlist of read-only `com.atproto.space.*` methods (mls-ds `server/src/federation/space_read_relay.rs`). The client still verifies every relayed response itself ([SPACE_CONVERSATIONS.md](SPACE_CONVERSATIONS.md), "Reading a conversation Space").

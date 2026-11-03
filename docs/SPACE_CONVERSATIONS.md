# Conversation history in Spaces

Labyrinth encrypts chat history before storage. Each conversation has one atproto Space, and every member writes its MEK distributions, sender batches and attachment manifests into **its own repo** in that Space. mls-ds stores no history and no index of it. It sequences the MLS entries and signs the `I13` receipts that order and authenticate archived frames ([MLSDS_BACKEND.md](MLSDS_BACKEND.md)). The decisions behind this file are in [DECISIONS.md](DECISIONS.md).

**Status (2026-11-04).** The bookmark `clean-slate-2026-10-31` holds R0 (labyrinth `6462096a`). The following Task 4 R1 changes are in an unsealed, provisional commit on top of the bookmark, and the R1 provisional commits of catbird-mls build only against them:
- witness copies and `Rejection`;
- the `&ArchivedReceipt` archive APIs;
- the receipt binding in owner AEAD and `sequencer_receipt_key_for_authority`;
- message-positioned pages.

R1 is not sealed, and the final Task 4 gate has not passed.

## Storage and identity

A conversation's Space is `at://{sequencerDid}/space/blue.catbird.labyrinth.conversation/{conversationId}-{generation}`. catbird-mls pins it per account as a `ThreadPlacement` (`{space, generation}`) under `native.placements:threads:{did}` in the encrypted account database:
- Before every flush, rescue or restore, `pin_native_conversation` re-derives the pin from the authenticated local conversation row. It refuses a Space whose authority differs from the conversation's pinned `sequencerDid`.
- `blue.catbird.chat.getConversationState` (`conversationSpace`, or `sequencerDid` plus the generation) fills a missing pin. It never replaces an existing one.

Writes go through the account's PDS OAuth session as `com.atproto.space.applyWrites` into the writer's own repo (`SpaceThreadStore`, `src/store/space/thread.rs`):

| Record | rkey |
|---|---|
| `blue.catbird.labyrinth.mek` | `hex(mekId)` ([CB-21]) |
| `blue.catbird.labyrinth.batch` | `<16-hex first receipt seq>-<TID>` |
| `blue.catbird.labyrinth.attachmentManifest` | deterministic manifest key (SPEC §8) |

Readers list the Space's repos (`listRepos`) and each repo's records. The production store attaches no server order, so the history merge sees batches in listing order: by writer DID, then by rkey.

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

Labyrinth then checks, per item:
- the batch's thread;
- the receipt under the conversation's receipt key;
- the archive commitment and the MEK;
- that the sealing key is one of the writer's chat devices at the receipt's order (SPEC §7.4).

## Committed frames (`I13`)

The archived frame is the canonical `MLSMessagePayload` JSON that the sender put inside the MLS plaintext envelope together with a random 32-byte `frameNonce`. The MLS AAD and the sequencer receipt both bind `archiveCommitment = HMAC-SHA256(frameNonce, frame)`. The nonce travels only inside encrypted payloads (the MLS plaintext, then the MEK- or owner-encrypted archive item), so the commitment stays hiding.

`archive_outgoing_committed` and `archive_owner_committed` both take `&ArchivedReceipt` (`{signed, generation}`), so re-archiving keeps the receipt's generation. Before sealing, they check that the receipt names the thread and that the commitment matches.

Verified committed `LoadedMessage`s keep `archived_receipt` and `frame_nonce`, so import and later rescue keep the original MLS coordinates and commitment.

Committed owner records (kind `0x02`) bind the **full** receipt, including its issuer, signature and generation, into the owner AEAD associated data (`\0catbird.labyrinth.owner_receipt_v1\0` followed by the receipt's DAG-CBOR). Changing or removing the receipt fails decryption before any authority lookup:
- A device with no receipt key for the thread (for example, a fresh device after removal) may resolve the key for that authenticated issuer with `sequencer_receipt_key_for_authority`. An existing pin cannot be replaced.
- Without a trusted key, a committed owner record is undecryptable.
- A `0x02` record without a receipt fails, and so does a `0x00` or `0x03` record that carries one.

## Active members and the owner fallback

`Labyrinth::load_thread` returns the conversation Space's copies together with this account's owner copies. It clears `space_readable` only when the Space answers `Forbidden`. On that basis catbird-mls treats the conversation Space as authoritative for active members: they recover from sender and witness copies (and MEKs), never from personal owner copies. Only these cases permit the owner-mailbox fallback:
- `Forbidden`;
- an authenticated local kick or leave: a verified MLS Commit removed this device, or the local MLS roster no longer contains this account.

A missing active Space is an error (`NotFound("space")`), not a fallback.

The rules in catbird-mls (`src/client/native_archive.rs`):

| Operation | Behavior |
|---|---|
| `flush_labyrinth_queue` | For each conversation, a `getConversationState` read with the local roster still holding this account writes sender copies. If the sender write returns `Forbidden`, that chunk is sealed into owner batches instead. The flush goes owner-only when the state read is `Forbidden`, or when the local roster lacks this account (on a successful read, or on `ConversationNotFound`). `ConversationNotFound` while the local roster still holds this account, or any other error, fails that conversation and keeps its rows. |
| `rescue_conversation_on_kick` | Seals every local message of the conversation from its retained evidence, plus any queued rows, into owner batches. A message without evidence fails the rescue. Live sync calls it after a verified Commit removed this device, and platforms can also call it. |
| `restore_conversation_from_owner_mailbox` | Despite its name, an active member restores from the conversation Space. Owner copies are dropped whenever the Space was readable. It reads only the owner archive when the local roster lacks this account, or when there is no local group and `getConversationState` returns `ConversationNotFound`. |

Owner batches always use the same canonical frame bytes and `I13` evidence as sender batches. Open a whole owner batch before applying its delete-for-me tombstones; finalizing each item separately can resurrect an earlier tombstoned message.

## Witness copies

A member that authenticated and decrypted another member's application entry archives the same canonical frame, nonce and `I13` receipt in its own repo with `archive_outgoing_committed`, under its receive-time MLS roster. Pre-removal history therefore survives a sender that an admin removes before it flushes, with no flush needed before the removal. The removed sender's own fallback remains its owner batch.

catbird-mls queues a witness copy for every verified message from another account. A message that the notification extension decrypted is queued only once the app has verified its `I13` receipt. An own-account message remains the sending device's duty.

A reader accepts a witness item only after the same checks as any sender item:
- the receipt verifies under the conversation's receipt key and names this thread;
- the archive commitment matches;
- the MEK opens;
- the sealing key is one of the **archiving** member's chat devices with a leaf at the receipt's order.

The message is attributed to the receipt's sender, never to the witness, as `MessageSource::Witness`.

**Nothing authenticates the message ID a witness files a copy under.** The frame carries none, and the receipt names mls-ds's own `entryId`, which is independent of the message ID. A witness copy is therefore a third party's claim (the "ruling 3" in code comments; [DECISIONS.md](DECISIONS.md), 2026-11-03).

Sender and owner copies are accepted first. Witness copies follow in the store's order: server order when the store supplies one, otherwise listing order. A witness copy is accepted only if one of these holds:
- it equals an accepted copy with its message ID (same frame, nonce, receipt and sender);
- no accepted copy holds its message ID or its receipt's entry.

Otherwise it goes to `ThreadHistory::rejected`, as `Rejection::Contradicts` (its message ID holds different content) or `Rejection::ReceiptReused` (its receipt's entry is already claimed under another ID). A rejected copy is never returned, never flags `conflict`, and never replaces or re-attributes an accepted copy.

Accepted copies merge in this order: the sender's own copy, then the earliest witness copy, then attributed owner copies, then unattributed legacy owner copies. Differing sender or owner copies of one ID are returned with `conflict = true`. Because every member archives byte-identical committed copies, the copies converge: equal copies merge into one message.

**Restore.** Native restore imports one copy per message ID. Copies can still disagree only between members' own copies; restore then keeps the copy equal to the local message. With no local message, or none that matches, it skips that ID and logs it instead of failing. Rejected witness copies are logged and ignored.

**Pages.** `load_thread_page` positions each message once, using all of its copies: its sender copy's earliest timestamp, otherwise its earliest witness copy's, otherwise its earliest owner copy's. A message appears on exactly one page, together with every copy. A page can come back short when its window holds copies of messages positioned on other pages.

## Account deletion

A verified unsend or account-deletion redaction for `(messageId, sender)` hides every other copy attributed to that sender: witness copies in other repos, and owner copies. A delete-for-me tombstone also hides them. A sequencer's account-deletion redaction covers every item attributed to the deleted account, including witness copies of messages the account never archived itself. Readers find the deleted sender through the item's plain receipt and verify the DS signature for that sender.

mls-ds does not produce these redaction overlays today. Its `deleteAccountData` sequences a signed `accountDeletedEntry` instead, and catbird-mls acts on that entry:
- **Verify.** The entry must bind this conversation and its pinned `sequencerDid`, and carry a low-S ES256 signature under `{sequencerDid}#mls-receipt-1` over `catbird-mls-account-deletion-v1\0` and the length-prefixed fields. An entry that does not verify has no effect.
- **Apply.** A verified entry records `native.account_deleted:{cid}:{did}` (its seq), drops that account's queued witness copies and retained evidence, and purges its local messages.
- **Hide.** From then on, `restore_conversation_from_owner_mailbox` and `open_rescued_owner_batch` hide each copy attributed to the deleted account (sender, witness and owner copies alike) unless the copy's receipt orders it after the deletion entry. A copy without a receipt is hidden.
- **Restore.** A fresh device never sees the entry in `getEntries`, so restore verifies and applies each entry listed in `getConversationState.accountDeletions`, under the pinned sequencer (or, with no local state, the one whose receipts authenticated the restored copies). If this device may not read the state (`ConversationNotFound`, `NotEntitled`, `AccessOutsideMembershipInterval`), only the deletions live sync already recorded apply.
- **Roster.** Flushes leave a recorded deleted account out of the send-time roster, so its purged mailbox cannot block the survivors' archive. A server 404 alone never excludes anyone.

## Deletion and cleanup

- **Unsend** (`redact_item`) rewrites the author's own batches in place (`applyWrites#update`). The item's `signedEncMessage` is emptied, its receipt is removed and the signed `redaction` is attached. Space writes have no `swapRecord`.
- **Leave** (`rearchive_and_clear_before_leave`) copies what reading accepts (after redactions, tombstones and witness rejection) into owner batches. Committed copies keep their receipt and nonce. It also copies the account's own attachments, then deletes this account's MEK, batch and attachment-manifest records from the conversation Space.
- **Account cleanup** inventories conversation Spaces from the saved pins and the owner's `listSpaces`, including records written by other devices and conversations already left. It then deletes only the signed-in account's own records. Before erasing local state, the app must save the placement, the pinned Spaces and whether Space cleanup is required in a durable deletion journal. In catbird-mls, `MLSOrchestrator::labyrinth_delete_account` stores them as `PendingDeletion`. An unreachable required host leaves cleanup pending. Cleanup never deletes foreign records or the authority's shared Space.
- **Close.** catbird-mls's terminal close (`apply_terminal_close`) erases the conversation's archive queue, retained evidence and staged C33 opening along with its MLS state. Nothing is archived or rescued for that conversation afterwards. The local message rows stay, unsendable.

## Verification boundaries

These tests pin the behavior above:
- in this crate, `tests/witness_archive.rs`, `tests/gate1_receipt_commitment.rs`, `tests/history_ops.rs` (including `missing_active_space_is_not_an_owner_archive_fallback`), `tests/fault_lines.rs` and `tests/gate6_composite_directory.rs`;
- in catbird-mls, the in-crate `native_restore_tests`, `native_archive_space_auth` tests and `live_sync` tests.

They establish local protocol behavior, not real OAuth, cross-host identity, production deployment or native device behavior.

`MemorySpaceHost` (`src/store/space/host.rs`) models repository operations and canonical batch CIDs; it does not model credentials or MACs. The live PDS lifecycle test (`tests/live_space_pds.rs`) is ignored by default. Running it with `--ignored` requires a provisioned session and fails if the session is missing.

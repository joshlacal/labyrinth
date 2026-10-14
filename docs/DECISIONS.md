# Decision log

This log records choices where the Labyrinth whitepaper is silent, or where it's written for Messenger rather than Catbird. Each entry is provisional and can be overridden before the `labyrinth-1.1` bookmark merges. `docs/SPEC.md` uses the same `[CB-n]` tags. Format follows the Catbird workspace convention: what we chose, why, and how to undo it.

## 2026-10-04 · Scope and architecture

**Implement Labyrinth 1.1 in full, with hybrid storage.** Josh asked for full 1.1 because Catbird chat is heading to more platforms.
- Labyrinth key state (devices, epochs, recovery bundles) lives in a **per-user mailbox**.
- Each message ciphertext is stored **once per conversation**, written by its sender.
- *Why:* in 1.1, sender-encrypted bytes don't depend on the recipient. Per-recipient copies would multiply storage by group size for no security gain.
- *Rejected:*
  - a pure per-user mailbox (N× duplication);
  - a pure group Space (no per-user custody of keys, and no recovery story).
- *Override by:* moving `batch` records into each recipient's mailbox. The protocol code doesn't change.

**mls-ds stays the delivery service and sequencer.** Spaces has no cross-member order and doesn't let a service write into members' repos, so it can't order MLS Commits.

## [CB-n] profile choices

| Tag | Choice | Why | Override |
|---|---|---|---|
| CB-1 | `userFbid` → the account DID; `user_fbid=` → `user_did=` | atproto identity | rename the field strings |
| CB-2 | threadId = UTF-8 conversation id | it is the MLS conversation id already | — |
| CB-3 | transport signing key = the chat device's Ed25519 key (Ed25519, not XEdDSA) | it is the existing MLS chat device key in `chat.device_keys` | swap the `TransportSigner` implementation |
| CB-4 | multi-output `kdf` = expand once and split | the paper doesn't say how | — |
| CB-5 | timestamps in ms | matches chat | — |
| CB-6 | a 1-byte suite id prefixes every AEAD ciphertext | v1.0 and v1.1 ciphertexts coexist | — |
| CB-7 | PADMÉ padding on all message plaintexts | the paper pads only under AES-GCM-Extended; length leakage matters either way | — |
| CB-8 | Hawk byte layout and KDF | the paper gives only the structure | — |
| CB-9 | epochID = backend-assigned string; in Space, the rkey = zero-padded seq | create-if-absent is the only CAS Space writes offer | — |
| CB-10 | the epoch head is signed as raw bytes | the paper's `+` is ambiguous | — |
| CB-11 | rotation is mandatory on revoke | Messenger admits it doesn't enforce this; we can | — |
| CB-12 | ECC uses a 3-erasure cap, not the "any 4 columns" MDS claim | 38 columns can't be MDS over GF(32); the maximum arc is 33 | — |
| CB-13 | passkey PRF wrap of the recovery code | Josh chose passkey and iCloud Keychain first | — |
| CB-14 | CPace on Ristretto255 for one-time codes | matches the paper; current CFRG draft | — |
| CB-15 | sender ciphertext stored once per conversation | hybrid storage, see above | — |
| CB-16 | MEK roster = enrolled DIDs in the MLS group, sender included | gives join and leave semantics equal to MLS | — |
| CB-17 | the ORF server role always belongs to mls-ds | the PDS has no compute hook | — |
| CB-18 | the epoch head is attested with the chat transport key | anchors Labyrinth keys to MLS identity; closes key substitution by a backend | drop `attestation` |
| CB-19 | the latest epoch public keys go in a public-repo record | discovery works on every PDS. **Privacy cost:** enrollment and rotation timing become public | serve via mls-ds instead |
| CB-20 | batches of up to 256 messages per record | PDS rate limit, 1 MB cap, export ceiling | tune the size |
| CB-21 | MEK distribution is one record in the sender's repo in the conversation Space | Space owner-only writes | — |
| CB-22 | on leave, re-archive into one's own mailbox | Space removal also removes read access to the conversation's history | — |
| CB-23 | a transport MEK is reusable only by the device that minted it | it is authenticated by no epoch key, so reuse rule 2 (p.38–39) never holds for its readers; the minting device is its authenticator | let readers reuse transport MEKs too |
| CB-24 | both MEK distribution AADs end with `;thread_id=hex(threadId)` | the paper's AADs don't bind the thread, so a backend could move a MEK record between threads | drop the field (restores the paper's AAD bytes) |
| CB-25 | the opener encrypts entropy to itself; **amended 2026-10-05:** an invalid or unbound previous-epoch member is excluded *and reported* (`RotationReport::excluded`, `SyncReport::invalid_members`); only a member this client already verified in that epoch failing aborts (`MemberTampered`) | self-recovery for the opener's other installs; aborting let one planted row block revocation forever (G-P0-2), a silent drop would be an unannounced revocation | abort on any invalid member (restores the DoS); drop silently |
| CB-26 | OTC payload is a fixed big-endian binary layout, not CBOR | avoids a CBOR dependency for one five-field struct | switch to CBOR (bump the format byte) |
| CB-27 | history reads accept MEK attestations and message signatures from any chat key the DID ever registered, but a removed key only for messages timestamped before its `removed_at`; addressing a MEK requires a *current* chat device | a revoked or lost device signed real history; only new MEKs need a live device. Timestamps are sender-chosen, so this is a bound, not a guarantee | require current devices for reads too (old history becomes unreadable after device loss) |
| CB-28 | epoch-integrity check: a device compares the newest epoch it reached with the directory's published latest epoch and fails with `EpochTruncated` if the directory is ahead | the SPEC §10 mitigation; the directory (public `mailboxKeys` / mls-ds roster view) is independent of the mailbox store | drop the check (truncation becomes silent) |
| CB-29 | senders pin each addressed DID's newest accepted `(epochNumber, epochHead, signingPubkey)`; reject older/forked epochs (`EpochRollback`) and advance only through a verified `prev_sig` chain fetched via `MailboxDirectory::epoch`; first contact is TOFU anchored by [CB-18]; every epoch is also kept at `mailboxKeys/<12-digit seq>` | a peer's PDS could replay an older attested `mailboxKeys` and make senders encrypt to keys a revoked device holds | drop the pins (replay becomes silent); long term, move latest heads into MLS-authenticated group state |
| CB-30 | client state persists as a versioned binary blob (`LBYS` v1) from `Labyrinth::export_state`, restored with `from_state`; the caller keeps it in the keychain / SQLCipher | the revoked set and pins must survive restarts; one blob is the simplest UniFFI surface | per-field storage callbacks |
| CB-31 | history merges copies only on `(author DID, messageId)` with byte-equal frames (owner copies: byte-equal frame); other id collisions are all returned with `conflict = true` | messageId is chosen by the sender, so an insider could otherwise suppress another member's message | dedup on messageId alone (restores the suppression) |
| CB-32 | attachment ciphertext is chat's per-blob AES-256-GCM, not the paper's AES-256-CBC + PKCS7; mls-ds streams bytes instead of CDN URLs with TTLs | GCM is authenticated and already shipped by chat; no URL to expire | adopt CBC for Messenger parity (no security gain) |
| CB-33 | attachment reference input `json([backupID, objectID])` with backupID = threadId, objectID = blobId; token = HMAC(ORF output under the token scope, `json([threadId, messageId])`); one message per attachment object; messageId = chat message UUID | the paper names the fields but not Catbird's ids; the MAC binds the message so unsend/delete revoke access | backupID = DID (refs would no longer be per thread) |
| CB-34 | `labyrinthID` = the account DID | one mailbox per DID; no extra id to assign or leak | add a server-assigned instance id |
| CB-35 | no v1.0→v1.1 upgrade: a null previous head only at epoch 0 | Catbird has no v1.0 mailboxes; a mid-chain null link would let a backend restart a chain | allow one null link at an upgrade epoch |
| CB-36 | physical device records carry a `chatBinding` signed by the enrolling chat device; rotation drops devices whose binding fails or names a non-current chat device | couples Labyrinth revocation to chat-device removal; a planted device record can't pass as bound | drop the binding (unbound devices stay until revoked by hand) |
| CB-37 | owner cipher version 5: v3 key with `_cipher_version_5_`, AAD binding messageId and timestamp, content-kind byte | the paper's owner AAD leaves id/timestamp swappable; the kind byte hides tombstones among messages | write v3 again (tombstones then need a record type) |
| CB-38 | deletion: delete-for-me = encrypted v5 tombstone in the owner mailbox; unsend = author-signed server redaction keeping id/timestamp; account deletion = redact authored items + purge mailbox; edits are frame-level | decision J1 defaults; per-item signatures make single-item redaction safe | J1 alternatives (hard-drop authored items, no unsend) |
| CB-39 | keychain and passkey bundles expire 180 days after `max(createdAt, lastUsedAt)`; a restore touches the bundle; removing a method rotates its virtual device out and deletes the bundle | decision J2 defaults; paper p.46 expires auto-stored codes | other TTL, or heartbeat on every sync |
| CB-40 | a next epoch that does not chain (no valid `prev_sig`, invalid or locally revoked opener, entropy does not open) is reported as `EpochSquatted`, never retried | create-if-absent epoch numbers let one bogus record wedge rotation; retrying can't help | treat as `NotEpochMember` (looks like a revocation) |
| CB-41 | fingerprint = `kdf(head, MINOS_SALT, "catbird.labyrinth.fingerprint.v1:" ‖ did, 30)` as 30 digits per account, 60 per pair (or 8 emoji) | the paper says heads can serve as fingerprints but defines no display | another encoding |
| CB-42 | a Labyrinth MEK is reused only by the account that minted it; members who opened a peer's MEK mint their own | a reader can verify only its own recipient entry, so reusing a peer's MEK lets that peer blackhole another member from the reader's messages (2026-10-13 review, I2) | reuse any opened MEK under rules 1–2 (paper p.38–39) |

## 2026-10-04 · labyrinth · MEK and message layer
Chose: bind the thread id into MEK AADs ([CB-24]) and restrict transport-MEK reuse to its minting device ([CB-23]) (provisional). Because: a MEK record's `threadId` was otherwise unauthenticated, and the reuse rule's "authenticated to the latest epoch keys" has no epoch to point at for a transport MEK. Rejected: paper-exact AAD plus an equality check against the caller's thread (a backend could still rewrite both consistently); letting any reader reuse a transport MEK (rule 2 would be vacuous).
Owner-mode records still leave `messageId` and `timestamp` unauthenticated, as in the paper (SPEC §7.1).
Reversible until: merge of `labyrinth-1.1`. Override by: deleting the `;thread_id=` suffix in `src/mek/distribute.rs::aad`, and changing `Mek::reusable_for`.

## 2026-10-04 · labyrinth · Record layer and lexicon reconciliation
Chose (provisional): reconcile the draft lexicons with the protocol structs so every record round-trips, and pin these record-shape choices:
- `mek#labyrinthSender` carries the sender's full `senderEpoch` (`defs#epochPublic`). Readers need the sender's Hawk auth key for the epoch that sealed the MEK, and the public `mailboxKeys` record only shows the *latest* epoch; the embedded copy is self-authenticating (head, self signature, [CB-18] attestation). Cost: about 1.6 KB per MEK record.
- `mek.recipients` max 512 (was 700): one recipient entry is about 1.65 KB of JSON, so 700 overran the 1 MB write cap.
- `virtualDevice` gains a required `vdeviceId` (equal to its rkey) so the record is self-contained; `mechanism` is required. `device.virtual` and `epoch.openedBy` are required. `ownerBatch` gains a required top-level `threadId` (one thread per batch) so stores can list by thread.
- `ownerMessage.version` accepts 0–4 (readers decrypt 0/2/4), fixed-size byte fields carry `minLength = maxLength`, and empty `description` strings are gone.
- Bytes serialize as `{"$bytes": base64-no-pad}` under human-readable serializers and raw bytes otherwise (DAG-CBOR).
Because: the round-trip test (`tests/lexicon_records.rs`) validates every emitted record against the lexicon JSON. Rejected: looking up historical sender epochs from the sender's personal mailbox (not readable by other members under Spaces); per-item thread ids only in owner batches (forces stores to scan every batch).
Reversible until: merge of `labyrinth-1.1` / Spaces GA. Override by: editing `lexicons/` and `src/records/` together; the round-trip test pins them to each other.

## 2026-10-04 · labyrinth · Storage traits are synchronous
Chose (provisional): `store::{MailboxStore, ThreadStore, MailboxDirectory}` are plain synchronous traits returning `Result`; a store handle is bound to one authenticated DID; epochs are created atomically with their initial members (`create_epoch(epoch, members)`, one `applyWrites`). Because: the crate stays runtime-free, and a crash between "epoch created" and "members written" would otherwise brick the mailbox. Rejected: `async fn` in traits (forces a runtime choice on UniFFI/WASM consumers and is not object-safe without boxing). Reversible until: merge of `labyrinth-1.1`. Override by: adding async twins of the traits; the client logic is unchanged.

## 2026-10-04 · labyrinth · High-level client (`src/client`)
Chose (provisional):
- Revocation marks the device `revokedAt` *before* rotating, and every rotation carries over all unrevoked devices with a valid MAC (virtual devices included), so a crash mid-revoke still excludes the device next time. On `Conflict` (a sibling opened the same epoch first) the client syncs and retries, up to 3 times.
- History reads use the directory's *historical* chat keys ([CB-27]); the [CB-18] check for addressing uses *current* keys. A MEK record whose Labyrinth sender DID differs from the repo it was read from is rejected.
- `initialize` creates epoch 0 before the device record (the epoch create is the race guard); restore and OTC enrollment run the [CB-28] integrity check before writing anything.
- A conversation space that refuses reads (`Forbidden`) degrades `load_thread` to the owner archive (`space_readable = false`). Owner records carry no sender DID, so re-archived messages lose sender attribution unless the frame carries it.
- The client does not persist device secrets or the epoch cache; that is left to the embedding app (deferred).
Because: these are the behaviours `tests/e2e_memory.rs` pins. Rejected: rotating before marking revoked (a crash leaves the lost device in the next epoch); a single "current keys" set for reads (losing a phone would make its history unreadable).
Reversible until: merge of `labyrinth-1.1`. Override by: editing `src/client/epochs.rs` (rotation) or `src/client/read.rs` (read checks).

## 2026-10-04 · labyrinth · security review fixes
A security review of the `labyrinth-1.1` bookmark proved three bugs with tests (now `tests/review_regressions.rs`, written as security assertions that failed before the fixes) and listed six smaller items. All nine are fixed on this bookmark. Chose (provisional):
- **Revocation does not trust the store (HIGH).** A store that drops `revokedAt` used to re-admit the revoked device into the very epoch opened to revoke it. The client now keeps a local revoked-device set, `rotate()` takes the exclusion set explicitly, every rotation excludes the whole set, and success is reported only after checking the new epoch neither lists nor encrypts to an excluded device. `SyncReport::readmitted` surfaces locally revoked devices that are still members. Rejected: re-reading `revokedAt` after writing it (the same store answers).
- **Peer epoch pinning, [CB-29] (HIGH/MEDIUM).** Replaying an old `mailboxKeys` let a revoked device read new messages. Senders now pin per DID and reject rollback with `Error::EpochRollback`; advancing requires the `prev_sig` chain, fetched through the new `MailboxDirectory::epoch(did, seq)`, so `publish_mailbox_keys` also keeps immutable per-epoch copies (lexicon key `any`). First contact stays TOFU. Rejected: a `chain(did, from, to)` trait method (one-epoch lookups are simpler to cache and serve); comparing against the directory's latest alone (that is the value being replayed).
- **Insider messageId collision, [CB-31] (MEDIUM).** Dedup is per author with byte-equal frames; colliding copies are all returned and flagged. Re-archive keeps every distinct `(messageId, frame)`.
- **[CB-25] enforced (LOW).** A continuing member with a bad MAC now aborts the rotation instead of being skipped.
- **Suite pinning (LOW).** `aead::decrypt_suite` requires `0x02` on every v1.1 path; only owner messages accept `0x01`.
- **Overflow (LOW).** Client epoch arithmetic is checked, and `epochNumber` is bounded at 2⁴⁰ in records and lexicons.
- **State persistence, [CB-30].** `export_state` / `from_state`; the blob is secret. This supersedes the "client does not persist device secrets" bullet of the *High-level client* entry above.
- **Historical keys bounded by removal time, [CB-27].** `MailboxDirectory::device_transport_keys` now returns every key with an optional `removed_at` (ms) and `historical_transport_keys` is gone; a removed key vouches only for messages (and MEKs, at the first message that needs them) timestamped before removal. **Residual risk:** timestamps are sender-chosen, so a removed device can backdate; mls-ds ordering (server-assigned sequence numbers bound into the MEK/message) is the real fix and is not built. Rejected: dropping removed keys entirely (makes a lost phone's history unreadable).
- **Zeroization.** `XSigningKey::generate` wipes its stack copy; `seal_sender` / `seal_owner` wipe the padded plaintext.
Because: each item is a concrete attack or invariant break the review demonstrated or reasoned; the fixes are local to the client and records layers and keep the wire formats except the lexicon changes above.
Reversible until: merge of `labyrinth-1.1`. Override by: reverting the individual commits on the bookmark (one per finding group); the regression tests name which behaviour each one pins.

## 2026-10-04 · labyrinth · mls-ds backend (design Y1–Y8)
The crate side of `docs/MLSDS_BACKEND.md` is built: server order on stored records, the per-conversation leaf view, the stamped removed-key rule ([CB-27]), `CompositeDirectory` ([CB-28], [CB-29]), ORF and head publishing from the client, single-MEK batches, and the `xrpc` feature (stores over the `blue.catbird.labyrinth.*` endpoints, plus a memory-backed reference server). The mls-ds server side (tables, endpoints, federation relay) is **not** built. Chose (provisional), as the design recommends:
- **Y1.** labyrinth stays private; mls-ds re-implements the sha256 head recomputation and the Ed25519 attestation check and leaves XEdDSA to clients. *Override:* make labyrinth public and depend on its verifier.
- **Y2.** No client-claimed "last seen seq" bound into batches or messages in v1; server stamps are enough, and a seq assigned after signing can't be signed. Revisit with MLS-authenticated heads.
- **Y3.** Thread records live on the conversation's sequencer DS, with a home-DS relay (`labyrinthRelay`) for remote devices.
- **Y4.** Batches are single-MEK (`MixedMekBatch`), so per-MEK read authorization is a row filter. The client now starts a new batch whenever the MEK changes (`src/client/send.rs`). *Cost:* more batch records when the roster churns.
- **Y5.** `labyrinthHead` is an optional field on `participantView` in `getConversationState`, not a new endpoint (`XrpcDirectory::conversation_heads` reads it).
- **Y6.** Quotas: 256 MiB per mailbox, 1 GiB of thread records per author DID, 4096 epochs and 64 virtual devices per DID.
- **Y7.** No `chat.events` kind for Labyrinth in v1; clients pull on sync and restore.
- **Y8.** ORF server state is stored raw, relying on database at-rest encryption; revocation deletes the row.

Where the build deviates from the design (each also provisional):
- **Transport errors stay structured.** `XrpcTransport::{query, procedure}` return `Result<Vec<u8>, XrpcError>` (status plus atproto error name), not the crate `Result`, so the error mapping lives in the crate and is tested once. Mapping adds to the design's three rules: `*NotFound` → `Error::NotFound` (a `get*` returns `None`), `AttestationNotCurrent` → `Unattested`, `NotParticipant`/`DeviceRevoked` → `Forbidden`.
- **The leaf view is on `MailboxDirectory`** (`member_device_keys(thread, did)` → `MemberDeviceKey {key, joined_chat_seq, removed_chat_seq}`), not on `ThreadStore` with a `removed_chat_seq` on `ChatDeviceKey`. It is part of the MLS device view mls-ds serves, and a Space thread store has none. A key whose DID has a leaf view in the conversation but no leaf of its own vouches for nothing there; epoch attestation keys are bounded account-wide only, since the attesting device need not be in the conversation.
- **Two endpoints the design lacks:** `getMemberDevices` (serves `chat.member_devices` join/removal seqs; `getConversationState` lists only current leaves) and `deleteOrfState` (a Space-mailbox client never calls `markDeviceRevoked` on mls-ds, so revocation needs its own ORF delete).
- **One-time-code ORF registration.** The responder registers its temporary ORF state under `sha256("catbird.labyrinth.otc_temp_orf:" || CPace isk)`, which only the two devices can name; the new device evolves its own state from it and deletes it. The design had no way to register a state without a device key, and without it an OTC-enrolled device could never create a recovery bundle.
- **`createVirtualDevice` takes `member` and `orf` as optional fields.** `MailboxStore::create_virtual_device` is unchanged, so the client writes the membership and ORF state with their own calls (not atomic, as on a Space). *Override:* widen the trait method and send all three.
- **`XrpcOrf::map` refuses** (mls-ds has no raw ORF oracle); `Labyrinth::orf_evaluate` works against an `OrfServer` that maps, such as the memory one. Attachment-reference endpoints have lexicons but no client wrapper yet.
- Wire names: `ServerOrder.labyrinth_seq` is `serverOrder.seq`, and `receivedAt` is an RFC 3339 datetime (`records::ms_from_datetime`). The module is `src/store/xrpc/` rather than `src/store/xrpc.rs`.

Because: these are the pieces the design assigns to the crate, and the reference server lets the same e2e lifecycle run over XRPC with every request and response validated against the lexicons (`tests/e2e_xrpc.rs`). Rejected: putting the stores in catbird-mls (design §5); a raw ORF map endpoint (an oracle).
Reversible until: merge of `labyrinth-1.1`. Override by: editing `docs/MLSDS_BACKEND.md` and the matching module (`src/store/keys.rs` for the vouching rule, `src/client/composite.rs`, `src/store/xrpc/`), then the lexicons; `tests/review_regressions.rs` and `tests/directory_and_orf.rs` pin the behaviour.

## 2026-10-04 · mls-ds · Labyrinth backend server build (local bookmark `local/labyrinth-backend-20261004`)
Chose (provisional): the server-build deviations from `docs/MLSDS_BACKEND.md` listed below. Because: each one keeps the frozen chat transcript and claim code untouched, or matches the test-database constraints. Reversible until: the first mls-ds push or merge carrying the bookmark. Override by: the alternative named in each item.
1. Signed write bodies travel in the `catbird-labyrinth-write` and `catbird-labyrinth-write-signature` headers, under domain `CATBIRD-LABYRINTH-WRITE\0`. They are not a new chat signed-mutation kind, because that would touch the frozen transcript code. The client transport (catbird-mls) must add these headers. Alternative: a chat mutation kind.
2. Idempotency uses its own `labyrinth.operations` table rather than `chat.operation_claims`.
3. The ORF server domains are two fixed constants, `catbird.labyrinth.orf.attachment_index` and `catbird.labyrinth.orf.attachment_token`.
4. Access rules:
   - `getMemberDevices` answers only current and former participants; anyone else gets `ConversationNotFound`, so existence isn't leaked.
   - `putAttachmentRef` requires participation plus an existing blob.
   - MEK recipients must be current participants.
5. `labyrinthHead` appears only on `getConversationState`, and only when the `labyrinth` schema exists.
6. Test fixtures seed conversations with `session_replication_role = replica`, which needs a superuser test role.
Not built:
- The `labyrinthRelay` federation relay. Writes to remote-sequenced conversations return 501.
- Retention purge.
- Protecting attachment blobs from chat object GC, which needs a change to `chat.claim_blob_object_gc`.
- Swift and Kotlin Petrel regeneration for `labyrinthHead`.

## 2026-10-05 · labyrinth · Whitepaper gap closure, crate half
Context: the 2026-10-05 gap audit of both whitepapers against this crate and the mls-ds backend (scratchpad `gap-audit.md`) found an insider DoS against revocation (G-P0-2) and missing deletion, lookup, attachment and recovery-lifecycle features. This entry covers the crate. The mls-ds lane (`mlsds-lab-completion`) builds the server half and writes the endpoint lexicons; the shapes below were agreed with it.

Chose (provisional):
- **G-P0-2, crate half ([CB-25] amended, [CB-36], [CB-40]).** Rotation audits the previous epoch and drops, *and reports*, any member that fails parsing, its device record, its signatures, its MAC, or its chat binding. A planted row can no longer block revocation, and no drop is silent. The one abort left is a member this client already verified in the same epoch failing now (`MemberTampered`), because only the store can cause that. The verified set is per epoch, not "devices I ever trusted": an insider can plant a row under a trusted-but-since-excluded key, so a global trusted set would have restored the DoS. A next epoch that doesn't chain is `EpochSquatted` and is never retried.
  - Rejected: aborting on any invalid member (the DoS), and dropping silently (unannounced revocation).
- **Device binding ([CB-36]).** It is client-verifiable, so it also protects a Space mailbox. Genesis now writes the device record before epoch 0, and a recovery bundle writes its device record before the `virtualDevice`, because mls-ds admits only registered, bound devices as members. The epoch create is still the race guard; a loser leaves an orphan device record that is never a member.
- **Deletion ([CB-37], [CB-38], decision J1 defaults).** Delete-for-me tombstones live inside owner cipher v5, so they need no new record type and the server can't tell them from messages. Redactions are signed by the author's chat key, so readers can tell an author's unsend (`by_author`) from a server removal.
  - Rejected: a separate `ownerTombstone` record (it leaks which records are deletions), and unsigned redaction.
- **Lookup.** `load_message`, `load_thread_page` (newest first, opaque `"<ts>:<messageId>"` cursor) and `list_threads`. Each rests on a trait method whose default scans an existing listing, so they work today on every backend; an indexed mls-ds endpoint is only an optimization. `list_batches_before` documents when a backend may stop early.
- **Attachments ([CB-32], [CB-33], decision J4 default).** The server keeps the owner and the (thread, message) pair only as keyed digests, plus blobId in clear for GC pinning and the one-message-per-blob rule.
- **Recovery lifecycle ([CB-39], decision J2 defaults).** Expiry is computed from the server-stamped `lastUsedAt`. A restore touches its bundle before writing anything; `touchVirtualDevice` failing with `NotSupported` is ignored.
- **Publish path.** Every epoch goes to the mailbox and to every `KeyPublisher`. That was already true; it is now pinned by `tests/attachments_recovery.rs::every_epoch_is_published_to_every_publisher`. A publish that fails after its epoch was created surfaces as an error, and `publish_latest_keys` retries it.
- **XRPC.** The stores do not wrap the new endpoints until their lexicons land; those trait methods return `Error::NotSupported`. `MemoryXrpcServer` serves the agreed shapes (`src/store/xrpc/server/lookup.rs`), so the wrappers have an executable spec.
  - The XRPC layer must add: `redactMessage`, `purgeMailbox`, `touchVirtualDevice`, `deleteVirtualDevice`, and `putAttachmentRef`/`getAttachmentBlob` in their new shapes.
  - Also `deleteAttachmentRef`, plus a `KeyPublisher::retract` for the PDS `mailboxKeys` records.
  - Optionally `getMessages`, `listThreads`, `listOwnerThreads` and a reverse `listBatches`/`listOwnerBatches` (not built in mls-ds yet).
  - The existing `putAttachmentRef`/`getAttachmentRef` lexicons in this crate still have the old shape, which stores conversation and message in clear. mls-ds replaces them.
- **Client state** moves to `LBYS` version 2, which adds the verified set; version 1 still loads.

Because: these are the crate-side fixes the audit assigns, with J1, J2 and J4 taken at their recommended defaults so work could continue without blocking.

Reversible until: merge of `labyrinth-1.1`.

Override by:
- J1, J2 or J4 answered differently: edit `src/client/delete.rs`, `src/client/recovery.rs` or `src/attachment.rs`.
- To restore abort-on-invalid: revert `src/client/members.rs` and the rotate changes in `src/client/epochs.rs`.
- The tests `tests/rotation_audit.rs`, `tests/history_ops.rs`, `tests/attachments_recovery.rs` and `tests/xrpc_pending.rs` pin the behaviour.
- **Amendment (agreed with the mls-ds lane):** `defs#redaction` has `required: []`. Server-side account deletion (`deleteAccountData`) has no author signature, so it writes `{redactedAt}` alone, and readers flag it `account_deleted`, never as an author unsend. Attachment fetch failures (missing ref, wrong token, redacted message) are all `NotFound`; a put the caller isn't entitled to is `AttachmentNotEntitled`. `getAttachmentBlob` is a query with hex params, as in mls-ds.

## 2026-10-05 · labyrinth · XRPC wiring of the gap-closure endpoints
Context: the gap-closure entry above left the new trait methods returning `NotSupported` over XRPC until mls-ds published its lexicons. The mls-ds lane published them (PetrelCatbird `local/labyrinth-backend-20261004` = `046ec4f2`). They are now copied into `lexicons/`, and from here on this crate is the canonical copy.

Chose (provisional):
- **Wrappers.** `XrpcThreadStore::redact_item` calls `redactMessage`. `XrpcMailboxStore` gains `touch_virtual_device`, `delete_virtual_device`, `purge_mailbox` and a new trait method `MailboxStore::delete_account_data` (`deleteAccountData`). `XrpcOrf` gains `put_attachment_ref`, `fetch_attachment` (raw-bytes `getAttachmentBlob`), `delete_attachment_ref`, plus an inherent `attachment_ref_created_at` (`getAttachmentRef`).
- **Unsend is idempotent over XRPC.** mls-ds counts an unknown or already-redacted id as zero, so `redact_item` returns `Ok(0)` there. The memory store still says `NotFound`, and the trait documents both.
- **Account purge over mls-ds is server-side** (`deleteAccountData`); see the `purge_account` amendment below for how the client chooses.
- **`XrpcDirectory::retract` is `purgeMailbox`.** mls-ds drops a head chain only along with the mailbox.
- **Error map additions.**
  - `AttachmentAlreadyReferenced` → `Conflict`.
  - `LabyrinthDeviceNotBound` and `AttachmentNotEntitled` → `Forbidden`.
  - `MemberDeviceNotRegistered` → `NotFound("device")`.
  - The bare `NotFound` → `NotFound("attachment")`, since only the attachment reads use it.
  - `InvalidChatBinding` and `InvalidRedaction` → `BadSignature`.
  - `RelayUnavailable`, `ConversationMoved` and `AttachmentsUnavailable` → `Backend`.
- **Reference server parity.** `MemoryXrpcServer` serves every endpoint the stores call, including `getAttachmentRef` and `deleteAccountData`, with mls-ds's errors (`InvalidRedaction`, `VirtualDeviceNotFound`). It enforces the mls-ds binding rules (`server/binding.rs`): a chat binding by the caller on `createDevice`, a bound caller on epoch writes and revocation, and registered members.
  - The one known difference: re-putting the identical attachment reference succeeds here, where mls-ds answers `RecordAlreadyExists`.
- **Lookups (amendment, mls-ds lexicon change `lzsxqrnx`).** `getMessages`, `listThreads`, `listOwnerThreads`, and `reverse`/`since`/`until` on `listBatches`/`listOwnerBatches` are wrapped, overriding the scan-based defaults. Newest-first reads page by *server seq*, not sender timestamp, so `list_batches_before` / `list_owner_batches_before` read every page in the window and sort locally; they never stop early at `limit`. `server/lookup.rs` (formerly `pending.rs`) serves the lookups.
- **`purge_account` prefers the server.** It calls `MailboxStore::delete_account_data` first (mls-ds `deleteAccountData`, atomic across delivery services) and falls back to the client loop only on `NotSupported`. The memory mailbox does not offer it, so the memory path is unchanged.

Reversible until: merge of `labyrinth-1.1`. Override by: edit `src/store/xrpc/*`. The behaviour is pinned by `tests/e2e_xrpc.rs` (every call is validated against the lexicons), `tests/xrpc_server.rs` and `tests/xrpc_pending.rs`.

## 2026-10-05 · labyrinth · Second security review, client half
Context: the second Labyrinth security review found that one bad roster member aborted every archive flush, that a peer who legitimately reset its mailbox stayed `EpochRollback` forever, that reads were authorized by the service-auth token alone, that a failed remote account deletion left the user unable to delete, and that any unsigned server redaction was labelled "account deleted". The mls-ds lane (`mlsds-review2-fixes`) implements the server half; the wire shapes below were agreed with it and its tests pin the same golden vector.

Chose (provisional):
- **Per-member roster exclusion.** `resolve_roster_report` excludes, and reports (`RosterExclusion`), a member whose epoch fails a trust check (`EpochRollback`, `Unattested`, `DirectoryFork`, records that don't verify). Transient errors (`Backend`, `Rng`) still fail the roster, so a network blip never drops a member. The strict `resolve_roster` is unchanged.
  - Rejected: excluding on transient errors (silent, permanent loss of the member's access to those messages).
- **User-confirmed re-pin ([CB-29]).** `propose_repin(did)` verifies the peer's chain from epoch 0, which must be attested by a *current* chat device of the DID, and shows the old and new safety numbers. `repin_peer(did, head)` replaces the pin only with the head the user saw (`Conflict` otherwise).
  - A genesis attested by a since-removed chat device cannot be re-pinned, even if the latest epoch is attested by a current one. That is the review's literal rule. It means a peer who reset and then changed devices needs a fresh reset.
- **Device-signed reads.** `read_auth`: `catbird-labyrinth-read` = base64url-nopad canonical JSON `{"v":1,"nsid","query","did","deviceId","issuedAt"}`. `query` covers every wire parameter (including `actorDeviceId`), sorted by decoded (key, value) bytes and RFC 3986-encoded. `catbird-labyrinth-read-signature` = Ed25519 by the chat device key over `CATBIRD-LABYRINTH-READ\0` || claim. The window is ±300 s.
  - `XrpcTransport::query_with_headers` is now the required method, so wrappers must forward headers. `SignedReadTransport` signs.
  - `MemoryXrpcServer` verifies the headers, and with `require_signed_reads` it refuses unsigned queries. The errors match mls-ds: 401 `InvalidSignature` or 400 `InvalidRequest`.
  - Golden vector: `tests/vectors/labyrinth_read_header.json`, also pinned in mls-ds.
- **Account deletion never strands the user.** `purge_account` returns `Ok` with `remote_pending` when the remote half fails, and still clears local caches. `delete_account_remote` retries without client state.
- **Redaction labels ([CB-38]).** `defs#redaction` gains optional `by` and `reason`. `"accountDeleted"` means the sequencer DS signed the redaction over `catbird.labyrinth.ds_redaction:by=…;did=…;message_id=…;reason=accountDeleted;redacted_at=…;thread_id=<hex>`. `account_deleted` is set only when that signature verifies under `MailboxDirectory::sequencer_key` with `by` equal to the reported DS DID. Anything else that isn't a verified unsend is `removed_by_server`.
  - `XrpcDirectory` has no source for the DS key yet, so returns `None`. Over mls-ds alone, account deletions therefore read as "removed by server" (fail closed) until a key source exists: a DID-document key or an endpoint. **Open item for the mls-ds lane.**
- **`listThreads` `incomplete`.** `ThreadStore::list_threads_report` and `Labyrinth::list_threads_report` return the partial list plus the unreachable sequencer DIDs. The strict `list_threads` now fails (`Backend`) instead of hiding the gap.
- **Also added:** `flush_thread` and `discard_pending`, for per-conversation archiving. The reference server now answers `ConversationNotFound` for a conversation with no leaves.

Reversible until: merge of `labyrinth-1.1`. Override by:
- Roster exclusion and re-pin: edit `src/client/send.rs` and `src/client/pins.rs` (`tests/roster_and_repin.rs`).
- Signed reads: edit `src/store/xrpc/read_auth.rs` (`tests/signed_reads.rs`).
- Account deletion: edit `src/client/delete.rs` (`tests/purge_retry.rs`).
- Redaction labels: edit `src/deletion.rs` and `src/client/read.rs` (`tests/history_ops.rs`, `tests/lexicon_records.rs`).

## 2026-10-11 · labyrinth · Space mailbox store (plan Phase 4, crate half)
Context: the README listed the atproto Space store as the main missing piece. Decision 2 scopes storage to a per-user mailbox with mls-ds as sequencer, and the plan defers group Spaces until after GA, so only the mailbox side is built. Upstream reference: `bluesky-social/atproto` branch `permissioned-data` at `5b95b2f2` (2026-10-01 alpha).

Chose (provisional):
- **`store::space::SpaceMailboxStore`** (feature `space`, implies `xrpc`) implements `MailboxStore` over `com.atproto.space.{applyWrites,getRecord,listRecords,deleteRecord}`. It reuses `XrpcTransport`: the app passes one bound to the user's PDS with the OAuth session; `operation_id` is ignored there.
- **One Space per account:** `at://<did>/space/blue.catbird.labyrinth.mailbox/self`. The store never calls `createSpace`. On the live dev PDS a member's own PDS accepts writes to a Space no authority governs and serves them back with `read_self`, which is all an owner-only mailbox needs. An app may still create it once #119 moves `createSpace` into `com.atproto.space`. Before any write, the owner's own repo lists as empty; another account's repo answers `RepoNotFound`, which reads as empty too.
- **Writes:** `#create` with our rkeys, so `RecordAlreadyExists` → `Conflict` is the race guard ([CB-9]); `create_epoch` is one `applyWrites` and is refused (not split) past 200 ops; owner batches are `#create` without an rkey and take the PDS's TID from the result URI; `validate: false`.
- **Revocation and `lastUsedAt`** are read-then-`#update`. There is no `swapRecord` in Space writes, and both fields are only ever set, so a lost race costs at most a different timestamp. `lastUsedAt` comes from the client's clock (`with_clock`), since no server stamps it ([CB-39] expiry trusts the owner's devices on this backend).
- **Reads** page `listRecords` ascending (`reverse=true`, 50 per page by default, `with_page_size`) and filter client side; `get_epoch_member` overrides the scan with a `getRecord`.
- **`mailboxKeys`** goes to the public repo through a `KeyPublisher` passed at construction (`PdsPublisher` in production); the Space keeps no copy. `purge_mailbox` deletes every mailbox record in 200-op batches, then retracts it. ORF states and attachment references stay on mls-ds and go with its `purgeMailbox`, reached through the mls-ds publisher's `retract`.
- **`MemorySpaceHost`** is a reference PDS for those four endpoints with the upstream limits and errors (own-repo writes, 200 ops, 1,000,000-byte bodies, `read_self` only, URI-ordered listing and cursor). `tests/e2e_space.rs` runs the lifecycle with every mailbox in a Space, the production directory composition (PDS × mls-ds heads), and every call validated against the vendored upstream lexicons in `tests/vectors/atproto-space/`.
  - Rejected for now: thread-tagged owner-batch rkeys with `excludeValues` scans. Owner batches are rare (re-archive on leave, delete-for-me), and the lexicon fixes the key as a TID.

- **Live check.** `tests/live_space_pds.rs` (opt-in, `LABYRINTH_SPACE_PDS`) runs enrollment, revocation, restore, re-archive, recovery-method removal and purge against the upstream dev PDS started by `scripts/space-pds/start.mjs`, with `mailboxKeys` in the public repo over `com.atproto.repo.*` and the production directory composition. It passed on 2026-10-11 against `5b95b2f2`, and corrected two assumptions in the reference host: writes need no prior `createSpace`, and an unwritten own repo lists as empty rather than `RepoNotFound`.

Reversible until: merge of `labyrinth-1.1`. Override by: edit `src/store/space/*` (`tests/e2e_space.rs`, `tests/live_space_pds.rs`). Revisit when the upstream repo-format rework and #119 land.

## 2026-10-11 · labyrinth · Initialization keeps the genesis keys
Context: a review (Codex, on #1) found that `initialize` discarded the only copy of the genesis device and epoch-0 secrets when ORF registration, randomness or publishing failed after epoch 0 was created, leaving epoch 0 squatted and the mailbox unusable.

Chose: the DID check and randomness move before the first mailbox write. The wire order is unchanged (`createDevice`, `createEpoch`, `registerOrfState`, publish), so the mls-ds trace fixture still replays. The steps after epoch 0, ORF registration and publishing, no longer fail `initialize`: `initialize_with_report` returns the first error, and `finish_initialize` retries both (an existing ORF state counts as done). It publishes every epoch from 0 up, so a rotation made before the retry cannot leave the mls-ds head chain without epoch 0. During the replay a PDS's `mailboxKeys/self` briefly names an older epoch. Until then the device cannot use attachment references, and peers see the account as not enrolled in any directory that missed the publish.

Reversible until: merge of `labyrinth-1.1`. Override by: edit `Labyrinth::initialize_with_report` in `src/client/epochs.rs` (`tests/init_recovery.rs`).

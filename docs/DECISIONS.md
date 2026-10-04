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
| CB-25 | the opener encrypts entropy to itself; an invalid continuing device aborts rotation instead of being dropped | self-recovery for the opener's other installs; a silent drop would be an unannounced revocation | drop the self-entry; skip invalid devices |
| CB-26 | OTC payload is a fixed big-endian binary layout, not CBOR | avoids a CBOR dependency for one five-field struct | switch to CBOR (bump the format byte) |
| CB-27 | history reads accept MEK attestations and message signatures from any chat key the DID ever registered, but a removed key only for messages timestamped before its `removed_at`; addressing a MEK requires a *current* chat device | a revoked or lost device signed real history; only new MEKs need a live device. Timestamps are sender-chosen, so this is a bound, not a guarantee | require current devices for reads too (old history becomes unreadable after device loss) |
| CB-28 | epoch-integrity check: a device compares the newest epoch it reached with the directory's published latest epoch and fails with `EpochTruncated` if the directory is ahead | the SPEC §10 mitigation; the directory (public `mailboxKeys` / mls-ds roster view) is independent of the mailbox store | drop the check (truncation becomes silent) |
| CB-29 | senders pin each addressed DID's newest accepted `(epochNumber, epochHead, signingPubkey)`; reject older/forked epochs (`EpochRollback`) and advance only through a verified `prev_sig` chain fetched via `MailboxDirectory::epoch`; first contact is TOFU anchored by [CB-18]; every epoch is also kept at `mailboxKeys/<12-digit seq>` | a peer's PDS could replay an older attested `mailboxKeys` and make senders encrypt to keys a revoked device holds | drop the pins (replay becomes silent); long term, move latest heads into MLS-authenticated group state |
| CB-30 | client state persists as a versioned binary blob (`LBYS` v1) from `Labyrinth::export_state`, restored with `from_state`; the caller keeps it in the keychain / SQLCipher | the revoked set and pins must survive restarts; one blob is the simplest UniFFI surface | per-field storage callbacks |
| CB-31 | history merges copies only on `(author DID, messageId)` with byte-equal frames (owner copies: byte-equal frame); other id collisions are all returned with `conflict = true` | messageId is chosen by the sender, so an insider could otherwise suppress another member's message | dedup on messageId alone (restores the suppression) |

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

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
| CB-27 | history reads accept MEK attestations and message signatures from any chat key the DID ever registered; addressing a MEK requires a *current* chat device | a revoked or lost device signed real history; only new MEKs need a live device | require current devices for reads too (old history becomes unreadable after device loss) |
| CB-28 | epoch-integrity check: a device compares the newest epoch it reached with the directory's published latest epoch and fails with `EpochTruncated` if the directory is ahead | the SPEC §10 mitigation; the directory (public `mailboxKeys` / mls-ds roster view) is independent of the mailbox store | drop the check (truncation becomes silent) |

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

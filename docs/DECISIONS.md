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

## 2026-10-04 · labyrinth · MEK and message layer
Chose: bind the thread id into MEK AADs ([CB-24]) and restrict transport-MEK reuse to its minting device ([CB-23]) (provisional). Because: a MEK record's `threadId` was otherwise unauthenticated, and the reuse rule's "authenticated to the latest epoch keys" has no epoch to point at for a transport MEK. Rejected: paper-exact AAD plus an equality check against the caller's thread (a backend could still rewrite both consistently); letting any reader reuse a transport MEK (rule 2 would be vacuous).
Owner-mode records still leave `messageId` and `timestamp` unauthenticated, as in the paper (SPEC §7.1).
Reversible until: merge of `labyrinth-1.1`. Override by: deleting the `;thread_id=` suffix in `src/mek/distribute.rs::aad`, and changing `Mek::reusable_for`.

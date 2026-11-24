# labyrinth

A Rust implementation of Meta's **Labyrinth 1.1** encrypted message-history storage protocol, adapted for Catbird's MLS chat on atproto (the "Catbird profile").

## Documentation

Rust API documentation: <https://joshlacal.github.io/labyrinth/> (rustdoc, rebuilt from `main`; start at `labyrinth`).

MLS keeps chat messages end-to-end encrypted in transit, but it does not give a new or restored device the conversation's history. Labyrinth adds an encrypted per-account *mailbox* of key material (devices, epochs, recovery bundles) and an encrypted archive of messages that only the account's enrolled devices, or a recovery code, can open. Both live in atproto Spaces, which see only ciphertext: the mailbox in the account's personal Space, and history in each conversation's Space. Catbird's `mls-ds` delivery service stores no Labyrinth content. It is only the directory and sequencer (`docs/MLSDS_BACKEND.md`).

**Status: pre-GA draft.** Nothing here has been audited, the wire formats and lexicons may still change, and the crate is not published. Do not rely on it to protect real data yet. The bookmark `clean-slate-2026-10-31` holds R0 (`6462096a`). The Task 4 archive work on top of it (latest reviewed cut `276c0972`) is unsealed. Its independent R3 review failed, and Fix Round 4 is in progress; see `docs/SPACE_CONVERSATIONS.md` and `docs/DECISIONS.md`.

## Catbird profile vs. Messenger

The whitepapers leave many choices open and are written around Facebook identities. `docs/SPEC.md` fixes every choice for Catbird and tags each one **[CB-n]**; `docs/DECISIONS.md` records why. The main differences from Messenger:

- Accounts are atproto DIDs, threads are MLS conversation ids, and the "transport key" that signs messages is the sender's MLS chat device key (Ed25519).
- Each epoch head is also signed by a chat device key ([CB-18]), so neither a storage backend nor the delivery service can substitute someone's mailbox keys.
- Sender-encrypted messages are stored once per conversation, in the sender's own repo, instead of once per recipient ([CB-15]).
- Every archived application frame is bound by the conversation sequencer's signed `I13` receipt, and receiving members store witness copies of it, so history survives a sender removed before it flushes (`docs/SPACE_CONVERSATIONS.md`).
- MEK (message encryption key) distributions bind the thread id ([CB-24]).
- Revoking a device always opens a new epoch ([CB-11]), excluding every device the client has revoked even if the store forgets `revokedAt`.
- Senders pin each peer's epoch head and only move forward along its signed chain ([CB-29]).
- Hawk HPKE byte layout, the recovery-code error-correcting code and the one-time-code payload are our own definitions.

**We do not claim wire compatibility with Messenger.** Meta publishes no test vectors; ours are in `tests/vectors/`.

## Crate layout

| Path | What it does |
|---|---|
| `src/aead/`, `src/hpke/`, `src/sign.rs`, `src/padding.rs`, `src/encoding.rs` | Primitives: AES-256-DNDK-GCM and AES-GCM-Extended, Labyrinth and Hawk (X25519 + ML-KEM-768) HPKE, XEdDSA and Ed25519, PADMÉ padding, KDF helpers. The paper's ORF is retired (SPEC §3.6). |
| `src/device.rs`, `src/epoch/`, `src/mailbox.rs` | Devices, epoch opening and chaining, mailbox key pairs and epoch heads |
| `src/recovery_code.rs`, `src/virtual_device/`, `src/otc.rs` | Recovery codes with typo correction, recovery bundles, passkey wrap, CPace one-time codes |
| `src/mek/`, `src/message.rs` | MEK distribution and opening; owner-mode and sender-mode message encryption |
| `src/records/` | atproto record types for every lexicon, with lossless conversions to the protocol structs |
| `src/store/` | Async storage traits (`MailboxStore`, `ThreadStore`, `MailboxDirectory`, `KeyPublisher`), the chat-key vouching rule, an in-memory backend, the public `mailboxKeys` directory and publisher (`store::pds`), and the Space stores (`store::space`): the personal mailbox, the conversation thread store, and the `MemorySpaceHost` reference host |
| `src/client/` | `Labyrinth`, the high-level client a chat app calls. It covers initialize, sync, revoke (with membership audit), recover, enroll, archive (including receipt-committed and witness copies), and export and restore of its state; loading by range, by id or newest-first page, with witness acceptance and rejection; delete-for-me, unsend and account purge; attachment manifests; recovery-method lifecycle; and fingerprints. Also `CompositeDirectory`, which cross-checks the PDS and mls-ds epoch heads |
| `src/deletion.rs`, `src/attachment.rs`, `src/fingerprint.rs` | Signed redactions, attachment-manifest ciphertext checks, safety numbers |
| `lexicons/blue/catbird/labyrinth/` | Draft `blue.catbird.labyrinth.*` record lexicons. The directory also still holds lexicons for retired mls-ds content endpoints (`appendBatch`, `getEpoch`, `listSpaceBatches`, …); mls-ds serves only the six in `docs/MLSDS_BACKEND.md` |
| `docs/SPEC.md`, `docs/DECISIONS.md`, `docs/SPACE_CONVERSATIONS.md`, `docs/MLSDS_BACKEND.md` | The protocol profile, the decision log, the conversation-Space archive contract (witness copies, owner fallback, account deletion), and what mls-ds provides |

The protocol layers do no I/O. The client talks to storage only through the `store` traits. They are async (`Send + Sync` on native targets, `?Send` on `wasm32`), and the crate brings no runtime of its own.

A minimal flow on the in-memory backend:

```rust
use labyrinth::client::{Backends, Labyrinth, SystemClock};
use labyrinth::store::{memory::MemoryBackend, TimeRange};

let net = MemoryBackend::new();
let backends = |did: &str| Backends {
    mailbox: Box::new(net.mailbox(did)),
    threads: Box::new(net.threads(did)),
    directory: Box::new(net.directory()),
    publishers: vec![],
    clock: Box::new(SystemClock),
};
// Inside an async fn. `transport` is the device's MLS chat key, registered with the directory.
let mut alice = Labyrinth::initialize("did:plc:alice", Box::new(transport), backends("did:plc:alice")).await?;
let roster = alice.resolve_roster(&["did:plc:alice", "did:plc:bob"]).await?;
alice.archive_outgoing("conv-1", &roster, "msg-1", now_ms, frame).await?;
alice.flush().await?;
let history = alice.load_thread("conv-1", TimeRange::ALL).await?;
```

`tests/e2e_memory.rs` is the full worked example.

## Running the tests

```bash
cargo test --release                  # release mode keeps the ML-KEM and recovery-code tests fast
cargo test --release --all-features   # `space` is the only feature, and it is on by default
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

The tests include the AES-256-DNDK-GCM and CPace draft vectors, our own recovery-code vectors, a lexicon validator that checks every emitted record against `lexicons/`, and an end-to-end lifecycle on the memory backend: multi-device accounts, revocation, recovery from a typo'd code, members leaving and joining, and malicious-backend checks. `tests/review_regressions.rs` pins the fixes from the 2026-10-04 security review. `tests/directory_and_orf.rs` and `tests/gate6_composite_directory.rs` cover the PDS × mls-ds directory cross-check (the first file's name predates the ORF's retirement). `tests/witness_archive.rs`, `tests/gate1_receipt_commitment.rs` and `tests/history_ops.rs` cover witness copies, `I13` commitments and the owner fallback. `tests/e2e_space.rs` runs the lifecycle with every mailbox in a personal Space, validating each `com.atproto.space.*` call against the vendored upstream lexicons (`tests/vectors/atproto-space/`). `tests/live_space_pds.rs` is ignored by default.

## Security caveats and limitations

- **Unaudited draft.** The profile choices ([CB-n]) are provisional until the `clean-slate-2026-10-31` bookmark merges and atproto Spaces reach GA.
- **Limitations kept from the paper** (SPEC §10): a backend that controls both the mailbox and the directory can hide newer epochs, and membership can be enumerated.
- **Epoch truncation** is detected only when the `MailboxDirectory` is independent of the mailbox store ([CB-28]). `CompositeDirectory` cross-checks the PDS and mls-ds, so truncation needs the mailbox host and the other directory to collude.
- **Public enrollment signal.** Publishing `mailboxKeys` in the public repo reveals that an account uses Labyrinth and when it rotates epochs ([CB-19]).
- **Owner-mode records.** Legacy versions 0–4 authenticate the thread and epoch but not `messageId` or `timestamp`, as in the paper, and carry no sender DID. Version 5 ([CB-37]) binds `messageId` and `timestamp`. Its `0x03` kind carries the sender DID, and its `0x02` kind binds the full `I13` receipt into the AEAD.
- **History reads trust removed devices, up to their removal.** Messages and MEKs signed by a chat device that has since been removed still verify if they were admitted before its removal ([CB-27]). The boundary is the sequencer's signed `I13` receipt (`seq`, `issuedAtMs`) checked against mls-ds's per-leaf `joinedSeq`/`removedSeq`. A conversation without a resolvable receipt key falls back to sender timestamps, which do not establish that boundary. Addressing a new MEK requires a current device.
- **First contact.** Senders pin each peer's newest epoch and refuse rollbacks afterwards ([CB-29]). `CompositeDirectory::new` requires the peer's PDS and mls-ds to agree on the first epoch. A head in only one source fails with `DirectoryIncomplete`; trust-on-first-use requires the explicit `new_allowing_single_source`. Carrying latest heads in MLS-authenticated group state is the long-term fix.
- **Client state is secret.** `Labyrinth::export_state()` returns the device's private keys, epoch roots, MEKs, revoked set and pins ([CB-30]). Store it only in the platform keychain or SQLCipher; flush pending batches first, since they are not included.
- **Revocation can't be wedged by a planted row.** A rotation drops and reports invalid or unbound members instead of aborting ([CB-25], [CB-36]), and a squatted next epoch is reported as `EpochSquatted` ([CB-40]). Clearing a squat still needs the backend.
- **Deletion is cooperative.** An unsend writes a separate immutable, author-signed `blue.catbird.labyrinth.redaction` record and never rewrites the source batch ([CB-38]). Readers hide every sender, witness and owner copy of the message; the witness copies themselves stay stored in other members' repos. Account deletion is the sequencer's signed `accountDeletedEntry`. Readers can tell an author's unsend from an account deletion. Deleted data survives in Space-host backups for their retention window.
- **Space mailbox caveats.** In a Space, `lastUsedAt` on a recovery bundle is stamped by the owner's own device clock (no server), device revocation is a read-then-`#update` (Space writes have no `swapRecord`), and per-thread owner reads scan the owner-batch collection. The store needs no `createSpace`: the owner's PDS accepts writes to an ungoverned Space. `tests/live_space_pds.rs` runs the lifecycle against the upstream dev PDS (opt-in; see `scripts/space-pds/start.mjs`).
- **Not yet provided:**
  - live qualification of the conversation-Space store across real OAuth, authority and foreign repository hosts; its current tests use a reference Space host and sequencer;
  - a UniFFI surface.

## References

- Labyrinth v1 whitepaper (Dec 2023): <https://engineering.fb.com/wp-content/uploads/2023/12/TheLabyrinthEncryptedMessageStorageProtocol_12-6-2023.pdf>
- Labyrinth v1.1 / Minos whitepaper (Apr 2026): <https://engineering.fb.com/wp-content/uploads/2026/05/Minos-Updates-2026-Encrypted-Backups-White-Paper.pdf>
- AES-256-DNDK-GCM: <https://datatracker.ietf.org/doc/draft-gueron-cfrg-dndkgcm/>
- CPace: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/>
- XEdDSA: <https://signal.org/docs/specifications/xeddsa/>
- Oblivious revocable functions: <https://eprint.iacr.org/2022/1044>

## License

MIT OR Apache-2.0, at your option (see `Cargo.toml`). `LICENSE` carries the MIT text and `LICENSE-APACHE` the Apache-2.0 text.

# labyrinth

A Rust implementation of Meta's **Labyrinth 1.1** encrypted message-history storage protocol, adapted for Catbird's MLS chat on atproto (the "Catbird profile").

MLS keeps chat messages end-to-end encrypted in transit, but it does not give a new or restored device the conversation's history. Labyrinth adds an encrypted per-account *mailbox* of key material (devices, epochs, recovery bundles) and an encrypted archive of messages that only the account's enrolled devices, or a recovery code, can open. Storage servers (an atproto PDS Space, or Catbird's `mls-ds` delivery service) see only ciphertext.

**Status: pre-GA draft.** Nothing here has been audited, the wire formats and lexicons may still change, and the crate is not published. Do not rely on it to protect real data yet.

## Catbird profile vs. Messenger

The whitepapers leave many choices open and are written around Facebook identities. `docs/SPEC.md` fixes every choice for Catbird and tags each one **[CB-n]**; `docs/DECISIONS.md` records why. The main differences from Messenger:

- Accounts are atproto DIDs, threads are MLS conversation ids, and the "transport key" that signs messages is the sender's MLS chat device key (Ed25519).
- Each epoch head is also signed by a chat device key ([CB-18]), so neither a storage backend nor the delivery service can substitute someone's mailbox keys.
- Sender-encrypted messages are stored once per conversation, in the sender's own repo, instead of once per recipient ([CB-15]).
- MEK (message encryption key) distributions bind the thread id ([CB-24]).
- Revoking a device always opens a new epoch ([CB-11]), excluding every device the client has revoked even if the store forgets `revokedAt`.
- Senders pin each peer's epoch head and only move forward along its signed chain ([CB-29]).
- Hawk HPKE byte layout, the recovery-code error-correcting code and the one-time-code payload are our own definitions.

**We do not claim wire compatibility with Messenger.** Meta publishes no test vectors; ours are in `tests/vectors/`.

## Crate layout

| Path | What it does |
|---|---|
| `src/aead/`, `src/hpke/`, `src/sign.rs`, `src/orf.rs`, `src/padding.rs`, `src/encoding.rs` | Primitives: AES-256-DNDK-GCM and AES-GCM-Extended, Labyrinth and Hawk (X25519 + ML-KEM-768) HPKE, XEdDSA and Ed25519, ORF, PADMÉ padding, KDF helpers |
| `src/device.rs`, `src/epoch/`, `src/mailbox.rs` | Devices, epoch opening and chaining, mailbox key pairs and epoch heads |
| `src/recovery_code.rs`, `src/virtual_device/`, `src/otc.rs` | Recovery codes with typo correction, recovery bundles, passkey wrap, CPace one-time codes |
| `src/mek/`, `src/message.rs` | MEK distribution and opening; owner-mode and sender-mode message encryption |
| `src/records/` | atproto record types for every lexicon, with lossless conversions to the protocol structs |
| `src/store/` | Synchronous storage traits (`MailboxStore`, `ThreadStore`, `MailboxDirectory`, `KeyPublisher`, `OrfServer`), the chat-key vouching rule, an in-memory backend, and (feature `xrpc`) stores over the mls-ds `blue.catbird.labyrinth.*` endpoints with a memory-backed reference server |
| `src/client/` | `Labyrinth`, the high-level client a chat app calls. It covers initialize, sync, revoke (with membership audit), recover, enroll, archive, and export and restore of its state; loading by range, by id or newest-first page; delete-for-me, unsend and account purge; attachment references; recovery-method lifecycle; and fingerprints. Also `CompositeDirectory`, which cross-checks the PDS and mls-ds epoch heads |
| `src/deletion.rs`, `src/attachment.rs`, `src/fingerprint.rs` | Signed redactions, attachment-reference derivations, safety numbers |
| `lexicons/blue/catbird/labyrinth/` | Draft `blue.catbird.labyrinth.*` record lexicons and the mls-ds XRPC queries and procedures |
| `docs/SPEC.md`, `docs/DECISIONS.md`, `docs/MLSDS_BACKEND.md` | The protocol profile, the decision log, and the mls-ds backend design |

The protocol layers do no I/O. The client talks to storage only through the `store` traits, which are synchronous so the crate needs no async runtime.

A minimal flow on the in-memory backend:

```rust
use labyrinth::client::{Backends, Labyrinth, SystemClock};
use labyrinth::store::{memory::MemoryBackend, TimeRange};

let net = MemoryBackend::new();
let backends = |did: &str| Backends {
    mailbox: Box::new(net.mailbox(did)),
    threads: Box::new(net.threads(did)),
    directory: Box::new(net.directory()),
    orf: Box::new(net.orf(did)),
    publishers: vec![],
    clock: Box::new(SystemClock),
};
// `transport` is the device's MLS chat key, registered with the directory.
let mut alice = Labyrinth::initialize("did:plc:alice", transport, backends("did:plc:alice"))?;
let roster = alice.resolve_roster(&["did:plc:alice", "did:plc:bob"])?;
alice.archive_outgoing("conv-1", &roster, "msg-1", now_ms, frame)?;
alice.flush()?;
let history = alice.load_thread("conv-1", TimeRange::ALL)?;
```

`tests/e2e_memory.rs` is the full worked example.

## Running the tests

```bash
cargo test --release                  # release mode keeps the ML-KEM and recovery-code tests fast
cargo test --release --all-features   # adds the xrpc stores and their e2e run
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

The tests include the AES-256-DNDK-GCM and CPace draft vectors, our own known-answer vectors for HPKE, ORF and recovery codes, a lexicon validator that checks every emitted record against `lexicons/`, and an end-to-end lifecycle on the memory backend: multi-device accounts, revocation, recovery from a typo'd code, members leaving and joining, and malicious-backend checks. `tests/review_regressions.rs` pins the fixes from the 2026-10-04 security review (revocation, epoch pinning, messageId collisions, state persistence, removed chat keys, with and without server order). `tests/directory_and_orf.rs` covers the PDS × mls-ds directory cross-check and the client's ORF calls; `tests/e2e_xrpc.rs` runs the lifecycle over the XRPC stores with every call validated against the lexicons.

## Security caveats and limitations

- **Unaudited draft.** The profile choices ([CB-n]) are provisional until the `labyrinth-1.1` bookmark merges and atproto Spaces reach GA.
- **Limitations kept from the paper** (SPEC §10): a backend that controls both the mailbox and the directory can hide newer epochs; membership can be enumerated; entropy distribution between devices stays classical X25519, so post-quantum protection is partial.
- **Epoch truncation** is detected only when the `MailboxDirectory` is independent of the mailbox store ([CB-28]). `CompositeDirectory` cross-checks the PDS and mls-ds, so truncation needs the mailbox host and the other directory to collude.
- **Public enrollment signal.** Publishing `mailboxKeys` in the public repo reveals that an account uses Labyrinth and when it rotates epochs ([CB-19]).
- **Owner-mode records** (v1.0 compatibility and re-archive on leave) authenticate the thread and epoch but not `messageId` or `timestamp`, as in the paper, and carry no sender DID.
- **History reads trust removed devices, up to their removal.** Messages and MEKs signed by a chat device that has since been removed still verify if they were written before its removal ([CB-27]). With mls-ds that is decided by the server's stamp (receive time and conversation sequence), so a removed device cannot backdate; records in a Space carry no stamp, so there the sender's timestamp decides and a removed device can backdate. Addressing a new MEK requires a current device.
- **First contact.** Senders pin each peer's newest epoch and refuse rollbacks afterwards ([CB-29]). With `CompositeDirectory` the first epoch must also agree between the peer's PDS and mls-ds; with a single directory it is trust-on-first-use. Carrying latest heads in MLS-authenticated group state is the long-term fix.
- **Client state is secret.** `Labyrinth::export_state()` returns the device's private keys, epoch roots, MEKs, revoked set and pins ([CB-30]). Store it only in the platform keychain or SQLCipher; flush pending batches first, since they are not included.
- **Revocation can't be wedged by a planted row.** A rotation drops and reports invalid or unbound members instead of aborting ([CB-25], [CB-36]), and a squatted next epoch is reported as `EpochSquatted` ([CB-40]). Clearing a squat still needs the backend.
- **Deletion is cooperative.** An unsend asks the server to redact, and readers can tell an author's unsend from a server removal. Deleted data survives in server backups for their retention window.
- **Not yet provided:**
  - the atproto Space store;
  - `listThreads` / `listOwnerThreads` over XRPC (mls-ds has neither). Account purge over mls-ds therefore runs server-side through `deleteAccountData`; see DECISIONS "XRPC wiring of the gap-closure endpoints";
  - a UniFFI surface.

## References

- Labyrinth v1 whitepaper (Dec 2023): <https://engineering.fb.com/wp-content/uploads/2023/12/TheLabyrinthEncryptedMessageStorageProtocol_12-6-2023.pdf>
- Labyrinth v1.1 / Minos whitepaper (Apr 2026): <https://engineering.fb.com/wp-content/uploads/2026/05/Minos-Updates-2026-Encrypted-Backups-White-Paper.pdf>
- AES-256-DNDK-GCM: <https://datatracker.ietf.org/doc/draft-gueron-cfrg-dndkgcm/>
- CPace: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/>
- XEdDSA: <https://signal.org/docs/specifications/xeddsa/>
- Oblivious revocable functions: <https://eprint.iacr.org/2022/1044>

## License

MIT OR Apache-2.0 (see `Cargo.toml`); the `LICENSE` file carries the MIT text.

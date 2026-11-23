# Building and testing

## Layout

Labyrinth is a Cargo workspace with two crates:

| Crate | Path | What it holds |
|---|---|---|
| `labyrinth` | repository root | The client (`Labyrinth`), the store traits and their memory and Space implementations, recovery, enrollment, deletion |
| `labyrinth-protocol` | `labyrinth-protocol/` | Pure verification code shared with servers: epoch-head chains, sequencer receipts, and the errors they raise |

Rust 1.85 or newer is required (`edition = "2024"`).

## The sibling checkout

`labyrinth` depends on the `atproto-spaces` crate by path:

```toml
atproto-spaces = { path = "../catbird-atproto/atproto-spaces", default-features = false }
```

Clone [`catbird-atproto`](https://github.com/joshlacal/catbird-atproto) next to this repository before building. The README records the commit the current `main` was tested against.

```text
workspace/
├── catbird-atproto/
└── labyrinth/
```

Some of `catbird-atproto`'s dependencies are fetched over git. If Cargo's built-in git client can't reach a host, set `CARGO_NET_GIT_FETCH_WITH_CLI=true` so it uses the system `git` instead.

## Tests

```bash
cargo test --release                  # release mode keeps the ML-KEM and recovery-code tests fast
cargo test --release --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

`space` is on by default and is now a no-op alias kept for downstream feature flags. `sim` and `plant_p16` exist only for fault-injection tests.

The suite includes:

- vectors for AES-256-DNDK-GCM, CPace and the recovery code (`tests/dndk_gcm.rs`, `tests/cpace_vectors.rs`, `tests/recovery_code_vectors.rs`, `tests/recovery_code_v3.rs`);
- a lexicon validator that checks every emitted record against `lexicons/` (`tests/lexicon_records.rs`);
- an end-to-end lifecycle on the memory backend (`tests/e2e_memory.rs`) and the same lifecycle with every mailbox in a reference personal Space (`tests/e2e_space.rs`);
- regressions for each fix from the security reviews (`tests/review_regressions.rs`) and adversarial-backend tests (`tests/mek_tamper.rs`, `tests/rotation_audit.rs`, `tests/fault_lines.rs`, `tests/space_read_authentication.rs`).

### The live Space test

`tests/live_space_pds.rs` runs against a real PDS that serves `com.atproto.space.*`. It is ignored by default. Start the helper in `scripts/space-pds/` (`node start.mjs`), point `LABYRINTH_SPACE_PDS` at the session file it writes, and run the test with `--ignored`.

## WebAssembly

The crate builds for `wasm32-unknown-unknown`. On that target every store trait is `async_trait(?Send)` (the `MaybeSend`/`MaybeSync` bounds become empty), and randomness comes from the browser through `getrandom`'s `wasm_js` backend. Catbird's web client wraps it from the `catbird-mls` web build.

## API documentation

```bash
cargo doc --no-deps -p labyrinth -p labyrinth-protocol --open
```

The published copy is under [API reference](../reference/api.md).

## This book

The book is built with [mdBook](https://rust-lang.github.io/mdBook/) 0.4:

```bash
cargo install mdbook --version 0.4.52 --locked
mdbook serve docs/book
```

The reference chapters include `docs/*.md` directly, so editing `docs/SPEC.md` updates the book.

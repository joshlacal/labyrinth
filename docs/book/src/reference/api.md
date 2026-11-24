# API reference (rustdoc)

The Rust API documentation is generated with `cargo doc` and published next to this book:

- [`labyrinth`](../api/labyrinth/index.html): the client (`Labyrinth`), `Backends`, the store traits and their implementations, records, recovery codes and errors.
- [`labyrinth_protocol`](../api/labyrinth_protocol/index.html): epoch-head chain and sequencer-receipt verification shared with mls-ds.

The links work on the published site. Locally, build the same pages with:

```bash
cargo doc --no-deps -p labyrinth -p labyrinth-protocol --open
```

The crate is not published to crates.io yet, so there is no docs.rs page.

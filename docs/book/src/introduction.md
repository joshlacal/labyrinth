# Labyrinth for Catbird

Catbird's chat is end-to-end encrypted with MLS (the Messaging Layer Security protocol, RFC 9420). MLS protects messages in transit between the devices that are in a conversation at that moment. It does not, by itself, give a new phone, a reinstalled app or a restored account the conversation's earlier messages.

**Labyrinth** fills that gap. It is a Rust implementation of Meta's *Labyrinth Encrypted Message Storage Protocol*, version 1.1, adapted for Catbird's MLS chat on AT Protocol. It keeps an encrypted archive of chat history that only the account's own enrolled devices, or a recovery method the user set up, can open. The servers that store the archive see ciphertext and some metadata, which [the security model](overview/security-model.md) lists exactly.

> **Status: pre-GA draft.** Nothing here has been independently audited. Wire formats, record lexicons and the public API may still change, and the crate is not published to crates.io. The in-repository status notes (dated 2026-11-07) record that the independent review of the current archive work had failed and a fourth fix round was in progress. Do not rely on Labyrinth to protect real data yet.
>
> We do **not** claim wire compatibility with Meta's Messenger implementation. Meta publishes no test vectors; ours are in `tests/vectors/`.

## Who this book is for

- **Readers and security reviewers** who want to know what Labyrinth protects, what it does not, and where each guarantee comes from. Start with [Architecture](overview/architecture.md) and the [Security model](overview/security-model.md).
- **Developers** integrating Labyrinth into a chat client or writing a storage backend. Start with [Building and testing](guide/building.md) and [Using the client](guide/integrating.md).
- **Protocol reviewers** who want every byte. The [protocol profile](reference/SPEC.md) fixes every choice the whitepaper leaves open, tagged **[CB-n]**, and the [decision log](reference/DECISIONS.md) records why.

## How Labyrinth fits into Catbird

| Component | Role |
|---|---|
| [`catbird-mls`](https://github.com/joshlacal/catbird-mls) | Catbird's MLS client SDK. It sends and receives messages and calls Labyrinth to archive and restore them. |
| `labyrinth` (this crate) | The history protocol: device and epoch keys, message encryption keys, archive records, recovery. It does no network I/O itself. |
| [`mls-ds`](https://github.com/joshlacal/mls-ds) | Catbird's MLS delivery service. For Labyrinth it is only a **directory** (a second, independent copy of each account's public epoch keys) and a **sequencer** (it signs receipts that order messages). It is also the authority for the conversation Spaces it sequences and holds the server share of version-3 recovery codes. |
| AT Protocol **Spaces** | Permissioned data on the user's PDS. Each account's private key material lives in its *personal mailbox Space*; each conversation's archived history lives in that conversation's *conversation Space*. |

## Primary sources

- Labyrinth v1 whitepaper (December 2023): <https://engineering.fb.com/wp-content/uploads/2023/12/TheLabyrinthEncryptedMessageStorageProtocol_12-6-2023.pdf>
- Labyrinth v1.1 / Minos whitepaper (April 2026): <https://engineering.fb.com/wp-content/uploads/2026/05/Minos-Updates-2026-Encrypted-Backups-White-Paper.pdf>
- AES-256-DNDK-GCM: <https://datatracker.ietf.org/doc/draft-gueron-cfrg-dndkgcm/>
- CPace: <https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/>
- XEdDSA: <https://signal.org/docs/specifications/xeddsa/>

## Reporting a vulnerability

Please don't open a public issue. Report privately through [GitHub private vulnerability reporting](https://github.com/joshlacal/labyrinth/security/advisories/new) or email `security@catbird.blue`. The full policy is in [`SECURITY.md`](https://github.com/joshlacal/labyrinth/blob/main/SECURITY.md).

## License

MIT OR Apache-2.0, at your option.

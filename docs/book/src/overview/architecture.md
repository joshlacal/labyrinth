# Architecture

Labyrinth has three kinds of state, and each lives in a different place so that no single server holds everything.

```text
             ┌───────────────────────── a Catbird device ──────────────────────────┐
             │  catbird-mls (MLS chat)  ──archive/restore──▶  labyrinth::Labyrinth │
             │                                                (no I/O of its own)  │
             └───────┬──────────────────────┬───────────────────────┬──────────────┘
                     │ store traits         │                       │
        ┌────────────▼───────────┐ ┌────────▼──────────────┐ ┌──────▼─────────────────┐
        │ Personal mailbox Space │ │ Conversation Space    │ │ Directory (two copies) │
        │ on the account's PDS   │ │ one per conversation  │ │  • public PDS repo:    │
        │  devices, epochs,      │ │  each member's own    │ │    mailboxKeys         │
        │  recovery bundles,     │ │  repo holds its MEKs, │ │  • mls-ds: epoch-head  │
        │  owner archive,        │ │  message batches,     │ │    chain, chat device  │
        │  read state            │ │  unsends, attachments │ │    keys, leaf history  │
        └────────────────────────┘ └───────────────────────┘ └────────────────────────┘
                 private                 members only                  public
```

## The three kinds of state

**1. The personal mailbox.** Every account (an atproto DID) has exactly one mailbox, stored in a personal Space on its own PDS at `at://<did>/space/blue.catbird.labyrinth.mailbox/self`. It holds the account's Labyrinth devices, its chain of *epochs* (the account-wide keys that rotate whenever a device is removed), encrypted *recovery bundles*, an encrypted *owner archive* of history the account can no longer read from a conversation, and encrypted multi-device state such as read position. Only the account's own devices can write here.

**2. Conversation history.** Each MLS conversation has one Space, `at://{sequencerDid}/space/blue.catbird.labyrinth.conversation/{conversationId}-{generation}`, created by the conversation's sequencer with a membership policy derived from the authenticated MLS membership. Every member writes into **its own repo** inside that Space: the message encryption keys (MEKs) it distributed, immutable batches of encrypted messages, signed unsends and attachment manifests. Members read each other's repos with a short-lived Space credential. When an account leaves or is removed, the Space stops issuing it credentials.

**3. The directory.** To encrypt history so that a peer can read it, a sender needs that peer's current mailbox public keys. Each account publishes them twice: as `blue.catbird.labyrinth.mailboxKeys` records in its **public** PDS repo, and on mls-ds's append-only epoch-head chain. Readers use `CompositeDirectory`, which accepts a peer's keys only when both copies agree exactly. A single dishonest host therefore cannot substitute or roll back someone's keys.

## What mls-ds does and does not do

mls-ds is Catbird's MLS delivery service. For Labyrinth it does two things:

- **Directory.** It keeps each account's append-only chain of public epoch heads, the complete history of each account's chat-device signing keys, and each conversation's per-leaf join and removal history. These answer "was this device a member at the time?" when verifying old messages.
- **Sequencer.** It orders MLS entries and signs an `I13` *sequencer receipt* for each one. The receipt is an ES256 (P-256) signature naming the conversation, group, epoch, sender device, a *blinded* commitment to the archived frame, a sequence number and a timestamp. Archived history carries these receipts so that order survives even when the sender is gone.

mls-ds's Labyrinth endpoints are listed in [the mls-ds contract](../reference/MLSDS_BACKEND.md). Members keep their archive records, MEKs, owner batches, recovery bundles and attachment blobs on their own PDS, not on mls-ds. Two things sit closer to mls-ds than that summary suggests:

- **It is the authority of each conversation Space it sequences.** It issues Space credentials to active members and records each writer's repository heads. Its Space host also implements `com.atproto.space.putRecord`, which can store a writer's records (up to 1 MiB each) in the delivery service's own database. Those are the same encrypted records a member would otherwise keep on its PDS, with the same visible metadata.
- **It holds the server share of version-3 recovery codes**, encrypted under a key kept outside its database. See [Recovery](recovery.md).

## Inside the crate

The protocol layers do no I/O. The client talks to storage only through four async traits, so the same code runs natively and in the browser (`wasm32`).

| Module | What it does |
|---|---|
| `aead`, `hpke`, `sign`, `padding`, `encoding` | Primitives: AES-256-DNDK-GCM and AES-GCM-Extended, Hawk HPKE (X25519 + ML-KEM-768), XEdDSA and Ed25519, PADMÉ padding, KDF helpers |
| `device`, `epoch`, `mailbox` | Devices, opening and chaining epochs, mailbox key pairs and epoch heads |
| `recovery_code`, `virtual_device`, `otc` | Recovery codes with typo correction, recovery bundles, the passkey wrap, one-time codes |
| `mek`, `message` | MEK distribution and opening; owner-mode and sender-mode message encryption |
| `records` | atproto record types for every lexicon |
| `store` | The storage traits (`MailboxStore`, `ThreadStore`, `MailboxDirectory`, `KeyPublisher`), an in-memory backend, the public `mailboxKeys` publisher, and the Space stores |
| `client` | `Labyrinth`, the high-level client a chat app calls, and `CompositeDirectory` |
| `deletion`, `attachment`, `fingerprint` | Signed unsends, attachment ciphertext checks, safety numbers |
| `labyrinth-protocol` (workspace crate) | Shared verifiers for `I13` receipts and the epoch-head chain, used by both clients and mls-ds |

## Where the code that calls it lives

- Client side: catbird-mls `src/labyrinth/` (session wiring, the mls-ds transport) and `src/client/native_archive*.rs` (the production archive and the authenticated Space reader).
- Server side: mls-ds `server/src/handlers/labyrinth/` and `server/src/labyrinth/`.

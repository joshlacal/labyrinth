# Security model

This page says what Labyrinth is meant to protect, against whom, and what it leaves visible. Every claim points to the section of the [protocol profile](../reference/SPEC.md) that defines it. Where the protocol has a known weakness, it is listed here rather than left for a reader to find.

> Labyrinth is an **unaudited pre-GA draft**. The properties below are design goals that the code implements and that the test suite exercises; they have not been confirmed by an independent audit, and the in-repository review notes record open findings.

## Goals

1. **Confidential history.** Archived messages, the keys that open them and the account's recovery material are readable only by the account's currently enrolled devices and its recovery methods, never by the servers that store them.
2. **Recoverable history.** A user who loses every device can restore history with a recovery method (a recovery code, a passkey, or a copy of the code in the platform keychain). A user who adds a device can enroll it from an existing one with a 6-digit one-time code.
3. **Revocation.** Removing a device opens a new epoch that the removed device cannot reach, so it cannot read history archived afterwards.
4. **Membership boundaries.** A member removed from a conversation can't read what is archived after its removal, and a new member can't read what was archived before it joined.
5. **Authenticated, ordered history.** Each archived message carries its original sender's signature and the sequencer's signed receipt, so a storage host can't forge, reorder or misattribute history.

## Who we defend against

| Adversary | Assumed able to | Labyrinth's answer |
|---|---|---|
| A **Space host** (a PDS storing a mailbox or a conversation Space) | read every record it stores, withhold or replay records, serve stale data, plant records | Everything secret is encrypted and authenticated. Readers verify signatures, MACs and CIDs before trusting bytes; each device pins the newest writer revision it has seen and fails with `WriterRollback` on an older one. |
| **mls-ds** | see directory and sequencing metadata, refuse service, sign receipts | It stores no Labyrinth content. It cannot substitute an account's keys alone, because readers require the public PDS copy to agree ([CB-28], [CB-29]). |
| **One directory source** (a PDS or mls-ds) | publish a different or older epoch head | `CompositeDirectory` requires exact agreement between the public PDS and mls-ds. Disagreement fails as `DirectoryFork`; a head in only one source fails as `DirectoryIncomplete`. |
| A **removed device or member** | keep everything it had before removal | It keeps what it already decrypted. It cannot open epochs or MEKs created after its removal. |
| A **future quantum computer** | break X25519 and Ristretto255 discrete logs on recorded traffic | Every secret-bearing step uses a hybrid X25519 + ML-KEM-768 construction (`I16`, SPEC §10). |

**Out of scope.** A compromised device that is still enrolled; malware on the user's phone; a user who shares their recovery code. Labyrinth also does not hide *that* two accounts share a conversation from the hosts that store that conversation (see below).

## What is encrypted

| Data | Protection | Spec |
|---|---|---|
| Message bodies (sender copies) | Per-message key derived from a MEK; AES-256-DNDK-GCM with key commitment; PADMÉ padding; Ed25519-signed by the sender's chat device | §7.2 |
| Message bodies (owner copies, after leaving) | Per-epoch, per-thread key; AES-256-DNDK-GCM; PADMÉ padding | §7.1 |
| Message encryption keys (MEKs) | Hawk HPKE (X25519 + ML-KEM-768) to each recipient's mailbox key; the AAD binds the thread, roster and both epoch heads | §7.3 |
| Epoch entropy for each device | Hawk HPKE in PSK mode, keyed with the previous epoch's distribution key | §5.5 |
| Recovery bundles | AES-256-DNDK-GCM under a key derived from the recovery code (and, for version-3 codes, a server-held share) | §6.1–§6.2 |
| One-time-code enrollment payload | CPace + ephemeral ML-KEM-768, then AES-256-DNDK-GCM | §6.5 |
| Attachments | AES-256-GCM with a per-blob random key carried inside the encrypted message; the stored ciphertext is checked by size and SHA-256 before decrypting | §8 |
| Read state, circle owner state | AES-256-DNDK-GCM under keys derived from the mailbox epoch root | [Spaces](../reference/SPACE_CONVERSATIONS.md) |

Every v1.1 object is pinned to the DNDK-GCM suite byte (`0x02`), so a backend can't relabel it as the weaker v1.0 construction (§3.1).

## What the hosts can see

Encryption hides content, not everything. This is what each party can observe.

**The account's PDS, for its personal mailbox Space.**
- How many Labyrinth devices and recovery methods the account has, their public keys, and the recovery mechanism of each bundle (`code`, `keychain`, `passkey` or `otc`).
- When epochs rotate, and how many devices each epoch includes.
- For the owner archive: which conversation IDs the account archived, and each archived message's ID, timestamp, sequence number, epoch and (for receipt-committed copies) its sequencer receipt, which names the original sender. The bodies are encrypted.
- Which conversations have synced read state (the record key is the conversation ID; the read position itself is encrypted).
- Write timing and record sizes.

**The host of a conversation Space** (and every current member, who can read the same records).
- Which accounts write in the conversation (the writer DIDs), and the recipient DIDs and epoch heads listed on each MEK record (SPEC §10, "Membership enumeration"; this limitation is inherited from the paper).
- Per archived message: its message ID, timestamp, sequence number, MEK ID, the sender's chat-device public key, and the sequencer receipt, which names the sender DID and device, the MLS group and epoch, and the time it was sequenced.
- The size of each batch and each attachment ciphertext, and an attachment's optional MIME type hint.
- That a message was unsent (the redaction record is visible; the message stays encrypted).

**The public PDS repo.** Publishing `mailboxKeys` reveals that the account uses Labyrinth and when it rotates epochs ([CB-19]).

**mls-ds.** As the MLS delivery service it already sees each conversation's full membership and device list, the sender DID and device of every MLS message, exact server timestamps and ciphertext sizes. For Labyrinth it adds the epoch-head chain, the account's chat-device key history and each conversation's per-leaf join and removal history. As the authority of the conversation Spaces it sequences, it sees each writer's repository heads, and any records written through its own Space host (encrypted, with the metadata listed above). For version-3 recovery codes it stores one encrypted 32-byte share per recovery method and records when each is fetched. The share opens nothing without the recovery code.

## Residual limitations

These are known, documented and not yet solved.

- **Hidden newer epochs.** A backend that controls *both* the mailbox and the directory can hide newer epochs from a device (SPEC §10, inherited from the paper). Truncation is detected only while the directory is independent of the mailbox store ([CB-28]); `CompositeDirectory` means the mailbox host would have to collude with a second, separately operated directory.
- **First contact.** The first time a device sees a peer, it trusts the head both directory sources agree on. Pins are per device and are not restored, so a restored device repeats first contact ([CB-29]). The long-term fix, carrying the latest heads inside MLS-authenticated group state, is not implemented.
- **Removed devices and old messages.** A message signed by a chat device that was later removed still verifies if the sequencer's signed receipt orders it before the removal ([CB-27]). A conversation with no resolvable receipt key falls back to sender timestamps, which do not establish that boundary.
- **Legacy owner records.** Owner records of versions 0–4, as in the paper, authenticate the thread and epoch but not the message ID or timestamp. Labyrinth writes version 5, which binds both ([CB-37]).
- **Deletion is cooperative.** Unsend writes a signed redaction that honest readers apply; it does not erase ciphertext from other members' repos or from host backups. See [Deletion](deletion.md).
- **No cross-member consistency check on the sequencer.** Sequencer receipts hold mls-ds to what it signed, but nothing lets members compare the receipts they hold. A dishonest sequencer could withhold entries from some members, or show different members different sequences; MLS epoch agreement exposes some forks at the next Commit, but not all. The Space writer-inventory commitment covers the archive's set of writers only.
- **Squatted epochs.** Epoch records are create-if-absent, so a planted record at the next epoch number can block rotation. Clients detect it (`EpochSquatted`) and can clear an unanchored squat only after several checks ([CB-40]).
- **Client state is a secret.** `Labyrinth::export_state()` returns the device's private keys, epoch roots and MEKs ([CB-30]). Apps must store it only in the platform keychain or an encrypted database.
- **Erasable recovery is limited.** Deleting a version-3 recovery code's server-held share stops *future* derivations. It does not revoke a copy already taken, a decrypted bundle, or devices already enrolled (SPEC §6.1, "Erasure boundary").
- **Not yet qualified live.** The conversation-Space store has not been qualified across real OAuth, authority and foreign repository hosts; its tests use a reference Space host. The live fault test for Space reads (`G5`) is recorded as pending.

## Cryptographic primitives

| Use | Primitive |
|---|---|
| Symmetric encryption | AES-256-DNDK-GCM (key-committing, 24-byte nonce); AES-GCM-Extended accepted only for v1.0 owner records |
| Key encapsulation | Hawk HPKE: X25519 + ML-KEM-768 (FIPS 203), with a PSK mode for epoch entropy |
| Device and epoch signatures | XEdDSA over X25519 keys |
| Chat-device signatures | Ed25519 (the MLS chat device key) |
| Sequencer receipts | ES256 (P-256), low-S |
| Device-to-device enrollment | CPace over Ristretto255/SHA-512 + ML-KEM-768 |
| KDF / MAC / hash | HKDF-SHA256, HMAC-SHA256, SHA-256 |
| Recovery code ECC | 4 check symbols over GF(32), corrects up to three typos |

Signatures are used only for online authentication; the profile does not claim post-quantum signatures.

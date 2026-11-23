# Devices, epochs and revocation

## Two kinds of device key

A Catbird install has two related identities.

- Its **MLS chat device**, registered with mls-ds. Its Ed25519 key signs MLS traffic and, in Labyrinth, signs archived messages and attests epoch heads. Labyrinth calls this the *transport key* ([CB-3]).
- Its **Labyrinth device**, enrolled in the account's mailbox. It has three keys (SPEC §4):

| Key | Type | Purpose |
|---|---|---|
| `deviceKey` | XEdDSA | The device's membership identity. Signs its two storage keys. |
| `epochStorageKey` | Hawk HPKE (X25519 + ML-KEM-768) | Receives each new epoch's entropy. |
| `epochStorageAuthKey` | X25519 | Authenticates entropy this device sends to others. |

A physical device record carries a `chatBinding`: the chat device's Ed25519 signature over the Labyrinth device key ([CB-36]). That ties each Labyrinth device to a current chat device of the same account, so a planted device record without a live chat device is excluded at the next rotation.

A **virtual device** is a recovery bundle (see [Recovery](recovery.md)). It is a member of epochs like a physical device but has no auth key and no chat binding.

## Epochs

An **epoch** is the account-wide key generation. Each epoch has a 32-byte root key, from which the mailbox key pairs are derived (SPEC §5.2): an auth key, a Hawk encryption key, and an XEdDSA signing key.

- Epoch 0's root is random.
- Each later epoch's root is derived from the previous root **and** fresh entropy (SPEC §5.1). The new entropy is encrypted to every continuing member's `epochStorageKey` with Hawk HPKE in PSK mode, using a key chained from the previous epoch (§5.5). A device that can open one epoch can therefore *forward-chain* to the next ones it is a member of, and the previous root is stored encrypted under the new epoch, so it can also walk *backwards* to read older history.
- Epochs are stored at zero-padded 12-digit record keys (`000000000000`, …) in the personal mailbox Space ([CB-9]).

### The epoch head

Each epoch is summarized by a 32-byte **epoch head** that commits to the DID, the epoch's public keys, the epoch number, the previous head and `membersHash`, a hash of the canonical set of member devices (SPEC §5.3). The head is signed three times:

- `self_sig`, by the epoch's own signing key;
- `prev_sig`, by the previous epoch's signing key, so heads form a signed chain;
- an **attestation** by the chat device that opened the epoch ([CB-18]), so neither a storage host nor mls-ds can substitute someone's mailbox keys.

A sender accepts a peer's head only if the attesting key belongs to one of that peer's chat devices in the MLS group.

### Publication and pinning

Each new head is published to the account's **public** PDS repo (`blue.catbird.labyrinth.mailboxKeys/<12-digit epoch>`, then `self`) and to mls-ds's append-only chain. A locally opened epoch stays *pending* until both sources hold exactly the same head, and the client retries on session open and sync ([CB-19]).

Each device **pins**, per peer DID, the newest `(epochNumber, epochHead, signingPubkey)` it has accepted ([CB-29]):

- an older epoch, or the same number with a different head, fails with `EpochRollback`;
- a newer epoch is accepted only through a `prev_sig` chain whose every step both directory sources provide identically;
- pins are per device and are not carried across a restore, so a restored device repeats strict first contact.

### Safety numbers

The head commits to the whole chain, so a fingerprint derived from it changes on every rotation. `Labyrinth::safety_number_with(did)` shows six groups of five digits (or 16 emoji) for comparing out of band ([CB-41]).

## Rotation and revocation

Revoking a device **always** opens a new epoch that excludes it ([CB-11]). Because the new entropy is encrypted only to the remaining members, the revoked device cannot derive the new root and cannot open MEKs addressed to the new epoch.

Before rotating, the client audits every member of the previous epoch (SPEC §5.6, [CB-25]):

- A member whose record doesn't parse, whose signatures or MAC fail, or whose physical device is not bound to a *current* chat device is **excluded and reported** in `RotationReport::excluded`, rather than allowed to block the rotation.
- If a member this client had already verified in the same epoch now fails a check, the rotation aborts with `MemberTampered`.
- The rotating device's own chat key must be current, or the rotation fails with `Unattested`.

The revoking client records the device in a **local revoked set** and checkpoints its state before touching storage, and every later rotation excludes that whole set even if the store forgets the revocation. Stale keychain and passkey recovery bundles (older than 180 days by the client clock) are also excluded at ordinary rotations and reported (§6.4, [CB-39]).

### Squatted epochs

Epoch numbers are create-if-absent, so a corrupt or planted record at `latest + 1` would block rotation. `sync_epochs` and `revoke_device` classify such a record and report `EpochSquatted { seq, reason }` instead of looping. An active device can clear an unanchored squat with `clear_squatted_epoch`, which deletes only after five checks, including that neither directory source anchors anything at or above that number ([CB-40]).

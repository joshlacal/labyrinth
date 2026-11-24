# Recovery

Labyrinth gives three ways to get history onto a device that has none.

| Situation | Method | What the user needs |
|---|---|---|
| All devices lost | Recovery code | The 40-character code |
| All devices lost, on the same platform account | Passkey or platform keychain | Their passkey, or their iCloud Keychain / Android backup |
| Adding a device while another still works | One-time code | A 6-digit code shown on the old device |

## Virtual devices

Each recovery method is a **virtual device**: a full member of the account's epochs whose private keys are sealed in a *bundle* in the personal mailbox Space (SPEC §6.2). The bundle holds the virtual device's XEdDSA key, its 96-byte Hawk secret, the epoch root at the time it was sealed and that epoch's number, each under AES-256-DNDK-GCM with its own AAD.

Restoring (SPEC §6.3) opens the bundle, forward-chains to the newest epoch the virtual device belongs to, checks that epoch against both directory sources, creates fresh physical device keys bound to the caller's chat device, and opens a new epoch including the new device. The bundle update, the new device, the new epoch and its member rows are written in one atomic `com.atproto.space.applyWrites`.

## Recovery codes

A code is 40 characters from a 32-symbol alphabet that avoids look-alikes (`B`, `G`, `I` and `O` are read as `8`, `C`, `1` and `0`). It carries a version character, 34 characters of entropy (about 170 bits) and 4 check characters that let the client correct up to **three** typos (SPEC §6.1, [CB-12]). The paper claimed a stronger property that cannot hold at this length; the profile documents why and what the code actually guarantees.

- **Version 2** derives the bundle ID and key from the code alone.
- **Version 3** ("erasable") splits the key: part comes from the code, part from a random 32-byte share held by the account's home delivery service, released only to a request that presents a token derived from the code. If the service has durably deleted the share, the code alone can no longer open the bundle. A version-3 code without its share fails with `RecoveryShareUnavailable`; there is no code-only fallback.

The crate reads both versions. The repository history records that version-3 enrollment and vectors were qualified "without enabling the writer"; check the release notes before assuming new codes are version 3.

**What erasure does not do.** Deleting a version-3 share stops *future* derivations only. It does not revoke a share or key someone already copied, a bundle already decrypted, epoch roots already recovered, or devices already enrolled. Removing a device's membership still needs its own epoch rotation.

## Passkey and keychain

- **Passkey (WebAuthn PRF).** The code is stored next to the bundle, encrypted under a key derived from the passkey's PRF output ([CB-13]).
- **Platform keychain.** The code is stored as-is in iCloud Keychain or Android Auto Backup.

Keychain and passkey bundles are marked **stale** 180 days after they were created or last used, judged by the client's clock. A stale bundle can still restore; the app is told to prompt for a replacement. Ordinary rotations exclude stale keychain and passkey bundles and report them. A client clock alone never deletes a bundle or removes a member ([CB-39]).

A PIN vault (HSM or Juicebox) is out of scope for the first release.

## One-time codes

To add a device while another is still enrolled, the new device shows a 6-digit code and the old device enters it (SPEC §6.5, [CB-14]). The two run **CPace** (a password-authenticated key exchange over Ristretto255) with an ephemeral **ML-KEM-768** encapsulation bound into it, so the transferred epoch root stays confidential even against a future quantum adversary who later learns the code. A code allows three attempts. The new device then verifies the epoch against both directory sources and rotates to a new epoch that includes itself.

## Managing methods

`Labyrinth::list_recovery_methods` lists every bundle with its mechanism, creation and last-use time and staleness. `remove_recovery_method` asks the configured share store to delete a version-3 share (a refusal aborts), then rotates the virtual device out, then deletes the bundle.

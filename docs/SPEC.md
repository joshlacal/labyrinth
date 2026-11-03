# Labyrinth 1.1, Catbird profile

**What this is.** This crate implements Meta's *Labyrinth Encrypted Message Storage Protocol*, version 1.1 ("Minos", whitepaper "Version 2", April 2026). The goal is end-to-end-encrypted chat **history** for Catbird. Catbird's chat runs on MLS through `mls-ds`, our delivery service on atproto. The whitepaper leaves several choices to the implementer and is written around Facebook identities. This document fixes every such choice for Catbird. **We do not claim wire compatibility with Messenger.** Meta publishes no test vectors; ours are in `tests/vectors/`.

Primary sources:
- Labyrinth v1 (Dec 2023): <https://engineering.fb.com/wp-content/uploads/2023/12/TheLabyrinthEncryptedMessageStorageProtocol_12-6-2023.pdf>
- Labyrinth v1.1 (Apr 2026): <https://engineering.fb.com/wp-content/uploads/2026/05/Minos-Updates-2026-Encrypted-Backups-White-Paper.pdf>
- AES-256-DNDK-GCM: <https://datatracker.ietf.org/doc/draft-gueron-cfrg-dndkgcm/>
- XEdDSA: <https://signal.org/docs/specifications/xeddsa/>
- ORF: <https://eprint.iacr.org/2022/1044> *(historical paper reference; retired in Catbird clean-slate profile `2A`, §3.6)*

Whitepaper page numbers below refer to the v1.1 paper, e.g. "(p.27)". Every place we choose something the paper leaves open is tagged **[CB-n]**. `docs/DECISIONS.md` lists the tags and why we chose each one.

---

## 1. Roles in Catbird

| Labyrinth term | Catbird meaning |
|---|---|
| user / account (`userFbid`) | atproto account DID, e.g. `did:plc:abc…` **[CB-1]** |
| inbox / mailbox | one per DID |
| `labyrinthID` (the server-assigned instance id, p.21) | the account DID itself: a DID has exactly one mailbox, so there is no separate instance id **[CB-34]** |
| device | a Catbird install that is enrolled in the mailbox. It is distinct from (but usually paired with) an mls-ds chat device |
| virtual device | a recovery bundle unlocked by a recovery code |
| thread | an MLS conversation (`chat.conversations.conversation_id`) **[CB-2]** |
| message | an MLS application frame body (opaque bytes) plus `messageId`, `timestamp` |
| transport signing key | the sending chat device's Ed25519 key, the key `mls-ds` registers in `chat.device_keys` **[CB-3]** |
| metastore + mailbox server | **ATProto Spaces only** (`I14`, `I15`): `at://<did>/space/blue.catbird.labyrinth.mailbox/self` for the personal mailbox Space and `at://<authority>/space/blue.catbird.labyrinth.conversation/<id>` for conversation Spaces; `mls-ds` serves strictly as directory + sequencer, never a content store (§9) |

## 2. Encodings

- Strings are UTF-8. Integers inside strings are decimal with no leading zeros (p.50).
- `hex()` is lowercase hex.
- `base64_encode(n)` means standard Base64 with padding, applied to the decimal string of `n`. For example, 3 → `"Mw=="` (p.50).
- `a || b` and `concat` are byte concatenation.
- `kdf(ikm, salt, info, L)` is HKDF-SHA256 with output length `L`, default 32.
  - A `null`/`NULL` salt means HKDF's default salt (32 zero bytes).
  - When the paper writes `(a, b) := kdf(...)`, we expand `len(a)+len(b)` bytes and split them in order. `(epochChainingKey, epochDistributionPreSharedKey)` is 32+32. `(vdeviceId, vdeviceDecryptionKey)` is 16+32. **[CB-4]**
- `mac(data, key)` is HMAC-SHA256(key, data).
- `MINOS_SALT = sha256("minos encrypted backup protocol\n")` (p.27).
- `userFbid` appears in strings only as `user_fbid=<decimal>`. We replace that field with `user_did=<did>` everywhere **[CB-1]**. In the recovery-code KDF, `user_id` becomes the DID string.
- `threadId` is the UTF-8 bytes of the conversation ID. Where the paper writes `hex(threadId)`, we hex those bytes. Where it concatenates `threadId` directly, we concatenate the UTF-8 string **[CB-2]**.
- `messageId` is the UTF-8 message ID that MLS chat already assigns. `timestamp` is integer milliseconds since the Unix epoch **[CB-5]**.

## 3. Primitives

### 3.1 Symmetric AEAD: `encrypt(key, aad, pt)` / `decrypt`

- **v1.1 default: AES-256-DNDK-GCM** with `KC_Choice = 1` (key commitment) and `LN = 24` (p.16).
  - The output is `nonce(24) || ct || tag(16)`, plus the commitment value that `KC_Choice=1` defines in the draft. The nonce is random.
  - We follow the latest draft revision; `tests/vectors/dndk_gcm.json` holds the draft's own vectors.
- **v1.0 compatibility: AES-GCM-Extended** (p.15).
  - `subkey = HChaCha20(key, nonce[0..16])` and `subnonce = nonce[16..28]`, then AES-256-GCM.
  - The output is `nonce(28) || ct || tag`.
- Each ciphertext starts with a one-byte **suite id** that selects the AEAD: `0x01` = AES-GCM-Extended, `0x02` = DNDK-GCM **[CB-6]**.
- **Suite pinning.** Every object this profile seals on a v1.1 path must use `0x02`, and readers refuse anything else before using the key (`aead::decrypt_suite`): sender messages (§7.2), the encrypted epoch back-link (§5.4), every virtual-device bundle field (§6.2), the passkey wrap (§6.4) and the one-time-code payload (§6.5). Only owner messages (§7.1), which may come from a Labyrinth 1.0 writer, still dispatch on the suite byte. Without the pin, a backend could relabel a v1.1 object as the weaker v1.0 construction.

### 3.2 Padding (p.15)

- The plaintext is `u32_be(len) || data || zero padding`. PADMÉ padding is applied to the length of `data`, and anything under 10 bytes pads to 10.
- We pad **all** message plaintexts, under both AEADs **[CB-7]**. Key material is never padded.

### 3.3 Signatures: XEdDSA

- Keys are X25519 key pairs and signatures are 64 bytes.
- `pk_sign(priv, use_case_byte, data)` signs `use_case_byte || data`.
- "Unstructured" and "structured" signatures with a string prefix sign `prefix_bytes || data` with no use-case byte.
- Use-case bytes: `0x30` (physical `epochStorageKey`), `0x31` (physical `epochStorageAuthKey`) (p.24), and `0x32` (virtual `epochStorageKey` domain separation, `Gate 2`).

### 3.4 Classical Labyrinth HPKE (p.17, reference primitive only)

```
fresh = X25519(sender_auth_priv, recip_enc_pub) || X25519(eph_priv, recip_enc_pub)
inner_aad = 0x01 || sender_auth_pub || recip_enc_pub || eph_pub || aad
subkey = kdf(fresh, psk, inner_aad)          // psk ≤ 32 bytes; salt = psk
ct = AES-256-GCM(subkey, nonce = 0^12, aad, pt)
out = 0x01 || eph_pub || ct
```

Recipient public keys are checked for low-order points, and an all-zero X25519 output is rejected. In the Catbird PQ clean-slate profile (`I16`), classical `labyrinth_hpke` is **not** used on any active wire path; both MEK distribution (§7.3) and `EpochMember.encryptedEntropy` (§5.5) use hybrid post-quantum **Hawk HPKE** (§3.5).

### 3.5 Hawk HPKE (p.18; standard + PSK modes) **[CB-8]** (`I16`)

The paper gives the structure for MEK distribution; we fix the byte layout and extend it with a PSK mode (`hawk_encrypt_with_psk`) so `Device.epochStorageKey` also achieves post-quantum confidentiality and post-compromise healing via `distPsk` (§5.5).

- **Keys.**
  - An auth key pair is an X25519 key pair (`32` bytes).
  - An encryption key pair is an X25519 key pair plus an ML-KEM-768 key pair (`HawkEncSecret = x25519(32) || mlkem_seed(64) = 96 bytes`; `HawkEncPublic = x25519_pub(32) || mlkem768_ek(1184) = 1,216 bytes`, FIPS 203 modulus-checked on parse).
- **`hawk_derive_auth(seed)`:** `priv = kdf(seed, MINOS_SALT, "catbird.labyrinth.hawk.auth.x25519")`.
- **`hawk_derive_enc(seed)`:**
  - `x = kdf(seed, MINOS_SALT, "catbird.labyrinth.hawk.enc.x25519")`
  - `(d, z) = kdf(seed, MINOS_SALT, "catbird.labyrinth.hawk.enc.mlkem768", 64)`
  - ML-KEM-768 is derived deterministically from `(d, z)` (FIPS 203 `ML-KEM.KeyGen_internal`).
- **Standard mode — `hawk_encrypt(recipEncPub, senderAuthPriv, senderAuthPub, aad, pt)` (MEK distribution):**

```
ss1 = X25519(senderAuthPriv, recip.x25519)
(eph_priv, eph_pub) = X25519 keygen
ss2 = X25519(eph_priv, recip.x25519)
(kem_ct, ss3) = ML-KEM-768.Encaps(recip.mlkem)
info = "catbird.labyrinth.hawk.v1:" || senderAuthPub || recip.x25519 || sha256(recip.mlkem)
       || eph_pub || kem_ct
key  = kdf(ss1 || ss2 || ss3, MINOS_SALT, info)
ct   = AES-256-GCM(key, 0^12, aad, pt)
out  = 0x01 || eph_pub || kem_ct || ct
```

- **PSK mode — `hawk_encrypt_with_psk(recipEncPub, senderAuthPriv, senderAuthPub, psk, aad, pt)` (`EpochMember.encryptedEntropy`):**

```
info = "catbird.labyrinth.hawk.psk.v1:" || senderAuthPub || recip.x25519 || sha256(recip.mlkem)
       || eph_pub || kem_ct || aad
key  = kdf(ss1 || ss2 || ss3, salt = psk, info)      // psk = distPsk (32 bytes)
ct   = AES-256-GCM(key, 0^12, aad, pt)
out  = 0x01 || eph_pub || kem_ct || ct
```

### 3.6 ORF Retired (`2A`)

The paper's Ristretto255 Oblivious Random Function (`ORF`, p.18–20) required a stateful `OrfServer` on `mls-ds` and was classical-only. In the Spaces-only PQ profile (`2A`, `Gate 5`), **ORF and `OrfServer` are retired completely**: encrypted attachment blobs live in ATProto Spaces via `blue.catbird.labyrinth.attachmentManifest` records (§8) authorized by Space capability credentials rather than server-held ORF scalars.

## 4. Device (p.21, p.24; `Gate 2`, `I16`)

| Key | Type | Purpose |
|---|---|---|
| `deviceKey` | XEdDSA (`32` bytes) | membership identity; signs `epochStorageKeyPub` (`0x30` physical / `0x32` virtual) and `epochStorageAuthKeyPub` (`0x31`) |
| `epochStorageKey` | Hawk HPKE enc (`X25519 + ML-KEM-768`, `1,216`-byte pub / `96`-byte priv) | receives new epoch entropy (`hawk_encrypt_with_psk`) |
| `epochStorageAuthKey` | X25519 (`32` bytes, Hawk HPKE auth) | authenticates entropy it sends; virtual devices have none |

Public record (`blue.catbird.labyrinth.device`): `deviceKeyPub`, `epochStorageKeyPub` (`1,216` bytes), `sigStorage` (`0x30` for physical, `0x32` for virtual), `epochStorageAuthKeyPub?`, `sig_0x31?`, `isVirtual`, `chatBinding?`, `revokedAt?`.

## 5. Epochs (p.22–30)

### 5.1 Opening an epoch

- `epochSequenceID` starts at 0. Epoch 0 has a uniformly random root.
- Each later epoch:

```
(chainKey, distPsk) = kdf(prevRoot, null, "epoch_chaining_" || prevSeq || "_" || prevEpochID, 64)
root = kdf(entropy, chainKey, "epoch_root_key")
```

- **`epochID`** in the Space mailbox is the epoch record's `rkey`: the decimal `epochSequenceID`, zero-padded to 12 digits (`000000000000`, …) so records sort lexicographically **[CB-9]**.

### 5.2 Mailbox key pairs (v1.1, p.27)

```
authSeed = kdf(root, MINOS_SALT, "minos.kdf.export_root_key.auth_keypair:epoch_number=" || seq)
encSeed  = kdf(root, MINOS_SALT, "minos.kdf.export_root_key.encryption_keypair:epoch_number=" || seq)
sigPriv  = kdf(root, MINOS_SALT, "minos.kdf.export_root_key.signing_keypair:epoch_number=" || seq)
```

- `hawk_derive_auth(authSeed)` and `hawk_derive_enc(encSeed)` produce the auth and encryption key pairs.
- `sigPub = X25519_base(clamp(sigPriv))`.

### 5.3 Epoch head and `membersHash` (p.22–23; `Gate 2`)

Each epoch binds its canonical active member set into `membersHash` (`labyrinth_protocol::epoch_chain::compute_members_hash`): the SHA-256 digest over sorted `(deviceKeyPub, epochStorageKeyPub, isVirtual)` tuples.

```
epochHash = sha256("epoch_public_data:" || "auth_pubkey=" || hex(authPub) || ";encryption_pubkey=" || hex(encPub)
            || ";epoch_number=" || seq || ";members_hash=" || hex(membersHash)
            || ";previous_epoch_head=" || (prev ? hex(prev) : "null")
            || ";signing_pubkey=" || hex(sigPub) || ";user_did=" || did)
epochHead = sha256("epoch_head:" || "epoch_hash=" || hex(epochHash) || ";epoch_number=" || seq
            || ";previous_epoch_head=" || (prev ? hex(prev) : "null"))
self_sig = XEdDSA(sigPriv, "minos.unstructured_signature.epoch_self:" || epochHead)
prev_sig = XEdDSA(prevSigPriv, "minos.unstructured_signature.epoch_prev:" || epochHead)   // epoch > 0
```

- **[CB-10]** `epochHead` is the raw 32-byte digest. In signature prefixes above it is concatenated as raw bytes.
- **[CB-35] No v1.0 upgrade path.** `EpochPublic::sign`/`verify` reject a null previous head at any epoch above 0.
- **[CB-41] Fingerprints.** The head commits to the DID, the current mailbox keys, `membersHash`, and the whole chain (`src/fingerprint.rs`): `fp = kdf(head, MINOS_SALT, "catbird.labyrinth.fingerprint.v1:" || did, 30)`, shown as six 5-digit groups (`Labyrinth::safety_number_with` uses the [CB-29] pin for the peer) or 16 emoji. It changes on every rotation.
- **[CB-18] Transport attestation.** The device that opens an epoch also signs the head with its chat transport key (Ed25519):
  - `attestation = Ed25519(transportKey, "catbird.labyrinth.epoch_head_attest:" || did || ":" || epochHead)`.
  - A sender accepts a recipient's head only if the attesting key belongs to one of that DID's devices in the MLS group.
- **[CB-43] Own epoch records.** A device adopts its own newest epoch record only after checking all of it (`epochs::verified_own`, on restart, sync, recovery restore and one-time-code enrollment):
  - its keys and `membersHash` match the epoch secret and audited member set, and its self signature and attestation verify;
  - above epoch 0, its `prev_sig` verifies under epoch `seq - 1`'s mailbox signing key, re-derived by backward-chaining from the secret;
  - its attesting key is one of the account's chat devices in the `MailboxDirectory`, current or removed (a removed sibling may have opened it; peers still apply [CB-18]).
  - The client keeps that verified copy (`Labyrinth::latest_public`) in memory instead of re-reading the mailbox. Offline restarts verify mailbox-only invariants immediately and finish the directory attester check on the next `sync_epochs` or roster resolution.
- **[CB-19] Discovery.** The latest `epochPublic` is published as `blue.catbird.labyrinth.mailboxKeys/self` in the account's **public** PDS repo (plus immutable `mailboxKeys/<12-digit epochNumber>` copies) AND anchored on `mls-ds`'s append-only `EpochPublicHeader` chain (`L-F01` `floor_seq`, `Gate 6`).
- **[CB-29] Peer epoch pinning.** A sender pins, per DID it addresses, the newest `(epochNumber, epochHead, signingPubkey)` it has accepted, and immediately checkpoints the pin via `StateSink` / `export_state()` (§9.3) before any network flush:
  - an offered epoch older than the pin, or with the pinned number but another head, fails with `EpochRollback`;
  - a newer epoch is accepted only if the `prev_sig` chain from the pinned head verifies through every intermediate epoch, fetched with `MailboxDirectory::epoch(did, seq)` (at most 4,096 epochs per advance);
  - first contact is cross-checked by `CompositeDirectory` across PDS and `mls-ds`.

### 5.4 Epoch metadata and membership (p.28–29)

```
dataKey = kdf(root, null, "epoch_data_storage_" || base64(seq))
macKey  = kdf(root, null, "epoch_devices_"      || base64(seq))
encPrevSeq  = encrypt(dataKey, "epoch_data_metadata", decimal(prevSeq))   // decrypt: ≤11 decimal chars
encPrevRoot = encrypt(dataKey, "epoch_data_metadata", prevRoot)
deviceMac[d] = mac(deviceKeyPub_d, macKey)    // only after verifying mac under the previous macKey
```

### 5.5 Entropy distribution (p.29; `I16` Hawk HPKE + PSK)

For each continuing device `d` whose `sig_0x30` (physical) or `0x32` (virtual) and FIPS 203 ML-KEM-768 encapsulation key verify:

```
encEntropy[d] = hawk_encrypt_with_psk(d.epochStorageKeyPub, self.authPriv, self.authPub,
                                      distPsk, "epoch__" || seq, entropy)
```

### 5.6 Revocation and squatted-epoch recovery (p.36)

- Revoking a device opens a new epoch that excludes it (`[CB-11]` rotation is mandatory).
- **Local revoked set.** The revoking client records the device in its local revoked set and immediately checkpoints `export_state()` via `StateSink` (§9.3) before touching the store. Every rotation excludes the whole set regardless of `revokedAt` in the store, and `rotate` checkpoints the newly created `EpochSecret` via `StateSink` **before** `publish_keys` so a transient directory/PDS failure never strands the new epoch's secret.
- **[CB-25] Rotation rules (amended 2026-10-05).**
  - The opener carries itself over and encrypts the entropy to its own storage key too, so any install holding its keys can forward-chain.
  - Before rotating, the client audits every member of the previous epoch (`src/client/members.rs`). A member whose record does not parse, whose device record is missing or fails `sig_0x30`/`sig_0x31`/`sig_0x32`, whose MAC fails, or (physical devices) that is not bound to a *current* chat device of the DID ([CB-36]) is **excluded and reported** in `RotationReport::excluded`.
  - Exception: if a member this client already verified **in that same epoch** now fails a record or MAC check, the rotation aborts with `MemberTampered`. The verified set is persisted ([CB-30], state v3).
  - The rotating device's own chat key must be current in the directory, or the rotation fails with `Unattested`.
- **[CB-36] Device binding.** A physical device record carries `chatBinding = {transportPubkey, Ed25519(chat key, "catbird.labyrinth.device_binding:" || did || ":" || deviceKeyPub)}` from the chat device that enrolled it; virtual devices carry none.
- **[CB-40] Squatted epochs and safe Space clearing.** Epoch numbers are create-if-absent, so a corrupt or insider-planted record at `seq = latest + 1` blocks rotation.
  - `sync_epochs` and `revoke_device` classify the next epoch: if it fails parsing, is not signed with `latest`'s mailbox signing key (`prev_sig`), names an invalid/non-physical or locally revoked opener, fails the opener's previous-epoch MAC (when present), or fails `forward_chain` decryption for this device's member row, they report `Error::EpochSquatted { seq, reason }` rather than looping; a validly chained epoch without a valid membership for this device returns `Error::NotEpochMember` (revoked).
  - Because ATProto Spaces has no server-side XEdDSA gate on `epoch/<seq>`, `Labyrinth::clear_squatted_epoch(seq)` (`MailboxStore::delete_squatted_epoch`) allows an active device to clear an unanchored squat at `seq == latest + 1` **only** after verifying: (1) `seq == latest + 1` (never clearing local-revocation quarantine at `<= latest`), (2) the caller's chat transport key is currently active in `MailboxDirectory`, (3) `step_forward` confirms `epoch/<seq>` is neither `Valid` (sibling rotation in flight) nor `NotEpochMember` (legitimate revocation or multi-chunk write), (4) `MailboxDirectory` (`CompositeDirectory` over PDS + `mls-ds`) anchors nothing at `>= seq` (refusing with `EpochTruncated` or `DirectoryIncomplete` so an anchored rotation is never clobbered), and (5) a final `step_forward` re-check right before deleting `epochMember/<seq>-*` and `epoch/<seq>` via `com.atproto.space.applyWrites`.

## 6. Recovery codes and virtual devices (p.30–36)

### 6.1 Recovery codes

- Alphabet `ACDEFHJKLMNPQRSTUVWXYZ0123456789`. On input, `B→8`, `G→C`, `I→1`, `O→0`.
- 40 characters: version `2`, identifier `0`, 34 entropy characters, 4 ECC characters.
- **ECC over GF(32)** **[CB-12]**:
  - The field is GF(2⁵) with modulus x⁵+x²+1. Symbol value = index in the alphabet.
  - The paper says "any four columns" of the 4×38 matrix `G` are invertible. **That can't hold at length 38.** Such columns would form an arc in PG(3,32), and the largest arc there has q+1 = 33 points (Segre).
  - What the paper actually promises is correcting **three** errors. That needs only any **three** columns to be independent, i.e. columns that form a cap with no three points collinear.
  - Construction: we take the columns from the elliptic quadric `x₁ = a² + ab + c·b²` in PG(3,32):
    - `c` is the smallest field element that makes `X²+X+c` irreducible. That is `c = 1`.
    - Let `ω` be a root of `X²+X+1`, so GF(1024) = GF(32)[ω] and `ω² = ω + 1`. Then `a² + ab + b²` is the norm of `a + bω`.
    - Let `γ = 6 + ω`, where `6` is the field element x²+x. It is the primitive element `t + ω` of GF(1024) with the smallest `t` (as an integer).
    - For j = 0..37, write `γʲ = a_j + b_j·ω`. Column j is `(1, a_j² + a_j·b_j + b_j², a_j, b_j)`.
    - Why not take `(a, b)` in lexicographic order? Every point with the same `a` lies on the plane `x₂ = a·x₀`. So the first 38 pairs make the four ECC columns (34..37) coplanar, and encoding would have no unique solution. Powers of `γ` spread the points out. ECC columns 34..37 are independent, and only 2,091 of the C(38,4) four-column sets are singular, against 31,770 for lexicographic order.
    - The matrix is hard-coded in `src/recovery_code.rs`, and a unit test regenerates it from this rule.
  - `tests/` checks all C(38,3) triples exhaustively.
  - Encoding solves `G·(entropy||ecc) = 0` for the 4 ECC symbols (columns 34..37, which tests also check are independent).
  - Decoding brute-forces up to 3 erasures, solves the overdetermined system, and accepts a candidate only if it is consistent and the derived `vdeviceId` exists on the backend.
    - A typo'd code yields a few hundred triple-erasure candidates, because each 3-erasure set passes the single redundant equation with probability about 1/32.
    - A character outside the alphabet (after the homoglyph mapping) counts as a known erasure.
- Derivation:

```
(vdeviceId, vdeviceKey) = kdf(entropyChars, null, "BackupRecoveryCode_v" || ver || "_" || id || "_" || did, 48)
```

- `entropyChars` is the 34 ASCII characters.

### 6.2 Virtual device bundle (p.32–34; ORF-free PQ layout)

The bundle (`blue.catbird.labyrinth.virtualDevice`) is AEAD-sealed (`Suite::DndkGcm`, `0x02`) under `vdeviceKey`:

| Field | Plaintext | AAD |
|---|---|---|
| `deviceKeyPriv` | 32-byte XEdDSA secret | `virtual_device:virtual_device_private_key` |
| `epochStorageKeyPriv` | 96-byte `HawkEncSecret` (`x25519 \|\| mlkem_seed`) | `virtual_device:epoch_storage_private_key` |
| `mailboxRootSalt` | 32 bytes | `virtual_device:mailbox_root_key` |
| `epochRootKey` | 32 bytes | `virtual_device:epoch_root_key` |
| `base64(seq)` | Base64 of decimal `seq` | `virtual_device:epoch_anon_id` |

The bundle also publishes the virtual device's public record (`isVirtual = true`, `sigStorage` signed under use-case byte `0x32`, `Gate 2`) and its `epochMember` record. The bundle seals the epoch's sequence number; a restoring device looks up `space_epoch_id(seq)` in the mailbox Space.

### 6.3 Atomic enrollment from a recovery code (`Gate 3`)

1. Fetch the bundle by `vdeviceId`, check expiry ([CB-39]), and decrypt it under `vdeviceKey`.
2. Forward-chain with the virtual device's `HawkEncSecret` to the newest reachable epoch `E`, then run `verified_own` ([CB-43]) and `check_candidate_integrity` ([CB-28]) against `CompositeDirectory`.
3. Generate fresh physical device keys (`DeviceSecrets::generate()`) bound to the caller's current chat transport key ([CB-36]).
4. Open `E + 1` via `open_next_enrolling` (carrying over every valid unrevoked member of `E` plus the newly enrolled physical device, signed under `E`'s mailbox signing key) and commit `touchVirtualDevice` + `device` + `epoch(E+1)` + `epochMember`s in one atomic `com.atproto.space.applyWrites` (`MailboxStore::atomic_enroll`), then publish `mailboxKeys` for `E + 1`.

### 6.4 Recovery storage (p.43–46)

Each recovery mechanism gets its own virtual device. This crate provides helpers for two of them:
- **Passkey PRF.** `wrapKey = kdf(prf_output, MINOS_SALT, "catbird.labyrinth.passkey_wrap.v1")`, and the code is stored AEAD-sealed next to the bundle **[CB-13]**: `encrypt(wrapKey, "catbird.labyrinth.passkey_wrapped_code", code40)`, where `code40` is the canonical 40-character ASCII code.
- **Platform keychain.** The code is stored raw, for iCloud Keychain or Android Auto Backup.

A PIN vault (HSM or Juicebox) is out of scope for the first release.

**[CB-39] Recovery-method lifecycle** (decision J2 defaults, paper p.46). `Labyrinth::list_recovery_methods` lists every bundle with its mechanism, `createdAt`, `lastUsedAt` and expiry:
- `keychain` and `passkey` bundles, which a platform stores for the user, expire 180 days (`AUTO_RECOVERY_TTL_MS`) after `max(createdAt, lastUsedAt)`; `code` and `otc` bundles never expire.
- A restore touches its bundle (`lastUsedAt` updated atomically inside `atomic_enroll`); the app may also call `touch_recovery_method` when it confirms its keychain copy still exists.
- `remove_recovery_method` revokes the virtual device (rotating to a new epoch without it) and then deletes the bundle (`delete_virtual_device`); `remove_expired_recovery_methods` does this for every expired bundle by the client clock.

### 6.5 Hybrid post-quantum one-time code (`CPace + ML-KEM-768`, `I16`, `Gate 3`)

- Combines **CPace** over Ristretto255 / SHA-512 (`draft-irtf-cfrg-cpace-21`, `tests/vectors/cpace_ristretto255.json`, `PRS` = 6 ASCII digits, `sid` = 16 random bytes, `CI = "catbird.labyrinth.otc.v1" || did`) with an ephemeral **ML-KEM-768** key encapsulation bound into the CPace associated data **[CB-14]**:
  1. **Initiator (new device):** generates `(dk_otc, ek_otc) = ML-KEM-768.KeyGen()`, sets `ad_a = sha256(ek_otc)`, and sends `InitiatorMessage { sid, ya, ek_otc, ad_a }`.
  2. **Responder (enrolled device):** consumes 1 of 3 attempts, encapsulates `(kem_ct, mlkem_ss) = ML-KEM-768.Encaps(ek_otc)`, sets `ad_b = sha256(kem_ct)`, computes `cpace_isk = CPace_ISK(ya, ad_a, yb, ad_b)`, derives `otc_seal_key = kdf(cpace_isk || mlkem_ss, MINOS_SALT, "catbird.labyrinth.otc.pq.v2")`, and returns `ResponderMessage { yb, kem_ct, ad_b }` plus `OtcPayload` AEAD-sealed (`0x02` DNDK-GCM, AAD `"otc_payload"`).
  3. **Initiator:** decapsulates `mlkem_ss`, derives `otc_seal_key`, opens `OtcPayload`, verifies `E` against the mailbox and `CompositeDirectory`, and atomically rotates `E -> E + 1` (`Gate 3`, optionally consuming `otcSession/<rkey>` in the same `applyWrites`).
- **[CB-26] Payload encoding (version `0x02`, big-endian, no trailing bytes):**

```
0x02                     format version (ORF-free PQ clean-slate; 0x01 rejected)
mailboxRootSalt    (32)
epochRootKey       (32)
epochSequenceID    (u64, 8)
len(epochID)       (u16, 2)    at most 512
epochID            (UTF-8)
```
- A code allows 3 attempts.

## 7. Messages

Code: `src/message.rs` (§7.1–7.2), `src/mek.rs` and `src/mek/distribute.rs` (§7.3–7.4).

### 7.1 Owner upload (cipher versions 3 and 5; p.37–38)

```
messageKey = kdf(root, null, "message_key_in_epoch_" || seq || "_cipher_version_3_thread_" || threadId)
encrypted  = encrypt(messageKey, "message_thread_" || threadId, pad(messageData))
```

Stored record: `(threadId, messageId, timestamp, epochSequenceID, version, encrypted)`.

- **[CB-37] We write version 5**: the version-3 key derivation with `_cipher_version_5_`, and
  ```
  aad     = "catbird.labyrinth.owner_message_v5:message_id=" || messageId || ";thread_id=" || hex(threadId)
            || ";timestamp=" || timestamp
            [ || "\0catbird.labyrinth.owner_receipt_v1\0" || DAG-CBOR(sequencerReceipt) ]   // only when the record carries one
  content = kind(1) || body
  encrypted = encrypt(messageKey, aad, pad(content))
  ```
  where `kind` selects one of four padded, server-indistinguishable payloads:
  - `0x00` — plain unattributed message frame (`body = frame`);
  - `0x01` — delete-for-me tombstone (`body = author_did_utf8`, empty if unscoped, §7.5);
  - `0x02` — `I13` sequencer-receipt-committed frame (`body = frame_nonce(32) || frame`). The enclosing `OwnerMessage` carries the full `sequencerReceipt` (`ArchivedReceipt`: the signed receipt plus its generation), which the AAD above binds. On read, the receipt must name this thread, verify under the conversation's `sequencer_receipt_key` (`ES256`, `#mls-receipt-1`) and match the blinded `HMAC-SHA256` commitment; `LoadedMessage::sender` comes from `receipt.signed.payload.split_sender_device()`. Only when no receipt key resolves for the thread may the reader resolve one for the AEAD-authenticated issuer (`MailboxDirectory::sequencer_receipt_key_for_authority`), and that lookup never replaces a pinned authority. A `0x02` record without a receipt, or a `0x00`/`0x03` record with one, is undecryptable (`ReceiptCommitmentMismatch`);
  - `0x03` — sender-attributed frame (`body = u16_be(len(sender_did)) || sender_did || frame`), preserving authenticated `sender_did` when re-archiving plain sender batches before leave or rescuing locally cached/queued messages after involuntary removal ([CB-22]).
- Readers also accept version 3 (the paper's writer) and versions 0, 2, 4 from the paper's implementation notes (p.51–52), all with the paper's AAD; version 1 and anything above 5 are rejected.

### 7.2 Sender upload (v1.1, p.38–39)

```
messageKey = kdf(mek, MINOS_SALT, "minos.kdf.mek.single_message_key:" || ";message_id=" || messageId
                 || ";thread_id=" || hex(threadId) || ";timestamp=" || timestamp)
aad = "minos.symmetric_enc.message_v2:" || "mek_id=" || hex(mekId) || ";message_id=" || messageId
      || ";sender_transport_pk=" || hex(senderTransportPk) || ";thread_id=" || hex(threadId)
      || ";timestamp=" || timestamp
ct  = encrypt(messageKey, aad, pad(messageData))
sig = Ed25519(transportKey, "minos.unstructured_signature.message:" || ct)     // [CB-3]
signedEncMessage = sig(64) || ct
```

- The key label is taken literally, so it reads `single_message_key:;message_id=…` (colon then semicolon). It does not include `mek_id`; the AAD does.
- Stored record (`defs#sealedMessage`): `(messageId, timestamp, mekId, senderTransportPk, signedEncMessage)`. The thread id comes from the enclosing `batch` record.
- Opening: check `mekId` equals the MEK's id, verify `sig` (strict Ed25519) under `senderTransportPk`, rebuild the AAD from the record fields and the batch's thread id, decrypt, unpad. The reader separately checks that `senderTransportPk` is one of the claimed sender's MLS chat devices (`verify_sender_device`).
- **Committed items (`I13`).** For a sequenced application message, `messageData = frame_nonce(32) || frame`, where `frame` is the canonical chat frame and the nonce never leaves encrypted payloads. The item also stores the signed `sequencerReceipt` and its `seq` (`seal_sender_committed`). Before sealing, `archive_outgoing_committed(thread, roster, messageId, timestamp, frameNonce, frame, &ArchivedReceipt)` checks that the receipt names the thread and that `HMAC-SHA256(frame_nonce, frame)` equals its `archiveCommitment`. Readers repeat both checks after decrypting.

**[CB-15] (the hybrid storage choice).** The `signedEncMessage` bytes don't depend on the recipient. So we store each message **once per conversation**, in the sender's repo in the conversation Space, not once per recipient mailbox. The MEK distributions sit next to it, in the sender's repo ([CB-21]). Readers check `sig` against the sender's chat device key, which they get from MLS. A member that received a committed message may also store a **witness copy** of the same committed frame in its own repo (§7.4).

### 7.3 MEK distribution (p.39–41)

```
rosterHash = sha256("mek_recipient_list:" || hex(head_0) || hex(head_1) || …)   // hex strings, sorted ascending
mek   = random(32)
mekId = kdf(mek, MINOS_SALT, "minos.kdf.mek.mek_id:recipient_roster_hash=" || hex(rosterHash), 12)
```

- The paper's prose says to hex-encode and sort the heads, but its pseudocode concatenates `epochHeads[i]`. We concatenate the sorted lowercase **hex strings** (ASCII), not the raw bytes.
- **Labyrinth sender MEK:**

```
aad = "minos.hpke.mek_distribution_from_minos_v2:" || "mek_id=" || hex(mekId)
      || ";recipient_epoch=" || hex(recipHead) || ";recipient_roster_hash=" || hex(rosterHash)
      || ";sender_epoch=" || hex(senderHead) || ";thread_id=" || hex(threadId)        // [CB-24]
ct  = hawk_encrypt(recip.encPub, sender.authPriv, sender.authPub, aad, mek)
```

- **Transport sender MEK** (from a device that is not enrolled):

```
(ephPriv, ephPub) = X25519 keygen (Hawk auth key pair)
sig = Ed25519(transportKey, "minos.structured_signature.mek_distribution.ephemeral_auth:"
              || "k=" || hex(ephPub) || ";mek_id=" || hex(mekId))
aad = "minos.hpke.mek_distribution_from_transport_v2:" || "mek_id=" || hex(mekId)
      || ";recipient_epoch=" || hex(recipHead) || ";recipient_roster_hash=" || hex(rosterHash)
      || ";sender_transport_pubkey=" || hex(transportPub) || ";thread_id=" || hex(threadId)  // [CB-24]
ct  = hawk_encrypt(recip.encPub, ephPriv, ephPub, aad, mek)
```

- **[CB-24] Thread binding.** Both AADs end with `;thread_id=hex(threadId)`, which the paper's AADs lack. Without it a backend could move a MEK record into another thread unnoticed. The field keeps the AAD's alphabetical key order. This breaks byte compatibility with Messenger MEKs, which we don't claim anyway.
- **Record** (`blue.catbird.labyrinth.mek`): `(threadId, mekId, rosterHash, sender, recipients[])`. `sender` is either `{did, senderEpochHead}` or `{transportPubkey, ephemeralAuthPubkey, sig}`. Each recipient is `{did, recipientEpochHead, ciphertext}`.
- **Sender checks.** Every recipient `epochPublic` is verified (head, self signature, transport attestation; the caller checks the attesting key is that DID's MLS device, [CB-18]). DIDs and heads must be unique. `rosterHash(recipient heads)` must equal the MEK's roster hash. A Labyrinth sender's own `(did, head)` must be a recipient ([CB-16]), and its mailbox keys must match its epoch.
- **Opening** a record, in order:
  1. DIDs and heads in `recipients` are unique, and `rosterHash` recomputes from **all** recipient heads.
  2. Find my entry by DID; its head must be the head of the epoch I open with, that epoch must verify, and my mailbox keys must match it.
  3. Labyrinth sender: the sender's `epochPublic` must have the record's `senderEpochHead`, verify for the sender DID, and appear among the recipients. Transport sender: `sig` must verify under `transportPubkey`; the Hawk auth key is `ephemeralAuthPubkey`.
  4. Rebuild the AAD from the record and `hawk_decrypt`; the plaintext must be 32 bytes.
  5. Re-derive `mekId` from the secret and `rosterHash`; it must match.
  - The opened MEK carries its *provenance*: the sender DID and epoch head, or the transport key. The caller still checks that key against the sender's MLS devices.
- **[CB-21] Where MEKs live.** Under Spaces only the account owner can write its own repo. So the sender writes **one** `blue.catbird.labyrinth.mek` record per MEK into its own repo inside the conversation Space, listing a ciphertext for every recipient. It does not write into each recipient's mailbox. Recipients read it with their conversation-Space capability credential.
- **[CB-22] Leaving or involuntary removal from a conversation.** After an account leaves or is removed, the Space authority refuses its conversation-Space reads and writes, which the store reports as `Error::Forbidden` (HTTP 401/403 or `SpaceDeleted`). `Forbidden` is the only Space answer that sends a reader to its owner archive. A missing Space (`NotFound("space")`) is an error, not a fallback.
  - **Voluntary leave:** Before leaving, the client runs `rearchive_and_clear_before_leave` (messages only: `rearchive_thread_before_leave`). It seals every copy that reading accepts (after redactions, tombstones and witness rejection, §7.4) into the personal mailbox Space as owner-mode v5: `0x02` when the copy carries a receipt, otherwise `0x03` sender-attributed (§7.1). It then copies its own attachment manifests (`blue.catbird.labyrinth.attachmentManifest`) and deletes its own MEK, batch and manifest records from the conversation Space.
  - **Involuntary removal / kick:** When an account is removed before it can re-archive, conversation-Space reads and sender flushes fail with `Error::Forbidden`. Queued outbox items and locally cached messages then fall back to owner-mode v5 in the personal mailbox Space before local conversation state is deleted. catbird-mls's native client (`CatbirdMlsClient`) takes that path only on `Forbidden` or an authenticated local removal (a verified Commit removed this device, or the local MLS roster no longer holds the account). It seals with `archive_owner_committed`, so every rescued copy keeps its canonical frame and `I13` evidence ([SPACE_CONVERSATIONS.md](SPACE_CONVERSATIONS.md)). The orchestrator fallback (`archive_owner_fallback`) seals `0x03` sender-attributed frames.
- **The roster** is every Labyrinth-enrolled DID that is currently a member of the MLS group, the sender included **[CB-16]**.
  - Any roster change, such as an add, a remove, or a member opening a new epoch, invalidates the cached MEK.
  - That is what stops a removed member from reading anything new, and stops a new member from reading anything older than their join.
- **Reuse rule (p.38–39).** A sender reuses a cached MEK only if both hold (`Mek::reusable_for(currentHeads)`):
  1. its roster hash equals `rosterHash(currentHeads)`, the caller's view of every roster member's latest head;
  2. it is authenticated to some participant's latest epoch keys. A Labyrinth MEK is authenticated by the sender's epoch auth key, so rule 2 holds iff its `senderEpochHead` is in `currentHeads`.
  - **[CB-42]** Only a Labyrinth MEK this account minted (`senderDid` = own DID, from any of its devices) is reused (`Mek::reusable_for(myDid, currentHeads)`).
  - **[CB-23]** A transport MEK is authenticated by no epoch key. Only the device that minted it may reuse it (under rule 1); members who opened it never reuse it and mint their own Labyrinth MEK instead. A freshly generated, undistributed MEK is never reusable.

### 7.4 Loading (p.41)

To read a message:
1. Find the MEK by `mekId` in the conversation's MEK records ([CB-21]) and open it under the mailbox encryption key of the epoch it was addressed to (§7.3).
2. Check the AAD fields against the record.
3. Verify `sig` and that the sender key is one of the sender's MLS devices: a current one, or one active at the `I13` `SequencerReceipt`'s `seq` / `issued_at_ms` ([CB-27]). A conversation whose receipt key resolves rejects items without a receipt (`ReceiptCommitmentMismatch`). Only where no receipt key resolves does the removal bound fall back to the message's timestamp.
4. Decrypt the message and remove the padding.

**Lookups.** `load_message(thread, messageId)` returns every copy of one message (`ThreadStore::get_messages` / `MailboxStore::get_owner_messages`). `load_thread_page(thread, before, limit)` returns the `limit` newest messages older than the cursor, newest first, decrypting only their copies.
- Each message has one position, taken from all of its copies: its sender copy's earliest `(timestamp, messageId)`, else its earliest witness copy's, else its earliest owner copy's. A witness stamps its receive time, so copies of one message can carry different timestamps.
- A message appears on exactly one page, with every copy. The next cursor (`"<ts>:<messageId>"`) is the oldest position covered.
- A page can come back short when tombstones hide messages or when its window holds copies of messages positioned on other pages.

`list_threads()` lists the threads this account has history in from its own records: MEKs it wrote or was addressed in, and its owner archive, so a restored device finds conversations it has left or been removed from.

**Witness copies.** A member that received and verified another member's committed message may archive the same frame, nonce and receipt in its own repo (`archive_outgoing_committed`, sealed under its own chat key and receive-time MLS roster). The reader runs the unchanged checks: the sealing key must be one of the **archiving** member's chat devices at the receipt's order. It then attributes the message to the receipt's sender, never to the witness (`MessageSource::Witness`).

**Duplicates [CB-31] and witness acceptance.** A thread can hold several copies of one `messageId`: a sender copy, witness copies, an attributed or legacy unattributed owner-archive copy, or a different member reusing the ID.
1. Sender and owner copies are accepted as they are.
2. Nothing authenticates the message ID a witness files a copy under (the receipt's `entryId` is mls-ds's own). In the store's order, a witness copy is accepted only if it equals an accepted copy with its ID (same frame, nonce, receipt and sender), or if no accepted copy holds its ID or its receipt's entry. Otherwise it goes to `ThreadHistory::rejected` (`Rejection::Contradicts` or `Rejection::ReceiptReused`), and is never returned, flagged or re-attributed.
3. Accepted copies merge in this order: the author's own sender copy, then the earliest witness copy, then attributed owner copies (`0x02`/`0x03`), then legacy unattributed owner copies (`0x00`/v3). Copies merge only when their frames are byte-equal, their senders agree (or one is unattributed), and, when both are committed, their receipts and nonces are equal.
4. Any other duplicate `messageId` among sender and owner copies is returned with `conflict = true`, so neither an insider nor a corrupt owner copy can silently rewrite sender attribution.

A verified unsend or account-deletion redaction for `(messageId, sender)` also hides that sender's witness and owner copies.

### 7.5 Deletion and edits [CB-38]

Decision J1 defaults (`src/deletion.rs`, `src/client/delete.rs`):

| Operation | Mechanism | Who sees what |
|---|---|---|
| **Delete for me** (`delete_for_me`) | an owner-mode v5 tombstone (§7.1, kind `0x01`) in the reader's personal mailbox Space, with the target's `messageId`, `timestamp`, and optional author DID | every device of the account hides matching messages (`ThreadHistory::deleted_for_me`); author-scoped tombstones match attributed sender and attributed owner copies of that author without hiding another sender's copy |
| **Unsend** (`unsend`) | the author's signed `redaction` replaces the item's `signedEncMessage` (now empty) inside the author's Space `batch` record (`ThreadStore::redact_item`) | every reader gets `ThreadHistory::redacted`, with `by_author = true` iff an active chat key of the author signed `"catbird.labyrinth.redaction:did=" \|\| did \|\| ";message_id=" \|\| id \|\| ";thread_id=" \|\| hex(threadId)` |
| **Account deletion, DS redaction** | when an account deletes its chat identity, the conversation's sequencer DS signs a `redaction` (`by = sequencerDid`, `reason = "accountDeleted"`, `redactedAt`, `sig` over `"catbird.labyrinth.ds_redaction:..."`) | readers resolve `MailboxDirectory::sequencer_key(thread)` for that conversation's `sequencerDid` (federation-aware) and set `RedactedMessage::account_deleted = true` iff `sig` verifies; unsigned or mismatched redactions fail closed. mls-ds does not write these overlays today: it sequences a signed `accountDeletedEntry`, and catbird-mls hides the deleted account's copies itself ([SPACE_CONVERSATIONS.md](SPACE_CONVERSATIONS.md), "Account deletion") |
| **Account deletion** (`purge_account`) | redact/delete authored records across every conversation Space, retract directory heads (`PdsPublisher` + `mls-ds`), and `purge_mailbox` on the personal mailbox Space | local state and personal mailbox records are wiped; peers see the user's messages as removed |
| **Edit** | frame level: a new message referencing the old id in the chat frame schema | Labyrinth stores both; the client applies the edit |

## 8. Space-native encrypted attachments (`Gate 5`, `2A` ORF retired)

- **[CB-32] Cipher and blob storage.** Attachment bytes are encrypted client-side with **AES-256-GCM** (per-blob random key + IV carried inside the encrypted MLS/Labyrinth message frame), bounded to `MAX_ATTACHMENT_BLOB_BYTES = 134,217,728` (128 MiB), uploaded via `com.atproto.repo.uploadBlob` to the sender's PDS, and immediately promoted from `.staged` to `.space` by writing a `blue.catbird.labyrinth.attachmentManifest` record in the Space.
- **[CB-33] `attachmentManifest` records** (`src/attachment.rs`, `src/records/mailbox.rs`). Instead of server-held ORF indices, each Space holds `blue.catbird.labyrinth.attachmentManifest` records (`rkey = <threadId_or_hash>-<messageId>-<cid_suffix>`):
  - Fields: `blob` (`BlobRef`), `sha256` (32-byte ciphertext digest), `ciphertextSize` (`1..=134_217_728`), optional `mimeTypeHint` (`<= 128` UTF-8 bytes), `createdAt`.
  - On download, `verify_attachment_ciphertext` enforces exact `ciphertextSize` and constant-time `SHA-256` equality before AEAD decryption.
  - On voluntary leave ([CB-22]), `rearchive_thread_before_leave` copies referenced `attachmentManifest` records into the user's personal mailbox Space so attachments remain readable after Space access is revoked.

## 9. Storage backends (ATProto Spaces only; `I14`, `I15`)

The protocol state machines do no raw network I/O. `src/records/` defines the ATProto lexicon record shapes, `src/store/` defines the async storage traits, and `src/client/` implements the state machine over those traits.

### 9.1 Records

Every record is a `blue.catbird.labyrinth.*` lexicon in `lexicons/blue/catbird/labyrinth/`. `tests/lexicon_records.rs` validates every emitted record against the lexicon JSON.

| Record | Space / Repo | rkey | Mutability |
|---|---|---|---|
| `device` | personal mailbox Space | `hex(deviceKeyPubkey)` | immutable except `revokedAt`, set once |
| `epoch` | personal mailbox Space | `epochID` = 12-digit zero-padded seq ([CB-9]) | immutable (`delete_squatted_epoch` clears unanchored squats only, [CB-40]) |
| `epochMember` | personal mailbox Space | `<12-digit seq>-<hex deviceKeyPubkey>` | immutable |
| `virtualDevice` | personal mailbox Space | `hex(vdeviceId)` | immutable except `lastUsedAt`; deleted on removal |
| `otcSession` | personal mailbox Space | `<session_id_hex>` | ephemeral OTC handshake record, consumed atomically in `Gate 3` |
| `ownerBatch` | personal mailbox Space | TID | append-only, one thread per batch |
| `attachmentManifest` | conversation or personal mailbox Space | deterministic manifest key | immutable blob promotion + SHA-256 integrity manifest (`Gate 5`) |
| `mailboxKeys` | **public** PDS repo | `self`, plus `<12-digit epochNumber>` per epoch | `self` updated on rotation; per-epoch copies immutable ([CB-19], [CB-29]) |
| `mek` | conversation Space, sender's repo | `hex(mekId)` | immutable ([CB-21]) |
| `batch` | conversation Space, sender's repo | `<16-hex-first-seq>-<tid>` (or TID when unstamped) | append-only (`Gate 4`, [CB-15]); items may be redacted in place |

Every `epochNumber` is bounded at 2⁴⁰. `mek#labyrinthSender` embeds the sender's full `epochPublic` (including `membersHash`, `self_sig`, and [CB-18] `attestation`).

### 9.2 Async store traits (`?Send` WASM + `Send + Sync` native)

All store traits (`MailboxStore`, `ThreadStore`, `MailboxDirectory`, `KeyPublisher`) are **`async`** (`#[async_trait]` on native targets requiring `Send + Sync`, and `#[async_trait(?Send)]` on `wasm32-unknown-unknown` via `MaybeSend`/`MaybeSync` marker traits so browser `JsFuture`/IndexedDB handles work without thread bounds):

- `MailboxStore`: personal mailbox Space CRUD (`SpaceMailboxStore` in `src/store/space/`), atomic enrollment (`atomic_enroll`, `Gate 3`), safe squatted-epoch deletion (`delete_squatted_epoch`, [CB-40]), owner-batch paging, and `purge_mailbox`.
- `ThreadStore`: conversation Space reads/writes (`SpaceThreadStore` in `src/store/space/thread.rs`; `ResolvingSpaceThreadStore` in `catbird-mls` adds the Space pins), ordered batch keys (`<16-hex-first-seq>-<tid>`), the `I13` `SequencerReceipt` on each sealed item (`SealedMessage::sequencer_receipt`, an `ArchivedReceipt`), and `redact_item`.
- `MailboxDirectory`: `CompositeDirectory` cross-checking the public PDS `mailboxKeys` repo against `mls-ds`'s `EpochPublicHeader` chain (`epoch_chain` + `floor_seq`, `Gate 6`), MLS chat device transport keys (`device_transport_keys`, `member_device_keys`), and **per-conversation** sequencer verification keys (`sequencer_key(thread)` for `[CB-38]` DS redactions and `sequencer_receipt_key(thread)` for `I13` ES256 receipts, resolved from each conversation's `sequencerDid` and `{sequencerDid}#mls-receipt-1` DID document under federation).
- `KeyPublisher`: publishes `EpochPublic` to the public PDS repo (`PdsPublisher`) and `mls-ds` (`DsDirectoryStore`).
- `MemoryBackend` (`src/store/memory.rs`) and `MemorySpaceHost` (`src/store/space/host.rs`) provide in-memory reference implementations for deterministic tests. `mls-ds` stores **zero** Labyrinth ciphertext, MEKs, owner batches, virtual devices, or attachment blobs (`I14`, `I15`); its six remaining directory endpoints are in [MLSDS_BACKEND.md](MLSDS_BACKEND.md).

**[CB-20] Batching.** Up to 256 messages per `batch`/`ownerBatch` record (flushing early near 900 KB JSON or when `mekId` changes; single-MEK sender batches), and up to 200 operations per `com.atproto.space.applyWrites` call (`MAX_WRITES`).

### 9.3 Client and crash-consistent persistence

`client::Labyrinth` represents one enrolled device, holding `DeviceSecrets`, cached `EpochSecret`s, the local `revoked` set, `[CB-29]` `PeerPin`s, and cached `Mek`s.

- **Persistence [CB-30] (`LBYS` version `0x03`):** `export_state()` serializes client state in version `0x03` (`96`-byte `HawkEncSecret`, `1,216`-byte `HawkEncPublic`, `0x30`/`0x32` `sigStorage`, verified-member set, pins, and MEKs; legacy versions `0x01`/`0x02` fail closed with `Error::Unsupported`) inside a `Zeroizing<Vec<u8>>` buffer. The encoding is canonical: every keyed collection (epochs, revoked, verified, pins, MEK threads) is written in ascending key order, so the same logical state always exports the same bytes and a load/save of unchanged state is a byte-identical no-op; `from_state` still accepts MEK threads in any order (blobs written before the ordered MEK cache).
- **Immediate `StateSink` checkpointing:** Callers attach a synchronous `StateSink` (`with_state_sink` / `set_state_sink`, backed by SQLCipher `StateVault` in `catbird-mls`). Every mutation of `epochs`, `revoked`, `[CB-29]` `pins`, or minted/opened `meks` invokes `StateSink::save_state` **immediately** — before network batch flushes or directory `publish_keys` calls — eliminating the crash/jetsam window where a newly minted MEK, peer pin, or rotated epoch secret could be lost on flush failure. Outgoing frames are durably persisted inside the same SQLCipher write transaction as the MLS ratchet advance (`I6`) before network I/O.

## 10. Security properties and residual paper limitations (p.47)

- **Full post-quantum confidentiality (`I16`).** Unlike the v1.1 paper's classical X25519 `epochStorageKey` and classical CPace OTC, **every secret-bearing transport in this profile is Harvest-Now-Decrypt-Later (`HNDL`) post-quantum secure**:
  - Sender message keys (`MEK`s) are encapsulated under **Hawk HPKE** (`X25519 + ML-KEM-768`, §3.5, §7.3) and message bodies use 256-bit **AES-256-DNDK-GCM** (§3.1).
  - Epoch entropy (`EpochMember.encryptedEntropy`) is encapsulated under **Hawk HPKE PSK mode** (`X25519 + ML-KEM-768` + `distPsk`, §3.5, §5.5).
  - Virtual-device recovery bundles seal the 96-byte `HawkEncSecret` and 32-byte `epochRootKey` under a 256-bit HKDF key derived from ~170 bits of recovery-code entropy (§6.2).
  - One-time-code device transfers combine **CPace + ephemeral ML-KEM-768** (`§6.5`), keeping `epochRootKey` confidential even if a quantum adversary later learns the 6-digit code and breaks Ristretto255 discrete logs.
  - Classical `Ed25519`, `XEdDSA`, and `ES256` (`P-256`) signatures are used strictly for online authentication (`[CB-3]`, `[CB-18]`, `I13`), which a future quantum computer cannot retroactively forge against already-verified transcripts.
- **Epoch truncation by a malicious Space host ([CB-28], `Gate 6`).** Mitigated by `CompositeDirectory` cross-checking the Space mailbox against both the public PDS `mailboxKeys` repo and `mls-ds`'s append-only `EpochPublicHeader` chain (`floor_seq`). The account's PDS hosts both the mailbox Space and `mailboxKeys`, so truncation requires that PDS and `mls-ds` to collude.
- **First contact ([CB-29]).** `CompositeDirectory` requires PDS and `mls-ds` agreement on first contact, and `[CB-29]` pins (immediately checkpointed via `StateSink`) protect every subsequent send.
- **Removed chat keys and ordering ([CB-27], `I13`, `Gate 4`).** Sequenced messages carry ES256 `SequencerReceipt`s (`#mls-receipt-1`, verified per conversation against that thread's `sequencerDid`) binding `(conversationId, seq, epoch, commitment, senderDevice, issuedAtMs)` and `<16-hex-first-seq>-<tid>` batch rkeys, preventing a removed device from backdating sequenced frames. A conversation whose receipt key resolves rejects unreceipted items. Only a conversation with no resolvable receipt key falls back to sender timestamps bounded by key removal time.
- **Membership enumeration.** Space repo DIDs and `mek` recipient DIDs remain visible to conversation Space readers and the Space host, as in the paper.

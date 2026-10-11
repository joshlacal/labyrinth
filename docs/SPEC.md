# Labyrinth 1.1, Catbird profile

**What this is.** This crate implements Meta's *Labyrinth Encrypted Message Storage Protocol*, version 1.1 ("Minos", whitepaper "Version 2", April 2026). The goal is end-to-end-encrypted chat **history** for Catbird. Catbird's chat runs on MLS through `mls-ds`, our delivery service on atproto. The whitepaper leaves several choices to the implementer and is written around Facebook identities. This document fixes every such choice for Catbird. **We do not claim wire compatibility with Messenger.** Meta publishes no test vectors; ours are in `tests/vectors/`.

Primary sources:
- Labyrinth v1 (Dec 2023): <https://engineering.fb.com/wp-content/uploads/2023/12/TheLabyrinthEncryptedMessageStorageProtocol_12-6-2023.pdf>
- Labyrinth v1.1 (Apr 2026): <https://engineering.fb.com/wp-content/uploads/2026/05/Minos-Updates-2026-Encrypted-Backups-White-Paper.pdf>
- AES-256-DNDK-GCM: <https://datatracker.ietf.org/doc/draft-gueron-cfrg-dndkgcm/>
- XEdDSA: <https://signal.org/docs/specifications/xeddsa/>
- ORF: <https://eprint.iacr.org/2022/1044>

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
| metastore + mailbox server | a storage *backend*: a personal atproto Space on the user's PDS, or `mls-ds` (§9) |

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
- Use-case bytes: `0x30` (epoch storage key) and `0x31` (epoch storage auth key) (p.24).

### 3.4 Labyrinth HPKE (p.17), exactly as specified

```
fresh = X25519(sender_auth_priv, recip_enc_pub) || X25519(eph_priv, recip_enc_pub)
inner_aad = 0x01 || sender_auth_pub || recip_enc_pub || eph_pub || aad
subkey = kdf(fresh, psk, inner_aad)          // psk ≤ 32 bytes; salt = psk
ct = AES-256-GCM(subkey, nonce = 0^12, aad, pt)
out = 0x01 || eph_pub || ct
```

Recipient public keys are checked for low-order points, and an all-zero X25519 output is rejected.

### 3.5 Hawk HPKE (p.18) **[CB-8]**

The paper gives the structure but not the byte layout, so we define it here.

- **Keys.**
  - An auth key pair is an X25519 key pair.
  - An encryption key pair is an X25519 key pair plus an ML-KEM-768 key pair.
  - `encPub = x25519_pub(32) || mlkem768_ek(1184)`.
- **`hawk_derive_auth(seed)`:** `priv = kdf(seed, MINOS_SALT, "catbird.labyrinth.hawk.auth.x25519")`.
- **`hawk_derive_enc(seed)`:**
  - `x = kdf(seed, MINOS_SALT, "catbird.labyrinth.hawk.enc.x25519")`
  - `(d, z) = kdf(seed, MINOS_SALT, "catbird.labyrinth.hawk.enc.mlkem768", 64)`
  - ML-KEM-768 is then derived deterministically from `(d, z)` (FIPS 203 `ML-KEM.KeyGen_internal`).
- **`hawk_encrypt(recipEncPub, senderAuthPriv, senderAuthPub, aad, pt)`:**

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

### 3.6 ORF (p.18–20), exactly as specified

- The group is Ristretto255.
- `hash_to_curve(x) = ristretto_from_uniform_bytes(sha512(x))`.
- `orf_client_map(state, domain, input) = hash_to_curve(hmac(input, key = domain)) * state`.
- `orf_server_map(state, domain, P) = hmac(encode(P * state), key = domain)`.
- `evolve`: the client multiplies its state by a random scalar `r`, and the server multiplies its state by `r⁻¹`.

## 4. Device (p.21, p.24)

| Key | Type | Purpose |
|---|---|---|
| `deviceKey` | XEdDSA | membership identity, signs the next two keys |
| `epochStorageKey` | X25519 (Labyrinth HPKE enc) | receives new epoch entropy |
| `epochStorageAuthKey` | X25519 (Labyrinth HPKE auth) | authenticates entropy it sends. Virtual devices have none |
| `orfClientState` | Ristretto scalar | attachment index |

Public record: `deviceKeyPub`, `epochStorageKeyPub`, `sig_0x30`, `epochStorageAuthKeyPub?`, `sig_0x31?`.

## 5. Epochs (p.22–30)

### 5.1 Opening an epoch

- `epochSequenceID` starts at 0. Epoch 0 has a uniformly random root.
- Each later epoch:

```
(chainKey, distPsk) = kdf(prevRoot, null, "epoch_chaining_" || prevSeq || "_" || prevEpochID, 64)
root = kdf(entropy, chainKey, "epoch_root_key")
```

- **`epochID`** is assigned by the backend.
  - In the Space backend it is the epoch record's rkey: the decimal `epochSequenceID`, zero-padded to 12 digits so records sort.
  - In the mls-ds backend it is the row id as a decimal string.
  - Either way it is an opaque string to the protocol **[CB-9]**.

### 5.2 Mailbox key pairs (v1.1, p.27)

```
authSeed = kdf(root, MINOS_SALT, "minos.kdf.export_root_key.auth_keypair:epoch_number=" || seq)
encSeed  = kdf(root, MINOS_SALT, "minos.kdf.export_root_key.encryption_keypair:epoch_number=" || seq)
sigPriv  = kdf(root, MINOS_SALT, "minos.kdf.export_root_key.signing_keypair:epoch_number=" || seq)
```

- `hawk_derive_auth(authSeed)` and `hawk_derive_enc(encSeed)` produce the auth and encryption key pairs.
- `sigPub = X25519_base(clamp(sigPriv))`.

### 5.3 Epoch head (p.22–23)

```
epochHash = sha256("epoch_public_data:" || "auth_pubkey=" || hex(authPub) || ";encryption_pubkey=" || hex(encPub)
            || ";epoch_number=" || seq || ";previous_epoch_head=" || (prev ? hex(prev) : "null")
            || ";signing_pubkey=" || hex(sigPub) || ";user_did=" || did)
epochHead = sha256("epoch_head:" || "epoch_hash=" || hex(epochHash) || ";epoch_number=" || seq
            || ";previous_epoch_head=" || (prev ? hex(prev) : "null"))
self_sig = XEdDSA(sigPriv, "minos.unstructured_signature.epoch_self:" || epochHead)
prev_sig = XEdDSA(prevSigPriv, "minos.unstructured_signature.epoch_prev:" || epochHead)   // epoch > 0
```

- **[CB-10]** `epochHead` is the raw 32-byte digest. In the `+` concatenation above it is used as raw bytes.
- **[CB-35] No v1.0 upgrade path.** The paper allows a null `previousEpochHead` at epoch 0 *or* at a one-time v1.0→v1.1 upgrade (p.23). A mailbox created by this crate always has a head from epoch 0 on, and `EpochPublic::sign`/`verify` reject a null previous head at any epoch above 0: Catbird has no v1.0 mailboxes to upgrade, and accepting a null link mid-chain would let a backend restart a chain.
- **[CB-41] Fingerprints.** The head commits to the DID, the current mailbox keys and the whole chain, so it doubles as a safety number (`src/fingerprint.rs`): `fp = kdf(head, MINOS_SALT, "catbird.labyrinth.fingerprint.v1:" || did, 30)`, shown as six 5-digit groups (each 5-byte chunk big-endian mod 100000); two accounts compare the 60 digits of both, ordered by DID (`Labyrinth::safety_number_with` uses the [CB-29] pin for the peer), or 8 emoji (`fp[i] mod 64`). It changes on every rotation.
- **[CB-18] Transport attestation.** The device that opens an epoch also signs the head with its chat transport key (Ed25519):
  - `attestation = Ed25519(transportKey, "catbird.labyrinth.epoch_head_attest:" || did || ":" || epochHead)`.
  - A sender accepts a recipient's head only if the attesting key belongs to one of that DID's devices in the MLS group.
  - This anchors the head chain to MLS identity, so neither a storage backend nor mls-ds can substitute mailbox keys.
- **[CB-19] Discovery.** The latest `epochPublic` is published as `blue.catbird.labyrinth.mailboxKeys/self` in the account's **public** repo, so any PDS works.
  - Every published epoch is also kept, immutable, at `mailboxKeys/<12-digit epochNumber>`, so a sender can walk the `prev_sig` chain ([CB-29]).
  - Cost: it shows publicly that the account uses Labyrinth, and when it rotates epochs.
- **[CB-29] Peer epoch pinning.** A sender pins, per DID it addresses, the newest `(epochNumber, epochHead, signingPubkey)` it has accepted, and keeps the pin in its persisted state (§9.3):
  - an offered epoch older than the pin, or with the pinned number but another head, fails with `EpochRollback`. This stops the peer's PDS from replaying an older, still-attested `mailboxKeys` record, which would make senders encrypt to keys a revoked device still holds;
  - a newer epoch is accepted only if the `prev_sig` chain from the pinned head verifies through every intermediate epoch, fetched with `MailboxDirectory::epoch(did, seq)`; the client walks at most 4096 epochs per advance;
  - first contact is trust-on-first-use, anchored by the [CB-18] attestation (a current chat device of the DID). A backend that replays an old epoch to a sender who has never addressed that DID is not detected;
  - **long-term plan:** carry each member's latest epoch head in MLS-authenticated group state (mls-ds roster / group context), so first contact is authenticated too and the directory is only a cache.

### 5.4 Epoch metadata and membership (p.28–29)

```
dataKey = kdf(root, null, "epoch_data_storage_" || base64(seq))
macKey  = kdf(root, null, "epoch_devices_"      || base64(seq))
encPrevSeq  = encrypt(dataKey, "epoch_data_metadata", decimal(prevSeq))   // decrypt: ≤11 decimal chars
encPrevRoot = encrypt(dataKey, "epoch_data_metadata", prevRoot)
deviceMac[d] = mac(deviceKeyPub_d, macKey)    // only after verifying mac under the previous macKey
```

### 5.5 Entropy distribution (p.29)

For each continuing device `d` whose `sig_0x30` verifies:

```
encEntropy[d] = labyrinth_hpke(d.epochStorageKeyPub, self.authPub, self.authPriv, distPsk,
                               "epoch__" || seq, entropy)
```

### 5.6 Revocation (p.36)

- Revoking a device opens a new epoch that excludes it.
- **Local revoked set.** The revoking client records the device in its own revoked set (persisted, §9.3) before touching the store, and every rotation it performs excludes the whole set, whatever the store says about `revokedAt`. It reports success only after checking that the new epoch neither lists an excluded device nor encrypts entropy to one. A store that drops `revokedAt` therefore cannot re-admit the device. `sync_epochs` reports locally revoked devices that are still members of the reached epoch (a sibling re-admitted them, or a rotation never completed) so the caller can revoke again.
- **[CB-25] Rotation rules (amended 2026-10-05).**
  - The opener carries itself over and encrypts the entropy to its own storage key too, so any install holding its keys can forward-chain.
  - Before rotating, the client audits every member of the previous epoch (`src/client/members.rs`). A member whose record does not parse, whose device record is missing or fails `sig_0x30`/`sig_0x31`, whose MAC fails, or (physical devices) that is not bound to a *current* chat device of the DID ([CB-36]) is **excluded and reported** in `RotationReport::excluded`. The same audit runs on every `sync_epochs` (`SyncReport::invalid_members`) and on demand (`audit_members`).
  - Why: any chat device of the DID can write a member row (gap audit G-P0-2). If an invalid row aborted rotation, one planted row would block every later revocation; if it were dropped silently, a backend could evict a real device unannounced. Exclusion with a report is neither.
  - Exception: if a member this client already verified **in that same epoch** now fails a record or MAC check, the store rewrote a row it had served intact. The rotation aborts with `MemberTampered`. (An insider can only add rows for new keys, never rewrite one; a failed chat binding is a legitimate exclusion and does not count.) The verified set is persisted ([CB-30], state v2).
  - The rotating device's own chat key must be current in the directory, or the rotation fails with `Unattested` (a wrong directory view would otherwise drop every sibling).
- **[CB-36] Device binding.** A physical device record carries `chatBinding = {transportPubkey, Ed25519(chat key, "catbird.labyrinth.device_binding:" || did || ":" || deviceKeyPub)}` from the chat device that enrolled it; virtual devices carry none. Rotation carries a physical device over only while its binding verifies and names a current chat device, so removing a chat device drops its Labyrinth device at the next rotation (and the report says so). mls-ds additionally requires the binding at `createDevice` and admits epochs and members only from bound, registered devices; genesis therefore writes the device record before epoch 0, and a recovery bundle writes its device record before the `virtualDevice`.
- **[CB-40] Squatted epochs.** Epoch numbers are create-if-absent, so a bogus record at `seq + 1` would block every rotation. Forward chaining classifies the next epoch: if it is not signed with the previous epoch's mailbox signing key (`prev_sig`), its opener is not a valid physical member of the previous epoch, its opener is in this client's revoked set, or its entropy does not open, it fails with `EpochSquatted {seq, reason}` and is never retried; only a validly chained epoch without a valid membership for this device means `NotEpochMember` (revoked). Removing a squat needs the backend (mls-ds refuses epoch writes from unbound devices).
  - Forward chaining checks, in order: the opener's record verifies, is physical, matches `openedBy`, and holds a valid MAC in the previous epoch; the entropy decrypts; the derived mailbox keys equal the published `epochPublic`, whose head, self signature, attestation and `prev_sig` link verify; the reader's own MAC verifies under the new epoch; and the encrypted back-link decrypts to the previous sequence number and root.
- The backend then deletes the device's ORF server state.
- **[CB-11]** The rotation is **mandatory**: unlike Messenger, the client library always rotates when it revokes.

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

### 6.2 Virtual device bundle (p.32–34)

The bundle is AEAD-sealed under `vdeviceKey`. Each field uses the AAD strings from the paper:

| Field | AAD |
|---|---|
| `deviceKeyPriv` | `virtual_device:virtual_device_private_key` |
| `epochStorageKeyPriv` | `virtual_device:epoch_storage_private_key` |
| ORF client state | `virtual_device:ocmf_client_state` |
| `mailboxRootSalt` | `virtual_device:mailbox_root_key` |
| `epochRootKey` | `virtual_device:epoch_root_key` |
| `base64(seq)` | `virtual_device:epoch_anon_id` |

The bundle also publishes the device public record, the `evolveToken`, and the device MAC.

The bundle seals the epoch's sequence number but not its `epochID`, as in the paper. A restoring device looks the id up on the backend by sequence number (in the Space backend it is `space_epoch_id(seq)`).

### 6.3 Enrolling from a recovery code (p.35)

1. Fetch the bundle by `vdeviceId` and decrypt it.
2. Generate fresh device keys.
3. Evolve ORF.
4. Publish the MAC. We publish it in the newest epoch the device reaches by forward chaining with the virtual device (step 5), not in the bundle's epoch, so the new device is a member of the current epoch.
5. Back-chain through the `encPrevRoot` links, and forward-chain through the `encEntropy` addressed to the virtual device's storage key.
6. Delete the recovery code and all virtual-device secrets.

### 6.4 Recovery storage (p.43–46)

Each recovery mechanism gets its own virtual device. This crate provides helpers for two of them:
- **Passkey PRF.** `wrapKey = kdf(prf_output, MINOS_SALT, "catbird.labyrinth.passkey_wrap.v1")`, and the code is stored AEAD-sealed next to the bundle **[CB-13]**: `encrypt(wrapKey, "catbird.labyrinth.passkey_wrapped_code", code40)`, where `code40` is the canonical 40-character ASCII code.
- **Platform keychain.** The code is stored raw, for iCloud Keychain or Android Auto Backup.

A PIN vault (HSM or Juicebox) is out of scope for the first release.

**[CB-39] Recovery-method lifecycle** (decision J2 defaults, paper p.46). `Labyrinth::list_recovery_methods` lists every bundle with its mechanism, `createdAt`, `lastUsedAt` and expiry:
- `keychain` and `passkey` bundles, which a platform stores for the user, expire 180 days (`AUTO_RECOVERY_TTL_MS`) after `max(createdAt, lastUsedAt)`; `code` and `otc` bundles never expire.
- A restore touches its bundle (`touchVirtualDevice`, server clock) before writing anything; the app may also call `touch_recovery_method` when it confirms its keychain copy still exists.
- `remove_recovery_method` revokes the virtual device (a rotation without it, its ORF state deleted) and then deletes the bundle (`deleteVirtualDevice`); `remove_expired_recovery_methods` does this for every expired bundle by the client clock. mls-ds also expires them server-side.

### 6.5 One-time code (p.44–45)

- **CPace** runs over Ristretto255 / SHA-512, using the 6-digit code as the password **[CB-14]**:
  - we follow draft-irtf-cfrg-cpace-21, and `tests/vectors/cpace_ristretto255.json` holds its Appendix B.3 vectors;
  - PRS = the 6 ASCII digits;
  - session id = 16 random bytes from the requesting device;
  - CI = `"catbird.labyrinth.otc.v1" || did`;
  - the requesting (new) device is the initiator, and the ISK uses `transcript_ir`. ADa and ADb are optional caller data.
- `otc_secret` is the CPace ISK.
- The payload is `{tempOrfClientState, mailboxRootSalt, epochRootKey, epochID, epochSequenceID}`, sealed with `encrypt(kdf(ISK, MINOS_SALT, "catbird.labyrinth.otc.payload"), "otc_payload", …)`.
- **[CB-26] Payload encoding.** We use a fixed binary layout instead of CBOR, to avoid a CBOR dependency for one five-field struct. Integers are big-endian, and the decoder rejects trailing bytes:

```
0x01                     format version
tempOrfClientState (32)
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
  content = kind(1) || body        // 0x00 = message frame, 0x01 = delete-for-me tombstone (§7.5)
  encrypted = encrypt(messageKey, aad, pad(content))
  ```
  so `messageId` and `timestamp` are authenticated, and a tombstone is padded and stored like a message (the server cannot tell them apart).
- Readers also accept version 3 (the paper's writer) and, for completeness, the other key derivations from the paper's implementation notes (p.51–52), all with the paper's AAD:
  - version 0: `kdf(root, threadId, "message_key_in_epoch_" || seq)` (the salt is the thread id);
  - version 2: `kdf(root, threadId, "message_key_in_epoch_" || seq || "cipher_version_2")` (no underscore before `cipher`, as printed);
  - version 4: version 3 with `_cipher_version_4_thread_`.
  - Version 1 and anything above 4 are rejected.
- In versions 0–4 only `threadId`, `epochSequenceID` and `version` are authenticated (they feed the key or the AAD). `messageId` and `timestamp` are not, exactly as in the paper: a backend can swap them between such owner messages of the same thread and epoch. Version 5 and sender mode (§7.2) bind both. Version 1 and anything above 5 are rejected.

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

**[CB-15] (the hybrid storage choice).** The `signedEncMessage` bytes don't depend on the recipient. So we store each message **once per conversation**, in the sender's record set in the conversation's shared store, not once per recipient mailbox. Each recipient's mailbox holds only the MEK distributions. Readers check `sig` against the sender's chat device key, which they get from MLS.

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
- **[CB-21] Where MEKs live.** Under Spaces only the account owner can write its own repo. So the sender writes **one** `blue.catbird.labyrinth.mek` record per MEK into its own repo inside the conversation space, listing a ciphertext for every recipient. It does not write into each recipient's mailbox. Recipients read it with their conversation-space credential.
- **[CB-22] Leaving a conversation.** After removal, Spaces no longer lets the user read the conversation space. Before that happens, the client re-archives the history it can read into its own mailbox as owner messages (§7.1). The mls-ds backend instead authorizes reads per MEK distribution, so no re-archive is needed there.
- **The roster** is every Labyrinth-enrolled DID that is currently a member of the MLS group, the sender included **[CB-16]**.
  - Any roster change, such as an add, a remove, or a member opening a new epoch, invalidates the cached MEK.
  - That is what stops a removed member from reading anything new, and stops a new member from reading anything older than their join.
- **Reuse rule (p.38–39).** A sender reuses a cached MEK only if both hold (`Mek::reusable_for(currentHeads)`):
  1. its roster hash equals `rosterHash(currentHeads)`, the caller's view of every roster member's latest head;
  2. it is authenticated to some participant's latest epoch keys. A Labyrinth MEK is authenticated by the sender's epoch auth key, so rule 2 holds iff its `senderEpochHead` is in `currentHeads`. This applies equally to the device that distributed it and to a member who opened it.
  - **[CB-23]** A transport MEK is authenticated by no epoch key. Only the device that minted it may reuse it (under rule 1); members who opened it never reuse it and mint their own Labyrinth MEK instead. A freshly generated, undistributed MEK is never reusable.

### 7.4 Loading (p.41)

To read a message:
1. Find the MEK by `mekId` in the conversation's MEK records ([CB-21]) and open it under the mailbox encryption key of the epoch it was addressed to (§7.3).
2. Check the AAD fields against the record.
3. Verify `sig` and that the sender key is one of the sender's MLS devices: a current one, or one removed *after* the message's timestamp ([CB-27]). The same bound applies to the key that attests a MEK's sender epoch (or signs a transport MEK), at the timestamp of the first message that needed the MEK.
4. Decrypt the message and remove the padding.

**Lookups.** `load_message(thread, messageId)` returns every copy of one message (via `ThreadStore::get_messages` / `MailboxStore::get_owner_messages`; the defaults scan, an indexed backend overrides them). `load_thread_page(thread, before, limit)` returns the `limit` newest distinct `(timestamp, messageId)` positions older than the cursor, newest first, decrypting only those; all copies at one position stay on one page, and the next cursor is the oldest position returned (`"<ts>:<messageId>"`). It reads `list_batches_before` / `list_owner_batches_before`, whose contract lets a backend stop early only once the page is provably complete. `list_threads()` lists the threads this account has history in from its own records: MEKs it wrote or was addressed in, and its owner archive, so a restored device finds conversations it has left.

**Duplicates [CB-31].** A thread can hold several copies of one `messageId`: a sender copy, my owner-archive copy, or a different member reusing the id. Copies are merged only when they are provably the same message: sender copies on `(author DID, messageId)` with a byte-equal frame; an owner copy only when its frame is byte-equal to a loaded copy with that `messageId`. Every other copy is returned with `conflict = true`, so a member cannot suppress someone else's message by reusing its id. Re-archiving on leave ([CB-22]) keeps every distinct `(messageId, frame)`.

### 7.5 Deletion and edits [CB-38]

Decision J1 defaults (provisional; `src/deletion.rs`, `src/client/delete.rs`):

| Operation | Mechanism | Who sees what |
|---|---|---|
| **Delete for me** (`delete_for_me`) | an owner-mode v5 tombstone (§7.1, kind `0x01`) in the reader's own mailbox, with the target's `messageId` and `timestamp` and an optional author DID; the message's attachment references are deleted | every device of the account hides the message (`ThreadHistory::deleted_for_me`); other members and the server see nothing |
| **Unsend** (`unsend`) | the author's signed `redaction` replaces the item's `signedEncMessage` (now empty), keeping `messageId`/`timestamp`/`mekId`; `ThreadStore::redact_item`, mls-ds `redactMessage` | every reader gets `ThreadHistory::redacted`, with `by_author` true only if a chat key of the author signed `"catbird.labyrinth.redaction:did=" \|\| did \|\| ";message_id=" \|\| id \|\| ";thread_id=" \|\| hex(threadId)`; attachment fetches for it fail |
| **Account deletion, server side** (mls-ds `deleteAccountData`) | the server redacts every item the DID authored with an **unsigned** `redaction` (`redactedAt` only; no key, no signature), then purges the mailbox | readers get `RedactedMessage::account_deleted = true`: "deleted (account removed)", never an unsend (`by_author` is false) |
| **Account deletion** (`purge_account`) | redact every authored item in every thread, retract the epochs from every extra publisher, then `purge_mailbox` (devices, epochs, members, bundles, owner archive, ORF states, attachment refs, `mailboxKeys`) | others keep their history with the user's messages shown as removed |
| **Edit** | frame level: a new message referencing the old id in the chat frame schema | Labyrinth stores both; the client applies the edit. Erasing the old text is an unsend |

Each sealed item is signed on its own (`sig || ct`), so redacting one leaves the rest of its batch verifiable. `defs#redaction` therefore has no required fields: `transportPubkey` and `sig` are absent exactly for an account-deletion redaction, and one without the other is malformed. A missing reference, a wrong token and a redacted message all fail an attachment fetch with the same `NotFound`, so callers cannot probe which. Server backups keep deleted data for their retention window (Messenger caveat 3, p.49).

## 8. Attachments (p.41–43)

- **[CB-32] Cipher and transport.** Attachment bytes stay where Catbird chat already puts them: mls-ds blob storage, encrypted by chat with **AES-256-GCM** under a per-blob key carried in the message frame. The paper's `encrypt_attachment` (AES-256-CBC + PKCS7, p.11) is not used: GCM is authenticated and is what chat already ships. mls-ds streams the bytes (`getAttachmentBlob`) instead of handing out CDN URLs, so there is no URL TTL to manage; if presigned URLs are added later they get short TTLs.
- **[CB-33] Reference objects** (`src/attachment.rs`, `src/client/attach.rs`). Each mailbox holds one reference per attachment:
  ```
  input         = json(["<backupID>", "<objectID>"])      backupID = threadId, objectID = blobId
  blindedIndex  = orf_client_map(orfClientState, "attachment_key_scope", input)
  blindedSalt   = orf_client_map(orfClientState, "attachment_token_salt_scope", input)
  index         = orf_server_map(s, "catbird.labyrinth.orf.attachment_index", blindedIndex)    (server)
  tokenSalt     = orf_server_map(s, "catbird.labyrinth.orf.attachment_token", blindedSalt)     (server)
  tokenMac      = HMAC-SHA256(key = tokenSalt, json(["<threadId>", "<messageId>"]))           (server)
  ```
  `json` is compact JSON with standard escaping (the paper's literal concatenation for plain ids). The server stores `index → {blobId, tokenMac}` with the owner and message only as keyed digests. On `fetch_attachment` the client presents the blinded values plus `threadId`/`messageId`; the server recomputes the MAC and checks the message still exists unredacted where the caller can read it. Only a device holding the account's ORF client state can name a reference, and the token can be computed or checked only while such a device is asking (p.42). ORF evolution preserves both values across restored devices; revocation deletes the device's ORF state.
  - **One message per attachment object** (v1.1 content unlinkability): a second message for the same blob fails with `Conflict` (`AttachmentAlreadyReferenced`); a forwarded attachment is re-uploaded. The `messageId` of an attachment-bearing message is the chat message UUID, which mls-ds checks against the blob's binding.
  - `attach_reference` must follow the message's archive flush (the server checks the message exists). Delete-for-me deletes the account's references; unsend revokes access for everyone.
- ORF needs an active server, so the ORF **server** role always belongs to `mls-ds`, whichever backend holds the mailbox **[CB-17]**.

## 9. Storage backends

The protocol layers do no I/O. `src/records/` defines the record shapes, `src/store/` the storage traits, and `src/client/` a client built only on those traits.

### 9.1 Records

Every record is a `blue.catbird.labyrinth.*` lexicon in `lexicons/blue/catbird/labyrinth/`. The Rust types in `src/records/` serialize to the atproto JSON data model: camelCase fields, `$type` = the NSID, bytes as `{"$bytes": "<base64, no padding>"}`, datetimes in RFC 3339. Each converts losslessly to its protocol struct. `tests/lexicon_records.rs` validates every emitted record against the lexicon JSON (required fields, unknown fields, types, length limits, integer bounds, closed unions).

| Record | Space | rkey | Mutability |
|---|---|---|---|
| `device` | personal mailbox | `hex(deviceKeyPubkey)` | immutable except `revokedAt`, set once |
| `epoch` | personal mailbox | `epochID` = 12-digit zero-padded seq ([CB-9]) | immutable; created together with its initial `epochMember`s |
| `epochMember` | personal mailbox | `<12-digit seq>-<hex deviceKeyPubkey>` | immutable |
| `virtualDevice` | personal mailbox | `hex(vdeviceId)` | immutable |
| `ownerBatch` | personal mailbox | TID | append-only, one thread per batch |
| `mailboxKeys` | **public** repo | `self`, plus `<12-digit epochNumber>` per epoch | `self` is overwritten on each rotation; per-epoch copies are immutable ([CB-19], [CB-29]) |
| `mek` | conversation space, sender's repo | `hex(mekId)` | immutable ([CB-21]) |
| `batch` | conversation space, sender's repo | TID | append-only ([CB-15]) |

Every `epochNumber` is bounded at 2⁴⁰ (lexicon `maximum`, checked again when records convert to protocol structs), so store-supplied epoch numbers stay far from `u64` overflow.

`mek#labyrinthSender` embeds the sender's full `epochPublic`, because the public `mailboxKeys` record only shows a sender's *latest* epoch and readers need the auth key of the epoch that sealed an older MEK. The embedded copy is self-authenticating (head, self signature, [CB-18] attestation).

### 9.2 Store traits

- `MailboxStore`: the caller's own mailbox (devices, epochs, epoch members, virtual devices, owner batches) plus publishing `mailboxKeys`.
- `ThreadStore`: the conversation spaces. Writes go to the caller's repo; reads see every member's repo.
- `MailboxDirectory`: other accounts' latest `epochPublic`, every published `epochPublic` by number (`epoch(did, seq)`, [CB-29]), their MLS chat device keys, each with an optional `removed_at` ([CB-27]), and, where the backend has one, their device leaves in a conversation with the chat seqs that added and removed each (`member_device_keys`).
- `KeyPublisher`: another destination for a new epoch's public keys (the PDS `mailboxKeys` record, or the mls-ds head directory), so two independent directories stay current.
- `OrfServer`: the ORF server role ([CB-17]): register a device's state (fresh, or evolved from a parent with an evolve token), map, and delete on revocation, plus the attachment references (§8). The server computes every step.

Methods added on 2026-10-05, each with a default so a backend can lag: `ThreadStore::{redact_item, get_messages, list_batches_before, list_threads}`, `MailboxStore::{get_owner_messages, list_owner_batches_before, list_owner_threads, touch_virtual_device, delete_virtual_device, purge_mailbox}`, `KeyPublisher::retract`, `OrfServer::{put_attachment_ref, fetch_attachment, delete_attachment_ref}`. The lookups default to scans of the existing listings (correct on every backend); the others default to `Error::NotSupported` until the mls-ds endpoints and their XRPC wrappers exist. The memory backend implements all of them, and `MemoryXrpcServer` serves the agreed shapes (`src/store/xrpc/server/lookup.rs`).

A record read back is a `Stored<T>` with an optional `ServerOrder {labyrinth_seq, chat_seq, received_at_ms}`: mls-ds stamps every MEK, batch and owner batch when it is written; a Space assigns none.

The traits are **synchronous** and return `Result`, so the crate needs no async runtime. A handle is bound to one authenticated DID. Every backend must provide:

- **Create-if-absent.** `create_*` on an existing rkey fails with `Error::Conflict`. Space writes have no `swapRecord`; instead `#create` on an existing rkey fails with `RecordAlreadyExists` (reference `actor-store/space/transactor.ts`), and epoch rkeys are the zero-padded sequence number, so creating an epoch is the race guard between devices.
- **Atomic epoch creation.** `create_epoch(epoch, members)` writes the epoch and its initial members in one `applyWrites`.
- **Immutability** as in the table above.
- `Error::Forbidden` when a space refuses reads (e.g. after removal, [CB-22]); `Error::Backend` for I/O failures.

| Backend | Where | Writes | Reads | Race guard |
|---|---|---|---|---|
| **atproto Space** | Mailbox: a personal Space on the user's PDS, `spaceType = blue.catbird.labyrinth.mailbox`, authority = the user's DID. Sender records: a conversation Space whose authority is mls-ds's service DID; each sender writes into their own repo | OAuth `com.atproto.space.applyWrites` | the owner uses `read_self`; other members use space credentials | create-if-absent on the epoch rkey. The mailbox client store is built (`store::space::SpaceMailboxStore`, feature `space`, over an app-supplied `XrpcTransport` to the user's PDS; Space ref `at://<did>/space/blue.catbird.labyrinth.mailbox/self`); the conversation-Space thread store is not |
| **mls-ds** | `blue.catbird.labyrinth.*` XRPC endpoints on the delivery service (`docs/MLSDS_BACKEND.md`; lexicons in `lexicons/blue/catbird/labyrinth/`). The client stores are built (`store::xrpc`, feature `xrpc`, over an app-supplied `XrpcTransport`); the server side is not | service auth plus a signed `labyrinthWriteBody` from a current chat device | owner-only for the mailbox; per MEK for threads (the caller wrote or received the MEK) | row uniqueness; `operationId` replay |
| **memory** (`store::memory`) | tests; one value plays every server, including the mls-ds head directory, ORF server and (with `enable_server_order`) stamps and leaf view; `store::xrpc::server::MemoryXrpcServer` serves it over the XRPC endpoints | per-DID handles | no read ACL unless a space revokes a member | create-if-absent |

**[CB-20] Batching.** Messages are batched, up to 256 per `batch`/`ownerBatch` record, and a client flushes earlier if a batch would exceed about 900 KB of JSON, or when the next message is sealed under a different MEK: every sender batch holds a single `mekId` (design Y4), so mls-ds can authorize reads per MEK. This keeps us within the reference PDS's per-account write budget (about 1.7k creates/hour), the 1 MB write cap, and the current ~60k-record export ceiling. A MEK record lists at most 512 recipients for the same reason.

### 9.3 Client

`client::Labyrinth` is one enrolled device. It holds the device secrets, the epoch-secret cache, its revoked-device set, its peer pins ([CB-29]) and its MEK cache.

- **Persistence [CB-30]:** `export_state()` returns a versioned binary encoding of all of that (magic `LBYS`, version 2 (adds the [CB-25] verified-member set; version 1 still loads), big-endian, length-prefixed; layout in `src/client/state.rs`) in a buffer that zeroizes on drop; `from_state(bytes, did, transport, backends)` rebuilds the client after checking the DID, the transport key, the device secrets against their public record and the newest epoch against the store. **The bytes are secret**: the embedding app stores them only in the platform keychain or SQLCipher. Unflushed batches are not included; flush first.
- **Lifecycle:** `initialize` (epoch 0, device, `mailboxKeys`), `sync_epochs` (forward-chain into epochs opened by sibling devices, then the [CB-28] integrity check, and report re-admitted revoked devices), `revoke_device` (add to the local revoked set, mark revoked, open the next epoch without any locally revoked device, publish `mailboxKeys`; retries on `Conflict`).
- **Enrollment:** `create_recovery_code`, `create_passkey_recovery`, `restore_with_recovery_code` (typo correction, forward-chaining with the virtual device, integrity check, then enrollment in the newest epoch), `restore_with_passkey`, and one-time codes (`otc_offer`/`otc_respond` on the existing device, `otc_start`/`enroll_via_otc` on the new one).
- **Backends:** `mailbox`, `threads`, `directory`, `orf`, `publishers` and `clock`. In production `directory` is a `client::CompositeDirectory` over the PDS `mailboxKeys` records and the mls-ds head chain: equal heads pass, a newer head passes only through a verified `prev_sig` chain from the older one, and anything else fails with `DirectoryFork`. Every new epoch goes to the mailbox and to each publisher. The client registers each new device's ORF state (genesis; recovery bundle and restore, evolved from the parent; a one-time code's temporary state under an id both devices derive from the CPace key) and deletes a revoked device's state before rotating.
- **Sending:** `resolve_roster` and `archive_outgoing` check every recipient epoch against the DID's current chat devices ([CB-18]) and its pin ([CB-29]), reuse a cached MEK under the reuse rules or distribute a new one, and buffer the sealed message; `flush` writes batches.
- **History management:** `delete_for_me`, `unsend`, `purge_account` (§7.5); `load_message`, `load_thread_page`, `list_threads` (§7.4); `attach_reference`, `fetch_attachment`, `delete_attachment_reference` (§8); `list_recovery_methods`, `touch_recovery_method`, `remove_recovery_method`, `remove_expired_recovery_methods` (§6.4); `audit_members` (§5.6); `own_fingerprint`, `safety_number_with` (§5.3); `publish_latest_keys` retries a publish that failed after its epoch was created.
- **Reading:** a chat key vouches for a message or MEK only if it was valid when the record was written ([CB-27]): by the record's `ServerOrder` when it has one (received before the key's account-wide revocation, and, where the directory reports the conversation's leaves, while the device had a leaf at the stamp's `chat_seq`), else by the sender's timestamp. `load_thread` opens sender batches through any MEK addressed to any of the caller's epochs (backward-chaining as needed) plus owner batches, merges only provably identical copies (§7.4), and reports what it could not open (for example `NotRecipient` before a join or after a leave). `archive_owner` writes v1.0 owner messages; `rearchive_thread_before_leave` implements [CB-22].

## 10. Known limitations we keep from the paper (p.47)

- **Epoch truncation by a malicious backend.**
  - Mitigation **[CB-28]**: a device compares the newest epoch it reached (on sync, restore and one-time-code enrollment) with the latest epoch the `MailboxDirectory` publishes for its own DID, and fails with `EpochTruncated` if the directory is ahead or its head forks. With a `CompositeDirectory` the comparison is against the newest head either the PDS or mls-ds knows, and the client publishes every epoch to both. For a Space mailbox mls-ds is the independent source; for an mls-ds mailbox the PDS `mailboxKeys` record is, so the client must keep publishing it. Truncation now needs the mailbox host and the other directory to collude.
- **First contact** ([CB-29]): with a `CompositeDirectory`, a sender's first view of a DID is the head the PDS and mls-ds agree on (or one extends the other along a verified chain); mls-ds accepts heads only as an append-only chain attested by a current chat device. A replay now needs mls-ds and the peer's PDS to collude. With a single directory it stays trust-on-first-use. Pins protect every later send. Carrying heads in MLS-authenticated group state remains the long-term fix.
- **Removed chat keys and timestamps** ([CB-27]): with mls-ds the bound uses server order, so a removed device cannot backdate. Readers trust mls-ds's stamps, as they already trust it to sequence MLS. Two gaps remain: under federation an account revocation and a receipt can come from two DSes' clocks (leaf removal by `chat_seq` has no clock problem), and records in a Space carry no server order, so there the bound still uses the sender's timestamp and a removed device can backdate.
- **Membership enumeration.**
- **Only partial post-quantum security.** Entropy distribution stays classical X25519, as in the paper.

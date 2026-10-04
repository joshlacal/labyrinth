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
- A mailbox created by this crate always has a head from epoch 0 on. We have no v1.0 mailboxes to upgrade.
- **[CB-18] Transport attestation.** The device that opens an epoch also signs the head with its chat transport key (Ed25519):
  - `attestation = Ed25519(transportKey, "catbird.labyrinth.epoch_head_attest:" || did || ":" || epochHead)`.
  - A sender accepts a recipient's head only if the attesting key belongs to one of that DID's devices in the MLS group.
  - This anchors the head chain to MLS identity, so neither a storage backend nor mls-ds can substitute mailbox keys.
- **[CB-19] Discovery.** The latest `epochPublic` is published as `blue.catbird.labyrinth.mailboxKeys/self` in the account's **public** repo, so any PDS works.
  - Cost: it shows publicly that the account uses Labyrinth, and when it rotates epochs.

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
- **[CB-25] Rotation rules.**
  - The opener carries itself over and encrypts the entropy to its own storage key too, so any install holding its keys can forward-chain.
  - A device listed as continuing whose previous-epoch MAC or `sig_0x30`/`sig_0x31` fails aborts the rotation with an error. It is never dropped silently, because a silent drop would be an unannounced revocation.
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

### 7.1 Owner upload (v1.0 mode, cipher version 3; p.37–38)

```
messageKey = kdf(root, null, "message_key_in_epoch_" || seq || "_cipher_version_3_thread_" || threadId)
encrypted  = encrypt(messageKey, "message_thread_" || threadId, pad(messageData))
```

Stored record: `(threadId, messageId, timestamp, epochSequenceID, version = 3, encrypted)`.

- We write only version 3. For completeness we also **decrypt** the other key derivations from the paper's implementation notes (p.51–52), all with the same AAD:
  - version 0: `kdf(root, threadId, "message_key_in_epoch_" || seq)` (the salt is the thread id);
  - version 2: `kdf(root, threadId, "message_key_in_epoch_" || seq || "cipher_version_2")` (no underscore before `cipher`, as printed);
  - version 4: version 3 with `_cipher_version_4_thread_`.
  - Version 1 and anything above 4 are rejected.
- Only `threadId`, `epochSequenceID` and `version` are authenticated (they feed the key or the AAD). `messageId` and `timestamp` are not, exactly as in the paper: a backend can swap them between owner messages of the same thread and epoch. Sender mode (§7.2) binds both.

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
3. Verify `sig` and that the sender key is one of the sender's MLS devices.
4. Decrypt the message and remove the padding.

## 8. Attachments (p.41–43)

- Attachment bytes stay where Catbird chat already puts them: `mls-ds` blob storage, already encrypted per message.
- Each mailbox gets a reference object per attachment, indexed by `orf_client_map(orfClientState, "attachment_key_scope", json([backupID, objectID]))`.
- The object carries an access token: `orf_client_map(…, "attachment_token_salt_scope", …)`, MAC'd over the thread and message.
- ORF needs an active server, so the ORF **server** role always belongs to `mls-ds`, whichever backend holds the mailbox **[CB-17]**.

## 9. Storage backends

The protocol core does no I/O. It defines `MetaStore` (devices, epochs, virtual devices, MEK distributions) and `MailboxStore` (owner records and the shared sender records), with compare-and-swap on the mailbox head.

| Backend | Where | Writes | Reads | CAS |
|---|---|---|---|---|
| **atproto Space** | Mailbox: a personal Space on the user's PDS, `spaceType = blue.catbird.labyrinth.mailbox`, authority = the user's DID. Sender records: a conversation Space whose authority is mls-ds's service DID; each sender writes into their own repo | OAuth `com.atproto.space.applyWrites` | the owner uses `read_self`; other members use space credentials | Space writes have no `swapRecord`. Instead, `#create` on an existing rkey fails with `RecordAlreadyExists` (reference `actor-store/space/transactor.ts:202`), and epoch rkeys are the zero-padded sequence number, so a create-if-absent on rkey acts as the guard |
| **mls-ds** | `blue.catbird.labyrinth.*` XRPC procedures on the delivery service | DPoP-authenticated chat device | same | row version |
| **memory** | tests | – | – | – |

**[CB-20] Batching.** Messages are batched, up to 256 per `batch`/`ownerBatch` record. This keeps us within the reference PDS's per-account write budget (about 1.7k creates/hour), the 1 MB write cap, and the current ~60k-record export ceiling.

The record lexicons are in `lexicons/blue/catbird/labyrinth/`. They are drafts until the Spaces GA in mid-November 2026.

## 10. Known limitations we keep from the paper (p.47)

- **Epoch truncation by a malicious backend.**
  - Planned mitigation: `mls-ds` publishes each member's latest epoch head in the MLS roster view, so a restoring device can check that it reached it.
- **Membership enumeration.**
- **Only partial post-quantum security.** Entropy distribution stays classical X25519, as in the paper.

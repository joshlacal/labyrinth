# Messages, MEKs and the archive

## Two ways to store a message

Labyrinth stores history in two modes (SPEC §7).

**Sender mode (normal).** While an account is a member of a conversation, it archives the messages it sends into its own repo in the conversation's Space. Each message is encrypted once, under a key derived from a **message encryption key (MEK)**, and signed with the sender's chat-device key. The MEK itself is encrypted to every recipient account's current mailbox key and stored once, next to the messages, in the sender's repo ([CB-15], [CB-21]). Storing each message once per conversation, instead of once per recipient, is Catbird's main departure from Messenger.

**Owner mode (fallback).** When an account can no longer write to the conversation Space, because it left or was removed, it re-encrypts the history it holds into its **own personal mailbox** under a per-epoch, per-thread key (§7.1). Only that account can read these copies.

## MEKs and rosters

A MEK is a random 32-byte key with an ID derived from the hash of its **roster**, the set of recipient epoch heads (§7.3). The roster is every Labyrinth-enrolled account that is currently in the MLS group, the sender included ([CB-16]).

- **Any roster change invalidates the cached MEK.** When someone is added or removed, or a member rotates epochs, the next message gets a new MEK. This is what stops a removed member from reading anything new, and a new member from reading anything archived before it joined.
- Each recipient's copy is Hawk-HPKE-encrypted with an AAD that binds the MEK ID, the roster hash, both parties' epoch heads and the thread ID. The thread binding ([CB-24]) stops a backend from moving a MEK into another conversation.
- Only the account that minted a MEK reuses it ([CB-42]). A device that is not yet enrolled can still distribute a *transport MEK*, authenticated by its chat key; only that device may reuse it ([CB-23]).

## Committed frames and sequencer receipts (`I13`)

What gets archived is the canonical chat frame (`MLSMessagePayload` JSON) together with a random 32-byte `frameNonce`. When the message is sent, the MLS AAD and the sequencer's receipt bind `archiveCommitment = HMAC-SHA256(frameNonce, frame)`. The nonce only ever travels inside encrypted payloads, so the commitment reveals nothing about the frame.

Every archived message carries two pieces of evidence:

- the **sequencer receipt**: an ES256 signature from the conversation's sequencer over the conversation, group, epoch, sender device, entry ID, archive commitment, sequence number and time. It names its exact verification method, `{sequencerDid}#mls-receipt-N`. It provides **order**, not sender identity;
- the **original-sender attestation**: the sender device's Ed25519 signature over the thread ID, message ID and archive commitment. It provides **identity**.

The first valid receipt for a conversation durably switches it to *receipts required*. Retired receipt keys are kept by key ID, and a key ID can never be reused with different bytes, so removing a key from the sequencer's DID document never lets receiptless history back in.

## Witness copies

A member that received and verified another member's message may store a **witness copy** of the same frame, nonce, receipt and attestation in its own repo. That way history survives a sender who is removed before its device flushes its archive. A witness authenticates only *that it stored the copy*; original identity still comes from the sender's attestation. Copies merge only when every piece of evidence is byte-equal. A contradicting witness or a reused receipt goes to `ThreadHistory::rejected` and is never shown ([SPACE_CONVERSATIONS.md](../reference/SPACE_CONVERSATIONS.md)).

## Reading history

To read a committed message (SPEC §7.4), a client:

1. finds the MEK by its ID and opens it under the mailbox key of the epoch it was addressed to;
2. checks the AAD fields against the record;
3. verifies the sequencer receipt under the exact retained key it names;
4. verifies the original-sender attestation, and that the sender's device key and conversation leaf were active at the receipt's position;
5. opens the ciphertext, checks the archive commitment and removes the padding.

`load_thread_page` returns history newest-first, one page at a time; each message appears on exactly one page with all its accepted copies.

## Leaving and removal

- **Voluntary leave.** Before leaving, the client re-archives every copy it can read into owner batches in its personal mailbox, and copies its attachment manifests there. It deletes nothing from the conversation Space, because its records may be the only copy the remaining members have ([CB-22]).
- **Removal.** When the Space starts refusing the account (`Forbidden`), queued and locally cached messages fall back to owner batches before local conversation state is deleted. Only a real `Forbidden`, or a locally authenticated removal (a verified MLS Commit removed this device), sends a client to the owner fallback; a missing Space is an error, never a fallback.

## Attachments

Attachment bytes are encrypted on the device with AES-256-GCM under a per-blob random key, which travels inside the encrypted message. The ciphertext (up to 128 MiB) is uploaded as a blob to the sender's PDS and recorded with a `blue.catbird.labyrinth.attachmentManifest` that holds its size and SHA-256. A downloader checks both, in constant time, before decrypting (§8).

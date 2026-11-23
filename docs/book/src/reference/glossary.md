# Glossary

**Account.** One AT Protocol identity (a DID). It may have several devices.

**Archive commitment.** `HMAC-SHA256(frameNonce, frame)`, carried in the MLS AAD and the sequencer receipt, binding an archived frame to the message that was sent without revealing it.

**Attestation.** A chat device's Ed25519 signature over an epoch head ([CB-18]) or an archived message (the *original-sender attestation*).

**Batch.** A record holding one or more encrypted messages in a conversation Space.

**Chat device / transport key.** An install's MLS identity, registered with mls-ds. Its Ed25519 key is the *transport key* Labyrinth signs with.

**`CompositeDirectory`.** The directory that requires the public PDS and mls-ds to agree on every epoch head.

**Conversation Space.** The AT Protocol Space holding a conversation's archive, one per conversation generation. Each member writes to its own repo in it.

**DNDK-GCM.** AES-256-DNDK-GCM: AES-GCM with a derived nonce and derived key, giving a 24-byte nonce and key commitment. Suite byte `0x02`.

**Epoch.** An account-wide key generation, opened on enrollment, rotation, revocation or restore.

**Epoch head.** A 32-byte commitment to an epoch's public keys, number, previous head and member set.

**Hawk HPKE.** The hybrid key encapsulation used for every secret-bearing step: X25519 combined with ML-KEM-768.

**`I13` / sequencer receipt.** The sequencer's ES256 signature ordering one MLS entry and binding its archive commitment.

**Mailbox / personal mailbox Space.** The account's private Space, holding its devices, epochs, recovery bundles and owner archive.

**MEK.** Message encryption key: a random key, scoped to one conversation and roster, from which per-message keys are derived.

**mls-ds.** Catbird's MLS delivery service. For Labyrinth: a directory and sequencer.

**Owner batch / owner mode.** History an account re-encrypts into its own mailbox after it can no longer write to a conversation Space.

**Pin.** A device's record of the newest epoch head it has accepted for a peer.

**Roster.** The set of recipient epoch heads a MEK is addressed to.

**Sequencer.** The delivery service that created a conversation; it assigns sequence numbers and signs receipts.

**Space.** AT Protocol permissioned data: records readable only by a Space's members, hosted by an authority. Spaces are a proposal that has not reached general availability.

**Virtual device.** A recovery method, modelled as an epoch member whose keys are sealed in a bundle.

**Witness copy.** Another member's stored copy of a message it received and verified.

**[CB-n].** A numbered Catbird profile decision in the [protocol profile](SPEC.md).

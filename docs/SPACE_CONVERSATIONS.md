# Sequenced conversation history in Spaces

Labyrinth encrypts chat history before storage. `SequencedSpaceThreadStore` writes each ciphertext batch once in its sender's repository and asks the delivery service to admit an immutable reference. The delivery service still enforces current MLS membership and assigns sequence and receive time. This prevents a removed device from using a sender-selected timestamp to invent earlier authority.

The October 23 integration extends the earlier personal-mailbox Space backend. The governing choices are recorded in [DECISIONS.md](DECISIONS.md); the existing delivery-service contract remains described in [MLSDS_BACKEND.md](MLSDS_BACKEND.md).

## Storage and identity

`getThreadStorage` returns a durable placement, an immutable UUID generation, and a Space URI for a Space placement. The URI uses type `blue.catbird.labyrinth.conversation` and its key equals that generation. An encrypted account-isolated `ThreadPlacementPins` adapter must reject any later replacement of the placement. A legacy conversation continues using `XrpcThreadStore`; an explicitly selected Space never falls back after an outage or missing platform capability.

On append, the store serializes the batch as canonical DAG-CBOR with native byte strings and computes its CID. It creates an owner-OAuth record whose key is the SHA-256 of that CID string. A lost acknowledgement is retried at the same key; an existing record must match the computed CID. `appendSpaceBatch` then sends the typed record and reference for admission. The service validates it but stores only reference metadata and tombstones for a Space placement. MEK distribution remains on the delivery service.

On read, `listSpaceBatches` supplies references and server order. The platform Space adapter must authenticate foreign `getRecord` responses through the October 22 credential, fresh KEM and MAC protocol. This crate additionally checks exact URI, repository, generation, CID, thread and item count before attaching server order. Owner OAuth reads do not need a foreign-access MAC. A raw record listing never becomes authoritative conversation history.

## Deletion and retry

Partial redactions are applied only after the original record verifies. Once every original item has a distinct authenticated tombstone, the service metadata can render a tombstone-only batch even after its owner physically purges the source record. That path never fabricates ciphertext or claims to have verified a now-absent CID.

Account cleanup inventories owner `listSpaces` for conversation Spaces, including records written by other devices and conversations already left, then deletes only the signed-in account's batch records. The app must save placement, pinned targets and required inventory cleanup in a durable deletion journal before erasing local state. An unreachable required host leaves cleanup pending. Cleanup neither deletes foreign records nor deletes the authority's shared Space.

## Verification boundaries

The focused tests cover lost sequence acknowledgement, immutable generation pins, changed-record rejection, missing source/order, partial and full tombstones, owner-only purge and unavailable platform transport. A deterministic CID fixture was cross-checked against an independently implemented canonical-CBOR encoder. These checks establish local protocol behavior, not real OAuth, cross-host identity, production deployment or native device behavior.

`MemorySpaceHost` models owner repository operations and canonical batch CIDs; it does not model credentials or MACs. The normal test run explicitly ignores the live PDS lifecycle test. Running that test with `--ignored` requires a provisioned session and fails if the session is missing.

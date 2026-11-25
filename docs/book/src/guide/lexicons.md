# Lexicons and records

Labyrinth's records are defined as AT Protocol lexicons under `lexicons/blue/catbird/labyrinth/`. They are drafts and may change before release. `tests/lexicon_records.rs` validates every record the crate writes against them.

## Spaces

| Lexicon | Space |
|---|---|
| `blue.catbird.labyrinth.mailbox` | The personal mailbox Space type: `at:space/<did>/blue.catbird.labyrinth.mailbox/self` |
| `blue.catbird.labyrinth.conversation` | The conversation Space type: one per conversation generation, under the sequencer's DID |
| `blue.catbird.labyrinth.conversationPolicy` | The policy object a conversation Space carries |

## Records

| Record | Where it lives | What it holds |
|---|---|---|
| `device` | Personal mailbox | A Labyrinth device's public keys and its chat binding |
| `epoch` | Personal mailbox, 12-digit record key | One epoch's public keys, head signatures and the encrypted previous root |
| `epochMember` | Personal mailbox | One device's encrypted share of an epoch's entropy |
| `virtualDevice` | Personal mailbox | A recovery bundle: mechanism, encrypted keys and epoch root |
| `otcSession` | Personal mailbox | A one-time-code enrollment exchange in progress |
| `ownerBatch` | Personal mailbox | Owner-mode archive copies, after leaving or removal |
| `readState` | Personal mailbox, record key = conversation ID | Encrypted read position |
| `circleOwnerState` | Personal mailbox | Encrypted owner state for Catbird circles |
| `mailboxKeys` | **Public** repo | The account's current epoch head, for the directory |
| `mek` | Conversation Space, sender's repo | A MEK encrypted to each recipient's mailbox key |
| `batch` | Conversation Space, sender's repo | Encrypted sender and witness copies of messages |
| `authorRedaction` | Conversation Space, author's repo | A signed unsend |
| `attachmentManifest` | Conversation Space, sender's repo | Size and SHA-256 of an encrypted attachment blob |

[What the hosts can see](../overview/security-model.md#what-the-hosts-can-see) lists which fields of these records are plaintext.

## XRPC methods

mls-ds serves only the six directory methods (`publishEpochHead`, `getEpochHead`, `getChatDeviceKeys`, `getMemberDevices`, `purgeMailbox`, `deleteAccountData`) and `getMailboxKeysRecord` from this directory, as described in [the mls-ds contract](../reference/MLSDS_BACKEND.md). Its recovery-share methods are defined in the mls-ds repository.

The directory also still holds lexicons for **retired** endpoints from the design in which mls-ds stored archive content (`appendBatch`, `createEpoch`, `getMessages`, `listSpaceBatches` and others). No server implements them. Archive reads and writes go through `com.atproto.space.*` on the account's PDS and the conversation Space host.

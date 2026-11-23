# Deletion

Deletion in Labyrinth is **cooperative**: honest clients hide what they're told to hide, but ciphertext that other members stored in their own repos, and copies in host backups, are not erased. The mechanisms are in SPEC §7.5 ([CB-38]).

| Operation | How it works | Who sees what |
|---|---|---|
| **Delete for me** | An encrypted owner tombstone in the account's personal mailbox | Every device of this account hides the message. Other members are unaffected. |
| **Unsend** | An immutable, author-signed `blue.catbird.labyrinth.authorRedaction` record in the author's repo in the conversation Space. The original batch is never rewritten. | Readers hide every sender, witness and owner copy with the same authenticated original sender and message ID. That a message was unsent is visible to members and the host; its content stays encrypted. |
| **Account deletion (others' view)** | When an account deletes its chat identity, the sequencer records a signed `accountDeletedEntry` in each affected conversation | Readers verify it and hide every copy attributed to that account unless its receipt orders it after the deletion. A copy without a receipt is hidden. |
| **Account deletion (own data)** | `purge_account` deletes the account's own conversation records (keeping the redaction evidence peers need), retracts its directory heads, and purges its personal mailbox | Local state and the personal mailbox are wiped. |
| **Edit** | A new message that references the old one in the chat frame | Both versions are stored; the client shows the edit. |

Data deleted from a Space may survive in that host's backups for their retention period.

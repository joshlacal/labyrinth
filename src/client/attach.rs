//! Attachment references from the client side (SPEC §8, [CB-32], [CB-33];
//! the derivations are in [`crate::attachment`]).

use super::Labyrinth;
use crate::Result;
use crate::attachment::blind;
use crate::store::{AttachmentFetch, AttachmentPut};

impl Labyrinth {
    /// Record in this account's mailbox that message `message_id` of
    /// `thread_id` carries chat blob `blob_id`, so any device of the
    /// account (including one restored later) can fetch it.
    ///
    /// Call it after the message is archived and flushed: the server
    /// checks the message exists where this account can read it. One
    /// attachment object belongs to one message: re-upload a forwarded
    /// attachment as a new blob, or the server answers
    /// [`crate::Error::Conflict`]. `message_id` is the chat message UUID
    /// the blob is bound to.
    pub fn attach_reference(&self, thread_id: &str, message_id: &str, blob_id: &str) -> Result<()> {
        let (blinded_index, blinded_token_salt) = blind(&self.device.orf, thread_id, blob_id);
        self.b.orf.put_attachment_ref(
            &self.device.public().device_key_pub,
            &AttachmentPut {
                blinded_index,
                blinded_token_salt,
                blob_id: blob_id.to_owned(),
                thread_id: thread_id.to_owned(),
                message_id: message_id.to_owned(),
            },
        )
    }

    /// The blob ciphertext of `blob_id` in `message_id`. Decrypting it is
    /// chat's job (AES-256-GCM under the key in the message frame,
    /// [CB-32]). Fails once the message is unsent, the reference deleted
    /// (delete-for-me), or this device revoked (its ORF state is gone).
    pub fn fetch_attachment(
        &self,
        thread_id: &str,
        message_id: &str,
        blob_id: &str,
    ) -> Result<Vec<u8>> {
        let (blinded_index, blinded_token_salt) = blind(&self.device.orf, thread_id, blob_id);
        self.b.orf.fetch_attachment(
            &self.device.public().device_key_pub,
            &AttachmentFetch {
                blinded_index,
                blinded_token_salt,
                thread_id: thread_id.to_owned(),
                message_id: message_id.to_owned(),
            },
        )
    }

    /// Delete this account's reference to `blob_id` in `thread_id`.
    pub fn delete_attachment_reference(&self, thread_id: &str, blob_id: &str) -> Result<()> {
        let (blinded_index, _) = blind(&self.device.orf, thread_id, blob_id);
        self.b
            .orf
            .delete_attachment_ref(&self.device.public().device_key_pub, &blinded_index)
    }
}

use crate::base32;

#[cfg(feature = "key")]
mod blob;
#[cfg(feature = "key")]
mod node;
#[cfg(feature = "key")]
pub use self::{blob::BlobTicket, node::NodeTicket};

/// A ticket is a serializable object that combines all information required
/// for an operation. E.g. an iroh blob ticket would contain the hash of the
/// data as well as information about how to reach the provider.
///
/// Tickets support serialization to a string using base32 encoding. The kind of
/// ticket will be prepended to the string to make it somewhat self describing.
///
/// Versioning is left to the implementer. Some kinds of tickets might need
/// versioning, others might not.
///
/// The serialization format for converting the ticket from and to bytes is left
/// to the implementer. We recommend using [postcard] for serialization.
///
/// [postcard]: https://docs.rs/postcard/latest/postcard/
pub trait Ticket: Sized {
    /// String prefix describing the kind of iroh ticket.
    ///
    /// This should be lower case ascii characters.
    const KIND: &'static str;

    /// Serialize to bytes used in the base32 string representation.
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize from the base32 string representation bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;

    /// Serialize to string.
    fn serialize(&self) -> String {
        let mut out = Self::KIND.to_string();
        base32::fmt_append(&self.to_bytes(), &mut out);
        out
    }

    /// Deserialize from a string.
    fn deserialize(str: &str) -> Result<Self, Error> {
        let expected = Self::KIND;
        let Some(rest) = str.strip_prefix(expected) else {
            return Err(Error::Kind { expected });
        };
        let bytes = base32::parse_vec(rest)?;
        let ticket = Self::from_bytes(&bytes)?;
        Ok(ticket)
    }
}

/// An error deserializing an iroh ticket.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Found a ticket of with the wrong prefix, indicating the wrong kind.
    #[error("wrong prefix, expected {expected}")]
    Kind { expected: &'static str },
    /// This looks like a ticket, but postcard deserialization failed.
    #[error("deserialization failed: {_0}")]
    Postcard(#[from] postcard::Error),
    /// This looks like a ticket, but base32 decoding failed.
    #[error("decoding failed: {_0}")]
    Encoding(#[from] base32::DecodeError),
    /// Verification of the deserialized bytes failed.
    #[error("verification failed: {_0}")]
    Verify(&'static str),
}

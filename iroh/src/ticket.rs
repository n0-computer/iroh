//! This module manages the different tickets Iroh has.

pub mod blob;
pub mod doc;

/// Kind of ticket.
#[derive(Debug, strum::EnumString, strum::Display, PartialEq, Eq, Clone, Copy)]
#[strum(serialize_all = "snake_case")]
pub enum Kind {
    /// A blob ticket.
    Blob,
    /// A document ticket.
    Doc,
    /// A ticket for an Iroh node.
    Node,
}

/// An error deserializing an [`IrohTicket`].
#[derive(Debug, derive_more::Display, thiserror::Error)]
pub enum Error {
    /// Found a ticket of the wrong [`Kind`].
    #[display("expected a {expected} ticket but found {found}")]
    WrongKind {
        /// Expected [`Kind`] of ticket.
        expected: Kind,
        /// Found [`Kind`] of ticket.
        found: Kind,
    },
    /// It appears to be a ticket but the prefix is not a known one.
    #[display("unrecogized ticket prefix")]
    UnrecognizedKind(#[from] strum::ParseError),
    /// This does not appear to be a ticket.
    #[display("not a {expected} ticket")]
    MissingKind {
        /// Prefix that is missing.
        expected: Kind,
    },
    /// This looks like a ticket, but postcard deserialization failed.
    #[display("deserialization failed: {_0}")]
    Postcard(#[from] postcard::Error),
    /// This looks like a ticket, but basse32 decoding failed.
    #[display("decoding failed: {_0}")]
    Encoding(#[from] data_encoding::DecodeError),
}

trait IrohTicket: serde::Serialize + for<'de> serde::Deserialize<'de> {
    /// Kinf of Iroh ticket.
    const KIND: Kind;

    /// Serialize to postcard bytes.
    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("postcard::to_stdvec is infallible")
    }

    /// Deserialize from postcard bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    /// Serialize to string.
    fn serialize(&self) -> String {
        let mut out = Self::KIND.to_string();
        out.push(':');
        let bytes = self.to_bytes();
        data_encoding::BASE32_NOPAD.encode_append(&bytes, &mut out);
        out
    }

    /// Deserialize from a string.
    fn deserialize(str: &str) -> Result<Self, Error> {
        let expected = Self::KIND;
        let (prefix, bytes) = str.split_once(':').ok_or(Error::MissingKind { expected })?;
        let found: Kind = prefix.parse()?;
        if expected != found {
            return Err(Error::WrongKind { expected, found });
        }
        let bytes = data_encoding::BASE32_NOPAD.decode(bytes.as_bytes())?;
        let ticket = Self::from_bytes(&bytes)?;
        Ok(ticket)
    }
}

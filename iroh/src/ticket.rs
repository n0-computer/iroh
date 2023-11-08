//! This module manages the different tickets Iroh has.

use iroh_base::base32;
use strum::{AsRefStr, Display, EnumIter, IntoEnumIterator};

pub mod blob;
pub mod doc;

/// Kind of ticket.
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy, EnumIter, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum Kind {
    /// A blob ticket.
    Blob,
    /// A document ticket.
    Doc,
    /// A ticket for an Iroh node.
    Node,
}

impl Kind {
    /// Parse the ticket prefix to obtain the [`Kind`] and remainig string.
    pub fn parse_prefix(s: &str) -> Result<(Self, &str), Error> {
        // we don't know the kind of ticket so try them all
        for kind in Kind::iter() {
            if let Some(rest) = s.strip_prefix(kind.as_ref()) {
                return Ok((kind, rest));
            }
        }
        Err(Error::MissingKind)
    }
}

/// An error deserializing an iroh ticket.
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
    /// This does not appear to be a ticket.
    #[display("not a ticket: prefix missing")]
    MissingKind,
    /// This looks like a ticket, but postcard deserialization failed.
    #[display("deserialization failed: {_0}")]
    Postcard(#[from] postcard::Error),
    /// This looks like a ticket, but base32 decoding failed.
    #[display("decoding failed: {_0}")]
    Encoding(#[from] base32::DecodeError),
    /// Verification of the deserialized bytes failed.
    #[display("verification failed: {_0}")]
    Verify(&'static str),
}

trait IrohTicket: serde::Serialize + for<'de> serde::Deserialize<'de> {
    /// Kind of Iroh ticket.
    const KIND: Kind;

    /// Serialize to postcard bytes.
    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("postcard::to_stdvec is infallible")
    }

    /// Deserialize from postcard bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let ticket: Self = postcard::from_bytes(bytes)?;
        ticket.verify().map_err(Error::Verify)?;
        Ok(ticket)
    }

    /// Verify this ticket.
    fn verify(&self) -> Result<(), &'static str> {
        Ok(())
    }

    /// Serialize to string.
    fn serialize(&self) -> String {
        let mut out = Self::KIND.to_string();
        base32::fmt_append(&self.to_bytes(), &mut out);
        out
    }

    /// Deserialize from a string.
    fn deserialize(str: &str) -> Result<Self, Error> {
        let expected = Self::KIND;
        let (found, bytes) = Kind::parse_prefix(str)?;
        if expected != found {
            return Err(Error::WrongKind { expected, found });
        }
        let bytes = base32::parse_vec(&bytes)?;
        let ticket = Self::from_bytes(&bytes)?;
        Ok(ticket)
    }
}

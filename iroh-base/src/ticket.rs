//! Tickets is a serializable object combining information required for an operation.
//! Typically tickets contain all information required for an operation, e.g. an iroh blob
//! ticket would contain the hash of the data as well as information about how to reach the
//! provider.

use std::{collections::BTreeSet, net::SocketAddr};

use nested_enum_utils::common_fields;
use serde::{Deserialize, Serialize};
use snafu::{Backtrace, Snafu};

use crate::{key::NodeId, relay_url::RelayUrl};

mod node;

pub use self::node::NodeTicket;

/// A ticket is a serializable object combining information required for an operation.
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
    fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError>;

    /// Serialize to string.
    fn serialize(&self) -> String {
        let mut out = Self::KIND.to_string();
        data_encoding::BASE32_NOPAD.encode_append(&self.to_bytes(), &mut out);
        out.to_ascii_lowercase()
    }

    /// Deserialize from a string.
    fn deserialize(str: &str) -> Result<Self, ParseError> {
        let expected = Self::KIND;
        let Some(rest) = str.strip_prefix(expected) else {
            return Err(KindSnafu { expected }.build());
        };
        let bytes = data_encoding::BASE32_NOPAD.decode(rest.to_ascii_uppercase().as_bytes())?;
        let ticket = Self::from_bytes(&bytes)?;
        Ok(ticket)
    }
}

/// An error deserializing an iroh ticket.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[allow(missing_docs)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum ParseError {
    /// Found a ticket with the wrong prefix, indicating the wrong kind.
    #[snafu(display("wrong prefix, expected {expected}"))]
    Kind {
        /// The expected prefix.
        expected: &'static str,
    },
    /// This looks like a ticket, but postcard deserialization failed.
    #[snafu(transparent)]
    Postcard { source: postcard::Error },
    /// This looks like a ticket, but base32 decoding failed.
    #[snafu(transparent)]
    Encoding { source: data_encoding::DecodeError },
    /// Verification of the deserialized bytes failed.
    #[snafu(display("verification failed: {message}"))]
    Verify { message: &'static str },
}

impl ParseError {
    /// Returns a [`ParseError`] that indicates the given ticket has the wrong
    /// prefix.
    ///
    /// Indicate the expected prefix.
    pub fn wrong_prefix(expected: &'static str) -> Self {
        KindSnafu { expected }.build()
    }

    /// Return a `ParseError` variant that indicates verification of the
    /// deserialized bytes failed.
    pub fn verification_failed(message: &'static str) -> Self {
        VerifySnafu { message }.build()
    }
}

#[derive(Serialize, Deserialize)]
struct Variant0NodeAddr {
    node_id: NodeId,
    info: Variant0AddrInfo,
}

#[derive(Serialize, Deserialize)]
struct Variant0AddrInfo {
    relay_url: Option<RelayUrl>,
    direct_addresses: BTreeSet<SocketAddr>,
}

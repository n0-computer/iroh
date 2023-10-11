//! Protocol for transferring content-addressed blobs and collections over quic
//! connections. This can be used either with normal quic connections when using
//! the [quinn](https://crates.io/crates/quinn) crate or with magicsock connections
//! when using the [iroh-net](https://crates.io/crates/iroh-net) crate.
//!
//! # Participants
//!
//! The protocol is a request/response protocol with two parties, a *provider* that
//! serves blobs and a *getter* that requests blobs.
//!
//! # Goals
//!
//! - Be paranoid about data integrity.
//!
//!   Data integrity is considered more important than performance. Data will be
//! validated both on the provider and getter side. A well behaved provider will
//! never send invalid data. Responses to range requests contain sufficient
//! information to validate the data.
//!
//!   Note: Validation using blake3 is extremely fast, so in almost all scenarios the
//! validation will not be the bottleneck even if we validate both on the provider
//! and getter side.
//!
//! - Do not limit the size of blobs or collections.
//!
//!   Blobs can be of arbitrary size, up to terabytes. Likewise, collections
//! can contain an arbitrary number of links. A well behaved implementation will
//! not require the entire blob or collection to be in memory at once.
//!
//! - Be efficient when transferring large blobs, including range requests.
//!
//!   It is possible to request entire blobs or ranges of blobs, where the
//! minimum granularity is a chunk group of 16KiB or 16 blake3 chunks. The worst
//! case overhead when doing range requests is about two chunk groups per range.
//!
//! - Be efficient when transferring multiple tiny blobs.
//!
//!   For tiny blobs the overhead of sending the blob hashes and the round-trip time
//! for each blob would be prohibitive.
//!
//! To avoid roundtrips, the protocol allows grouping multiple blobs into *collections*.
//! The semantic meaning of a collection is up to the application. For the purpose
//! of this protocol, a collection is just a grouping of related blobs.
//!
//! # Non-goals
//!
//! - Do not attempt to be generic in terms of the used hash function.
//!
//!   The protocol makes extensive use of the [blake3](https://crates.io/crates/blake3)
//! hash function and it's special properties such as blake3 verified streaming.
//!
//! - Do not support graph traversal.
//!
//!   The protocol only supports collections that directly contain blobs. If you have
//! deeply nested graph data, you will need to either do multiple requests or flatten
//! the graph into a single temporary collection.
//!
//! - Do not support discovery.
//!
//!   The protocol does not yet have a discovery mechanism for asking the provider
//! what ranges are available for a given blob. Currently you have to have some
//! out-of-band knowledge about what node has data for a given hash, or you can
//! just try to retrieve the data and see if it is available.
//!
//! A discovery protocol is planned in the future though.
//!
//! # Requests
//!
//! ## Getter defined requests
//!
//! In this case the getter knows the hash of the blob it wants to retrieve and
//! whether it wants to retrieve a single blob or a collection.
//!
//! The getter needs to define exactly what it wants to retrieve and send the
//! request to the provider.
//!
//! The provider will then respond with the bao encoded bytes for the requested
//! data and then close the connection. It will immediately close the connection
//! in case some data is not available or invalid.
//!
//! ## Provider defined requests
//!
//! In this case the getter sends a blob to the provider. This blob can contain
//! some kind of query. The exact details of the query are up to the application.
//!
//! The provider evaluates the query and responds with a serialized request in
//! the same format as the getter defined requests, followed by the bao encoded
//! data. From then on the protocol is the same as for getter defined requests.
//!
//! ## Specifying the required data
//!
//! A [`GetRequest`] contains a hash and a specification of what data related to
//! that hash is required. The specification is using a [`RangeSpecSeq`] which
//! has a compact representation on the wire but is otherwise identical to a
//! sequence of sets of ranges.
//!
//! In the following, we describe how the [`RangeSpecSeq`] is to be created for
//! different common scenarios.
//!
//! Ranges are always given in terms of 1024 byte blake3 chunks, *not* in terms
//! of bytes or chunk groups. The reason for this is that chunks are the fundamental
//! unit of hashing in blake3. Addressing anything smaller than a chunk is not
//! possible, and combining multiple chunks is merely an optimization to reduce
//! metadata overhead.
//!
//! ### Individual blobs
//!
//! In the easiest case, the getter just wants to retrieve a single blob. In this
//! case, the getter specifies [`RangeSpecSeq`] that contains a single element.
//! This element is the set of all chunks to indicate that we
//! want the entire blob, no matter how many chunks it has.
//!
//! Since this is a very common case, there is a convenience method
//! [`GetRequest::single`] that only requires the hash of the blob.
//!
//! ```rust
//! # use iroh_bytes::protocol::GetRequest;
//! # let hash: iroh_bytes::Hash = [0; 32].into();
//! let request = GetRequest::single(hash);
//! ```
//!
//! ### Ranges of blobs
//!
//! In this case, we have a (possibly large) blob and we want to retrieve only
//! some ranges of chunks. This is useful in similar cases as HTTP range requests.
//!
//! We still need just a single element in the [`RangeSpecSeq`], since we are
//! still only interested in a single blob. However, this element contains all
//! the chunk ranges we want to retrieve.
//!
//! For example, if we want to retrieve chunks 0-10 of a blob, we would
//! create a [`RangeSpecSeq`] like this:
//!
//! ```rust
//! # use bao_tree::{ChunkNum, ChunkRanges};
//! # use iroh_bytes::protocol::{GetRequest, RangeSpecSeq};
//! # let hash: iroh_bytes::Hash = [0; 32].into();
//! let spec = RangeSpecSeq::from_ranges([ChunkRanges::from(..ChunkNum(10))]);
//! let request = GetRequest::new(hash, spec);
//! ```
//!
//! Here `ChunkNum` is a newtype wrapper around `u64` that is used to indicate
//! that we are talking about chunk numbers, not bytes.
//!
//! While not that common, it is also possible to request multiple ranges of a
//! single blob. For example, if we want to retrieve chunks `0-10` and `100-110`
//! of a large file, we would create a [`RangeSpecSeq`] like this:
//!
//! ```rust
//! # use bao_tree::{ChunkNum, ChunkRanges};
//! # use iroh_bytes::protocol::{GetRequest, RangeSpecSeq};
//! # let hash: iroh_bytes::Hash = [0; 32].into();
//! let ranges = &ChunkRanges::from(..ChunkNum(10)) | &ChunkRanges::from(ChunkNum(100)..ChunkNum(110));
//! let spec = RangeSpecSeq::from_ranges([ranges]);
//! let request = GetRequest::new(hash, spec);
//! ```
//!
//! To specify chunk ranges, we use the [`ChunkRanges`] type alias.
//! This is actually the [`RangeSet`] type from the
//! [range_collections](https://crates.io/crates/range_collections) crate. This
//! type supports efficient boolean operations on sets of non-overlapping ranges.
//!
//! The [`RangeSet2`] type is a type alias for [`RangeSet`] that can store up to
//! 2 boundaries without allocating. This is sufficient for most use cases.
//!
//! [`RangeSet`]: range_collections::range_set::RangeSet
//! [`RangeSet2`]: range_collections::range_set::RangeSet2
//!
//! ### Collections
//!
//! In this case the provider has a collection that contains multiple blobs.
//! We want to retrieve all blobs in the collection.
//!
//! When used for collections, the first element of a [`RangeSpecSeq`] refers
//! to the collection itself, and all subsequent elements refer to the blobs
//! in the collection. When a [`RangeSpecSeq`] specifies ranges for more than
//! one blob, the provider will interpret this as a request for a collection.
//!
//! One thing to note is that we might not yet know how many blobs are in the
//! collection. Therefore, it is not possible to download an entire collection
//! by just specifying [`ChunkRanges::all()`] for all children.
//!
//! Instead, [`RangeSpecSeq`] allows defining infinite sequences of range sets.
//! The [`RangeSpecSeq::all()`] method returns a [`RangeSpecSeq`] that, when iterated
//! over, will yield [`ChunkRanges::all()`] forever.
//!
//! So specifying a collection would work like this:
//!
//! ```rust
//! # use bao_tree::{ChunkNum, ChunkRanges};
//! # use iroh_bytes::protocol::{GetRequest, RangeSpecSeq};
//! # let hash: iroh_bytes::Hash = [0; 32].into();
//! let spec = RangeSpecSeq::all();
//! let request = GetRequest::new(hash, spec);
//! ```
//!
//! Downloading an entire collection is also a very common case, so there is a
//! convenience method [`GetRequest::all`] that only requires the hash of the
//! collection.
//!
//! ### Parts of collections
//!
//! The most complex common case is when we have retrieved a collection and
//! it's children, but were interrupted before we could retrieve all children.
//!
//! In this case we need to specify the collection we want to retrieve, but
//! exclude the children and parts of children that we already have.
//!
//! For example, if we have a collection with 3 children, and we already have
//! the first child and the first 1000000 chunks of the second child.
//!
//! We would create a [`GetRequest`] like this:
//!
//! ```rust
//! # use bao_tree::{ChunkNum, ChunkRanges};
//! # use iroh_bytes::protocol::{GetRequest, RangeSpecSeq};
//! # let hash: iroh_bytes::Hash = [0; 32].into();
//! let spec = RangeSpecSeq::from_ranges([
//!   ChunkRanges::empty(), // we don't need the collection itself
//!   ChunkRanges::empty(), // we don't need the first child either
//!   ChunkRanges::from(ChunkNum(1000000)..), // we need the second child from chunk 1000000 onwards
//!   ChunkRanges::all(), // we need the third child completely
//! ]);
//! let request = GetRequest::new(hash, spec);
//! ```
//!
//! ### Requesting chunks for each child
//!
//! The RangeSpecSeq allows some scenarios that are not covered above. E.g. you
//! might want to request a collection and the first chunk of each child blob to
//! do something like mime type detection.
//!
//! You do not know how many children the collection has, so you need to use
//! an infinite sequence.
//!
//! ```rust
//! # use bao_tree::{ChunkNum, ChunkRanges};
//! # use iroh_bytes::protocol::{GetRequest, RangeSpecSeq};
//! # let hash: iroh_bytes::Hash = [0; 32].into();
//! let spec = RangeSpecSeq::from_ranges_infinite([
//!   ChunkRanges::all(), // the collection itself
//!   ChunkRanges::from(..ChunkNum(1)), // the first chunk of each child
//! ]);
//! let request = GetRequest::new(hash, spec);
//! ```
//!
//! ### Requesting a single child
//!
//! It is of course possible to request a single child of a collection. E.g.
//! the following would download the second child of a collection:
//!
//! ```rust
//! # use bao_tree::{ChunkNum, ChunkRanges};
//! # use iroh_bytes::protocol::{GetRequest, RangeSpecSeq};
//! # let hash: iroh_bytes::Hash = [0; 32].into();
//! let spec = RangeSpecSeq::from_ranges([
//!   ChunkRanges::empty(), // we don't need the collection itself
//!   ChunkRanges::empty(), // we don't need the first child either
//!   ChunkRanges::all(), // we need the second child completely
//! ]);
//! let request = GetRequest::new(hash, spec);
//! ```
//!
//! However, if you already have the collection, you might as well locally
//! look up the hash of the child and request it directly.
//!
//! ```rust
//! # use bao_tree::{ChunkNum, ChunkRanges};
//! # use iroh_bytes::protocol::{GetRequest, RangeSpecSeq};
//! # let child_hash: iroh_bytes::Hash = [0; 32].into();
//! let request = GetRequest::single(child_hash);
//! ```
//!
//! ### Why RangeSpec and RangeSpecSeq?
//!
//! You might wonder why we have [`RangeSpec`] and [`RangeSpecSeq`], when a simple
//! sequence of [`ChunkRanges`] might also do.
//!
//! The [`RangeSpec`] and [`RangeSpecSeq`] types exist to provide an efficient
//! representation of the request on the wire. In the [`RangeSpec`] type,
//! sequences of ranges are encoded alternating intervals of selected and
//! non-selected chunks. This results in smaller numbers that will result in fewer bytes
//! on the wire when using the [postcard](https://crates.io/crates/postcard) encoding
//! format that uses variable length integers.
//!
//! Likewise, the [`RangeSpecSeq`] type is a sequence of [`RangeSpec`]s that
//! does run length encoding to remove repeating elements. It also allows infinite
//! sequences of [`RangeSpec`]s to be encoded, unlike a simple sequence of
//! [`ChunkRanges`]s.
//!
//! [`RangeSpecSeq`] should be efficient even in case of very fragmented availability
//! of chunks, like a download from multiple providers that was frequently interrupted.
//!
//! # Responses
//!
//! The response stream contains the bao encoded bytes for the requested data.
//! The data will be sent in the order in which it was requested, so ascending
//! chunks for each blob, and blobs in the order in which they appear in the
//! collection.
//!
//! For details on the bao encoding, see the [bao specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
//! and the [bao-tree](https://crates.io/crates/bao-tree) crate. The bao-tree crate
//! is identical to the bao crate, except that it allows combining multiple blake3
//! chunks to chunk groups for efficiency.
//!
//! As a consequence of the chunk group optimization, chunk ranges in the response
//! will be rounded up to chunk groups ranges, so e.g. if you ask for chunks 0..10,
//! you will get chunks 0-16. This is done to reduce metadata overhead, and might
//! change in the future.
//!
//! For a complete response, the chunks are guaranteed to completely cover the
//! requested ranges.
//!
//! Reasons for not retrieving a complete response are two-fold:
//!
//! - the connection to the provider was interrupted, or the provider encountered
//! an internal error. In this case the provider will close the entire quinn connection.
//!
//! - the provider does not have the requested data, or discovered on send that the
//! requested data is not valid.
//!
//! In this case the provider will close just the stream used to send the response.
//! The exact location of the missing data can be retrieved from the error.
//!
//! # Request tokens
//!
//! Request tokens are an optional feature of the protocol. They are opaque byte
//! sequences that are associated with a single request. Applications can use
//! request tokens to implement request level authorization.
//!
//! # Requesting multiple unrelated blobs
//!
//! Currently, the protocol does not support requesting multiple unrelated blobs
//! in a single request. As an alternative, you can create a collection
//! on the provider side and use that to efficiently retrieve the blobs.
//!
//! If that is not possible, you can create a custom request handler that
//! accepts a custom request struct that contains the hashes of the blobs.
//!
//! If neither of these options are possible, you have no choice but to do
//! multiple requests. However, note that multiple requests will be multiplexed
//! over a single connection, and the overhead of a new QUIC stream on an existing
//! connection is very low.
//!
//! In case nodes are permanently exchanging data, it is probably valuable to
//! keep a connection open and reuse it for multiple requests.
use std::fmt::{self, Display};
use std::str::FromStr;

use anyhow::{ensure, Result};
use bao_tree::{ChunkNum, ChunkRanges};
use bytes::Bytes;
use derive_more::From;
use quinn::VarInt;
use serde::{Deserialize, Serialize};
mod range_spec;
pub use range_spec::{NonEmptyRequestRangeSpecIter, RangeSpec, RangeSpecSeq};

use crate::util::Hash;

/// Maximum message size is limited to 100MiB for now.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 100;

/// The ALPN used with quic for the iroh bytes protocol.
pub const ALPN: [u8; 13] = *b"/iroh-bytes/2";

/// Maximum size of a request token, matches a browser cookie max size:
/// <https://datatracker.ietf.org/doc/html/rfc2109#section-6.3>.
const MAX_REQUEST_TOKEN_SIZE: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, From)]
/// A Request token is an opaque byte sequence associated with a single request.
/// Applications can use request tokens to implement request authorization,
/// user association, etc.
pub struct RequestToken {
    bytes: Bytes,
}

impl RequestToken {
    /// Creates a new request token from bytes.
    pub fn new(bytes: impl Into<Bytes>) -> Result<Self> {
        let bytes: Bytes = bytes.into();
        ensure!(
            bytes.len() < MAX_REQUEST_TOKEN_SIZE,
            "request token is too large"
        );
        Ok(Self { bytes })
    }

    /// Generate a random 32 byte request token.
    pub fn generate() -> Self {
        Self {
            bytes: rand::random::<[u8; 32]>().to_vec().into(),
        }
    }

    /// Returns a reference the token bytes.
    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }
}

impl FromStr for RequestToken {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        RequestToken::new(bytes)
    }
}

/// Serializes to base32.
impl Display for RequestToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.bytes);
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, From)]
/// A request to the provider
pub enum Request {
    /// A get request for a blob or collection
    Get(GetRequest),
}

impl Request {
    /// Gets the request token.
    pub fn token(&self) -> Option<&RequestToken> {
        match self {
            Request::Get(get) => get.token(),
        }
    }

    /// Sets the request token and returns a new request.
    pub fn with_token(mut self, value: Option<RequestToken>) -> Self {
        match &mut self {
            Request::Get(get) => get.token = value,
        }
        self
    }
}

/// A request
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct GetRequest {
    /// Optional Request token
    token: Option<RequestToken>,
    /// blake3 hash
    pub hash: Hash,
    /// The range of data to request
    ///
    /// The first element is the parent, all subsequent elements are children.
    pub ranges: RangeSpecSeq,
}

impl GetRequest {
    /// Request a blob or collection with specified ranges
    pub fn new(hash: Hash, ranges: RangeSpecSeq) -> Self {
        Self {
            hash,
            ranges,
            token: None,
        }
    }

    /// Request a collection and all its children
    pub fn all(hash: Hash) -> Self {
        Self {
            hash,
            token: None,
            ranges: RangeSpecSeq::all(),
        }
    }

    /// Request just a single blob
    pub fn single(hash: Hash) -> Self {
        Self {
            hash,
            token: None,
            ranges: RangeSpecSeq::from_ranges([ChunkRanges::all()]),
        }
    }

    /// Request the last chunk of a single blob
    ///
    /// This can be used to get the verified size of a blob.
    pub fn last_chunk(hash: Hash) -> Self {
        Self {
            hash,
            token: None,
            ranges: RangeSpecSeq::from_ranges([ChunkRanges::from(ChunkNum(u64::MAX)..)]),
        }
    }

    /// Request the last chunk for all children
    ///
    /// This can be used to get the verified size of all children.
    pub fn last_chunks(hash: Hash) -> Self {
        Self {
            hash,
            token: None,
            ranges: RangeSpecSeq::from_ranges_infinite([
                ChunkRanges::all(),
                ChunkRanges::from(ChunkNum(u64::MAX)..),
            ]),
        }
    }

    /// Set the request token
    pub fn with_token(self, token: Option<RequestToken>) -> Self {
        Self { token, ..self }
    }

    /// Get the request token
    pub fn token(&self) -> Option<&RequestToken> {
        self.token.as_ref()
    }
}

/// Reasons to close connections or stop streams.
///
/// A QUIC **connection** can be *closed* and a **stream** can request the other side to
/// *stop* sending data.  Both closing and stopping have an associated `error_code`, closing
/// also adds a `reason` as some arbitrary bytes.
///
/// This enum exists so we have a single namespace for `error_code`s used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Closed {
    /// The [`quinn::RecvStream`] was dropped.
    ///
    /// Used implicitly when a [`quinn::RecvStream`] is dropped without explicit call to
    /// [`quinn::RecvStream::stop`].  We don't use this explicitly but this is here as
    /// documentation as to what happened to `0`.
    StreamDropped = 0,
    /// The provider is terminating.
    ///
    /// When a provider terminates all connections and associated streams are closed.
    ProviderTerminating = 1,
    /// The provider has received the request.
    ///
    /// Only a single request is allowed on a stream, if more data is received after this a
    /// provider may send this error code in a STOP_STREAM frame.
    RequestReceived = 2,
}

impl Closed {
    /// The close reason as bytes. This is a valid utf8 string describing the reason.
    pub fn reason(&self) -> &'static [u8] {
        match self {
            Closed::StreamDropped => b"stream dropped",
            Closed::ProviderTerminating => b"provider terminating",
            Closed::RequestReceived => b"request received",
        }
    }
}

impl From<Closed> for VarInt {
    fn from(source: Closed) -> Self {
        VarInt::from(source as u16)
    }
}

/// Unknown error_code, can not be converted into [`Closed`].
#[derive(thiserror::Error, Debug)]
#[error("Unknown error_code: {0}")]
pub struct UnknownErrorCode(u64);

impl TryFrom<VarInt> for Closed {
    type Error = UnknownErrorCode;

    fn try_from(value: VarInt) -> std::result::Result<Self, Self::Error> {
        match value.into_inner() {
            0 => Ok(Self::StreamDropped),
            1 => Ok(Self::ProviderTerminating),
            2 => Ok(Self::RequestReceived),
            val => Err(UnknownErrorCode(val)),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use iroh_test::{assert_eq_hex, hexdump::parse_hexdump};

    use super::{GetRequest, Request, RequestToken};

    #[test]
    fn request_wire_format() {
        let hash = [0xda; 32].into();
        let token = RequestToken::from(Bytes::from(b"TOKEN".as_slice()));
        let cases = [
            (
                Request::from(GetRequest::single(hash)),
                r"
                    00 # enum variant for GetRequest
                    00 # no token
                    dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada # the hash
                    020001000100 # the RangeSpecSeq
            ",
            ),
            (
                Request::from(GetRequest::all(hash)),
                r"
                    00 # enum variant for GetRequest
                    00 # no token
                    dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada # the hash
                    01000100 # the RangeSpecSeq
            ",
            ),
            (
                Request::from(GetRequest::all(hash).with_token(Some(token.clone()))),
                r"
                    00 # enum variant for GetRequest
                    01 # a token
                    05 # length 5
                    54 4f 4b 45 4e # token content
                    dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada # the hash
                    01000100 # the RangeSpecSeq
            ",
            ),
        ];
        for (case, expected_hex) in cases {
            let expected = parse_hexdump(expected_hex).unwrap();
            let bytes = postcard::to_stdvec(&case).unwrap();
            assert_eq_hex!(bytes, expected);
        }
    }
}

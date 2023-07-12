//! Protocol for communication between provider and client.
use std::fmt::{self, Display};
use std::io;
use std::str::FromStr;

use anyhow::{bail, ensure, Context, Result};
use bytes::{Bytes, BytesMut};
use derive_more::From;
use quinn::VarInt;
use range_collections::RangeSet2;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    /// A get request that allows the receiver to create a collection
    CustomGet(CustomGetRequest),
}

impl Request {
    /// Gets the request token.
    pub fn token(&self) -> Option<&RequestToken> {
        match self {
            Request::Get(get) => get.token(),
            Request::CustomGet(get) => get.token.as_ref(),
        }
    }

    /// Sets the request token and returns a new request.
    pub fn with_token(mut self, value: Option<RequestToken>) -> Self {
        match &mut self {
            Request::Get(get) => get.token = value,
            Request::CustomGet(get) => get.token = value,
        }
        self
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
/// A get request that allows the receiver to create a collection
/// Custom request handlers will receive this struct destructured into
/// handler arguments
pub struct CustomGetRequest {
    /// The optional request token
    pub token: Option<RequestToken>,
    /// The opaque request data
    pub data: Bytes,
}

/// Currently all requests are get requests. But that won't always be the case.
///
/// Hence this type alias that will at some point be replaced by a proper enum.
pub type AnyGetRequest = Request;

/// A request
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct GetRequest {
    /// blake3 hash
    pub hash: Hash,
    /// The range of data to request
    ///
    /// The first element is the parent, all subsequent elements are children.
    pub ranges: RangeSpecSeq,
    /// Optional Request token
    token: Option<RequestToken>,
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
            ranges: RangeSpecSeq::new([RangeSet2::all()]),
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

/// Write the given data to the provider sink, with a unsigned varint length prefix.
pub(crate) async fn write_lp<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() < MAX_MESSAGE_SIZE,
        "sending message is too large"
    );

    // send length prefix
    let data_len = data.len() as u64;
    writer.write_u64_le(data_len).await?;

    // write message
    writer.write_all(data).await?;
    Ok(())
}

/// Reads a length prefixed message.
///
/// # Returns
///
/// The message as raw bytes.  If the end of the stream is reached and there is no partial
/// message, returns `None`.
pub(crate) async fn read_lp(
    mut reader: impl AsyncRead + Unpin,
    buffer: &mut BytesMut,
) -> Result<Option<Bytes>> {
    let size = match reader.read_u64_le().await {
        Ok(size) => size,
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let reader = reader.take(size);
    read_fixed_size(reader, buffer, size).await
}

pub(crate) async fn read_fixed_size(
    reader: impl AsyncRead + Unpin,
    buffer: &mut BytesMut,
    size: u64,
) -> Result<Option<Bytes>> {
    if size > MAX_MESSAGE_SIZE as u64 {
        bail!("Incoming message exceeds MAX_MESSAGE_SIZE");
    }

    let mut reader = reader.take(size);
    let size = usize::try_from(size).context("frame larger than usize")?;

    buffer.reserve(size);
    loop {
        let r = reader.read_buf(buffer).await?;
        if r == 0 {
            break;
        }
    }
    Ok(Some(buffer.split_to(size).freeze()))
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

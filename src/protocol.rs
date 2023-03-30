//! Protocol for communication between provider and client.
use std::fmt::Display;
use std::io;
use std::str::FromStr;

use anyhow::{bail, ensure, Context, Result};
use bao_tree::io::tokio::AsyncResponseDecoder;
use bytes::{Bytes, BytesMut};
use postcard::experimental::max_size::MaxSize;
use quinn::VarInt;
use range_collections::RangeSet2;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    util::{self, Hash},
    IROH_BLOCK_SIZE,
};

/// Maximum message size is limited to 100MiB for now.
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 100;

/// Protocol version
pub const VERSION: u64 = 1;

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, MaxSize)]
pub(crate) struct Handshake {
    pub version: u64,
    pub token: AuthToken,
}

impl Handshake {
    pub fn new(token: AuthToken) -> Self {
        Self {
            version: VERSION,
            token,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, MaxSize)]
pub(crate) struct Request {
    /// blake3 hash
    pub name: Hash,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, MaxSize)]
pub(crate) struct Response {
    pub data: Res,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, MaxSize)]
pub(crate) enum Res {
    NotFound,
    // If found, a stream of bao data is sent as next message.
    Found,
    /// Indicates that the given hash referred to a collection of multiple blobs
    /// A stream of boa data that decodes to a `Collection` is sent as the next message,
    /// followed by `Res::Found` responses, send in the order indicated in the `Collection`.
    FoundCollection {
        /// The size of the raw data we are planning to transfer
        total_blobs_size: u64,
    },
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
    let mut reader = reader.take(size);
    let size = usize::try_from(size).context("frame larger than usize")?;
    if size > MAX_MESSAGE_SIZE {
        bail!("Incoming message exceeds MAX_MESSAGE_SIZE");
    }
    buffer.reserve(size);
    loop {
        let r = reader.read_buf(buffer).await?;
        if r == 0 {
            break;
        }
    }
    Ok(Some(buffer.split_to(size).freeze()))
}

/// Read and decode the given bao encoded data from the provided source.
///
/// After the data is read successfully, the reader will be at the end of the data.
/// If there is an error, the reader can be anywhere, so it is recommended to discard it.
pub(crate) async fn read_bao_encoded<R: AsyncRead + Unpin>(
    reader: R,
    hash: Hash,
) -> Result<Vec<u8>> {
    let mut decoder =
        AsyncResponseDecoder::new(hash.into(), RangeSet2::all(), IROH_BLOCK_SIZE, reader);
    // we don't know the size yet, so we just allocate a reasonable amount
    let mut decoded = Vec::with_capacity(4096);
    decoder.read_to_end(&mut decoded).await?;
    Ok(decoded)
}

/// A token used to authenticate a handshake.
///
/// The token has a printable representation which can be serialised using [`Display`] and
/// deserialised using [`FromStr`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, MaxSize)]
pub struct AuthToken {
    bytes: [u8; 32],
}

impl AuthToken {
    /// Generates a new random token.
    pub fn generate() -> Self {
        Self {
            bytes: rand::random(),
        }
    }
}

/// Serialises the [`AuthToken`] to base64.
impl Display for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", util::encode(self.bytes))
    }
}

/// Error for parsing [`AuthToken`] using [`FromStr`].
#[derive(thiserror::Error, Debug)]
pub enum AuthTokenParseError {
    /// Invalid base64 encoding.
    #[error("invalid encoding: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Invalid length.
    #[error("invalid length: {0}")]
    Length(usize),
}

/// Deserialises the [`AuthToken`] from base64.
impl FromStr for AuthToken {
    type Err = AuthTokenParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let decoded = util::decode(s)?;
        let bytes = decoded
            .try_into()
            .map_err(|v: Vec<u8>| AuthTokenParseError::Length(v.len()))?;
        Ok(AuthToken { bytes })
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
pub(crate) enum Closed {
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
    pub fn reason(&self) -> &'static [u8] {
        match self {
            Closed::StreamDropped => &b"stream dropped"[..],
            Closed::ProviderTerminating => &b"provider terminating"[..],
            Closed::RequestReceived => &b"request received"[..],
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
pub(crate) struct UnknownErrorCode(u64);

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
    use super::*;

    #[test]
    fn test_auth_token_base64() {
        let token = AuthToken::generate();
        println!("token: {token}");
        let base64 = token.to_string();
        println!("token: {base64}");
        let decoded = AuthToken::from_str(&base64).unwrap();
        assert_eq!(decoded, token);

        let err = AuthToken::from_str("not-base64").err().unwrap();
        println!("err {err:#}");
        assert!(matches!(err, AuthTokenParseError::Base64(_)));

        let err = AuthToken::from_str("abcd").err().unwrap();
        println!("err {err:#}");
        assert!(matches!(err, AuthTokenParseError::Length(3)));
    }
}

use std::fmt::Display;
use std::str::FromStr;

use anyhow::{ensure, Result};
use bytes::{Bytes, BytesMut};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::{
    bao_slice_decoder::AsyncSliceDecoder,
    util::{self, Hash},
};

/// Maximum message size is limited to 100MiB for now.
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 100;

pub const VERSION: u64 = 1;

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, MaxSize)]
pub struct Handshake {
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
pub struct Request {
    pub id: u64,
    /// blake3 hash
    pub name: Hash,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct Response {
    pub id: u64,
    pub data: Res,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum Res {
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
pub async fn write_lp<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
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

/// Read and deserialize into the given type from the provided source, based on the length prefix.
pub async fn read_lp<'a, R: AsyncRead + Unpin, T: Deserialize<'a>>(
    mut reader: R,
    buffer: &'a mut BytesMut,
) -> Result<Option<(T, usize)>> {
    // read length prefix
    let size = read_prefix(&mut reader).await?;
    let mut reader = reader.take(size);

    let size = usize::try_from(size)?;
    let mut read = 0;
    while read != size {
        let r = reader.read_buf(buffer).await?;
        read += r;
        if r == 0 {
            break;
        }
    }
    let response: T = postcard::from_bytes(&buffer[..size])?;
    debug!("read message of size {}", size);

    Ok(Some((response, size)))
}

/// Return a buffer for the data, based on a given size, from the given source.
/// The new buffer is split off from the buffer that is passed into the function.
pub async fn read_size_data<R: AsyncRead + Unpin>(
    size: u64,
    reader: R,
    buffer: &mut BytesMut,
) -> Result<Bytes> {
    debug!("reading {}", size);
    let mut reader = reader.take(size);
    let size = usize::try_from(size)?;
    let mut read = 0;
    while read != size {
        let r = reader.read_buf(buffer).await?;
        read += r;
        if r == 0 {
            break;
        }
    }
    debug!("finished reading");
    Ok(buffer.split_to(size).freeze())
}

/// Read and decode the given bao encoded data from the provided source.
///
/// After the data is read successfully, the reader will be at the end of the data.
/// If there is an error, the reader can be anywhere, so it is recommended to discard it.
pub async fn read_bao_encoded<R: AsyncRead + Unpin>(reader: R, hash: Hash) -> Result<Vec<u8>> {
    let mut decoder = AsyncSliceDecoder::new(reader, hash.into(), 0, u64::MAX);
    // we don't know the size yet, so we just allocate a reasonable amount
    let mut decoded = Vec::with_capacity(4096);
    decoder.read_to_end(&mut decoded).await?;
    Ok(decoded)
}

/// Return a buffer of the data, based on the length prefix, from the given source.
/// The new buffer is split off from the buffer that is passed in the function.
pub async fn read_lp_data<R: AsyncRead + Unpin>(
    mut reader: R,
    buffer: &mut BytesMut,
) -> Result<Option<Bytes>> {
    // read length prefix
    let size = read_prefix(&mut reader).await?;

    let response = read_size_data(size, reader, buffer).await?;
    Ok(Some(response))
}

async fn read_prefix<R: AsyncRead + Unpin>(mut reader: R) -> Result<u64> {
    // read length prefix
    let size = reader.read_u64_le().await?;
    Ok(size)
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
    #[error("invalid encoding: {0}")]
    Base64(#[from] base64::DecodeError),
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

use std::fmt::Display;
use std::str::FromStr;

use anyhow::{bail, ensure, Result};
use bytes::{Bytes, BytesMut};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

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
    pub name: [u8; 32],
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct Response<'a> {
    pub id: u64,
    #[serde(borrow)]
    pub data: Res<'a>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum Res<'a> {
    NotFound,
    // If found, a stream of bao data is sent as next message.
    Found {
        /// The size of the coming data in bytes, raw content size.
        size: u64,
        outboard: &'a [u8],
    },
    /// Indicates that the given hash referred to a collection of multiple blobs
    /// A stream of boa data that decodes to a `Collection` is sent as the next message,
    /// followed by `Res::Found` responses, send in the order indicated in the `Collection`.
    FoundCollection {
        /// The size of the coming data in bytes, raw content size.
        size: u64,
        outboard: &'a [u8],
        /// The size of the raw data we are planning to transfer
        total_blobs_size: u64,
    },
}

impl Res<'_> {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::Found { outboard, .. } => outboard.len(),
            _ => 0,
        }
    }
}

/// Write the given data to the provider sink, with a unsigned varint length prefix.
pub async fn write_lp<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() < MAX_MESSAGE_SIZE,
        "sending message is too large"
    );

    // send length prefix
    let mut buffer = [0u8; 10];
    let lp = unsigned_varint::encode::u64(data.len() as u64, &mut buffer);
    writer.write_all(lp).await?;

    // write message
    writer.write_all(data).await?;
    Ok(())
}

/// Read and deserialize into the given type from the provided source, based on the length prefix.
pub async fn read_lp<'a, R: AsyncRead + futures::io::AsyncRead + Unpin, T: Deserialize<'a>>(
    mut reader: R,
    buffer: &'a mut BytesMut,
) -> Result<Option<(T, usize)>> {
    // read length prefix
    let size = read_prefix(&mut reader, buffer).await?;

    while buffer.len() < size {
        debug!("reading message, buffered {} of {size}", buffer.len());
        if reader.read_buf(buffer).await? == 0 {
            bail!("no more data available");
        }
    }
    let response: T = postcard::from_bytes(&buffer[..size])?;
    debug!("read message of size {}", size);

    Ok(Some((response, size)))
}

/// Return a buffer for the data, based on a given size, from the given source.
/// The new buffer is split off from the buffer that is passed into the function.
pub async fn read_size_data<R: AsyncRead + futures::io::AsyncRead + Unpin>(
    size: u64,
    mut reader: R,
    buffer: &mut BytesMut,
) -> Result<Bytes> {
    while (buffer.len() as u64) < size {
        debug!("reading data, buffered {} of {size}", buffer.len());
        if reader.read_buf(buffer).await? == 0 {
            bail!("no more data available");
        }
    }
    // potential truncation from u64 to usize
    Ok(buffer.split_to(size as usize).freeze())
}

/// Return a buffer of the data, based on the length prefix, from the given source.
/// The new buffer is split off from the buffer that is passed in the function.
pub async fn read_lp_data<R: AsyncRead + futures::io::AsyncRead + Unpin>(
    mut reader: R,
    buffer: &mut BytesMut,
) -> Result<Option<Bytes>> {
    // read length prefix
    let size = read_prefix(&mut reader, buffer).await?;

    let response = read_size_data(size as u64, reader, buffer).await?;
    Ok(Some(response))
}

async fn read_prefix<R: AsyncRead + futures::io::AsyncRead + Unpin>(
    mut reader: R,
    buffer: &mut BytesMut,
) -> Result<usize> {
    // read length prefix
    let size = loop {
        if let Ok((size, rest)) = unsigned_varint::decode::u64(&buffer[..]) {
            let size = usize::try_from(size)?;
            ensure!(size < MAX_MESSAGE_SIZE, "received message is too large");

            let _ = buffer.split_to(buffer.len() - rest.len());
            break size;
        }

        if reader.read_buf(buffer).await? == 0 {
            bail!("no more data available");
        }
    };

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

/// Serialises the [`AuthToken`] to hex.
impl Display for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}

/// Error for parsing [`AuthToken`] using [`FromStr`].
#[derive(thiserror::Error, Debug)]
pub enum AuthTokenPraseError {
    #[error("invalid encoding: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid length: {0}")]
    Length(usize),
}

/// Deserialises the [`AuthToken`] from hex.
impl FromStr for AuthToken {
    type Err = AuthTokenPraseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let decoded = hex::decode(s)?;
        let bytes = decoded
            .try_into()
            .map_err(|v: Vec<u8>| AuthTokenPraseError::Length(v.len()))?;
        Ok(AuthToken { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_hex() {
        let token = AuthToken::generate();
        println!("token: {token}");
        let hex = token.to_string();
        println!("token: {hex}");
        let decoded = AuthToken::from_str(&hex).unwrap();
        assert_eq!(decoded, token);

        let err = AuthToken::from_str("not-hex").err().unwrap();
        println!("err {err:#}");
        assert!(matches!(err, AuthTokenPraseError::Hex(_)));

        let err = AuthToken::from_str("abcd").err().unwrap();
        println!("err {err:#}");
        assert!(matches!(err, AuthTokenPraseError::Length(2)));
    }
}

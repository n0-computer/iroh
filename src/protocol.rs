use std::fmt::Display;
use std::str::FromStr;

use anyhow::{ensure, Result};
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

/// Serialises the [`AuthToken`] to hex.
impl Display for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}

/// Error for parsing [`AuthToken`] using [`FromStr`].
#[derive(thiserror::Error, Debug)]
pub enum AuthTokenParseError {
    #[error("invalid encoding: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid length: {0}")]
    Length(usize),
}

/// Deserialises the [`AuthToken`] from hex.
impl FromStr for AuthToken {
    type Err = AuthTokenParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let decoded = hex::decode(s)?;
        let bytes = decoded
            .try_into()
            .map_err(|v: Vec<u8>| AuthTokenParseError::Length(v.len()))?;
        Ok(AuthToken { bytes })
    }
}

/// Serde support for [`bao::Hash`].
///
/// Decorate the `bao::Hash` field with `#[serde(with = "crate::protocol::serde_hash")]` to
/// use this.
pub mod serde_hash {
    use std::fmt;

    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S>(hash: &bao::Hash, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(hash.as_bytes())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<bao::Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        d.deserialize_bytes(HashVisitor)
    }

    struct HashVisitor;

    impl<'de> de::Visitor<'de> for HashVisitor {
        type Value = bao::Hash;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "an array of 32 bytes containing hash data")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes: [u8; 32] = v.try_into().map_err(E::custom)?;
            Ok(bao::Hash::from(bytes))
        }
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
        assert!(matches!(err, AuthTokenParseError::Hex(_)));

        let err = AuthToken::from_str("abcd").err().unwrap();
        println!("err {err:#}");
        assert!(matches!(err, AuthTokenParseError::Length(2)));
    }
}

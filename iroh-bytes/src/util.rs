//! Utility functions and types.
use anyhow::{ensure, Result};
use postcard::experimental::max_size::MaxSize;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Display},
    result,
    str::FromStr,
};
use thiserror::Error;
pub mod io;
pub mod progress;

/// Hash type used throught.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Hash(blake3::Hash);

impl Hash {
    /// Calculate the hash of the provide bytes.
    pub fn new(buf: impl AsRef<[u8]>) -> Self {
        let val = blake3::hash(buf.as_ref());
        Hash(val)
    }

    /// Bytes of the hash.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Hex string of the hash.
    pub fn to_hex(&self) -> String {
        self.0.to_hex().to_string()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<Hash> for blake3::Hash {
    fn from(value: Hash) -> Self {
        value.0
    }
}

impl From<blake3::Hash> for Hash {
    fn from(value: blake3::Hash) -> Self {
        Hash(value)
    }
}

impl From<[u8; 32]> for Hash {
    fn from(value: [u8; 32]) -> Self {
        Hash(blake3::Hash::from(value))
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.as_bytes().cmp(other.0.as_bytes()))
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = data_encoding::BASE32_NOPAD
            .encode(self.0.as_bytes())
            .to_ascii_lowercase();
        write!(f, "{text}")
    }
}

impl FromStr for Hash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut arr = [0u8; 32];
        let val = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?; // todo: use a custom error type
        ensure!(
            val.len() == 32,
            "invalid byte length, expected 32, got {}",
            val.len()
        );
        ensure!(
            val.len() == 32,
            "invalid byte length, expected 32, got {}",
            val.len()
        );
        arr.copy_from_slice(&val);
        let hash = blake3::Hash::from(arr);

        Ok(Hash(hash))
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(HashVisitor)
    }
}

struct HashVisitor;

impl<'de> de::Visitor<'de> for HashVisitor {
    type Value = Hash;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "an array of 32 bytes containing hash data")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes: [u8; 32] = v.try_into().map_err(E::custom)?;
        Ok(Hash::from(bytes))
    }
}

impl MaxSize for Hash {
    const POSTCARD_MAX_SIZE: usize = 32;
}

/// A serializable error type for use in RPC responses.
#[derive(Serialize, Deserialize, Debug, Error)]
pub struct RpcError(serde_error::Error);

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<anyhow::Error> for RpcError {
    fn from(e: anyhow::Error) -> Self {
        RpcError(serde_error::Error::new(&*e))
    }
}

/// A serializable result type for use in RPC responses.
#[allow(dead_code)]
pub type RpcResult<T> = result::Result<T, RpcError>;

/// A non-sendable marker type
#[derive(Debug)]
pub(crate) struct NonSend {
    _marker: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl NonSend {
    /// Create a new non-sendable marker.
    #[allow(dead_code)]
    pub const fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let data = b"hello world";
        let hash = Hash::new(data);

        let encoded = hash.to_string();
        assert_eq!(encoded.parse::<Hash>().unwrap(), hash);
    }

    #[test]
    fn test_canonicalize_path() {
        assert_eq!(io::canonicalize_path("foo/bar").unwrap(), "foo/bar");
    }
}

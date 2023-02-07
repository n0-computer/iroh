use std::{
    fmt::{self, Display},
    str::FromStr,
};

use anyhow::ensure;
use base64::{engine::general_purpose, Engine as _};
use postcard::experimental::max_size::MaxSize;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Encode the given buffer into Base64 URL SAFE without padding.
pub fn encode(buf: impl AsRef<[u8]>) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(buf.as_ref())
}

/// Decode the given buffer from Base64 URL SAFE without padding.
pub fn decode(buf: impl AsRef<str>) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(buf.as_ref())
}

/// Hash type used throught.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Hash(blake3::Hash);

impl Hash {
    /// Calculate the hash of the provide bytes.
    pub fn new(buf: impl AsRef<[u8]>) -> Self {
        let val = blake3::hash(buf.as_ref());
        Hash(val)
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

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", encode(self.0.as_bytes()))
    }
}

impl FromStr for Hash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut arr = [0u8; 32];
        let val = decode(s)?;
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
}

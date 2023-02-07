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

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3Cid(Hash);

const CID_PREFIX: [u8; 4] = [0x01, 0x55, 0x1e, 0x20];

impl Blake3Cid {
    pub fn new(hash: Hash) -> Self {
        Blake3Cid(hash)
    }

    pub fn hash(&self) -> &Hash {
        &self.0
    }

    pub fn into_bytes(&self) -> [u8; 36] {
        let hash: [u8; 32] = self.0 .0.into();
        let mut res = [0u8; 36];
        res[0..4].copy_from_slice(&CID_PREFIX);
        res[4..36].copy_from_slice(&hash);
        res
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(
            bytes.len() == 36,
            "invalid cid length, expected 36, got {}",
            bytes.len()
        );
        ensure!(bytes[0..4] == CID_PREFIX, "invalid cid prefix");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[4..36]);
        Ok(Blake3Cid(Hash::from(hash)))
    }
}

impl Display for Blake3Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // result will be 58 bytes plus prefix
        let mut res = [b'b'; 59];
        // write the encoded bytes
        data_encoding::BASE32_NOPAD.encode_mut(&self.into_bytes(), &mut res[1..]);
        // convert to string, this is guaranteed to succeed
        let t = std::str::from_utf8_mut(res.as_mut()).unwrap();
        // hack since data_encoding doesn't have BASE32LOWER_NOPAD as a const
        t.make_ascii_lowercase();
        // write the str, no allocations
        f.write_str(t)
    }
}

impl FromStr for Blake3Cid {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sb = s.as_bytes();
        if sb.len() == 59 && sb[0] == b'b' {
            // this is a base32 encoded cid, we can decode it directly
            let mut t = [0u8; 58];
            t.copy_from_slice(&sb[1..]);
            // hack since data_encoding doesn't have BASE32LOWER_NOPAD as a const
            std::str::from_utf8_mut(t.as_mut())
                .unwrap()
                .make_ascii_uppercase();
            // decode the bytes
            let mut res = [0u8; 36];
            data_encoding::BASE32_NOPAD
                .decode_mut(&t, &mut res)
                .map_err(|_e| anyhow::anyhow!("invalid base32"))?;
            // convert to cid, this will check the prefix
            Self::from_bytes(&res)
        } else {
            // if we want to support all the weird multibase prefixes, we have no choice
            // but to use the multibase crate
            let (_base, bytes) = multibase::decode(s)?;
            Self::from_bytes(bytes.as_ref())
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
    fn test_cid() {
        let expected = "bafkr4igxjga67jykbseaxdmmdgc5a5o3zp3htom2l6mrjznk7fvyggu6eq";
        let data = b"hello world";
        let hash = Hash::new(data);
        let cid = Blake3Cid::new(hash);
        // test to_string and parse from base32lower
        assert_eq!(cid.to_string(), expected.to_string());
        assert_eq!(Blake3Cid::from_str(expected).unwrap(), cid);
        // test parse from other multibase encodings
        for encoding in [
            multibase::Base::Base58Btc,
            multibase::Base::Base64,
            multibase::Base::Base32Upper,
        ] {
            let encoded = multibase::encode(encoding, cid.into_bytes());
            assert_eq!(Blake3Cid::from_str(&encoded).unwrap(), cid);
        }
    }
}

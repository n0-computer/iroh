//! The blake3 hash used in Iroh.

use std::str::FromStr;
use std::{borrow::Borrow, fmt};

use bao_tree::blake3;
use postcard::experimental::max_size::MaxSize;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::base32::{parse_array_hex_or_base32, HexOrBase32ParseError};

/// Hash type used throughout.
#[derive(PartialEq, Eq, Copy, Clone, Hash)]
pub struct Hash(blake3::Hash);

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash").field(&DD(self.to_hex())).finish()
    }
}

struct DD<T: fmt::Display>(T);

impl<T: fmt::Display> fmt::Debug for DD<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Hash {
    /// The hash for the empty byte range (`b""`).
    pub const EMPTY: Hash = Hash::from_bytes([
        175, 19, 73, 185, 245, 249, 161, 166, 160, 64, 77, 234, 54, 220, 201, 73, 155, 203, 37,
        201, 173, 193, 18, 183, 204, 154, 147, 202, 228, 31, 50, 98,
    ]);

    /// Calculate the hash of the provided bytes.
    pub fn new(buf: impl AsRef<[u8]>) -> Self {
        let val = blake3::hash(buf.as_ref());
        Hash(val)
    }

    /// Bytes of the hash.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Create a `Hash` from its raw bytes representation.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(blake3::Hash::from_bytes(bytes))
    }

    /// Convert the hash to a hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex().to_string()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Borrow<[u8]> for Hash {
    fn borrow(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Borrow<[u8; 32]> for Hash {
    fn borrow(&self) -> &[u8; 32] {
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

impl From<Hash> for [u8; 32] {
    fn from(value: Hash) -> Self {
        *value.as_bytes()
    }
}

impl From<&[u8; 32]> for Hash {
    fn from(value: &[u8; 32]) -> Self {
        Hash(blake3::Hash::from(*value))
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

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // result will be 52 bytes
        let mut res = [b'b'; 52];
        // write the encoded bytes
        data_encoding::BASE32_NOPAD.encode_mut(self.as_bytes(), &mut res);
        // convert to string, this is guaranteed to succeed
        let t = std::str::from_utf8_mut(res.as_mut()).unwrap();
        // hack since data_encoding doesn't have BASE32LOWER_NOPAD as a const
        t.make_ascii_lowercase();
        // write the str, no allocations
        f.write_str(t)
    }
}

impl FromStr for Hash {
    type Err = HexOrBase32ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_array_hex_or_base32(s).map(Hash::from)
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            self.0.as_bytes().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse().map_err(de::Error::custom)
        } else {
            let data: [u8; 32] = Deserialize::deserialize(deserializer)?;
            Ok(Self(blake3::Hash::from(data)))
        }
    }
}

impl MaxSize for Hash {
    const POSTCARD_MAX_SIZE: usize = 32;
}

/// A format identifier
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Default,
    Debug,
    MaxSize,
    Hash,
)]
pub enum BlobFormat {
    /// Raw blob
    #[default]
    Raw,
    /// A sequence of BLAKE3 hashes
    HashSeq,
}

impl From<BlobFormat> for u64 {
    fn from(value: BlobFormat) -> Self {
        match value {
            BlobFormat::Raw => 0,
            BlobFormat::HashSeq => 1,
        }
    }
}

impl BlobFormat {
    /// Is raw format
    pub const fn is_raw(&self) -> bool {
        matches!(self, BlobFormat::Raw)
    }

    /// Is hash seq format
    pub const fn is_hash_seq(&self) -> bool {
        matches!(self, BlobFormat::HashSeq)
    }
}

/// A hash and format pair
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, MaxSize, Hash)]
pub struct HashAndFormat {
    /// The hash
    pub hash: Hash,
    /// The format
    pub format: BlobFormat,
}

#[cfg(feature = "redb")]
mod redb_support {
    use super::{Hash, HashAndFormat};
    use postcard::experimental::max_size::MaxSize;
    use redb::{RedbKey, RedbValue};

    impl RedbValue for Hash {
        type SelfType<'a> = Self;

        type AsBytes<'a> = &'a [u8; 32];

        fn fixed_width() -> Option<usize> {
            Some(32)
        }

        fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
        where
            Self: 'a,
        {
            let contents: &'a [u8; 32] = data.try_into().unwrap();
            (*contents).into()
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
        where
            Self: 'a,
            Self: 'b,
        {
            value.as_bytes()
        }

        fn type_name() -> redb::TypeName {
            redb::TypeName::new("iroh_base::Hash")
        }
    }

    impl RedbKey for Hash {
        fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
            data1.cmp(data2)
        }
    }

    impl RedbValue for HashAndFormat {
        type SelfType<'a> = Self;

        type AsBytes<'a> = [u8; Self::POSTCARD_MAX_SIZE];

        fn fixed_width() -> Option<usize> {
            Some(Self::POSTCARD_MAX_SIZE)
        }

        fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
        where
            Self: 'a,
        {
            let t: &'a [u8; Self::POSTCARD_MAX_SIZE] = data.try_into().unwrap();
            postcard::from_bytes(t.as_slice()).unwrap()
        }

        fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
        where
            Self: 'a,
            Self: 'b,
        {
            let mut res = [0u8; 33];
            postcard::to_slice(&value, &mut res).unwrap();
            res
        }

        fn type_name() -> redb::TypeName {
            redb::TypeName::new("iroh_base::HashAndFormat")
        }
    }
}

impl HashAndFormat {
    /// Create a new hash and format pair.
    pub fn new(hash: Hash, format: BlobFormat) -> Self {
        Self { hash, format }
    }

    /// Create a new hash and format pair, using the default (raw) format.
    pub fn raw(hash: Hash) -> Self {
        Self {
            hash,
            format: BlobFormat::Raw,
        }
    }

    /// Create a new hash and format pair, using the collection format.
    pub fn hash_seq(hash: Hash) -> Self {
        Self {
            hash,
            format: BlobFormat::HashSeq,
        }
    }
}

impl fmt::Display for HashAndFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut slice = [0u8; 65];
        hex::encode_to_slice(self.hash.as_bytes(), &mut slice[1..]).unwrap();
        match self.format {
            BlobFormat::Raw => {
                write!(f, "{}", std::str::from_utf8(&slice[1..]).unwrap())
            }
            BlobFormat::HashSeq => {
                slice[0] = b's';
                write!(f, "{}", std::str::from_utf8(&slice).unwrap())
            }
        }
    }
}

impl FromStr for HashAndFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.as_bytes();
        let mut hash = [0u8; 32];
        match s.len() {
            64 => {
                hex::decode_to_slice(s, &mut hash)?;
                Ok(Self::raw(hash.into()))
            }
            65 if s[0].to_ascii_lowercase() == b's' => {
                hex::decode_to_slice(&s[1..], &mut hash)?;
                Ok(Self::hash_seq(hash.into()))
            }
            _ => anyhow::bail!("invalid hash and format"),
        }
    }
}

impl Serialize for HashAndFormat {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            (self.hash, self.format).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for HashAndFormat {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            s.parse().map_err(de::Error::custom)
        } else {
            let (hash, format) = <(Hash, BlobFormat)>::deserialize(deserializer)?;
            Ok(Self { hash, format })
        }
    }
}

#[cfg(test)]
mod tests {

    use iroh_test::{assert_eq_hex, hexdump::parse_hexdump};

    use super::*;

    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_display_parse_roundtrip() {
        for i in 0..100 {
            let hash: Hash = blake3::hash(&[i]).into();
            let text = hash.to_string();
            let hash1 = text.parse::<Hash>().unwrap();
            assert_eq!(hash, hash1);

            let text = hash.to_hex();
            let hash1 = Hash::from_str(&text).unwrap();
            assert_eq!(hash, hash1);
        }
    }

    #[test]
    fn test_hash() {
        let data = b"hello world";
        let hash = Hash::new(data);

        let encoded = hash.to_string();
        assert_eq!(encoded.parse::<Hash>().unwrap(), hash);
    }

    #[test]
    fn test_empty_hash() {
        let hash = Hash::new(b"");
        assert_eq!(hash, Hash::EMPTY);
    }

    #[test]
    fn hash_wire_format() {
        let hash = Hash::from([0xab; 32]);
        let serialized = postcard::to_stdvec(&hash).unwrap();
        let expected = parse_hexdump(r"
            ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab # hash
        ").unwrap();
        assert_eq_hex!(serialized, expected);
    }

    #[cfg(feature = "redb")]
    #[test]
    fn hash_redb() {
        use redb::RedbValue;
        let bytes: [u8; 32] = (0..32).collect::<Vec<_>>().as_slice().try_into().unwrap();
        let hash = Hash::from(bytes);
        assert_eq!(<Hash as RedbValue>::fixed_width(), Some(32));
        assert_eq!(
            <Hash as RedbValue>::type_name(),
            redb::TypeName::new("iroh_base::Hash")
        );
        let serialized = <Hash as RedbValue>::as_bytes(&hash);
        assert_eq!(serialized, &bytes);
        let deserialized = <Hash as RedbValue>::from_bytes(serialized.as_slice());
        assert_eq!(deserialized, hash);
        let expected = parse_hexdump(
            r"
            00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
            10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f # hash
        ",
        )
        .unwrap();
        assert_eq_hex!(serialized, expected);
    }

    #[cfg(feature = "redb")]
    #[test]
    fn hash_and_format_redb() {
        use redb::RedbValue;
        let hash_bytes: [u8; 32] = (0..32).collect::<Vec<_>>().as_slice().try_into().unwrap();
        let hash = Hash::from(hash_bytes);
        let haf = HashAndFormat::raw(hash);
        assert_eq!(<HashAndFormat as RedbValue>::fixed_width(), Some(33));
        assert_eq!(
            <HashAndFormat as RedbValue>::type_name(),
            redb::TypeName::new("iroh_base::HashAndFormat")
        );
        let serialized = <HashAndFormat as RedbValue>::as_bytes(&haf);
        let mut bytes = [0u8; 33];
        bytes[0..32].copy_from_slice(&hash_bytes);
        assert_eq!(serialized, bytes);
        let deserialized = <HashAndFormat as RedbValue>::from_bytes(serialized.as_slice());
        assert_eq!(deserialized, haf);
        let expected = parse_hexdump(
            r"
            00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
            10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f # hash
            00 # format (raw)
        ",
        )
        .unwrap();
        assert_eq_hex!(serialized, expected);
    }

    #[test]
    fn test_hash_serde() {
        let hash = Hash::new("hello");

        // Hashes are serialized as 32 tuples
        let mut tokens = Vec::new();
        tokens.push(Token::Tuple { len: 32 });
        for byte in hash.as_bytes() {
            tokens.push(Token::U8(*byte));
        }
        tokens.push(Token::TupleEnd);
        assert_eq!(tokens.len(), 34);

        assert_tokens(&hash.compact(), &tokens);

        let tokens = vec![Token::String(
            "5khrmpntq2bjexseshc6ldklwnig56gbj23yvbxjbdcwestheahq",
        )];
        assert_tokens(&hash.readable(), &tokens);
    }

    #[test]
    fn test_hash_postcard() {
        let hash = Hash::new("hello");
        let ser = postcard::to_stdvec(&hash).unwrap();
        let de = postcard::from_bytes(&ser).unwrap();
        assert_eq!(hash, de);

        assert_eq!(ser.len(), 32);
    }

    #[test]
    fn test_hash_json() {
        let hash = Hash::new("hello");
        let ser = serde_json::to_string(&hash).unwrap();
        let de = serde_json::from_str(&ser).unwrap();
        assert_eq!(hash, de);
        // 52 bytes of base32 + 2 quotes
        assert_eq!(ser.len(), 54);
    }

    #[test]
    fn test_hash_and_format_parse() {
        let hash = Hash::new("hello");

        let expected = HashAndFormat::raw(hash);
        let actual = expected.to_string().parse::<HashAndFormat>().unwrap();
        assert_eq!(expected, actual);

        let expected = HashAndFormat::hash_seq(hash);
        let actual = expected.to_string().parse::<HashAndFormat>().unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_hash_and_format_postcard() {
        let haf = HashAndFormat::raw(Hash::new("hello"));
        let ser = postcard::to_stdvec(&haf).unwrap();
        let de = postcard::from_bytes(&ser).unwrap();
        assert_eq!(haf, de);
    }

    #[test]
    fn test_hash_and_format_json() {
        let haf = HashAndFormat::raw(Hash::new("hello"));
        let ser = serde_json::to_string(&haf).unwrap();
        let de = serde_json::from_str(&ser).unwrap();
        assert_eq!(haf, de);
    }
}

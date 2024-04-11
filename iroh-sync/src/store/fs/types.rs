use std::mem::align_of;
use std::{fmt::Debug, mem::size_of};

use redb::{Key, Value};
use zerocopy::{native_endian::U64, FromBytes, IntoBytes, KnownLayout, NoCell, Unaligned};

type Signature = [u8; 64];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordIdentifierOwned(Box<[u8]>);

impl RecordIdentifierOwned {
    pub fn from_parts(namespace: &[u8; 32], value: &[u8; 32], key: &[u8]) -> Self {
        let mut data = Vec::with_capacity(32 + 32 + key.len());
        data.extend_from_slice(namespace);
        data.extend_from_slice(value);
        data.extend_from_slice(key);
        Self(data.into_boxed_slice())
    }
}

impl AsRef<RecordIdentifier> for RecordIdentifierOwned {
    fn as_ref(&self) -> &RecordIdentifier {
        RecordIdentifier::ref_from(&self.0).unwrap()
    }
}

impl From<&RecordIdentifier> for RecordIdentifierOwned {
    fn from(value: &RecordIdentifier) -> Self {
        Self::from_parts(&value.namespace, &value.author, &value.key)
    }
}

#[allow(missing_debug_implementations)]
#[derive(KnownLayout, FromBytes, NoCell, Unaligned, IntoBytes)]
#[repr(C, packed)]
pub struct RecordIdentifier {
    pub namespace: [u8; 32],
    pub author: [u8; 32],
    pub key: [u8],
}

impl Debug for &RecordIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordIdentifier")
            .field("namespace", &self.namespace)
            .field("author", &self.author)
            .field("key", &&self.key[..])
            .finish()
    }
}

impl PartialEq for &RecordIdentifier {
    fn eq(&self, other: &Self) -> bool {
        (self.namespace, self.author, &self.key).eq(&(other.namespace, other.author, &other.key))
    }
}

impl PartialOrd for &RecordIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (self.namespace, self.author, &self.key).partial_cmp(&(
            other.namespace,
            other.author,
            &other.key,
        ))
    }
}

impl Eq for &RecordIdentifier {}

impl Ord for &RecordIdentifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap()
    }
}
impl RecordIdentifier {
    pub fn new(key: &[u8]) -> &Self {
        RecordIdentifier::ref_from(key).expect("invalid key slice")
    }
}

impl<'a> Key for &'a RecordIdentifier {
    fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
        let a = Self::from_bytes(data1);
        let b = Self::from_bytes(data2);
        a.cmp(&b)
    }
}

impl AsRef<[u8]> for RecordIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Value for &RecordIdentifier {
    type SelfType<'a> = &'a RecordIdentifier where Self: 'a;
    type AsBytes<'a> = &'a RecordIdentifier where Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        RecordIdentifier::ref_from(data).expect("length must match")
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        value
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("RecordIdentifier")
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, PartialEq, Eq, KnownLayout, NoCell, Unaligned)]
#[repr(C)]
pub struct SignedRecord {
    /// Record creation timestamp. Counted as micros since the Unix epoch.
    pub timestamp: U64,
    pub namespace_signature: Signature,
    pub author_signature: Signature,
    /// Length of the data referenced by `hash`.
    pub len: U64,
    /// Hash of the content data.
    pub hash: [u8; 32],
}

impl AsRef<[u8]> for SignedRecord {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Value for &SignedRecord {
    type SelfType<'a> = &'a SignedRecord where Self: 'a;
    type AsBytes<'a> = &'a SignedRecord where Self: 'a;

    fn fixed_width() -> Option<usize> {
        Some(size_of::<SignedRecord>())
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        SignedRecord::ref_from(data).unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        value
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("SignedRecord")
    }
}

static_assertions::const_assert_eq!(align_of::<SignedRecord>(), 1);

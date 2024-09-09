//! Types for the basic data model of Willow.

use iroh_base::hash::Hash;
use ufotofu::sync::{consumer::IntoVec, producer::FromSlice};
use willow_encoding::sync::{Decodable, Encodable};

use super::{
    keys,
    meadowcap::{self},
};

pub use willow_data_model::InvalidPathError;
pub use willow_data_model::UnauthorisedWriteError;

/// A type for identifying namespaces.
pub type NamespaceId = keys::NamespaceId;

/// A type for identifying subspaces.
pub type SubspaceId = keys::UserId;

/// The capability type needed to authorize writes.
pub type WriteCapability = meadowcap::McCapability;

/// The capability type needed to authorize writes (serde serializable).
pub type SerdeWriteCapability = meadowcap::serde_encoding::SerdeMcCapability;

/// A Timestamp is a 64-bit unsigned integer, that is, a natural number between zero (inclusive) and 2^64 - 1 (exclusive).
/// Timestamps are to be interpreted as a time in microseconds since the Unix epoch.
pub type Timestamp = willow_data_model::Timestamp;

// A for proving write permission.
pub type AuthorisationToken = meadowcap::McAuthorisationToken;

/// A natural number for limiting the length of path components.
pub const MAX_COMPONENT_LENGTH: usize = 4096;

/// A natural number for limiting the number of path components.
pub const MAX_COMPONENT_COUNT: usize = 1024;

/// A natural number max_path_length for limiting the overall size of paths.
pub const MAX_PATH_LENGTH: usize = 4096;

/// The byte length of a [`PayloadDigest`].
pub const DIGEST_LENGTH: usize = 32;

/// See [`willow_data_model::Component`].
pub type Component<'a> = willow_data_model::Component<'a, MAX_COMPONENT_LENGTH>;

/// A payload digest used in entries.
///
/// This wraps a [`iroh_blobs::Hash`] blake3 hash.
#[derive(
    Debug,
    Clone,
    Copy,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    derive_more::From,
    derive_more::Into,
    derive_more::Display,
)]
pub struct PayloadDigest(pub Hash);

impl Default for PayloadDigest {
    fn default() -> Self {
        Self(Hash::from_bytes([0u8; 32]))
    }
}

impl willow_data_model::PayloadDigest for PayloadDigest {}

/// An immutable Willow [path].
///
/// Thread-safe, cheap to clone, cheap to take prefixes of, expensive to append to.
///
/// See [`willow_data_model::Path`].
///
/// [path]: https://willowprotocol.org/specs/data-model/index.html#Path
pub type Path = willow_data_model::Path<MAX_COMPONENT_LENGTH, MAX_COMPONENT_COUNT, MAX_PATH_LENGTH>;

/// Extension methods for [`Path`].
// TODO: Upstream the methods to willow-rs and remove the extension trait.
pub trait PathExt {
    /// Creates a new path from a slice of bytes.
    fn from_bytes(slices: &[&[u8]]) -> Result<Path, InvalidPathError2>;
}

impl PathExt for Path {
    fn from_bytes(slices: &[&[u8]]) -> Result<Self, InvalidPathError2> {
        let component_count = slices.len();
        let total_len = slices.iter().map(|x| x.len()).sum::<usize>();
        let iter = slices.iter().filter_map(|c| Component::new(c));
        // TODO: Avoid this alloc by adding willow_data_model::Path::try_new_from_iter or such.
        let mut iter = iter.collect::<Vec<_>>().into_iter();
        let path = willow_data_model::Path::new_from_iter(total_len, &mut iter)?;
        if path.get_component_count() != component_count {
            Err(InvalidPathError2::ComponentTooLong(
                path.get_component_count(),
            ))
        } else {
            Ok(path)
        }
    }
}

#[derive(Debug, thiserror::Error)]
/// An error arising from trying to construct a invalid [`Path`] from potentially invalid components.
pub enum InvalidPathError2 {
    /// One of the path's component is too large.
    #[error("One of the path's component is too large.")]
    ComponentTooLong(usize),
    /// The path's total length in bytes is too large.
    #[error("The path's total length in bytes is too large.")]
    PathTooLong,
    /// The path has too many components.
    #[error("The path has too many components.")]
    TooManyComponents,
}

impl From<InvalidPathError> for InvalidPathError2 {
    fn from(value: InvalidPathError) -> Self {
        match value {
            InvalidPathError::PathTooLong => Self::PathTooLong,
            InvalidPathError::TooManyComponents => Self::TooManyComponents,
        }
    }
}

/// An entry in a willow store.
///
/// Contains the metadata associated with each [`PayloadDigest`].
///
/// See [`willow_data_model::Entry`].
pub type Entry = willow_data_model::Entry<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    NamespaceId,
    SubspaceId,
    PayloadDigest,
>;

/// Extension methods for [`Entry`].
// TODO: Decide what to upstream to willow-rs.
pub trait EntryExt {
    /// Encodes the entry into a bytestring.
    fn encode_to_vec(&self) -> Vec<u8>;

    /// Decodes an entry from a bytestring.
    fn decode_from_slice(bytes: &[u8]) -> anyhow::Result<Entry>;

    /// Returns a tuple of namespace, subspace and path.
    fn as_sortable_tuple(&self) -> (&NamespaceId, &SubspaceId, &Path);
}

impl EntryExt for Entry {
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut consumer = IntoVec::<u8>::new();
        self.encode(&mut consumer).expect("encoding not to fail");
        consumer.into_vec()
    }
    fn decode_from_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut producer = FromSlice::<u8>::new(bytes);
        let entry = willow_data_model::Entry::decode(&mut producer)?;
        Ok(entry)
    }

    fn as_sortable_tuple(&self) -> (&NamespaceId, &SubspaceId, &Path) {
        (self.namespace_id(), self.subspace_id(), self.path())
    }
}

/// An entry in a willow store.
///
/// Contains the metadata associated with each [`PayloadDigest`].
///
/// See [`willow_data_model::Entry`].
pub type AuthorisedEntry = willow_data_model::AuthorisedEntry<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    NamespaceId,
    SubspaceId,
    PayloadDigest,
    AuthorisationToken,
>;

use syncify::syncify;
use syncify::syncify_replace;

#[syncify(encoding_sync)]
mod encoding {
    #[syncify_replace(use ufotofu::sync::{BulkConsumer, BulkProducer};)]
    use ufotofu::local_nb::{BulkConsumer, BulkProducer};

    #[syncify_replace(use willow_encoding::sync::{Decodable, Encodable};)]
    use willow_encoding::{Decodable, Encodable};

    use super::*;

    impl Encodable for PayloadDigest {
        async fn encode<Consumer>(&self, consumer: &mut Consumer) -> Result<(), Consumer::Error>
        where
            Consumer: BulkConsumer<Item = u8>,
        {
            consumer
                .bulk_consume_full_slice(self.0.as_bytes())
                .await
                .map_err(|err| err.reason)
        }
    }

    impl Decodable for PayloadDigest {
        async fn decode<Producer>(
            producer: &mut Producer,
        ) -> Result<Self, willow_encoding::DecodeError<Producer::Error>>
        where
            Producer: BulkProducer<Item = u8>,
            Self: Sized,
        {
            let mut bytes = [0u8; DIGEST_LENGTH];
            producer.bulk_overwrite_full_slice(&mut bytes).await?;
            Ok(Self(Hash::from_bytes(bytes)))
        }
    }
}

pub mod serde_encoding {
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    use crate::util::codec2::{from_bytes, to_vec};

    use super::*;

    pub mod path {

        use super::*;
        pub fn serialize<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
            to_vec(path).serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Path, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let decoded = from_bytes(&bytes).map_err(de::Error::custom)?;
            Ok(decoded)
        }
    }

    pub mod entry {
        use super::*;
        pub fn serialize<S: Serializer>(entry: &Entry, serializer: S) -> Result<S::Ok, S::Error> {
            to_vec(entry).serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Entry, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let decoded = from_bytes(&bytes).map_err(de::Error::custom)?;
            Ok(decoded)
        }
    }

    /// [`Entry`] wrapper that can be serialized with [`serde`].
    #[derive(
        Debug,
        Clone,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeEntry(#[serde(with = "entry")] pub Entry);

    pub mod authorised_entry {
        use crate::proto::meadowcap::serde_encoding::SerdeMcCapability;
        use keys::UserSignature;

        use super::*;
        pub fn serialize<S: Serializer>(
            entry: &AuthorisedEntry,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let (entry, token) = entry.clone().into_parts();
            (
                SerdeEntry(entry),
                SerdeMcCapability(token.capability),
                token.signature,
            )
                .serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<AuthorisedEntry, D::Error>
        where
            D: Deserializer<'de>,
        {
            let (entry, capability, signature): (SerdeEntry, SerdeMcCapability, UserSignature) =
                Deserialize::deserialize(deserializer)?;
            let token = AuthorisationToken::new(capability.0, signature);
            AuthorisedEntry::new(entry.0, token).map_err(de::Error::custom)
        }
    }

    /// [`AuthorisedEntry`] wrapper that can be serialized with [`serde`].
    #[derive(
        Debug,
        Clone,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeAuthorisedEntry(#[serde(with = "authorised_entry")] pub AuthorisedEntry);
}

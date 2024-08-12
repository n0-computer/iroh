use iroh_base::hash::Hash;
use ufotofu::sync::{consumer::IntoVec, producer::FromSlice};
use willow_data_model::{AuthorisationToken as _, InvalidPathError};
use willow_encoding::sync::{Decodable, Encodable};


use super::{
    keys,
    meadowcap::{self},
};

/// A type for identifying namespaces.
pub type NamespaceId = keys::NamespaceId;

/// A type for identifying subspaces.
pub type SubspaceId = keys::UserId;

/// The capability type needed to authorize writes.
pub type WriteCapability = meadowcap::McCapability;

/// The capability type needed to authorize writes (serializable).
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

pub type Component<'a> = willow_data_model::Component<'a, MAX_COMPONENT_LENGTH>;

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

// #[derive(
//     Debug,
//     Clone,
//     Hash,
//     Eq,
//     PartialEq,
//     Ord,
//     PartialOrd,
//     derive_more::From,
//     derive_more::Into,
//     derive_more::Deref,
// )]
// pub struct Path(
//     willow_data_model::Path<MAX_COMPONENT_LENGTH, MAX_COMPONENT_COUNT, MAX_PATH_LENGTH>,
// );

pub type Path = willow_data_model::Path<MAX_COMPONENT_LENGTH, MAX_COMPONENT_COUNT, MAX_PATH_LENGTH>;

#[derive(Debug, thiserror::Error)]
/// An error arising from trying to construct a invalid [`Path`] from valid components.
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

pub trait PathExt {
    fn new(slices: &[&[u8]]) -> Result<Path, InvalidPathError2>;
}

impl PathExt for Path {
    fn new(slices: &[&[u8]]) -> Result<Self, InvalidPathError2> {
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

pub type Entry = willow_data_model::Entry<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    NamespaceId,
    SubspaceId,
    PayloadDigest,
>;

pub trait EntryExt {
    fn encode_to_vec(&self) -> Vec<u8>;
    fn decode_from_slice(bytes: &[u8]) -> anyhow::Result<Entry>;
    fn as_set_sort_tuple(&self) -> (&NamespaceId, &SubspaceId, &Path);
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

    fn as_set_sort_tuple(&self) -> (&NamespaceId, &SubspaceId, &Path) {
        (self.namespace_id(), self.subspace_id(), self.path())
    }
}

#[derive(Debug, Clone)]
pub struct AuthorisedEntry(pub Entry, pub AuthorisationToken);

impl std::ops::Deref for AuthorisedEntry {
    type Target = Entry;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AuthorisedEntry {
    pub fn entry(&self) -> &Entry {
        &self.0
    }

    pub fn try_authorise(entry: Entry, token: AuthorisationToken) -> Result<Self, Unauthorised> {
        if token.is_authorised_write(&entry) {
            Ok(AuthorisedEntry(entry, token))
        } else {
            Err(Unauthorised)
        }
    }

    pub fn into_parts(self) -> (Entry, AuthorisationToken) {
        (self.0, self.1)
    }
}

/// Error returned for entries that are not authorised.
///
/// See [`is_authorised_write`] for details.
#[derive(Debug, thiserror::Error)]
#[error("Entry is not authorised")]
pub struct Unauthorised;

// #[derive(Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref)]
// pub type AuthorisedEntry =
//     willow_data_model::AuthorisedEntry<
//         MAX_COMPONENT_LENGTH,
//         MAX_COMPONENT_COUNT,
//         MAX_PATH_LENGTH,
//         NamespaceId,
//         SubspaceId,
//         PayloadDigest,
//         AuthorisationToken,
//     >;

// pub type Path = willow_data_model::Path<MAX_COMPONENT_LENGTH, MAX_COMPONENT_COUNT, MAX_PATH_LENGTH>;

// pub type Entry = willow_data_model::Entry<
//     MAX_COMPONENT_LENGTH,
//     MAX_COMPONENT_COUNT,
//     MAX_PATH_LENGTH,
//     NamespaceId,
//     SubspaceId,
//     PayloadDigest,
// >;

// pub type AuthorisedEntry = willow_data_model::AuthorisedEntry<
//     MAX_COMPONENT_LENGTH,
//     MAX_COMPONENT_COUNT,
//     MAX_PATH_LENGTH,
//     NamespaceId,
//     SubspaceId,
//     PayloadDigest,
//     AuthorisationToken,
// >;

impl willow_data_model::PayloadDigest for PayloadDigest {}

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
    use serde::{Deserialize, Deserializer, Serialize};
    use ufotofu::sync::{consumer::IntoVec, producer::FromSlice};
    use willow_encoding::sync::{Decodable, Encodable};

    use super::*;

    #[derive(Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref)]
    pub struct SerdeEntry(pub Entry);

    impl Serialize for SerdeEntry {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let encoded = {
                let mut consumer = IntoVec::<u8>::new();
                self.0.encode(&mut consumer).expect("encoding not to fail");
                consumer.into_vec()
            };
            encoded.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for SerdeEntry {
        fn deserialize<D>(deserializer: D) -> Result<SerdeEntry, D::Error>
        where
            D: Deserializer<'de>,
        {
            let data: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let decoded = {
                let mut producer = FromSlice::new(&data);
                let decoded = willow_data_model::Entry::decode(&mut producer)
                    .map_err(serde::de::Error::custom)?;
                Self(decoded)
            };
            Ok(decoded)
        }
    }
}

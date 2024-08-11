use iroh_base::hash::Hash;
use willow_data_model::InvalidPathError;

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
        let iter = slices.iter().map(|c| Component::new(c)).flatten();
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

#[derive(Debug, Clone, Eq, PartialEq, derive_more::From, derive_more::Into, derive_more::Deref)]
pub struct Entry(
    willow_data_model::Entry<
        MAX_COMPONENT_LENGTH,
        MAX_COMPONENT_COUNT,
        MAX_PATH_LENGTH,
        NamespaceId,
        SubspaceId,
        PayloadDigest,
    >,
);

#[derive(Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref)]
pub struct AuthorisedEntry(
    willow_data_model::AuthorisedEntry<
        MAX_COMPONENT_LENGTH,
        MAX_COMPONENT_COUNT,
        MAX_PATH_LENGTH,
        NamespaceId,
        SubspaceId,
        PayloadDigest,
        AuthorisationToken,
    >,
);

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

// /// A PossiblyAuthorisedEntry is a pair of an Entry and an AuthorisationToken.
// #[derive(Debug, Serialize, Deserialize)]
// pub struct PossiblyAuthorisedEntry(Entry, AuthorisationToken);

// impl PossiblyAuthorisedEntry {
//     pub fn new(entry: Entry, authorisation_token: AuthorisationToken) -> Self {
//         Self(entry, authorisation_token)
//     }
//     pub fn is_authorised(&self) -> bool {
//         is_authorised_write(&self.0, &self.1)
//     }

//     pub fn authorise(self) -> Result<AuthorisedEntry, Unauthorised> {
//         match self.is_authorised() {
//             true => Ok(AuthorisedEntry(self.0, self.1)),
//             false => Err(Unauthorised),
//         }
//     }

//     pub fn into_parts(self) -> (Entry, AuthorisationToken) {
//         (self.0, self.1)
//     }
// }

// impl TryFrom<PossiblyAuthorisedEntry> for AuthorisedEntry {
//     type Error = Unauthorised;
//     fn try_from(value: PossiblyAuthorisedEntry) -> Result<Self, Self::Error> {
//         value.authorise()
//     }
// }

// /// An AuthorisedEntry is a PossiblyAuthorisedEntry for which is_authorised_write returns true.
// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct AuthorisedEntry(Entry, AuthorisationToken);

// impl AuthorisedEntry {
//     pub fn try_from_parts(
//         entry: Entry,
//         static_token: StaticToken,
//         dynamic_token: DynamicToken,
//     ) -> Result<Self, Unauthorised> {
//         let authorisation_token = AuthorisationToken::from_parts(static_token, dynamic_token);
//         PossiblyAuthorisedEntry::new(entry, authorisation_token).authorise()
//     }

//     pub fn entry(&self) -> &Entry {
//         &self.0
//     }

//     pub fn into_entry(self) -> Entry {
//         self.0
//     }

//     pub fn is_authorised(&self) -> bool {
//         true
//     }

//     /// Use only if you can assure that the authorisation was previously checked!
//     pub fn from_parts_unchecked(entry: Entry, authorisation_token: AuthorisationToken) -> Self {
//         Self(entry, authorisation_token)
//     }

//     pub fn into_parts(self) -> (Entry, AuthorisationToken) {
//         (self.0, self.1)
//     }

//     pub fn namespace_id(&self) -> NamespaceId {
//         self.1.capability.granted_namespace().into()
//     }
// }

// // TODO: zerocopy support for path
// // #[allow(missing_debug_implementations)]
// // #[derive(KnownLayout, FromBytes, NoCell, Unaligned, IntoBytes)]
// // #[repr(C, packed)]
// // pub struct ComponentRef([u8]);
// //
// // #[allow(missing_debug_implementations)]
// // #[derive(KnownLayout, FromBytes, NoCell, Unaligned, IntoBytes)]
// // #[repr(C, packed)]
// // pub struct PathRef([ComponentRef]);
// // pub struct PathRef<'a>(&'a [&'a [u8]]);
// // impl<'a> AsRef<PathRef<'a>> for Path {
// //     fn as_ref(&'a self) -> &'a PathRef<'a> {
// //         todo!()
// //     }
// // }

// pub mod encodings {
//     //! Encoding for Willow entries
//     //!
//     //! TODO: Verify that these are correct accoring to the spec! These encodings are the message
//     //! bytes for authorisation signatures, so we better not need to change them again.

//     use std::io::Write;

//     use bytes::Bytes;

//     use crate::{
//         proto::willow::{NamespaceId, SubspaceId},
//         util::codec::Encoder,
//     };

//     use super::{Entry, Path, DIGEST_LENGTH};

//     /// `PATH_LENGTH_POWER` is the least natural number such that `256 ^ PATH_LENGTH_POWER ≥ MAX_COMPONENT_LENGTH`.
//     /// We can represent the length of any Component in path_length_power bytes.
//     /// UPathLengthPower denotes the type of numbers between zero (inclusive) and 256path_length_power (exclusive).
//     ///
//     /// The value `2` means that we can encode paths up to 64KiB long.
//     pub const PATH_LENGTH_POWER: usize = 2;
//     pub const PATH_COUNT_POWER: usize = PATH_LENGTH_POWER;
//     pub type UPathLengthPower = u16;
//     pub type UPathCountPower = u16;

//     impl Encoder for Path {
//         fn encoded_len(&self) -> usize {
//             let lengths_len = PATH_COUNT_POWER + self.len() * PATH_LENGTH_POWER;
//             let data_len = self.iter().map(Bytes::len).sum::<usize>();
//             lengths_len + data_len
//         }

//         /// Encode in the format for signatures into a mutable vector.
//         fn encode_into<W: Write>(&self, out: &mut W) -> anyhow::Result<()> {
//             let component_count = self.len() as UPathCountPower;
//             out.write_all(&component_count.to_be_bytes())?;
//             for component in self.iter() {
//                 let len = component.len() as UPathLengthPower;
//                 out.write_all(&len.to_be_bytes())?;
//                 out.write_all(component)?;
//             }
//             Ok(())
//         }
//     }

//     impl Encoder for entry {
//         fn encode_into<W: Write>(&self, out: &mut W) -> anyhow::Result<()> {
//             out.write_all(self.namespace_id.as_bytes())?;
//             out.write_all(self.subspace_id.as_bytes())?;
//             self.path.encode_into(out)?;
//             out.write_all(&self.timestamp.to_be_bytes())?;
//             out.write_all(&self.payload_length.to_be_bytes())?;
//             out.write_all(self.payload_digest.as_bytes())?;
//             Ok(())
//         }

//         fn encoded_len(&self) -> usize {
//             let path_len = self.path.encoded_len();
//             NamespaceId::LENGTH + SubspaceId::LENGTH + path_len + 8 + 8 + DIGEST_LENGTH
//         }
//     }

//     #[derive(Debug, Clone)]
//     pub struct RelativePath<'a> {
//         pub path: &'a Path,
//         pub reference: &'a Path,
//     }
//     impl<'a> RelativePath<'a> {
//         pub fn new(path: &'a Path, reference: &'a Path) -> Self {
//             Self { path, reference }
//         }
//     }

//     impl<'a> Encoder for RelativePath<'a> {
//         fn encoded_len(&self) -> usize {
//             let common_prefix_len = self.path.common_prefix_len(self.reference) as UPathCountPower;
//             let remaining_path = self.path.remove_prefix(common_prefix_len as usize);
//             PATH_COUNT_POWER + remaining_path.encoded_len()
//         }

//         fn encode_into<W: Write>(&self, out: &mut W) -> anyhow::Result<()> {
//             let common_prefix_len = self.path.common_prefix_len(self.reference) as UPathCountPower;
//             out.write_all(&common_prefix_len.to_be_bytes())?;
//             let remaining_path = self.path.remove_prefix(common_prefix_len as usize);
//             remaining_path.encode_into(out)?;
//             Ok(())
//         }
//     }
// }

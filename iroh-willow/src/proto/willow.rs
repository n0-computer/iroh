use std::{cmp::Ordering, sync::Arc};

use bytes::Bytes;
use iroh_base::hash::Hash;
use serde::{Deserialize, Serialize};
use zerocopy::{native_endian::U64, FromBytes, IntoBytes, KnownLayout, NoCell, Unaligned};

use super::{
    keys::{self, UserSecretKey, PUBLIC_KEY_LENGTH},
    meadowcap::{
        self, attach_authorisation, create_token, is_authorised_write, InvalidParams, McCapability,
    },
};

/// A type for identifying namespaces.
pub type NamespaceId = keys::NamespaceId;

/// A type for identifying subspaces.
pub type SubspaceId = keys::UserId;

/// A Timestamp is a 64-bit unsigned integer, that is, a natural number between zero (inclusive) and 2^64 - 1 (exclusive).
/// Timestamps are to be interpreted as a time in microseconds since the Unix epoch.
pub type Timestamp = u64;

/// A totally ordered type for content-addressing the data that Willow stores.
pub type PayloadDigest = Hash;

/// The type of components of a [`Path`].
pub type Component = Bytes;

// A for proving write permission.
pub type AuthorisationToken = meadowcap::MeadowcapAuthorisationToken;

/// A natural number for limiting the length of path components.
pub const MAX_COMPONENT_LENGTH: usize = 4096;

/// A natural number for limiting the number of path components.
pub const MAX_COMPONENT_COUNT: usize = 1024;

/// A natural number max_path_length for limiting the overall size of paths.
pub const MAX_PATH_LENGTH: usize = 4096;

/// The byte length of a [`PayloadDigest`].
pub const DIGEST_LENGTH: usize = 32;

/// Error returned for entries that are not authorised.
///
/// See [`is_authorised_write`] for details.
#[derive(Debug, thiserror::Error)]
#[error("Entry is not authorised")]
pub struct Unauthorised;

/// Error returned for invalid paths.
#[derive(Debug, thiserror::Error)]
#[error("Entry is not authorised")]
pub enum InvalidPath {
    #[error("Component with index {0} exceeds the maximum component length")]
    ComponentTooLong(usize),
    #[error("The path exceeds the maximum component length")]
    PathTooLong,
    #[error("The path exceeds the maximum component count")]
    TooManyComponents,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Path(Arc<[Component]>);

impl Default for Path {
    fn default() -> Self {
        Path::empty()
    }
}
impl Path {
    pub fn new(components: &[&[u8]]) -> Result<Self, InvalidPath> {
        Self::validate(components)?;
        let components: Vec<Component> = components
            .iter()
            .map(|c| Bytes::copy_from_slice(c))
            .collect();
        Ok(Self::from_bytes_unchecked(components))
    }

    pub fn from_bytes_unchecked(components: Vec<Bytes>) -> Self {
        let path: Arc<[Component]> = components.into();
        Path(path)
    }

    pub fn validate(components: &[&[u8]]) -> Result<(), InvalidPath> {
        if components.len() > MAX_COMPONENT_COUNT {
            return Err(InvalidPath::TooManyComponents);
        }
        let mut total_len = 0;
        for (i, component) in components.iter().enumerate() {
            let len = component.len();
            if len > MAX_COMPONENT_LENGTH {
                return Err(InvalidPath::ComponentTooLong(i));
            }
            total_len += len;
        }
        if total_len > MAX_PATH_LENGTH {
            return Err(InvalidPath::PathTooLong);
        }
        Ok(())
    }

    /// A `Path` `s` is a prefix of a `Path` `t` if the first [`Component`]s of `t` are exactly the `Component`s of `s`.
    pub fn is_prefix_of(&self, other: &Path) -> bool {
        other.0.starts_with(&self.0)
    }

    /// Create an empty path.
    pub fn empty() -> Self {
        Self(Arc::new([]))
    }

    pub fn intersection(&self, other: &Path) -> Option<Path> {
        if self.is_prefix_of(other) {
            Some(self.clone())
        } else if other.is_prefix_of(self) {
            Some(other.clone())
        } else {
            None
        }
    }
}

impl std::ops::Deref for Path {
    type Target = [Component];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Self) -> Ordering {
        for (i, component) in self.iter().enumerate() {
            match other.get(i) {
                Some(other_component) => match component.cmp(other_component) {
                    Ordering::Equal => continue,
                    ordering @ _ => return ordering,
                },
                None => return Ordering::Greater,
            }
        }
        Ordering::Equal
    }
}

/// The metadata for storing a Payload.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Hash)]
pub struct Entry {
    /// The identifier of the namespace to which the Entry belongs.
    pub namespace_id: NamespaceId,
    /// The identifier of the subspace to which the Entry belongs.
    pub subspace_id: SubspaceId,
    /// The Path to which the Entry was written.
    pub path: Path,
    /// The claimed creation time of the Entry.
    ///
    /// Wall-clock timestamps may come as a surprise. We are cognisant of their limitations,
    /// and use them anyway. To learn why, please see Timestamps, really?
    pub timestamp: Timestamp,
    /// The length of the Payload in bytes.
    pub payload_length: u64,
    /// The result of applying hash_payload to the Payload.
    pub payload_digest: PayloadDigest,
}

impl Entry {
    pub fn is_newer_than(&self, other: &Entry) -> bool {
        other.timestamp < self.timestamp
            || (other.timestamp == self.timestamp && other.payload_digest < self.payload_digest)
            || (other.timestamp == self.timestamp
                && other.payload_digest == self.payload_digest
                && other.payload_length < self.payload_length)
    }

    pub fn as_set_sort_tuple(&self) -> (&NamespaceId, &SubspaceId, &Path) {
        (&self.namespace_id, &self.subspace_id, &self.path)
    }

    pub fn attach_authorisation(
        self,
        capability: McCapability,
        secret_key: &UserSecretKey,
    ) -> Result<AuthorisedEntry, InvalidParams> {
        attach_authorisation(self, capability, secret_key)
    }
}

/// A PossiblyAuthorisedEntry is a pair of an Entry and an AuthorisationToken.
#[derive(Debug, Serialize, Deserialize)]
pub struct PossiblyAuthorisedEntry(Entry, AuthorisationToken);

impl PossiblyAuthorisedEntry {
    pub fn new(entry: Entry, authorisation_token: AuthorisationToken) -> Self {
        Self(entry, authorisation_token)
    }
    pub fn is_authorised(&self) -> bool {
        is_authorised_write(&self.0, &self.1)
    }

    pub fn authorise(self) -> Result<AuthorisedEntry, Unauthorised> {
        match self.is_authorised() {
            true => Ok(AuthorisedEntry(self.0, self.1)),
            false => Err(Unauthorised),
        }
    }

    pub fn into_parts(self) -> (Entry, AuthorisationToken) {
        (self.0, self.1)
    }
}

impl TryFrom<PossiblyAuthorisedEntry> for AuthorisedEntry {
    type Error = Unauthorised;
    fn try_from(value: PossiblyAuthorisedEntry) -> Result<Self, Self::Error> {
        value.authorise()
    }
}

/// An AuthorisedEntry is a PossiblyAuthorisedEntry for which is_authorised_write returns true.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthorisedEntry(Entry, AuthorisationToken);

impl AuthorisedEntry {
    pub fn try_from_parts(
        entry: Entry,
        authorisation_token: AuthorisationToken,
    ) -> Result<Self, Unauthorised> {
        PossiblyAuthorisedEntry::new(entry, authorisation_token).authorise()
    }

    pub fn entry(&self) -> &Entry {
        &self.0
    }

    pub fn into_entry(self) -> Entry {
        self.0
    }

    pub fn is_authorised(&self) -> bool {
        true
    }

    /// Use only if you can assure that the authorisation was previously checked!
    pub fn from_parts_unchecked(entry: Entry, authorisation_token: AuthorisationToken) -> Self {
        Self(entry, authorisation_token)
    }

    pub fn into_parts(self) -> (Entry, AuthorisationToken) {
        (self.0, self.1)
    }

    pub fn namespace_id(&self) -> NamespaceId {
        self.1.capability.granted_namespace().into()
    }
}

// TODO: zerocopy support for path
// #[allow(missing_debug_implementations)]
// #[derive(KnownLayout, FromBytes, NoCell, Unaligned, IntoBytes)]
// #[repr(C, packed)]
// pub struct ComponentRef([u8]);
//
// #[allow(missing_debug_implementations)]
// #[derive(KnownLayout, FromBytes, NoCell, Unaligned, IntoBytes)]
// #[repr(C, packed)]
// pub struct PathRef([ComponentRef]);
// pub struct PathRef<'a>(&'a [&'a [u8]]);
// impl<'a> AsRef<PathRef<'a>> for Path {
//     fn as_ref(&'a self) -> &'a PathRef<'a> {
//         todo!()
//     }
// }

pub mod encodings {
    //! Encoding for Willow entries
    //!
    //! TODO: Verify that these are correct accoring to the spec! These encodings are the message
    //! bytes for authorisation signatures, so we better not need to change them again.

    use bytes::Bytes;

    use crate::proto::keys::PUBLIC_KEY_LENGTH;

    use super::{Entry, Path, DIGEST_LENGTH};

    /// `PATH_LENGTH_POWER` is the least natural number such that `256 ^ PATH_LENGTH_POWER ≥ MAX_COMPONENT_LENGTH`.
    /// We can represent the length of any Component in path_length_power bytes.
    /// UPathLengthPower denotes the type of numbers between zero (inclusive) and 256path_length_power (exclusive).
    ///
    /// The value `2` means that we can encode paths up to 64KiB long.
    const PATH_LENGTH_POWER: usize = 2;
    const PATH_COUNT_POWER: usize = PATH_LENGTH_POWER;
    type UPathLengthPower = u16;
    type UPathCountPower = u16;

    impl Path {
        pub fn encoded_len(&self) -> usize {
            let lengths_len = PATH_COUNT_POWER + self.len() * PATH_LENGTH_POWER;
            let data_len = self.iter().map(Bytes::len).sum::<usize>();
            lengths_len + data_len
        }

        /// Encode in the format for signatures into a mutable vector.
        pub fn encode_into(&self, out: &mut Vec<u8>) {
            let component_count = self.len() as UPathCountPower;
            out.extend_from_slice(&component_count.to_be_bytes());
            for component in self.iter() {
                let len = component.len() as UPathLengthPower;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&component);
            }
        }

        pub fn encode(&self) -> Vec<u8> {
            let mut out = Vec::with_capacity(self.encoded_len());
            self.encode_into(&mut out);
            out
        }
    }

    impl Entry {
        /// Convert the entry to a byte slice.
        ///
        /// This is invoked to create the signable for signatures over the entry. Thus, any change in
        /// the encoding format here will make existing signatures invalid.
        ///
        /// The encoding follows the [`Willow spec for encoding`](https://willowprotocol.org/specs/encodings/index.html#enc_entry).
        // TODO: make sure that the encoding fits the spec
        pub fn encode(&self) -> Vec<u8> {
            let len = self.encoded_len();
            let mut out = Vec::with_capacity(len);
            self.encode_into(&mut out);
            out
        }

        pub fn encode_into(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(self.namespace_id.as_bytes());
            out.extend_from_slice(self.subspace_id.as_bytes());
            self.path.encode_into(out);
            out.extend_from_slice(&self.timestamp.to_be_bytes());
            out.extend_from_slice(&self.payload_length.to_be_bytes());
            out.extend_from_slice(self.payload_digest.as_bytes());
        }

        pub fn encoded_len(&self) -> usize {
            let path_len = self.path.encoded_len();
            PUBLIC_KEY_LENGTH + PUBLIC_KEY_LENGTH + path_len + 8 + 8 + DIGEST_LENGTH
        }
    }
}

//! Storage trait and implementation for iroh-sync documents

use std::num::NonZeroUsize;

use anyhow::Result;
use bytes::Bytes;
use iroh_bytes::Hash;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    ranger,
    sync::{Author, Namespace, Replica, SignedEntry},
    AuthorId, NamespaceId, PeerIdBytes,
};

#[cfg(feature = "fs-store")]
pub mod fs;
pub mod memory;
mod pubkeys;
pub use pubkeys::*;

/// Number of [`PeerIdBytes`] objects to cache per document.
pub(crate) const PEERS_PER_DOC_CACHE_SIZE: NonZeroUsize = match NonZeroUsize::new(5) {
    Some(val) => val,
    None => panic!("this is clearly non zero"),
};

/// Error return from [`Store::open_replica`]
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The replica was already opened.
    #[error("Replica is already open")]
    AlreadyOpen,
    /// The replica does not exist.
    #[error("Replica not found")]
    NotFound,
    /// Other error while opening the replica.
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Abstraction over the different available storage solutions.
pub trait Store: std::fmt::Debug + Clone + Send + Sync + 'static {
    /// The specialized instance scoped to a `Namespace`.
    type Instance: ranger::Store<SignedEntry> + PublicKeyStore + Send + Sync + 'static + Clone;

    /// Iterator over entries in the store, returned from [`Self::get_many`]
    type GetIter<'a>: Iterator<Item = Result<SignedEntry>>
    where
        Self: 'a;

    /// Iterator over all content hashes in the store, returned from [`Self::content_hashes`]
    type ContentHashesIter<'a>: Iterator<Item = Result<Hash>>
    where
        Self: 'a;

    /// Iterator over replica namespaces in the store, returned from [`Self::list_namespaces`]
    type NamespaceIter<'a>: Iterator<Item = Result<NamespaceId>>
    where
        Self: 'a;

    /// Iterator over authors in the store, returned from [`Self::list_authors`]
    type AuthorsIter<'a>: Iterator<Item = Result<Author>>
    where
        Self: 'a;

    /// Iterator over peers in the store for a document, returned from [`Self::get_sync_peers`].
    type PeersIter<'a>: Iterator<Item = PeerIdBytes>
    where
        Self: 'a;

    /// Create a new replica for `namespace` and persist in this store.
    fn new_replica(&self, namespace: Namespace) -> Result<Replica<Self::Instance>> {
        let id = namespace.id();
        self.import_namespace(namespace)?;
        self.open_replica(&id).map_err(Into::into)
    }

    /// Import a new replica namespace.
    fn import_namespace(&self, namespace: Namespace) -> Result<()>;

    /// List all replica namespaces in this store.
    fn list_namespaces(&self) -> Result<Self::NamespaceIter<'_>>;

    /// Open a replica from this store.
    ///
    /// Store implementers must ensure that only a single instance of [`Replica`] is created per
    /// namespace. On subsequent calls, a clone of that singleton instance must be returned.
    fn open_replica(&self, namespace: &NamespaceId) -> Result<Replica<Self::Instance>, OpenError>;

    /// Close a replica.
    fn close_replica(&self, replica: Replica<Self::Instance>);

    /// Remove a replica.
    ///
    /// Completely removes a replica and deletes both the namespace private key and all document
    /// entries.
    ///
    /// Note that a replica has to be closed before it can be removed. The store has to enforce
    /// that a replica cannot be removed while it is still open.
    fn remove_replica(&self, namespace: &NamespaceId) -> Result<()>;

    /// Create a new author key and persist it in the store.
    fn new_author<R: CryptoRngCore + ?Sized>(&self, rng: &mut R) -> Result<Author> {
        let author = Author::new(rng);
        self.import_author(author.clone())?;
        Ok(author)
    }

    /// Import an author key pair.
    fn import_author(&self, author: Author) -> Result<()>;

    /// List all author keys in this store.
    fn list_authors(&self) -> Result<Self::AuthorsIter<'_>>;

    /// Get an author key from the store.
    fn get_author(&self, author: &AuthorId) -> Result<Option<Author>>;

    /// Get an iterator over entries of a replica.
    ///
    /// The [`GetFilter`] has several methods of filtering the returned entries.
    fn get_many(
        &self,
        namespace: NamespaceId,
        query: Query,
        view: View,
    ) -> Result<Self::GetIter<'_>>;

    /// Get an entry by key and author.
    fn get_one(
        &self,
        namespace: NamespaceId,
        author: impl Into<AuthorMatcher>,
        key: impl Into<KeyMatcher>,
    ) -> Result<Option<SignedEntry>>;

    /// Get all content hashes of all replicas in the store.
    fn content_hashes(&self) -> Result<Self::ContentHashesIter<'_>>;

    /// Register a peer that has been useful to sync a document.
    fn register_useful_peer(&self, namespace: NamespaceId, peer: PeerIdBytes) -> Result<()>;

    /// Get peers to use for syncing a document.
    fn get_sync_peers(&self, namespace: &NamespaceId) -> Result<Option<Self::PeersIter<'_>>>;
}

/// Returns the first matching result.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Query {
    author: AuthorMatcher,
    key: KeyMatcher,
    range: Range,
}

impl Query {
    /// Returns a query that will match everything.
    pub fn all() -> Self {
        Query::default()
    }

    /// Creates a query restricted to matching an author.
    pub fn author(author: AuthorId) -> Self {
        Query {
            author: AuthorMatcher::Exact(author),
            ..Default::default()
        }
    }

    /// Creates a query restricted to matching a key prefix.
    pub fn prefix(prefix: impl AsRef<[u8]>) -> Self {
        Query {
            key: KeyMatcher::Prefix(Bytes::copy_from_slice(prefix.as_ref())),
            ..Default::default()
        }
    }

    /// Creates a query restricted to matching an exact key.
    pub fn key(key: impl AsRef<[u8]>) -> Self {
        Query {
            key: KeyMatcher::Exact(Bytes::copy_from_slice(key.as_ref())),
            ..Default::default()
        }
    }

    /// Creates a query restricted to matching an author.
    pub fn with_author(mut self, author: AuthorId) -> Self {
        self.author = AuthorMatcher::Exact(author);
        self
    }

    /// Creates a query restricted to matching a key prefix.
    pub fn with_prefix(mut self, prefix: impl AsRef<[u8]>) -> Self {
        self.key = KeyMatcher::Prefix(Bytes::copy_from_slice(prefix.as_ref()));
        self
    }

    /// Creates a query restricted to matching an exact key.
    pub fn with_key(mut self, key: impl AsRef<[u8]>) -> Self {
        self.key = KeyMatcher::Exact(Bytes::copy_from_slice(key.as_ref()));
        self
    }
}

/// A range.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Range {
    /// ..
    All,
    /// x..
    From(u64),
    /// ..=x
    ToInclusive(u64),
    /// x..=y
    Inclusive(u64, u64),
    /// ..x
    To(u64),
    /// x..y
    Exclusive(u64, u64),
}

impl Default for Range {
    fn default() -> Self {
        Range::All
    }
}

impl Range {
    /// The start of the range.
    pub fn start(&self) -> u64 {
        match self {
            Self::All => 0,
            Self::From(start) => *start,
            Self::ToInclusive(_) => 0,
            Self::Inclusive(start, _) => *start,
            Self::To(_) => 0,
            Self::Exclusive(start, _) => *start,
        }
    }

    /// The optional end of the range, exclusive.
    pub fn end(&self) -> Option<u64> {
        match self {
            Self::All => None,
            Self::From(start) => None,
            Self::ToInclusive(end) => end.checked_add(1),
            Self::Inclusive(_, end) => end.checked_add(1),
            Self::To(end) => Some(*end),
            Self::Exclusive(_, end) => Some(*end),
        }
    }
}

impl From<std::ops::Range<u64>> for Range {
    fn from(value: std::ops::Range<u64>) -> Self {
        Range::Exclusive(value.start, value.end)
    }
}

impl From<std::ops::RangeFrom<u64>> for Range {
    fn from(value: std::ops::RangeFrom<u64>) -> Self {
        Range::From(value.start)
    }
}

impl From<std::ops::RangeFull> for Range {
    fn from(_: std::ops::RangeFull) -> Self {
        Range::All
    }
}

impl From<std::ops::RangeInclusive<u64>> for Range {
    fn from(value: std::ops::RangeInclusive<u64>) -> Self {
        let (start, end) = value.into_inner();
        Range::Inclusive(start, end)
    }
}

impl From<std::ops::RangeToInclusive<u64>> for Range {
    fn from(value: std::ops::RangeToInclusive<u64>) -> Self {
        Range::ToInclusive(value.end)
    }
}

impl From<std::ops::RangeTo<u64>> for Range {
    fn from(value: std::ops::RangeTo<u64>) -> Self {
        Range::To(value.end)
    }
}

/// Key matching.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KeyMatcher {
    /// Matches any key
    Any,
    /// Only keys that are exactly the provided value.
    Exact(Bytes),
    /// All keys matching the provided value.
    Prefix(Bytes),
}

impl Default for KeyMatcher {
    fn default() -> Self {
        KeyMatcher::Any
    }
}

impl<T: AsRef<[u8]>> From<T> for KeyMatcher {
    fn from(value: T) -> Self {
        KeyMatcher::Exact(Bytes::copy_from_slice(value.as_ref()))
    }
}

/// Author matching.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AuthorMatcher {
    /// Matches any author
    Any,
    /// Matches exactly the provided author
    Exact(AuthorId),
}

impl Default for AuthorMatcher {
    fn default() -> Self {
        AuthorMatcher::Any
    }
}

impl From<AuthorId> for AuthorMatcher {
    fn from(value: AuthorId) -> Self {
        AuthorMatcher::Exact(value)
    }
}

/// Virtual representation of the data.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum View {
    /// Returns for each key and author the latest version
    ///
    /// This is how data is stored under the hood and matches
    /// what is currently the "default" view
    LatestByKey,
    /// Returns for each key, the lastest version, independent of the author.
    LatestByKeyAndAuthor,
}

impl Default for View {
    fn default() -> Self {
        Self::LatestByKey
    }
}

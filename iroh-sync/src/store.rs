//! Storage trait and implementation for iroh-sync documents

use std::num::{NonZeroU64, NonZeroUsize};

use anyhow::Result;
use bytes::Bytes;
use iroh_bytes::Hash;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    heads::AuthorHeads,
    keys::{Author, Namespace},
    ranger,
    sync::{Replica, SignedEntry},
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

    /// Iterator over the latest entry for each author.
    ///
    /// The iterator returns a tuple of (AuthorId, Timestamp, Key).
    type LatestIter<'a>: Iterator<Item = Result<(AuthorId, u64, Vec<u8>)>>
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
    fn get_many(
        &self,
        namespace: NamespaceId,
        query: impl Into<Query>,
    ) -> Result<Self::GetIter<'_>>;

    /// Get an entry by key and author.
    fn get_one(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>>;

    /// Get all content hashes of all replicas in the store.
    fn content_hashes(&self) -> Result<Self::ContentHashesIter<'_>>;

    /// Get the latest entry for each author in a namespace.
    fn get_latest_for_each_author(&self, namespace: NamespaceId) -> Result<Self::LatestIter<'_>>;

    /// Check if a [`AuthorHeads`] contains entry timestamps that we do not have locally.
    ///
    /// Returns the number of authors that the other peer has updates for.
    fn has_news_for_us(
        &self,
        namespace: NamespaceId,
        heads: &AuthorHeads,
    ) -> Result<Option<NonZeroU64>> {
        let our_heads = {
            let latest = self.get_latest_for_each_author(namespace)?;
            let mut heads = AuthorHeads::default();
            for e in latest {
                let (author, timestamp, _key) = e?;
                heads.insert(author, timestamp);
            }
            heads
        };
        let has_news_for_us = heads.has_news_for(&our_heads);
        Ok(has_news_for_us)
    }

    /// Register a peer that has been useful to sync a document.
    fn register_useful_peer(&self, namespace: NamespaceId, peer: PeerIdBytes) -> Result<()>;

    /// Get peers to use for syncing a document.
    fn get_sync_peers(&self, namespace: &NamespaceId) -> Result<Option<Self::PeersIter<'_>>>;
}

/// A query builder for document queries.
#[derive(Debug, Default)]
pub struct QueryBuilder<K> {
    kind: K,
    filter_author: AuthorMatcher,
    filter_key: KeyMatcher,
    limit_offset: LimitOffset,
    include_empty: bool,
    sort_direction: SortDirection,
}

impl<K> QueryBuilder<K> {
    /// Call to include empty entries (deletion markers).
    pub fn include_empty(mut self) -> Self {
        self.include_empty = true;
        self
    }
    /// Filter by exact key match.
    pub fn key_exact(mut self, key: impl AsRef<[u8]>) -> Self {
        self.filter_key = KeyMatcher::Exact(key.as_ref().to_vec().into());
        self
    }
    /// Filter by key prefix.
    pub fn key_prefix(mut self, key: impl AsRef<[u8]>) -> Self {
        self.filter_key = KeyMatcher::Prefix(key.as_ref().to_vec().into());
        self
    }
    /// Filter by author.
    pub fn author(mut self, author: AuthorId) -> Self {
        self.filter_author = AuthorMatcher::Exact(author);
        self
    }
    /// Set the maximum number of entries to be returned.
    pub fn limit(mut self, limit: u64) -> Self {
        self.limit_offset.limit = Some(limit);
        self
    }
    /// Set the offset within the result set from where to start returning results.
    pub fn offset(mut self, offset: u64) -> Self {
        self.limit_offset.offset = Some(offset);
        self
    }
}

/// Query type for a [Query::flat]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FlatQuery {
    sort_by: SortBy,
}

/// Query type for a [Query::single_latest_per_key]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SingleLatestPerKeyQuery {}

impl QueryBuilder<FlatQuery> {
    /// Set the sort for the query.
    pub fn sort_by(mut self, sort_by: SortBy, direction: SortDirection) -> Self {
        self.kind.sort_by = sort_by;
        self.sort_direction = direction;
        self
    }
    /// Build the query.
    pub fn build(self) -> Query {
        Query::from(self)
    }
}

impl QueryBuilder<SingleLatestPerKeyQuery> {
    /// Set the order direction for the query.
    ///
    /// Ordering is always by key for this query type.
    pub fn key_ordering(mut self, direction: SortDirection) -> Self {
        self.sort_direction = direction;
        self
    }

    /// Build the query.
    pub fn build(self) -> Query {
        Query::from(self)
    }
}

impl From<QueryBuilder<SingleLatestPerKeyQuery>> for Query {
    fn from(builder: QueryBuilder<SingleLatestPerKeyQuery>) -> Query {
        let QueryBuilder {
            kind,
            filter_author,
            filter_key,
            limit_offset,
            include_empty,
            sort_direction: ordering,
        } = builder;

        Query {
            kind: QueryKind::SingleLatestPerKey(kind),
            filter_author,
            filter_key,
            limit_offset,
            include_empty,
            ordering,
        }
    }
}

impl From<QueryBuilder<FlatQuery>> for Query {
    fn from(builder: QueryBuilder<FlatQuery>) -> Query {
        let QueryBuilder {
            kind,
            filter_author,
            filter_key,
            limit_offset,
            include_empty,
            sort_direction: ordering,
        } = builder;

        Query {
            kind: QueryKind::Flat(kind),
            filter_author,
            filter_key,
            limit_offset,
            include_empty,
            ordering,
        }
    }
}

/// Note: When using the `SingleLatestPerKey` query kind, the key filter is applied *before* the
/// grouping, the author filter is applied *after* the grouping.
#[derive(Debug, Serialize, Deserialize)]
pub struct Query {
    kind: QueryKind,
    filter_author: AuthorMatcher,
    filter_key: KeyMatcher,
    limit_offset: LimitOffset,
    include_empty: bool,
    ordering: SortDirection,
}

impl Query {
    /// Query all records.
    pub fn all() -> QueryBuilder<FlatQuery> {
        Default::default()
    }
    /// Query only the latest entry for each key, omitting older entries if the entry was written
    /// to by multiple authors.
    pub fn single_latest_per_key() -> QueryBuilder<SingleLatestPerKeyQuery> {
        Default::default()
    }

    /// Create a [Query::all] query filtered by a single author.
    pub fn author(author: AuthorId) -> QueryBuilder<FlatQuery> {
        Self::all().author(author)
    }

    /// Create a [Query::all] query filtered by a single key.
    pub fn key(key: impl AsRef<[u8]>) -> QueryBuilder<FlatQuery> {
        Self::all().key_exact(key)
    }

    /// Create a [Query::all] query filtered by a key prefix.
    pub fn prefix(prefix: impl AsRef<[u8]>) -> QueryBuilder<FlatQuery> {
        Self::all().key_prefix(prefix)
    }
}

/// Sort direction
#[derive(Debug, Default, Serialize, Deserialize)]
pub enum SortDirection {
    /// Sort ascending
    #[default]
    Asc,
    /// Sort descending
    Desc,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LimitOffset {
    limit: Option<u64>,
    offset: Option<u64>,
}

impl LimitOffset {
    fn offset(&self) -> u64 {
        self.offset.unwrap_or(0)
    }

    fn limit(&self) -> Option<u64> {
        self.limit
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum QueryKind {
    Flat(FlatQuery),
    SingleLatestPerKey(SingleLatestPerKeyQuery),
}

/// Fields by which the query can be sorted
#[derive(Debug, Default, Serialize, Deserialize)]
pub enum SortBy {
    /// Sort by key.
    Key,
    /// Sort by author.
    #[default]
    Author,
}

/// Key matching.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub enum KeyMatcher {
    /// Matches any key
    #[default]
    Any,
    /// Only keys that are exactly the provided value.
    Exact(Bytes),
    /// All keys matching the provided value.
    Prefix(Bytes),
}

impl<T: AsRef<[u8]>> From<T> for KeyMatcher {
    fn from(value: T) -> Self {
        KeyMatcher::Exact(Bytes::copy_from_slice(value.as_ref()))
    }
}

impl KeyMatcher {
    /// Test if a key is matched by this [`KeyMatcher`].
    pub fn matches(&self, key: &[u8]) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(k) => &k[..] == key,
            Self::Prefix(p) => key.starts_with(&p),
        }
    }
}

/// Author matching.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub enum AuthorMatcher {
    /// Matches any author
    #[default]
    Any,
    /// Matches exactly the provided author
    Exact(AuthorId),
}

impl AuthorMatcher {
    /// Test if an author is matched by this [`AuthorMatcher`].
    pub fn matches(&self, author: &AuthorId) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(a) => a == author,
        }
    }
}

impl From<AuthorId> for AuthorMatcher {
    fn from(value: AuthorId) -> Self {
        AuthorMatcher::Exact(value)
    }
}

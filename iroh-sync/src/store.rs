//! Storage trait and implementation for iroh-sync documents

use std::num::{NonZeroU64, NonZeroUsize};

use anyhow::Result;
use bytes::Bytes;
use iroh_base::hash::Hash;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    heads::AuthorHeads,
    keys::{Author, NamespaceSecret},
    ranger,
    sync::{Replica, SignedEntry},
    AuthorId, Capability, CapabilityKind, Entry, NamespaceId, PeerIdBytes,
};

#[cfg(feature = "fs-store")]
pub mod fs;
pub mod memory;
mod pubkeys;
mod util;
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
    /// The specialized instance scoped to a `NamespaceSecret`.
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
    type NamespaceIter<'a>: Iterator<Item = Result<(NamespaceId, CapabilityKind)>>
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
    fn new_replica(&self, namespace: NamespaceSecret) -> Result<Replica<Self::Instance>> {
        let id = namespace.id();
        self.import_namespace(namespace.into())?;
        self.open_replica(&id).map_err(Into::into)
    }

    /// Import a new replica namespace.
    fn import_namespace(&self, capability: Capability) -> Result<ImportNamespaceOutcome>;

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
    fn get_exact(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
        include_empty: bool,
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

    /// Set the download policy for a document.
    fn set_download_policy(&self, namespace: &NamespaceId, policy: DownloadPolicy) -> Result<()>;
    /// Get the download policy for a document.
    fn get_download_policy(&self, namespace: &NamespaceId) -> Result<DownloadPolicy>;
}

/// Outcome of [`Store::import_namespace`]
#[derive(Debug, Clone, Copy)]
pub enum ImportNamespaceOutcome {
    /// The namespace did not exist before and is now inserted.
    Inserted,
    /// The namespace existed and now has an upgraded capability.
    Upgraded,
    /// The namespace existed and its capability remains unchanged.
    NoChange,
}

/// Download policy to decide which content blobs shall be downloaded.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum DownloadPolicy {
    /// Do not download any blobs.
    Nothing,
    /// Download all blobs.
    #[default]
    Everything,
    /// Download blobs for entries matching a query.
    Query(Query),
}

/// Filter strategy used in download policies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FilterKind {
    /// Matches if the contained bytes are a prefix of the key.
    Prefix(Bytes),
    /// Matches if the contained bytes and the key are the same.
    Exact(Bytes),
}

impl std::fmt::Display for FilterKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // hardly usable but good enough as a poc
        let (kind, bytes) = match self {
            FilterKind::Prefix(bytes) => ("prefix", bytes),
            FilterKind::Exact(bytes) => ("exact", bytes),
        };
        let (encoding, repr) = match String::from_utf8(bytes.to_vec()) {
            Ok(repr) => ("utf8", repr),
            Err(_) => ("hex", hex::encode(bytes)),
        };
        write!(f, "{kind}:{encoding}:{repr}")
    }
}

impl std::str::FromStr for FilterKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let Some((kind, rest)) = s.split_once(":") else {
            anyhow::bail!("missing filter kind, either \"prefix:\" or \"exact:\"")
        };
        let Some((encoding, rest)) = rest.split_once(":") else {
            anyhow::bail!("missing encoding: either \"hex:\" or \"utf8:\"")
        };

        let is_exact = match kind {
            "exact" => true,
            "prefix" => false,
            other => {
                anyhow::bail!("expected filter kind \"prefix:\" or \"exact:\", found {other}")
            }
        };

        let decoded = match encoding {
            "utf8" => Bytes::from(rest.to_owned()),
            "hex" => match hex::decode(rest) {
                Ok(bytes) => Bytes::from(bytes),
                Err(_) => anyhow::bail!("failed to decode hex"),
            },
            other => {
                anyhow::bail!("expected encoding: either \"hex:\" or \"utf8:\", found {other}")
            }
        };

        if is_exact {
            Ok(FilterKind::Exact(decoded))
        } else {
            Ok(FilterKind::Prefix(decoded))
        }
    }
}

/*
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum DownloadPolicy {
    /// Download all keys unless a prefix matches it.
    #[default]
    EverythingExcept(Vec(KeyFilter)),
    /// Do not download any key unless a prefix matches it.
    NothingExcept(Vec(KeyFilter)),
}
*/

impl DownloadPolicy {
    /// Check if an entry should be downloaded according to this policy.
    pub fn matches(&self, entry: &Entry) -> bool {
        match self {
            DownloadPolicy::Nothing => false,
            DownloadPolicy::Everything => true,
            DownloadPolicy::Query(query) => {
                query.filter_author.matches(&entry.author())
                    && query.filter_key.matches(entry.key())
            }
        }
    }
}

/// A query builder for document queries.
#[derive(Debug, Default)]
pub struct QueryBuilder<K> {
    kind: K,
    filter_author: AuthorFilter,
    filter_key: KeyFilter,
    limit: Option<u64>,
    offset: u64,
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
        self.filter_key = KeyFilter::Exact(key.as_ref().to_vec().into());
        self
    }
    /// Filter by key prefix.
    pub fn key_prefix(mut self, key: impl AsRef<[u8]>) -> Self {
        self.filter_key = KeyFilter::Prefix(key.as_ref().to_vec().into());
        self
    }
    /// Filter by author.
    pub fn author(mut self, author: AuthorId) -> Self {
        self.filter_author = AuthorFilter::Exact(author);
        self
    }
    /// Set the maximum number of entries to be returned.
    pub fn limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
    /// Set the offset within the result set from where to start returning results.
    pub fn offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }
}

/// Query on all entries without aggregation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlatQuery {
    sort_by: SortBy,
}

/// Query that only returns the latest entry for a key which has entries from multiple authors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SingleLatestPerKeyQuery {}

impl QueryBuilder<FlatQuery> {
    /// Set the sort for the query.
    ///
    /// The default is to sort by author, then by key, in ascending order.
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
    /// Default direction is ascending.
    pub fn sort_direction(mut self, direction: SortDirection) -> Self {
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
        Query {
            kind: QueryKind::SingleLatestPerKey(builder.kind),
            filter_author: builder.filter_author,
            filter_key: builder.filter_key,
            limit: builder.limit,
            offset: builder.offset,
            include_empty: builder.include_empty,
            sort_direction: builder.sort_direction,
        }
    }
}

impl From<QueryBuilder<FlatQuery>> for Query {
    fn from(builder: QueryBuilder<FlatQuery>) -> Query {
        Query {
            kind: QueryKind::Flat(builder.kind),
            filter_author: builder.filter_author,
            filter_key: builder.filter_key,
            limit: builder.limit,
            offset: builder.offset,
            include_empty: builder.include_empty,
            sort_direction: builder.sort_direction,
        }
    }
}

/// Note: When using the `SingleLatestPerKey` query kind, the key filter is applied *before* the
/// grouping, the author filter is applied *after* the grouping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    kind: QueryKind,
    filter_author: AuthorFilter,
    filter_key: KeyFilter,
    limit: Option<u64>,
    offset: u64,
    include_empty: bool,
    sort_direction: SortDirection,
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

    /// Create a [`Query::all`] query filtered by a single author.
    pub fn author(author: AuthorId) -> QueryBuilder<FlatQuery> {
        Self::all().author(author)
    }

    /// Create a [`Query::all`] query filtered by a single key.
    pub fn key_exact(key: impl AsRef<[u8]>) -> QueryBuilder<FlatQuery> {
        Self::all().key_exact(key)
    }

    /// Create a [`Query::all`] query filtered by a key prefix.
    pub fn key_prefix(prefix: impl AsRef<[u8]>) -> QueryBuilder<FlatQuery> {
        Self::all().key_prefix(prefix)
    }

    /// Get the limit for this query (max. number of entries to emit).
    pub fn limit(&self) -> Option<u64> {
        self.limit
    }

    /// Get the offset for this query (number of entries to skip at the beginning).
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

/// Sort direction
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub enum SortDirection {
    /// Sort ascending
    #[default]
    Asc,
    /// Sort descending
    Desc,
}

#[derive(derive_more::Debug, Clone, Serialize, Deserialize)]
enum QueryKind {
    #[debug("Flat {{ sort_by: {:?}}}", _0)]
    Flat(FlatQuery),
    #[debug("SingleLatestPerKey")]
    SingleLatestPerKey(SingleLatestPerKeyQuery),
}

/// Fields by which the query can be sorted
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub enum SortBy {
    /// Sort by key, then author.
    KeyAuthor,
    /// Sort by author, then key.
    #[default]
    AuthorKey,
}

/// Key matching.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub enum KeyFilter {
    /// Matches any key.
    #[default]
    Any,
    /// Only keys that are exactly the provided value.
    Exact(Bytes),
    /// All keys that start with the provided value.
    Prefix(Bytes),
}

impl<T: AsRef<[u8]>> From<T> for KeyFilter {
    fn from(value: T) -> Self {
        KeyFilter::Exact(Bytes::copy_from_slice(value.as_ref()))
    }
}

impl KeyFilter {
    /// Test if a key is matched by this [`KeyFilter`].
    pub fn matches(&self, key: &[u8]) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(k) => &k[..] == key,
            Self::Prefix(p) => key.starts_with(p),
        }
    }
}

/// Author matching.
#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub enum AuthorFilter {
    /// Matches any author.
    #[default]
    Any,
    /// Matches exactly the provided author.
    Exact(AuthorId),
}

impl AuthorFilter {
    /// Test if an author is matched by this [`AuthorFilter`].
    pub fn matches(&self, author: &AuthorId) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(a) => a == author,
        }
    }
}

impl From<AuthorId> for AuthorFilter {
    fn from(value: AuthorId) -> Self {
        AuthorFilter::Exact(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_kind_encode_decode() {
        const REPR: &str = "prefix:utf8:memes/futurama";
        let filter: FilterKind = REPR.parse().expect("should decode");
        assert_eq!(
            filter,
            FilterKind::Prefix(Bytes::from(String::from("memes/futurama")))
        );
        assert_eq!(filter.to_string(), REPR)
    }
}

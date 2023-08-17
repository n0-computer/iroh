//! Storage trait and implementation for iroh-sync documents

use anyhow::Result;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    ranger,
    sync::{Author, AuthorId, Namespace, NamespaceId, RecordIdentifier, Replica, SignedEntry},
};

#[cfg(feature = "fs-store")]
pub mod fs;
pub mod memory;

/// Abstraction over the different available storage solutions.
pub trait Store: std::fmt::Debug + Clone + Send + Sync + 'static {
    /// The specialized instance scoped to a `Namespace`.
    type Instance: ranger::Store<RecordIdentifier, SignedEntry> + Send + Sync + 'static + Clone;

    /// Iterator over entries in the store, returned from [`Self::get`]
    type GetIter<'a>: Iterator<Item = Result<SignedEntry>>
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

    /// Create a new replica for `namespace` and persist in this store.
    fn new_replica(&self, namespace: Namespace) -> Result<Replica<Self::Instance>>;

    /// List all replica namespaces in this store.
    fn list_namespaces(&self) -> Result<Self::NamespaceIter<'_>>;

    /// Open a replica from this store.
    ///
    /// Store implementers must ensure that only a single instance of [`Replica`] is created per
    /// namespace. On subsequent calls, a clone of that singleton instance must be returned.
    ///
    // TODO: Add close_replica
    fn open_replica(&self, namespace: &NamespaceId) -> Result<Option<Replica<Self::Instance>>>;

    /// Create a new author key key and persist it in the store.
    fn new_author<R: CryptoRngCore + ?Sized>(&self, rng: &mut R) -> Result<Author>;

    /// List all author keys in this store.
    fn list_authors(&self) -> Result<Self::AuthorsIter<'_>>;

    /// Get an author key from the store.
    fn get_author(&self, author: &AuthorId) -> Result<Option<Author>>;

    /// Iterate over entries of a replica.
    ///
    /// The [`GetFilter`] has several methods of filtering the returne entries.
    fn get(&self, namespace: NamespaceId, filter: GetFilter) -> Result<Self::GetIter<'_>>;

    /// Gets the single latest entry for the specified key and author.
    fn get_latest_by_key_and_author(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>>;
}

/// Filter a get query onto a namespace
#[derive(Debug, Serialize, Deserialize)]
pub struct GetFilter {
    latest: bool,
    author: Option<AuthorId>,
    key: KeyFilter,
}

impl Default for GetFilter {
    fn default() -> Self {
        Self::latest()
    }
}

impl GetFilter {
    /// Create a new get filter, either for only latest or all entries.
    pub fn new(latest: bool) -> Self {
        GetFilter {
            latest,
            author: None,
            key: KeyFilter::All,
        }
    }
    /// No filter, iterate over all entries.
    pub fn all() -> Self {
        Self::new(false)
    }

    /// Only include the latest entries.
    pub fn latest() -> Self {
        Self::new(true)
    }

    /// Set the key filter.
    pub fn with_key_filter(mut self, key_filter: KeyFilter) -> Self {
        self.key = key_filter;
        self
    }

    /// Filter by exact key match.
    pub fn with_key(mut self, key: impl AsRef<[u8]>) -> Self {
        self.key = KeyFilter::Key(key.as_ref().to_vec());
        self
    }
    /// Filter by prefix key match.
    pub fn with_prefix(mut self, prefix: impl AsRef<[u8]>) -> Self {
        self.key = KeyFilter::Prefix(prefix.as_ref().to_vec());
        self
    }
    /// Filter by author.
    pub fn with_author(mut self, author: AuthorId) -> Self {
        self.author = Some(author);
        self
    }
    /// Include not only latest entries but also all historical entries.
    pub fn with_history(mut self) -> Self {
        self.latest = false;
        self
    }
}

/// Filter the keys in a namespace
#[derive(Debug, Serialize, Deserialize)]
pub enum KeyFilter {
    /// No filter, list all entries
    All,
    /// Filter for entries starting with a prefix
    Prefix(Vec<u8>),
    /// Filter for exact key match
    Key(Vec<u8>),
}

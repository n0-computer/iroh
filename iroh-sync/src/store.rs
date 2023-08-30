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

    /// Iterate over entries of a replica.
    ///
    /// The [`GetFilter`] has several methods of filtering the returned entries.
    fn get(&self, namespace: NamespaceId, filter: GetFilter) -> Result<Self::GetIter<'_>>;

    fn get_by_key_and_author(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>>;
}

/// Filter a get query onto a namespace
#[derive(Debug, Serialize, Deserialize)]
pub enum GetFilter {
    Author(AuthorId),
    Key(KeyFilter),
}

impl Default for GetFilter {
    fn default() -> Self {
        Self::all()
    }
}

impl GetFilter {
    /// Create a new get filter.
    pub fn new() -> Self {
        GetFilter::Key(KeyFilter::All)
    }

    /// No filter, iterate over all entries.
    pub fn all() -> Self {
        Self::new()
    }

    /// Set the key filter.
    pub fn with_key_filter(mut self, key_filter: KeyFilter) -> Self {
        self = Self::Key(key_filter);
        self
    }

    /// Filter by exact key match.
    pub fn with_key(mut self, key: impl AsRef<[u8]>) -> Self {
        self.with_key_filter(KeyFilter::Key(key.as_ref().to_vec()))
    }

    /// Filter by prefix key match.
    pub fn with_prefix(mut self, prefix: impl AsRef<[u8]>) -> Self {
        self.with_key_filter(KeyFilter::Prefix(prefix.as_ref().to_vec()))
    }

    /// Filter by author.
    pub fn with_author(mut self, author: AuthorId) -> Self {
        self = GetFilter::Author(author);
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

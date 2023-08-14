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

    type GetIter<'a>: Iterator<Item = Result<SignedEntry>>
    where
        Self: 'a;

    /// Open a replica
    ///
    /// Store implementers must ensure that only a single instance of [`Replica`] is created per
    /// namespace. On subsequent calls, a clone of that singleton instance must be returned.
    ///
    /// TODO: Add close_replica
    fn open_replica(&self, namespace: &NamespaceId) -> Result<Option<Replica<Self::Instance>>>;

    // TODO: return iterator
    fn list_replicas(&self) -> Result<Vec<NamespaceId>>;
    fn get_author(&self, author: &AuthorId) -> Result<Option<Author>>;
    fn new_author<R: CryptoRngCore + ?Sized>(&self, rng: &mut R) -> Result<Author>;

    // TODO: return iterator
    fn list_authors(&self) -> Result<Vec<Author>>;
    fn new_replica(&self, namespace: Namespace) -> Result<Replica<Self::Instance>>;

    /// Returns an iterator over the entries in a namespace.
    fn get(&self, namespace: NamespaceId, filter: GetFilter) -> Result<Self::GetIter<'_>>;
    /// Gets the latest entry this key and author.
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
    pub latest: bool,
    pub author: Option<AuthorId>,
    pub key: KeyFilter,
}

impl Default for GetFilter {
    fn default() -> Self {
        Self::latest()
    }
}

impl GetFilter {
    /// No filter, iterate over all entries.
    pub fn all() -> Self {
        Self {
            latest: false,
            author: None,
            key: KeyFilter::All,
        }
    }

    /// Only include the latest entries.
    pub fn latest() -> Self {
        Self {
            latest: true,
            author: None,
            key: KeyFilter::All,
        }
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

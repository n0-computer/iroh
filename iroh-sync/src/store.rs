use anyhow::{bail, Result};
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

    type GetLatestIter<'a>: Iterator<Item = Result<(RecordIdentifier, SignedEntry)>>
    where
        Self: 'a;
    type GetAllIter<'a>: Iterator<Item = Result<(RecordIdentifier, SignedEntry)>>
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

    /// Gets all entries matching this key and author.
    fn get_latest_by_key_and_author(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>>;

    /// Returns the latest version of the matching documents by key.
    fn get_latest_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> Result<Self::GetLatestIter<'_>>;

    /// Returns the latest version of the matching documents by prefix.
    fn get_latest_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<Self::GetLatestIter<'_>>;

    /// Returns the latest versions of all documents.
    fn get_latest(&self, namespace: NamespaceId) -> Result<Self::GetLatestIter<'_>>;

    /// Returns all versions of the matching documents by author.
    fn get_all_by_key_and_author<'a, 'b: 'a>(
        &'a self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]> + 'b,
    ) -> Result<Self::GetAllIter<'a>>;

    /// Returns all versions of the matching documents by key.
    fn get_all_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> Result<Self::GetAllIter<'_>>;

    /// Returns all versions of the matching documents by prefix.
    fn get_all_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<Self::GetAllIter<'_>>;

    /// Returns all versions of all documents.
    fn get_all(&self, namespace: NamespaceId) -> Result<Self::GetAllIter<'_>>;

    /// Returns an iterator over the entries in a namespace.
    fn get(&self, namespace: NamespaceId, filter: GetFilter) -> Result<GetIter<'_, Self>> {
        GetIter::new(self, namespace, filter)
    }
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
        Self {
            latest: true,
            author: None,
            key: KeyFilter::All,
        }
    }
}

impl GetFilter {
    /// Create a new get filter. Defaults to latest entries for all keys and authors.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by exact key match.
    pub fn with_key(mut self, key: Vec<u8>) -> Self {
        self.key = KeyFilter::Key(key);
        self
    }
    /// Filter by prefix key match.
    pub fn with_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.key = KeyFilter::Prefix(prefix);
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

/// Iterator over the entries in a namespace
pub enum GetIter<'s, S: Store> {
    All(S::GetAllIter<'s>),
    Latest(S::GetLatestIter<'s>),
    Single(std::option::IntoIter<anyhow::Result<SignedEntry>>),
}

impl<'s, S: Store> Iterator for GetIter<'s, S> {
    type Item = anyhow::Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            GetIter::All(iter) => iter.next().map(|x| x.map(|(_id, entry)| entry)),
            GetIter::Latest(iter) => iter.next().map(|x| x.map(|(_id, entry)| entry)),
            GetIter::Single(iter) => iter.next(),
        }
    }
}

impl<'s, S: Store> GetIter<'s, S> {
    fn new(store: &'s S, namespace: NamespaceId, filter: GetFilter) -> anyhow::Result<Self> {
        use KeyFilter::*;
        Ok(match filter.latest {
            false => match (filter.key, filter.author) {
                (All, None) => Self::All(store.get_all(namespace)?),
                (Prefix(prefix), None) => Self::All(store.get_all_by_prefix(namespace, &prefix)?),
                (Key(key), None) => Self::All(store.get_all_by_key(namespace, key)?),
                (Key(key), Some(author)) => {
                    Self::All(store.get_all_by_key_and_author(namespace, author, key)?)
                }
                (All, Some(_)) | (Prefix(_), Some(_)) => {
                    bail!("This filter combination is not yet supported")
                }
            },
            true => match (filter.key, filter.author) {
                (All, None) => Self::Latest(store.get_latest(namespace)?),
                (Prefix(prefix), None) => {
                    Self::Latest(store.get_latest_by_prefix(namespace, &prefix)?)
                }
                (Key(key), None) => Self::Latest(store.get_latest_by_key(namespace, key)?),
                (Key(key), Some(author)) => Self::Single(
                    store
                        .get_latest_by_key_and_author(namespace, author, key)?
                        .map(Ok)
                        .into_iter(),
                ),
                (All, Some(_)) | (Prefix(_), Some(_)) => {
                    bail!("This filter combination is not yet supported")
                }
            },
        })
    }

    /// Returns true if this iterator is known to return only a single result.
    pub fn single(&self) -> bool {
        matches!(self, Self::Single(_))
    }
}

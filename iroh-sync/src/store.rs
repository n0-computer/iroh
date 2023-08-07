use anyhow::Result;
use rand_core::CryptoRngCore;

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

    fn get_replica(&self, namespace: &NamespaceId) -> Result<Option<Replica<Self::Instance>>>;
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
}

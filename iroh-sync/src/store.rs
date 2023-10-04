//! Storage trait and implementation for iroh-sync documents

use std::num::NonZeroUsize;

use anyhow::Result;
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

    /// Iterator over authors in the store, returned from [`Self::get_sync_peers`]
    type PeersIter<'a>: Iterator<Item = PeerIdBytes>
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
    //
    // TODO: Add close_replica
    fn open_replica(&self, namespace: &NamespaceId) -> Result<Option<Replica<Self::Instance>>>;

    /// Close a replica.
    ///
    /// This removes the event subscription from the replica, if active, and removes the replica
    /// instance from the store's cache.
    fn close_replica(&self, namespace: &NamespaceId);

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
    fn get_many(&self, namespace: NamespaceId, filter: GetFilter) -> Result<Self::GetIter<'_>>;

    /// Get an entry by key and author.
    fn get_one(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>>;

    /// Get all content hashes of all replicas in the store.
    fn content_hashes(&self) -> Result<Self::ContentHashesIter<'_>>;

    /// Register a peer that has been useful to sync a document.
    fn register_useful_peer(&self, namespace: NamespaceId, peer: PeerIdBytes) -> Result<()>;

    /// Get peers to use for syncing a document.
    fn get_sync_peers(&self, namespace: &NamespaceId) -> Result<Option<Self::PeersIter<'_>>>;
}

/// Filter a get query onto a namespace
#[derive(Debug, Serialize, Deserialize)]
pub enum GetFilter {
    /// No filter, list all entries
    All,
    /// Filter for exact key match
    Key(Vec<u8>),
    /// Filter for key prefix
    Prefix(Vec<u8>),
    /// Filter by author
    Author(AuthorId),
    /// Filter by key prefix and author
    AuthorAndPrefix(AuthorId, Vec<u8>),
}

impl Default for GetFilter {
    fn default() -> Self {
        Self::All
    }
}

impl GetFilter {
    /// Create a [`GetFilter`] from author and prefix options.
    pub fn author_prefix(author: Option<AuthorId>, prefix: Option<impl AsRef<[u8]>>) -> Self {
        match (author, prefix) {
            (None, None) => Self::All,
            (Some(author), None) => Self::Author(author),
            (None, Some(prefix)) => Self::Prefix(prefix.as_ref().to_vec()),
            (Some(author), Some(prefix)) => Self::AuthorAndPrefix(author, prefix.as_ref().to_vec()),
        }
    }
}

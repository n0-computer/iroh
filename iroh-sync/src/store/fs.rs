//! On disk storage for replicas.

use std::{
    cmp::Ordering,
    collections::HashSet,
    iter::{Chain, Flatten},
    num::NonZeroU64,
    ops::Bound,
    path::Path,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use derive_more::From;
use ed25519_dalek::{SignatureError, VerifyingKey};
use iroh_base::hash::Hash;
use parking_lot::RwLock;
use rand_core::CryptoRngCore;
use redb::{
    Database, DatabaseError, ReadOnlyTable, ReadTransaction, ReadableMultimapTable, ReadableTable,
    ReadableTableMetadata,
};

use crate::{
    keys::Author,
    ranger::{Fingerprint, Range, RangeEntry},
    sync::{Entry, EntrySignature, Record, RecordIdentifier, Replica, SignedEntry},
    AuthorHeads, AuthorId, Capability, CapabilityKind, NamespaceId, NamespaceSecret, PeerIdBytes,
};

use super::{
    pubkeys::MemPublicKeyStore, DownloadPolicy, ImportNamespaceOutcome, OpenError, PublicKeyStore,
    Query,
};

mod bounds;
mod migrate_v1_v2;
mod migrations;
mod query;
mod ranges;
mod tables;

pub use tables::*;

use self::query::QueryIterator;
use self::{
    bounds::{ByKeyBounds, RecordsBounds},
    ranges::RangeExt,
};

pub use self::ranges::RecordsRange;

/// Manages the replicas and authors for an instance.
#[derive(Debug, Clone)]
pub struct Store {
    db: Arc<Database>,
    open_replicas: Arc<RwLock<HashSet<NamespaceId>>>,
    pubkeys: MemPublicKeyStore,
}

impl Store {
    /// Create a new store in memory.
    pub fn memory() -> Self {
        Self::memory_impl().expect("failed to create memory store")
    }

    fn memory_impl() -> Result<Self> {
        let db = Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::new_impl(db)
    }

    /// Create or open a store from a `path` to a database file.
    ///
    /// The file will be created if it does not exist, otherwise it will be opened.
    pub fn persistent(path: impl AsRef<Path>) -> Result<Self> {
        let db = match Database::create(&path) {
            Ok(db) => db,
            Err(DatabaseError::UpgradeRequired(1)) => migrate_v1_v2::run(&path)?,
            Err(err) => return Err(err.into()),
        };
        Self::new_impl(db)
    }

    fn new_impl(db: redb::Database) -> Result<Self> {
        // Setup all tables
        let write_tx = db.begin_write()?;
        {
            let _table = write_tx.open_table(RECORDS_TABLE)?;
            let _table = write_tx.open_table(NAMESPACES_TABLE)?;
            let _table = write_tx.open_table(LATEST_PER_AUTHOR_TABLE)?;
            let _table = write_tx.open_multimap_table(NAMESPACE_PEERS_TABLE)?;
            let _table = write_tx.open_table(DOWNLOAD_POLICY_TABLE)?;
            let _table = write_tx.open_table(AUTHORS_TABLE)?;
        }
        write_tx.commit()?;

        // Run database migrations
        migrations::run_migrations(&db)?;

        Ok(Store {
            db: Arc::new(db),
            open_replicas: Default::default(),
            pubkeys: Default::default(),
        })
    }
}

type AuthorsIter = std::vec::IntoIter<Result<Author>>;
type NamespaceIter = std::vec::IntoIter<Result<(NamespaceId, CapabilityKind)>>;
type PeersIter = std::vec::IntoIter<PeerIdBytes>;

impl Store {
    /// Create a new replica for `namespace` and persist in this store.
    pub fn new_replica(&self, namespace: NamespaceSecret) -> Result<Replica<StoreInstance>> {
        let id = namespace.id();
        self.import_namespace(namespace.into())?;
        self.open_replica(&id).map_err(Into::into)
    }

    /// Create a new author key and persist it in the store.
    pub fn new_author<R: CryptoRngCore + ?Sized>(&self, rng: &mut R) -> Result<Author> {
        let author = Author::new(rng);
        self.import_author(author.clone())?;
        Ok(author)
    }

    /// Check if a [`AuthorHeads`] contains entry timestamps that we do not have locally.
    ///
    /// Returns the number of authors that the other peer has updates for.
    pub fn has_news_for_us(
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

    /// Open a replica from this store.
    ///
    /// Store implementers must ensure that only a single instance of [`Replica`] is created per
    /// namespace. On subsequent calls, a clone of that singleton instance must be returned.
    pub fn open_replica(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<Replica<StoreInstance>, OpenError> {
        if self.open_replicas.read().contains(namespace_id) {
            return Err(OpenError::AlreadyOpen);
        }

        let read_tx = self.db.begin_read().map_err(anyhow::Error::from)?;
        let namespace_table = read_tx
            .open_table(NAMESPACES_TABLE)
            .map_err(anyhow::Error::from)?;
        let Some(db_value) = namespace_table
            .get(namespace_id.as_bytes())
            .map_err(anyhow::Error::from)?
        else {
            return Err(OpenError::NotFound);
        };
        let (raw_kind, raw_bytes) = db_value.value();
        let namespace = Capability::from_raw(raw_kind, raw_bytes)?;
        let replica = Replica::new(namespace, StoreInstance::new(*namespace_id, self.clone()));
        self.open_replicas.write().insert(*namespace_id);
        Ok(replica)
    }

    /// Close a replica.
    pub fn close_replica(&self, mut replica: Replica<StoreInstance>) {
        self.open_replicas.write().remove(&replica.id());
        replica.close();
    }

    /// List all replica namespaces in this store.
    pub fn list_namespaces(&self) -> Result<NamespaceIter> {
        // TODO: avoid collect
        let read_tx = self.db.begin_read()?;
        let namespace_table = read_tx.open_table(NAMESPACES_TABLE)?;
        let namespaces: Vec<_> = namespace_table
            .iter()?
            .map(|res| {
                let capability = parse_capability(res?.1.value())?;
                Ok((capability.id(), capability.kind()))
            })
            .collect();
        Ok(namespaces.into_iter())
    }

    /// Get an author key from the store.
    pub fn get_author(&self, author_id: &AuthorId) -> Result<Option<Author>> {
        let read_tx = self.db.begin_read()?;
        let author_table = read_tx.open_table(AUTHORS_TABLE)?;
        let Some(author) = author_table.get(author_id.as_bytes())? else {
            return Ok(None);
        };

        let author = Author::from_bytes(author.value());
        Ok(Some(author))
    }

    /// Import an author key pair.
    pub fn import_author(&self, author: Author) -> Result<()> {
        let write_tx = self.db.begin_write()?;
        {
            let mut author_table = write_tx.open_table(AUTHORS_TABLE)?;
            author_table.insert(author.id().as_bytes(), &author.to_bytes())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    /// Delte an author.
    pub fn delete_author(&self, author: AuthorId) -> Result<()> {
        let write_tx = self.db.begin_write()?;
        {
            let mut author_table = write_tx.open_table(AUTHORS_TABLE)?;
            author_table.remove(author.as_bytes())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    /// List all author keys in this store.
    pub fn list_authors(&self) -> Result<AuthorsIter> {
        // TODO: avoid collect
        let read_tx = self.db.begin_read()?;
        let authors_table = read_tx.open_table(AUTHORS_TABLE)?;
        let authors: Vec<_> = authors_table
            .iter()?
            .map(|res| match res {
                Ok((_key, value)) => Ok(Author::from_bytes(value.value())),
                Err(err) => Err(err.into()),
            })
            .collect();

        Ok(authors.into_iter())
    }

    /// Import a new replica namespace.
    pub fn import_namespace(&self, capability: Capability) -> Result<ImportNamespaceOutcome> {
        let write_tx = self.db.begin_write()?;
        let outcome = {
            let mut namespace_table = write_tx.open_table(NAMESPACES_TABLE)?;
            let (capability, outcome) = {
                let existing = namespace_table.get(capability.id().as_bytes())?;
                if let Some(existing) = existing {
                    let mut existing = parse_capability(existing.value())?;
                    let outcome = if existing.merge(capability)? {
                        ImportNamespaceOutcome::Upgraded
                    } else {
                        ImportNamespaceOutcome::NoChange
                    };
                    (existing, outcome)
                } else {
                    (capability, ImportNamespaceOutcome::Inserted)
                }
            };
            let id = capability.id().to_bytes();
            let (kind, bytes) = capability.raw();
            namespace_table.insert(&id, (kind, &bytes))?;
            outcome
        };
        write_tx.commit()?;
        Ok(outcome)
    }

    /// Remove a replica.
    ///
    /// Completely removes a replica and deletes both the namespace private key and all document
    /// entries.
    ///
    /// Note that a replica has to be closed before it can be removed. The store has to enforce
    /// that a replica cannot be removed while it is still open.
    pub fn remove_replica(&self, namespace: &NamespaceId) -> Result<()> {
        if self.open_replicas.read().contains(namespace) {
            return Err(anyhow!("replica is not closed"));
        }
        let write_tx = self.db.begin_write()?;
        {
            let mut record_table = write_tx.open_table(RECORDS_TABLE)?;
            let bounds = RecordsBounds::namespace(*namespace);
            record_table.retain_in(bounds.as_ref(), |_k, _v| false)?;
        }
        {
            let mut table = write_tx.open_table(RECORDS_BY_KEY_TABLE)?;
            let bounds = ByKeyBounds::namespace(*namespace);
            let _ = table.retain_in(bounds.as_ref(), |_k, _v| false);
        }
        {
            let mut namespace_table = write_tx.open_table(NAMESPACES_TABLE)?;
            namespace_table.remove(namespace.as_bytes())?;
        }
        {
            let mut peers_table = write_tx.open_multimap_table(NAMESPACE_PEERS_TABLE)?;
            peers_table.remove_all(namespace.as_bytes())?;
            let mut dl_policies_table = write_tx.open_table(DOWNLOAD_POLICY_TABLE)?;
            dl_policies_table.remove(namespace.as_bytes())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    /// Get an iterator over entries of a replica.
    pub fn get_many(
        &self,
        namespace: NamespaceId,
        query: impl Into<Query>,
    ) -> Result<QueryIterator> {
        let read_tx = self.db.begin_read()?;
        QueryIterator::new(&read_tx, namespace, query.into())
    }

    /// Get an entry by key and author.
    pub fn get_exact(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
        include_empty: bool,
    ) -> Result<Option<SignedEntry>> {
        let read_tx = self.db.begin_read()?;
        let record_table = read_tx.open_table(RECORDS_TABLE)?;
        get_exact(&record_table, namespace, author, key, include_empty)
    }

    /// Get all content hashes of all replicas in the store.
    pub fn content_hashes(&self) -> Result<ContentHashesIterator> {
        let read_tx = self.db.begin_read()?;
        ContentHashesIterator::new(&read_tx)
    }

    /// Get the latest entry for each author in a namespace.
    pub fn get_latest_for_each_author(&self, namespace: NamespaceId) -> Result<LatestIterator> {
        let tx = self.db.begin_read()?;
        LatestIterator::new(&tx, namespace)
    }

    /// Register a peer that has been useful to sync a document.
    pub fn register_useful_peer(
        &self,
        namespace: NamespaceId,
        peer: crate::PeerIdBytes,
    ) -> Result<()> {
        let peer = &peer;
        let namespace = namespace.as_bytes();
        // calculate nanos since UNIX_EPOCH for a time measurement
        let nanos = std::time::UNIX_EPOCH
            .elapsed()
            .map(|duration| duration.as_nanos() as u64)?;
        let write_tx = self.db.begin_write()?;
        {
            // ensure the document exists
            let namespaces = write_tx.open_table(NAMESPACES_TABLE)?;
            anyhow::ensure!(namespaces.get(namespace)?.is_some(), "document not created");

            let mut peers_table = write_tx.open_multimap_table(NAMESPACE_PEERS_TABLE)?;
            let mut namespace_peers = peers_table.get(namespace)?;

            // get the oldest entry since it's candidate for removal
            let maybe_oldest = namespace_peers.next().transpose()?.map(|guard| {
                let (oldest_nanos, &oldest_peer) = guard.value();
                (oldest_nanos, oldest_peer)
            });
            match maybe_oldest {
                None => {
                    // the table is empty so the peer can be inserted without further checks since
                    // super::PEERS_PER_DOC_CACHE_SIZE is non zero
                    drop(namespace_peers);
                    peers_table.insert(namespace, (nanos, peer))?;
                }
                Some((oldest_nanos, oldest_peer)) => {
                    let oldest_peer = &oldest_peer;

                    if oldest_peer == peer {
                        // oldest peer is the current one, so replacing the entry for the peer will
                        // maintain the size
                        drop(namespace_peers);
                        peers_table.remove(namespace, (oldest_nanos, oldest_peer))?;
                        peers_table.insert(namespace, (nanos, peer))?;
                    } else {
                        // calculate the len in the same loop since calling `len` is another fallible operation
                        let mut len = 1;
                        // find any previous entry for the same peer to remove it
                        let mut prev_peer_nanos = None;

                        for result in namespace_peers {
                            len += 1;
                            let guard = result?;
                            let (peer_nanos, peer_bytes) = guard.value();
                            if prev_peer_nanos.is_none() && peer_bytes == peer {
                                prev_peer_nanos = Some(peer_nanos)
                            }
                        }

                        match prev_peer_nanos {
                            Some(prev_nanos) => {
                                // the peer was already present, so we can remove the old entry and
                                // insert the new one without checking the size
                                peers_table.remove(namespace, (prev_nanos, peer))?;
                                peers_table.insert(namespace, (nanos, peer))?;
                            }
                            None => {
                                // the peer is new and the table is non empty, add it and check the
                                // size to decide if the oldest peer should be evicted
                                peers_table.insert(namespace, (nanos, peer))?;
                                len += 1;
                                if len > super::PEERS_PER_DOC_CACHE_SIZE.get() {
                                    peers_table.remove(namespace, (oldest_nanos, oldest_peer))?;
                                }
                            }
                        }
                    }
                }
            }
        }
        write_tx.commit()?;

        Ok(())
    }

    /// Get the peers that have been useful for a document.
    pub fn get_sync_peers(&self, namespace: &NamespaceId) -> Result<Option<PeersIter>> {
        let read_tx = self.db.begin_read()?;
        let peers_table = read_tx.open_multimap_table(NAMESPACE_PEERS_TABLE)?;
        let mut peers = Vec::with_capacity(super::PEERS_PER_DOC_CACHE_SIZE.get());
        for result in peers_table.get(namespace.as_bytes())?.rev() {
            let (_nanos, &peer) = result?.value();
            peers.push(peer);
        }
        if peers.is_empty() {
            Ok(None)
        } else {
            Ok(Some(peers.into_iter()))
        }
    }

    /// Set the download policy for a namespace.
    pub fn set_download_policy(
        &self,
        namespace: &NamespaceId,
        policy: DownloadPolicy,
    ) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let namespace = namespace.as_bytes();

            // ensure the document exists
            let namespaces = tx.open_table(NAMESPACES_TABLE)?;
            anyhow::ensure!(
                namespaces.get(&namespace)?.is_some(),
                "document not created"
            );

            let mut table = tx.open_table(DOWNLOAD_POLICY_TABLE)?;
            let value = postcard::to_stdvec(&policy)?;
            table.insert(namespace, value.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Get the download policy for a namespace.
    pub fn get_download_policy(&self, namespace: &NamespaceId) -> Result<DownloadPolicy> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(DOWNLOAD_POLICY_TABLE)?;
        let value = table.get(namespace.as_bytes())?;
        Ok(match value {
            None => DownloadPolicy::default(),
            Some(value) => postcard::from_bytes(value.value())?,
        })
    }
}

fn parse_capability((raw_kind, raw_bytes): (u8, &[u8; 32])) -> Result<Capability> {
    Capability::from_raw(raw_kind, raw_bytes)
}

fn get_exact(
    record_table: &RecordsTable,
    namespace: NamespaceId,
    author: AuthorId,
    key: impl AsRef<[u8]>,
    include_empty: bool,
) -> Result<Option<SignedEntry>> {
    let id = (namespace.as_bytes(), author.as_bytes(), key.as_ref());
    let record = record_table.get(id)?;
    Ok(record
        .map(|r| into_entry(id, r.value()))
        .filter(|entry| include_empty || !entry.is_empty()))
}

/// A wrapper around [`Store`] for a specific [`NamespaceId`]
#[derive(Debug, Clone)]
pub struct StoreInstance {
    namespace: NamespaceId,
    store: Store,
}

impl StoreInstance {
    fn new(namespace: NamespaceId, store: Store) -> Self {
        StoreInstance { namespace, store }
    }
}

impl PublicKeyStore for StoreInstance {
    fn public_key(&self, id: &[u8; 32]) -> std::result::Result<VerifyingKey, SignatureError> {
        self.store.pubkeys.public_key(id)
    }
}

impl super::DownloadPolicyStore for StoreInstance {
    fn get_download_policy(&self, namespace: &NamespaceId) -> Result<DownloadPolicy> {
        self.store.get_download_policy(namespace)
    }
}

impl crate::ranger::Store<SignedEntry> for StoreInstance {
    type Error = anyhow::Error;
    type RangeIterator<'a> = Chain<RecordsRange, Flatten<std::option::IntoIter<RecordsRange>>>;
    type ParentIterator<'a> = ParentIterator;

    /// Get a the first key (or the default if none is available).
    fn get_first(&self) -> Result<RecordIdentifier> {
        let read_tx = self.store.db.begin_read()?;
        let record_table = read_tx.open_table(RECORDS_TABLE)?;

        // TODO: verify this fetches all keys with this namespace
        let bounds = RecordsBounds::namespace(self.namespace);
        let mut records = record_table.range(bounds.as_ref())?;

        let Some(record) = records.next() else {
            return Ok(RecordIdentifier::default());
        };
        let (compound_key, _value) = record?;
        let (namespace_id, author_id, key) = compound_key.value();
        let id = RecordIdentifier::new(namespace_id, author_id, key);
        Ok(id)
    }

    fn get(&self, id: &RecordIdentifier) -> Result<Option<SignedEntry>> {
        self.store
            .get_exact(id.namespace(), id.author(), id.key(), true)
    }

    fn len(&self) -> Result<usize> {
        let read_tx = self.store.db.begin_read()?;
        let record_table = read_tx.open_table(RECORDS_TABLE)?;

        let bounds = RecordsBounds::namespace(self.namespace);
        let records = record_table.range(bounds.as_ref())?;
        Ok(records.count())
    }

    fn is_empty(&self) -> Result<bool> {
        let read_tx = self.store.db.begin_read()?;
        let record_table = read_tx.open_table(RECORDS_TABLE)?;
        Ok(record_table.is_empty()?)
    }

    fn get_fingerprint(&self, range: &Range<RecordIdentifier>) -> Result<Fingerprint> {
        // TODO: optimize
        let elements = self.get_range(range.clone())?;

        let mut fp = Fingerprint::empty();
        for el in elements {
            let el = el?;
            fp ^= el.as_fingerprint();
        }

        Ok(fp)
    }

    fn put(&mut self, e: SignedEntry) -> Result<()> {
        let id = e.id();
        let write_tx = self.store.db.begin_write()?;
        {
            // insert into record table
            let mut record_table = write_tx.open_table(RECORDS_TABLE)?;
            let key = (
                &id.namespace().to_bytes(),
                &id.author().to_bytes(),
                id.key(),
            );
            let hash = e.content_hash(); // let binding is needed
            let value = (
                e.timestamp(),
                &e.signature().namespace().to_bytes(),
                &e.signature().author().to_bytes(),
                e.content_len(),
                hash.as_bytes(),
            );
            record_table.insert(key, value)?;

            // insert into by key index table
            let mut idx_by_key = write_tx.open_table(RECORDS_BY_KEY_TABLE)?;
            let key = (
                &id.namespace().to_bytes(),
                id.key(),
                &id.author().to_bytes(),
            );
            idx_by_key.insert(key, ())?;

            // insert into latest table
            let mut latest_table = write_tx.open_table(LATEST_PER_AUTHOR_TABLE)?;
            let key = (&e.id().namespace().to_bytes(), &e.id().author().to_bytes());
            let value = (e.timestamp(), e.id().key());
            latest_table.insert(key, value)?;
        }
        write_tx.commit()?;
        Ok(())
    }

    fn get_range(&self, range: Range<RecordIdentifier>) -> Result<Self::RangeIterator<'_>> {
        let read_tx = self.store.db.begin_read()?;
        let iter = match range.x().cmp(range.y()) {
            // identity range: iter1 = all, iter2 = none
            Ordering::Equal => {
                // iterator for all entries in replica
                let bounds = RecordsBounds::namespace(self.namespace);
                let iter = RecordsRange::with_bounds(&read_tx, bounds)?;
                chain_none(iter)
            }
            // regular range: iter1 = x <= t < y, iter2 = none
            Ordering::Less => {
                // iterator for entries from range.x to range.y
                let start = Bound::Included(range.x().to_byte_tuple());
                let end = Bound::Excluded(range.y().to_byte_tuple());
                let bounds = RecordsBounds::new(start, end);
                let iter = RecordsRange::with_bounds(&read_tx, bounds)?;
                chain_none(iter)
            }
            // split range: iter1 = start <= t < y, iter2 = x <= t <= end
            Ordering::Greater => {
                // iterator for entries from start to range.y
                let end = Bound::Excluded(range.y().to_byte_tuple());
                let bounds = RecordsBounds::from_start(&self.namespace, end);
                let iter = RecordsRange::with_bounds(&read_tx, bounds)?;

                // iterator for entries from range.x to end
                let start = Bound::Included(range.x().to_byte_tuple());
                let bounds = RecordsBounds::to_end(&self.namespace, start);
                let iter2 = RecordsRange::with_bounds(&read_tx, bounds)?;

                iter.chain(Some(iter2).into_iter().flatten())
            }
        };
        Ok(iter)
    }

    fn remove(&mut self, id: &RecordIdentifier) -> Result<Option<SignedEntry>> {
        let write_tx = self.store.db.begin_write()?;
        let (namespace, author, key) = id.as_byte_tuple();
        {
            let mut table = write_tx.open_table(RECORDS_BY_KEY_TABLE)?;
            let id = (namespace, key, author);
            table.remove(id)?;
        }
        let entry = {
            let mut table = write_tx.open_table(RECORDS_TABLE)?;
            let id = (namespace, author, key);
            let value = table.remove(id)?;
            value.map(|value| into_entry(id, value.value()))
        };
        write_tx.commit()?;
        Ok(entry)
    }

    fn all(&self) -> Result<Self::RangeIterator<'_>> {
        let read_tx = self.store.db.begin_read()?;
        let bounds = RecordsBounds::namespace(self.namespace);
        let iter = RecordsRange::with_bounds(&read_tx, bounds)?;
        Ok(chain_none(iter))
    }

    fn prefixes_of(&self, id: &RecordIdentifier) -> Result<Self::ParentIterator<'_>, Self::Error> {
        let read_tx = self.store.db.begin_read()?;
        ParentIterator::new(&read_tx, id.namespace(), id.author(), id.key().to_vec())
    }

    fn prefixed_by(&self, id: &RecordIdentifier) -> Result<Self::RangeIterator<'_>> {
        let read_tx = self.store.db.begin_read()?;
        let bounds = RecordsBounds::author_prefix(id.namespace(), id.author(), id.key_bytes());
        let iter = RecordsRange::with_bounds(&read_tx, bounds)?;
        Ok(chain_none(iter))
    }

    fn remove_prefix_filtered(
        &mut self,
        id: &RecordIdentifier,
        predicate: impl Fn(&Record) -> bool,
    ) -> Result<usize> {
        let bounds = RecordsBounds::author_prefix(id.namespace(), id.author(), id.key_bytes());
        let write_tx = self.store.db.begin_write()?;
        let count = {
            let mut table = write_tx.open_table(RECORDS_TABLE)?;
            let cb = |_k: RecordsId, v: RecordsValue| {
                let (timestamp, _namespace_sig, _author_sig, len, hash) = v;
                let record = Record::new(hash.into(), len, timestamp);

                predicate(&record)
            };
            let iter = table.extract_from_if(bounds.as_ref(), cb)?;
            iter.count()
        };
        write_tx.commit()?;
        Ok(count)
    }
}

fn chain_none<'a, I: Iterator<Item = T> + 'a, T>(
    iter: I,
) -> Chain<I, Flatten<std::option::IntoIter<I>>> {
    iter.chain(None.into_iter().flatten())
}

/// Iterator over parent entries, i.e. entries with the same namespace and author, and a key which
/// is a prefix of the key passed to the iterator.
#[derive(Debug)]
pub struct ParentIterator {
    table: ReadOnlyTable<RecordsId<'static>, RecordsValue<'static>>,
    namespace: NamespaceId,
    author: AuthorId,
    key: Vec<u8>,
}

impl ParentIterator {
    fn new(
        tx: &ReadTransaction,
        namespace: NamespaceId,
        author: AuthorId,
        key: Vec<u8>,
    ) -> anyhow::Result<Self> {
        let table = tx.open_table(RECORDS_TABLE)?;
        Ok(Self {
            table,
            namespace,
            author,
            key,
        })
    }
}

impl Iterator for ParentIterator {
    type Item = Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.key.is_empty() {
            let entry = get_exact(&self.table, self.namespace, self.author, &self.key, false);
            self.key.pop();
            match entry {
                Err(err) => return Some(Err(err)),
                Ok(Some(entry)) => return Some(Ok(entry)),
                Ok(None) => continue,
            }
        }
        None
    }
}

/// Iterator over all content hashes for the fs store.
#[derive(Debug)]
pub struct ContentHashesIterator(RecordsRange);

impl ContentHashesIterator {
    fn new(tx: &ReadTransaction) -> anyhow::Result<Self> {
        let range = RecordsRange::all(tx)?;
        Ok(Self(range))
    }
}

impl Iterator for ContentHashesIterator {
    type Item = Result<Hash>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next_map(|_key, value| {
            let (_timestamp, _namespace_sig, _author_sig, _len, hash) = value;
            Hash::from(hash)
        })
    }
}

/// Iterator over the latest entry per author.
#[derive(derive_more::Debug)]
#[debug("LatestIterator")]
pub struct LatestIterator(
    redb::Range<'static, LatestPerAuthorKey<'static>, LatestPerAuthorValue<'static>>,
);

impl LatestIterator {
    fn new(read_tx: &ReadTransaction, namespace: NamespaceId) -> anyhow::Result<Self> {
        let start = (namespace.as_bytes(), &[u8::MIN; 32]);
        let end = (namespace.as_bytes(), &[u8::MAX; 32]);
        let table = read_tx.open_table(LATEST_PER_AUTHOR_TABLE)?;
        let range = table.range(start..=end)?;
        Ok(Self(range))
    }
}

impl Iterator for LatestIterator {
    type Item = Result<(AuthorId, u64, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next_map(|key, value| {
            let (_namespace, author) = key;
            let (timestamp, key) = value;
            (author.into(), timestamp, key.to_vec())
        })
    }
}

fn into_entry(key: RecordsId, value: RecordsValue) -> SignedEntry {
    let (namespace, author, key) = key;
    let (timestamp, namespace_sig, author_sig, len, hash) = value;
    let id = RecordIdentifier::new(namespace, author, key);
    let record = Record::new(hash.into(), len, timestamp);
    let entry = Entry::new(id, record);
    let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
    SignedEntry::new(entry_signature, entry)
}

#[cfg(test)]
mod tests {
    use crate::ranger::Store as _;

    use super::*;

    #[test]
    fn test_ranges() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let store = Store::persistent(dbfile.path())?;

        let author = store.new_author(&mut rand::thread_rng())?;
        let namespace = NamespaceSecret::new(&mut rand::thread_rng());
        let mut replica = store.new_replica(namespace)?;

        // test author prefix relation for all-255 keys
        let key1 = vec![255, 255];
        let key2 = vec![255, 255, 255];
        replica.hash_and_insert(&key1, &author, b"v1")?;
        replica.hash_and_insert(&key2, &author, b"v2")?;
        let res = store
            .get_many(replica.id(), Query::author(author.id()).key_prefix([255]))?
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(res.len(), 2);
        assert_eq!(
            res.into_iter()
                .map(|entry| entry.key().to_vec())
                .collect::<Vec<_>>(),
            vec![key1, key2]
        );
        Ok(())
    }

    #[test]
    fn test_basics() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let store = Store::persistent(dbfile.path())?;

        let authors: Vec<_> = store.list_authors()?.collect::<Result<_>>()?;
        assert!(authors.is_empty());

        let author = store.new_author(&mut rand::thread_rng())?;
        let namespace = NamespaceSecret::new(&mut rand::thread_rng());
        let replica = store.new_replica(namespace.clone())?;
        store.close_replica(replica);
        let replica = store.open_replica(&namespace.id())?;
        assert_eq!(replica.id(), namespace.id());

        let author_back = store.get_author(&author.id())?.unwrap();
        assert_eq!(author.to_bytes(), author_back.to_bytes(),);

        let mut wrapper = StoreInstance::new(namespace.id(), store.clone());
        for i in 0..5 {
            let id = RecordIdentifier::new(namespace.id(), author.id(), format!("hello-{i}"));
            let entry = Entry::new(id, Record::current_from_data(format!("world-{i}")));
            let entry = SignedEntry::from_entry(entry, &namespace, &author);
            wrapper.put(entry)?;
        }

        // all
        let all: Vec<_> = wrapper.all()?.collect();
        assert_eq!(all.len(), 5);

        // add a second version
        let mut ids = Vec::new();
        for i in 0..5 {
            let id = RecordIdentifier::new(namespace.id(), author.id(), format!("hello-{i}"));
            let entry = Entry::new(
                id.clone(),
                Record::current_from_data(format!("world-{i}-2")),
            );
            let entry = SignedEntry::from_entry(entry, &namespace, &author);
            wrapper.put(entry)?;
            ids.push(id);
        }

        // get all
        let entries = store
            .get_many(namespace.id(), Query::all())?
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 5);

        // get all prefix
        let entries = store
            .get_many(namespace.id(), Query::key_prefix("hello-"))?
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 5);

        // delete and get
        for id in ids {
            let res = wrapper.get(&id)?;
            assert!(res.is_some());
            let out = wrapper.remove(&id)?.unwrap();
            assert_eq!(out.entry().id(), &id);
            let res = wrapper.get(&id)?;
            assert!(res.is_none());
        }

        // get latest
        let entries = store
            .get_many(namespace.id(), Query::all())?
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 0);

        Ok(())
    }

    fn copy_and_modify(
        source: &Path,
        modify: impl Fn(&redb::WriteTransaction) -> Result<()>,
    ) -> Result<tempfile::NamedTempFile> {
        let dbfile = tempfile::NamedTempFile::new()?;
        std::fs::copy(source, dbfile.path())?;
        let db = Database::create(dbfile.path())?;
        let write_tx = db.begin_write()?;
        modify(&write_tx)?;
        write_tx.commit()?;
        drop(db);
        Ok(dbfile)
    }

    #[test]
    fn test_migration_001_populate_latest_table() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let namespace = NamespaceSecret::new(&mut rand::thread_rng());

        // create a store and add some data
        let expected = {
            let store = Store::persistent(dbfile.path())?;
            let author1 = store.new_author(&mut rand::thread_rng())?;
            let author2 = store.new_author(&mut rand::thread_rng())?;
            let mut replica = store.new_replica(namespace.clone())?;
            replica.hash_and_insert(b"k1", &author1, b"v1")?;
            replica.hash_and_insert(b"k2", &author2, b"v1")?;
            replica.hash_and_insert(b"k3", &author1, b"v1")?;

            let expected = store
                .get_latest_for_each_author(namespace.id())?
                .collect::<Result<Vec<_>>>()?;
            // drop everything to clear file locks.
            store.close_replica(replica);
            drop(store);
            expected
        };
        assert_eq!(expected.len(), 2);

        // create a copy of our db file with the latest table deleted.
        let dbfile_before_migration = copy_and_modify(dbfile.path(), |tx| {
            tx.delete_table(LATEST_PER_AUTHOR_TABLE)?;
            Ok(())
        })?;

        // open the copied db file, which will run the migration.
        let store = Store::persistent(dbfile_before_migration.path())?;
        let actual = store
            .get_latest_for_each_author(namespace.id())?
            .collect::<Result<Vec<_>>>()?;

        assert_eq!(expected, actual);

        Ok(())
    }

    #[test]
    fn test_migration_004_populate_by_key_index() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;

        let store = Store::persistent(dbfile.path())?;

        // check that the new table is there, even if empty
        {
            let read_tx = store.db.begin_read()?;
            let record_by_key_table = read_tx.open_table(RECORDS_BY_KEY_TABLE)?;
            assert_eq!(record_by_key_table.len()?, 0);
        }

        // TODO: write test checking that the indexing is done correctly

        Ok(())
    }
}

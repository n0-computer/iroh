//! On disk storage for replicas.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use derive_more::From;
use ed25519_dalek::{SignatureError, VerifyingKey};
use iroh_bytes::Hash;
use ouroboros::self_referencing;
use parking_lot::RwLock;
use redb::{
    Database, MultimapTableDefinition, Range as TableRange, ReadOnlyTable, ReadTransaction,
    ReadableMultimapTable, ReadableTable, StorageError, Table, TableDefinition,
};

use crate::{
    keys::{Author, NamespaceSecret},
    ranger::{Fingerprint, Range, RangeEntry},
    store::Store as _,
    sync::{Entry, EntrySignature, Record, RecordIdentifier, Replica, SignedEntry},
    AuthorId, NamespaceId, PeerIdBytes,
};

use super::{pubkeys::MemPublicKeyStore, OpenError, PublicKeyStore};

/// Manages the replicas and authors for an instance.
#[derive(Debug, Clone)]
pub struct Store {
    db: Arc<Database>,
    open_replicas: Arc<RwLock<HashSet<NamespaceId>>>,
    pubkeys: MemPublicKeyStore,
}

// Table Definitions

// Authors
// Table
// Key: [u8; 32] # AuthorId
// Value: #[u8; 32] # Author
const AUTHORS_TABLE: TableDefinition<&[u8; 32], &[u8; 32]> = TableDefinition::new("authors-1");

// Namespaces
// Table
// Key: [u8; 32] # NamespaceId
// Value: #[u8; 32] # Namespace
const NAMESPACES_TABLE: TableDefinition<&[u8; 32], &[u8; 32]> =
    TableDefinition::new("namespaces-1");

// Records
// Table
// Key: ([u8; 32], [u8; 32], Vec<u8>) # (NamespaceId, AuthorId, Key)
// Value:
//    (u64, [u8; 32], [u8; 32], u64, [u8; 32])
//  # (timestamp, signature_namespace, signature_author, len, hash)
const RECORDS_TABLE: TableDefinition<RecordsId, RecordsValue> = TableDefinition::new("records-1");

// Latest by author
// Table
// Key: ([u8; 32], [u8; 32]) # (NamespaceId, AuthorId)
// Value: (u64, Vec<u8>) # (Timestamp, Key)
const LATEST_TABLE: TableDefinition<LatestKey, LatestValue> =
    TableDefinition::new("latest-by-author-1");
type LatestKey<'a> = (&'a [u8; 32], &'a [u8; 32]);
type LatestValue<'a> = (u64, &'a [u8]);
type LatestTable<'a> = ReadOnlyTable<'a, LatestKey<'static>, LatestValue<'static>>;
type LatestRange<'a> = TableRange<'a, LatestKey<'static>, LatestValue<'static>>;

type RecordsId<'a> = (&'a [u8; 32], &'a [u8; 32], &'a [u8]);
type RecordsValue<'a> = (u64, &'a [u8; 64], &'a [u8; 64], u64, &'a [u8; 32]);
type RecordsRange<'a> = TableRange<'a, RecordsId<'static>, RecordsValue<'static>>;
type RecordsTable<'a> = ReadOnlyTable<'a, RecordsId<'static>, RecordsValue<'static>>;
type DbResult<T> = Result<T, StorageError>;

/// Number of seconds elapsed since [`std::time::SystemTime::UNIX_EPOCH`]. Used to register the
/// last time a peer was useful in a document.
// NOTE: resolution is nanoseconds, stored as a u64 since this covers ~500years from unix epoch,
// which should be more than enough
type Nanos = u64;
/// Peers stored per document.
/// - Key: [`NamespaceId::as_bytes`]
/// - Value: ([`Nanos`], &[`PeerIdBytes`]) representing the last time a peer was used.
const NAMESPACE_PEERS_TABLE: MultimapTableDefinition<&[u8; 32], (Nanos, &PeerIdBytes)> =
    MultimapTableDefinition::new("sync-peers-1");

/// migration 001: populate the latest table (which did not exist before)
fn migration_001_populate_latest_table(
    records_table: &Table<RecordsId<'static>, RecordsValue<'static>>,
    latest_table: &mut Table<LatestKey<'static>, LatestValue<'static>>,
) -> Result<()> {
    tracing::info!("Starting migration: 001_populate_latest_table");
    #[allow(clippy::type_complexity)]
    let mut heads: HashMap<([u8; 32], [u8; 32]), (u64, Vec<u8>)> = HashMap::new();
    let iter = records_table.iter()?;

    for next in iter {
        let next = next?;
        let (namespace, author, key) = next.0.value();
        let (timestamp, _namespace_sig, _author_sig, _len, _hash) = next.1.value();
        heads
            .entry((*namespace, *author))
            .and_modify(|e| {
                if timestamp >= e.0 {
                    *e = (timestamp, key.to_vec());
                }
            })
            .or_insert_with(|| (timestamp, key.to_vec()));
    }
    let len = heads.len();
    for ((namespace, author), (timestamp, key)) in heads {
        latest_table.insert((&namespace, &author), (timestamp, key.as_slice()))?;
    }
    tracing::info!("Migration finished (inserted {} entries)", len);
    Ok(())
}

impl Store {
    /// Create or open a store from a `path` to a database file.
    ///
    /// The file will be created if it does not exist, otherwise it will be opened.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path)?;

        // Setup all tables
        let write_tx = db.begin_write()?;
        {
            let records_table = write_tx.open_table(RECORDS_TABLE)?;
            let _table = write_tx.open_table(NAMESPACES_TABLE)?;
            let _table = write_tx.open_table(AUTHORS_TABLE)?;
            let mut latest_table = write_tx.open_table(LATEST_TABLE)?;
            let _table = write_tx.open_multimap_table(NAMESPACE_PEERS_TABLE)?;

            // migration 001: populate latest table if it was empty before
            if latest_table.is_empty()? && !records_table.is_empty()? {
                migration_001_populate_latest_table(&records_table, &mut latest_table)?;
            }
        }
        write_tx.commit()?;

        Ok(Store {
            db: Arc::new(db),
            open_replicas: Default::default(),
            pubkeys: Default::default(),
        })
    }

    /// Stores a new namespace
    fn insert_namespace(&self, namespace: NamespaceSecret) -> Result<()> {
        let write_tx = self.db.begin_write()?;
        {
            let mut namespace_table = write_tx.open_table(NAMESPACES_TABLE)?;
            namespace_table.insert(namespace.id().as_bytes(), &namespace.to_bytes())?;
        }
        write_tx.commit()?;

        Ok(())
    }

    fn insert_author(&self, author: Author) -> Result<()> {
        let write_tx = self.db.begin_write()?;
        {
            let mut author_table = write_tx.open_table(AUTHORS_TABLE)?;
            author_table.insert(author.id().as_bytes(), &author.to_bytes())?;
        }
        write_tx.commit()?;

        Ok(())
    }
}

impl super::Store for Store {
    type Instance = StoreInstance;
    type GetIter<'a> = RangeIterator<'a>;
    type ContentHashesIter<'a> = ContentHashesIterator<'a>;
    type LatestIter<'a> = LatestIterator<'a>;
    type AuthorsIter<'a> = std::vec::IntoIter<Result<Author>>;
    type NamespaceIter<'a> = std::vec::IntoIter<Result<NamespaceId>>;
    type PeersIter<'a> = std::vec::IntoIter<PeerIdBytes>;

    fn open_replica(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<Replica<Self::Instance>, OpenError> {
        if self.open_replicas.read().contains(namespace_id) {
            return Err(OpenError::AlreadyOpen);
        }

        let read_tx = self.db.begin_read().map_err(anyhow::Error::from)?;
        let namespace_table = read_tx
            .open_table(NAMESPACES_TABLE)
            .map_err(anyhow::Error::from)?;
        let Some(namespace) = namespace_table
            .get(namespace_id.as_bytes())
            .map_err(anyhow::Error::from)?
        else {
            return Err(OpenError::NotFound);
        };
        let namespace = NamespaceSecret::from_bytes(namespace.value());
        let replica = Replica::new(namespace, StoreInstance::new(*namespace_id, self.clone()));
        self.open_replicas.write().insert(*namespace_id);
        Ok(replica)
    }

    fn close_replica(&self, mut replica: Replica<Self::Instance>) {
        self.open_replicas.write().remove(&replica.id());
        replica.close();
    }

    fn list_namespaces(&self) -> Result<Self::NamespaceIter<'_>> {
        // TODO: avoid collect
        let read_tx = self.db.begin_read()?;
        let namespace_table = read_tx.open_table(NAMESPACES_TABLE)?;
        let namespaces: Vec<_> = namespace_table
            .iter()?
            .map(|res| match res {
                Ok((_key, value)) => Ok(NamespaceSecret::from_bytes(value.value()).id()),
                Err(err) => Err(err.into()),
            })
            .collect();
        Ok(namespaces.into_iter())
    }

    fn get_author(&self, author_id: &AuthorId) -> Result<Option<Author>> {
        let read_tx = self.db.begin_read()?;
        let author_table = read_tx.open_table(AUTHORS_TABLE)?;
        let Some(author) = author_table.get(author_id.as_bytes())? else {
            return Ok(None);
        };

        let author = Author::from_bytes(author.value());
        Ok(Some(author))
    }

    fn import_author(&self, author: Author) -> Result<()> {
        self.insert_author(author)?;
        Ok(())
    }

    fn list_authors(&self) -> Result<Self::AuthorsIter<'_>> {
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

    fn import_namespace(&self, namespace: NamespaceSecret) -> Result<()> {
        self.insert_namespace(namespace.clone())?;
        Ok(())
    }

    fn remove_replica(&self, namespace: &NamespaceId) -> Result<()> {
        if self.open_replicas.read().contains(namespace) {
            return Err(anyhow!("replica is not closed"));
        }
        let start = range_start(namespace);
        let end = range_end(namespace);
        let write_tx = self.db.begin_write()?;
        {
            let mut record_table = write_tx.open_table(RECORDS_TABLE)?;
            record_table.drain(start..=end)?;
            let mut namespace_table = write_tx.open_table(NAMESPACES_TABLE)?;
            namespace_table.remove(namespace.as_bytes())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    fn get_many(
        &self,
        namespace: NamespaceId,
        filter: super::GetFilter,
    ) -> Result<Self::GetIter<'_>> {
        match filter {
            super::GetFilter::All => self.get_all(namespace),
            super::GetFilter::Key(key) => self.get_by_key(namespace, key),
            super::GetFilter::Prefix(prefix) => self.get_by_prefix(namespace, prefix),
            super::GetFilter::Author(author) => self.get_by_author(namespace, author),
            super::GetFilter::AuthorAndPrefix(author, prefix) => {
                self.get_by_author_and_prefix(namespace, author, prefix)
            }
        }
    }

    fn get_one(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>> {
        let read_tx = self.db.begin_read()?;
        let record_table = read_tx.open_table(RECORDS_TABLE)?;
        get_one(&record_table, namespace, author, key)
    }

    fn content_hashes(&self) -> Result<Self::ContentHashesIter<'_>> {
        ContentHashesIterator::create(&self.db)
    }

    fn get_latest_for_each_author(&self, namespace: NamespaceId) -> Result<Self::LatestIter<'_>> {
        LatestIterator::create(&self.db, namespace)
    }

    fn register_useful_peer(&self, namespace: NamespaceId, peer: crate::PeerIdBytes) -> Result<()> {
        let peer = &peer;
        let namespace = namespace.as_bytes();
        // calculate nanos since UNIX_EPOCH for a time measurement
        let nanos = std::time::UNIX_EPOCH
            .elapsed()
            .map(|duration| duration.as_nanos() as u64)?;
        let write_tx = self.db.begin_write()?;
        {
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

    fn get_sync_peers(&self, namespace: &NamespaceId) -> Result<Option<Self::PeersIter<'_>>> {
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
}

fn get_one(
    record_table: &RecordsTable,
    namespace: NamespaceId,
    author: AuthorId,
    key: impl AsRef<[u8]>,
) -> Result<Option<SignedEntry>> {
    let db_key = (namespace.as_ref(), author.as_ref(), key.as_ref());
    let record = record_table.get(db_key)?;
    let Some(record) = record else {
        return Ok(None);
    };
    let (timestamp, namespace_sig, author_sig, len, hash) = record.value();
    // return early if the hash equals the hash of the empty byte range, which we treat as
    // delete marker (tombstone).
    if hash == Hash::EMPTY.as_bytes() {
        return Ok(None);
    }

    let record = Record::new(hash.into(), len, timestamp);
    let id = RecordIdentifier::new(namespace, author, key);
    let entry = Entry::new(id, record);
    let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
    let signed_entry = SignedEntry::new(entry_signature, entry);

    Ok(Some(signed_entry))
}

impl Store {
    fn get_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> Result<RangeIterator<'_>> {
        RangeIterator::namespace(
            &self.db,
            &namespace,
            RangeFilter::Key(key.as_ref().to_vec()),
        )
    }
    fn get_by_author(&self, namespace: NamespaceId, author: AuthorId) -> Result<RangeIterator<'_>> {
        let author = author.as_bytes();
        let start = (namespace.as_bytes(), author, &[][..]);
        let end = prefix_range_end(&start);
        RangeIterator::with_range(
            &self.db,
            |table| match end {
                Some(end) => table.range(start..(&end.0, &end.1, &end.2)),
                None => table.range(start..),
            },
            RangeFilter::None,
        )
    }

    fn get_by_author_and_prefix(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<RangeIterator<'_>> {
        let author = author.as_bytes();
        let start = (namespace.as_bytes(), author, prefix.as_ref());
        let end = prefix_range_end(&start);
        RangeIterator::with_range(
            &self.db,
            |table| match end {
                Some(end) => table.range(start..(&end.0, &end.1, &end.2)),
                None => table.range(start..),
            },
            RangeFilter::None,
        )
    }

    fn get_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<RangeIterator<'_>> {
        RangeIterator::namespace(
            &self.db,
            &namespace,
            RangeFilter::Prefix(prefix.as_ref().to_vec()),
        )
    }

    fn get_all(&self, namespace: NamespaceId) -> Result<RangeIterator<'_>> {
        RangeIterator::namespace(&self.db, &namespace, RangeFilter::None)
    }
}

/// Increment a byte string by one, by incrementing the last byte that is not 255 by one.
///
/// Returns false if all bytes are 255.
fn increment_by_one(value: &mut [u8]) -> bool {
    for char in value.iter_mut().rev() {
        if *char != 255 {
            *char += 1;
            return true;
        } else {
            *char = 0;
        }
    }
    false
}

// Get the end point of a prefix range
//
// Increments the last byte of the byte represenation of `prefix` and returns it as an owned tuple
// with the parts of the new [`RecordsId`].
// Returns `None` if all bytes are equal to 255.
fn prefix_range_end<'a>(prefix: &'a RecordsId<'a>) -> Option<([u8; 32], [u8; 32], Vec<u8>)> {
    let (mut namespace, mut author, mut prefix) = (*prefix.0, *prefix.1, prefix.2.to_vec());
    if !increment_by_one(&mut prefix)
        && !increment_by_one(&mut author)
        && !increment_by_one(&mut namespace)
    {
        // we have all-255 keys, so open-ended range
        None
    } else {
        Some((namespace, author, prefix))
    }
}

/// [`NamespaceSecret`] specific wrapper around the [`Store`].
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

fn range_start(namespace: &NamespaceId) -> RecordsId {
    (namespace.as_bytes(), &[u8::MIN; 32], &[][..])
}
fn range_end(namespace: &NamespaceId) -> RecordsId {
    (namespace.as_bytes(), &[u8::MAX; 32], &[][..])
}

impl PublicKeyStore for StoreInstance {
    fn public_key(&self, id: &[u8; 32]) -> std::result::Result<VerifyingKey, SignatureError> {
        self.store.pubkeys.public_key(id)
    }
}

impl crate::ranger::Store<SignedEntry> for StoreInstance {
    type Error = anyhow::Error;
    type RangeIterator<'a> = std::iter::Chain<RangeIterator<'a>, RangeIterator<'a>>;

    /// Get a the first key (or the default if none is available).
    fn get_first(&self) -> Result<RecordIdentifier> {
        let read_tx = self.store.db.begin_read()?;
        let record_table = read_tx.open_table(RECORDS_TABLE)?;

        // TODO: verify this fetches all keys with this namespace
        let start = range_start(&self.namespace);
        let end = range_end(&self.namespace);
        let mut records = record_table.range(start..=end)?;

        let Some(record) = records.next() else {
            return Ok(RecordIdentifier::default());
        };
        let (compound_key, _value) = record?;
        let (namespace_id, author_id, key) = compound_key.value();
        let id = RecordIdentifier::new(namespace_id, author_id, key);
        Ok(id)
    }

    fn get(&self, id: &RecordIdentifier) -> Result<Option<SignedEntry>> {
        self.store.get_one(id.namespace(), id.author(), id.key())
    }

    fn len(&self) -> Result<usize> {
        let read_tx = self.store.db.begin_read()?;
        let record_table = read_tx.open_table(RECORDS_TABLE)?;

        // TODO: verify this fetches all keys with this namespace
        let start = range_start(&self.namespace);
        let end = range_end(&self.namespace);
        let records = record_table.range(start..=end)?;
        Ok(records.count())
    }

    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
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
        let write_tx = self.store.db.begin_write()?;
        {
            // insert into record table
            let mut record_table = write_tx.open_table(RECORDS_TABLE)?;
            let key = (
                &e.id().namespace().to_bytes(),
                &e.id().author().to_bytes(),
                e.id().key(),
            );
            let hash = e.content_hash();
            let value = (
                e.timestamp(),
                &e.signature().namespace_signature().to_bytes(),
                &e.signature().author_signature().to_bytes(),
                e.content_len(),
                hash.as_bytes(),
            );
            record_table.insert(key, value)?;

            // insert into latest table
            let mut latest_table = write_tx.open_table(LATEST_TABLE)?;
            let key = (&e.id().namespace().to_bytes(), &e.id().author().to_bytes());
            let value = (e.timestamp(), e.id().key());
            latest_table.insert(key, value)?;
        }
        write_tx.commit()?;
        Ok(())
    }

    fn get_range(&self, range: Range<RecordIdentifier>) -> Result<Self::RangeIterator<'_>> {
        let iter = match range.x().cmp(range.y()) {
            // identity range: iter1 = all, iter2 = none
            Ordering::Equal => {
                let start = range_start(&self.namespace);
                let end = range_end(&self.namespace);
                // iterator for all entries in replica
                let iter = RangeIterator::with_range(
                    &self.store.db,
                    |table| table.range(start..=end),
                    RangeFilter::None,
                )?;
                // empty iterator, returns nothing
                let iter2 = RangeIterator::empty(&self.store.db)?;
                iter.chain(iter2)
            }
            // regular range: iter1 = x <= t < y, iter2 = none
            Ordering::Less => {
                let start = range.x().as_byte_tuple();
                let end = range.y().as_byte_tuple();
                // iterator for entries from range.x to range.y
                let iter = RangeIterator::with_range(
                    &self.store.db,
                    |table| table.range(start..end),
                    RangeFilter::None,
                )?;
                // empty iterator
                let iter2 = RangeIterator::empty(&self.store.db)?;
                iter.chain(iter2)
                // wrap-around range: iter1 = y <= t, iter2 = x >= t
            }
            Ordering::Greater => {
                let start = range_start(&self.namespace);
                let end = range.y().as_byte_tuple();
                // iterator for entries start to from range.y
                let iter = RangeIterator::with_range(
                    &self.store.db,
                    |table| table.range(start..end),
                    RangeFilter::None,
                )?;
                let start = range.x().as_byte_tuple();
                let end = range_end(&self.namespace);
                // iterator for entries from range.x to end
                let iter2 = RangeIterator::with_range(
                    &self.store.db,
                    |table| table.range(start..=end),
                    RangeFilter::None,
                )?;
                iter.chain(iter2)
            }
        };
        Ok(iter)
    }

    fn remove(&mut self, k: &RecordIdentifier) -> Result<Option<SignedEntry>> {
        let write_tx = self.store.db.begin_write()?;
        let res = {
            let mut records_table = write_tx.open_table(RECORDS_TABLE)?;
            let key = (&k.namespace().to_bytes(), &k.author().to_bytes(), k.key());
            let record = records_table.remove(key)?;
            record.map(|record| {
                let (timestamp, namespace_sig, author_sig, len, hash) = record.value();
                let record = Record::new(hash.into(), len, timestamp);
                let entry = Entry::new(k.clone(), record);
                let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
                SignedEntry::new(entry_signature, entry)
            })
        };
        write_tx.commit()?;
        Ok(res)
    }

    fn all(&self) -> Result<Self::RangeIterator<'_>> {
        let iter = RangeIterator::namespace(&self.store.db, &self.namespace, RangeFilter::None)?;
        let iter2 = RangeIterator::empty(&self.store.db)?;
        Ok(iter.chain(iter2))
    }

    type ParentIterator<'a> = ParentIterator<'a>;
    fn prefixes_of(&self, id: &RecordIdentifier) -> Result<Self::ParentIterator<'_>, Self::Error> {
        ParentIterator::create(
            &self.store.db,
            id.namespace(),
            id.author(),
            id.key().to_vec(),
        )
    }

    fn prefixed_by(&self, prefix: &RecordIdentifier) -> Result<Self::RangeIterator<'_>> {
        let start = prefix.as_byte_tuple();
        let end = prefix_range_end(&start);
        let iter = RangeIterator::with_range(
            &self.store.db,
            |table| match end {
                Some(end) => table.range(start..(&end.0, &end.1, &end.2)),
                None => table.range(start..),
            },
            RangeFilter::None,
        )?;
        let iter2 = RangeIterator::empty(&self.store.db)?;
        Ok(iter.chain(iter2))
    }

    fn remove_prefix_filtered(
        &mut self,
        prefix: &RecordIdentifier,
        predicate: impl Fn(&Record) -> bool,
    ) -> Result<usize> {
        let start = prefix.as_byte_tuple();
        let end = prefix_range_end(&start);

        let write_tx = self.store.db.begin_write()?;
        let count = {
            let mut table = write_tx.open_table(RECORDS_TABLE)?;
            let cb = |_k: RecordsId, v: RecordsValue| {
                let (timestamp, _namespace_sig, _author_sig, len, hash) = v;
                let record = Record::new(hash.into(), len, timestamp);

                predicate(&record)
            };
            let iter = match end {
                Some(end) => table.drain_filter(start..(&end.0, &end.1, &end.2), cb)?,
                None => table.drain_filter(start.., cb)?,
            };
            iter.count()
        };
        write_tx.commit()?;
        Ok(count)
    }
}

/// Iterator over parent entries, i.e. entries with the same namespace and author, and a key which
/// is a prefix of the key passed to the iterator.
#[self_referencing]
pub struct ParentIterator<'a> {
    read_tx: ReadTransaction<'a>,
    #[borrows(read_tx)]
    #[covariant]
    record_table: RecordsTable<'this>,
    namespace: NamespaceId,
    author: AuthorId,
    key: Vec<u8>,
}

impl<'a> ParentIterator<'a> {
    fn create(
        db: &'a Arc<Database>,
        namespace: NamespaceId,
        author: AuthorId,
        key: Vec<u8>,
    ) -> anyhow::Result<Self> {
        let iter = Self::try_new(
            db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            namespace,
            author,
            key,
        )?;
        Ok(iter)
    }
}

impl Iterator for ParentIterator<'_> {
    type Item = Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.with_mut(|fields| {
            while !fields.key.is_empty() {
                let entry = get_one(
                    fields.record_table,
                    *fields.namespace,
                    *fields.author,
                    &fields.key,
                );
                fields.key.pop();
                match entry {
                    Err(err) => return Some(Err(err)),
                    Ok(Some(entry)) => return Some(Ok(entry)),
                    Ok(None) => continue,
                }
            }
            None
        })
    }
}

/// Iterator over all content hashes for the fs store.
#[self_referencing]
pub struct ContentHashesIterator<'a> {
    read_tx: ReadTransaction<'a>,
    #[borrows(read_tx)]
    #[covariant]
    record_table: RecordsTable<'this>,
    #[covariant]
    #[borrows(record_table)]
    records: RecordsRange<'this>,
}
impl<'a> ContentHashesIterator<'a> {
    fn create(db: &'a Arc<Database>) -> anyhow::Result<Self> {
        let iter = Self::try_new(
            db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |table| table.iter().map_err(anyhow::Error::from),
        )?;
        Ok(iter)
    }
}

impl Iterator for ContentHashesIterator<'_> {
    type Item = Result<Hash>;

    fn next(&mut self) -> Option<Self::Item> {
        self.with_mut(|fields| match fields.records.next() {
            None => None,
            Some(Err(err)) => Some(Err(err.into())),
            Some(Ok((_key, value))) => {
                let (_timestamp, _namespace_sig, _author_sig, _len, hash) = value.value();
                Some(Ok(Hash::from(hash)))
            }
        })
    }
}

/// Iterator over the latest entry per author.
#[self_referencing]
pub struct LatestIterator<'a> {
    read_tx: ReadTransaction<'a>,
    #[borrows(read_tx)]
    #[covariant]
    record_table: LatestTable<'this>,
    #[covariant]
    #[borrows(record_table)]
    records: LatestRange<'this>,
}
impl<'a> LatestIterator<'a> {
    fn create(db: &'a Arc<Database>, namespace: NamespaceId) -> anyhow::Result<Self> {
        let iter = Self::try_new(
            db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_table(LATEST_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |table| {
                let start = (namespace.as_bytes(), &[u8::MIN; 32]);
                let end = (namespace.as_bytes(), &[u8::MAX; 32]);
                table.range(start..=end).map_err(anyhow::Error::from)
            },
        )?;
        Ok(iter)
    }
}

impl Iterator for LatestIterator<'_> {
    type Item = Result<(AuthorId, u64, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.with_mut(|fields| match fields.records.next() {
            None => None,
            Some(Err(err)) => Some(Err(err.into())),
            Some(Ok((key, value))) => {
                let (_namespace, author) = key.value();
                let (timestamp, key) = value.value();
                Some(Ok((author.into(), timestamp, key.to_vec())))
            }
        })
    }
}

#[self_referencing]
pub struct RangeIterator<'a> {
    read_tx: ReadTransaction<'a>,
    #[borrows(read_tx)]
    #[covariant]
    record_table: RecordsTable<'this>,
    #[covariant]
    #[borrows(record_table)]
    records: RecordsRange<'this>,
    filter: RangeFilter,
}

impl<'a> RangeIterator<'a> {
    fn with_range(
        db: &'a Arc<Database>,
        range: impl for<'this> FnOnce(&'this RecordsTable<'this>) -> DbResult<RecordsRange<'this>>,
        filter: RangeFilter,
    ) -> anyhow::Result<Self> {
        let iter = RangeIterator::try_new(
            db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| range(record_table).map_err(anyhow::Error::from),
            filter,
        )?;
        Ok(iter)
    }

    fn namespace(
        db: &'a Arc<Database>,
        namespace: &NamespaceId,
        filter: RangeFilter,
    ) -> anyhow::Result<Self> {
        let start = range_start(namespace);
        let end = range_end(namespace);
        Self::with_range(db, |table| table.range(start..=end), filter)
    }

    fn empty(db: &'a Arc<Database>) -> anyhow::Result<Self> {
        let start = (&[0u8; 32], &[0u8; 32], &[0u8][..]);
        let end = (&[0u8; 32], &[0u8; 32], &[0u8][..]);
        Self::with_range(db, |table| table.range(start..end), RangeFilter::None)
    }
}

#[derive(Debug)]
enum RangeFilter {
    None,
    Prefix(Vec<u8>),
    Key(Vec<u8>),
}

impl RangeFilter {
    fn matches(&self, id: &RecordIdentifier) -> bool {
        match self {
            RangeFilter::None => true,
            RangeFilter::Prefix(ref prefix) => id.key().starts_with(prefix),
            RangeFilter::Key(ref key) => id.key() == key,
        }
    }
}

impl std::fmt::Debug for RangeIterator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeIterator").finish_non_exhaustive()
    }
}

impl Iterator for RangeIterator<'_> {
    type Item = Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.with_mut(|fields| {
            for next in fields.records.by_ref() {
                let next = match next {
                    Ok(next) => next,
                    Err(err) => return Some(Err(err.into())),
                };

                let (namespace, author, key) = next.0.value();
                let (timestamp, namespace_sig, author_sig, len, hash) = next.1.value();
                if hash == Hash::EMPTY.as_bytes() {
                    continue;
                }
                let id = RecordIdentifier::new(namespace, author, key);
                if fields.filter.matches(&id) {
                    let record = Record::new(hash.into(), len, timestamp);
                    let entry = Entry::new(id, record);
                    let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
                    let signed_entry = SignedEntry::new(entry_signature, entry);

                    return Some(Ok(signed_entry));
                }
            }
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ranger::Store as _;
    use crate::store::{GetFilter, Store as _};

    use super::*;

    #[test]
    fn test_ranges() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let store = Store::new(dbfile.path())?;

        let author = store.new_author(&mut rand::thread_rng())?;
        let namespace = NamespaceSecret::new(&mut rand::thread_rng());
        let mut replica = store.new_replica(namespace)?;

        // test author prefix relation for all-255 keys
        let key1 = vec![255, 255];
        let key2 = vec![255, 255, 255];
        replica.hash_and_insert(&key1, &author, b"v1")?;
        replica.hash_and_insert(&key2, &author, b"v2")?;
        let res = store
            .get_many(
                replica.id(),
                GetFilter::AuthorAndPrefix(author.id(), vec![255]),
            )?
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
        let store = Store::new(dbfile.path())?;

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
        let entries = store.get_all(namespace.id())?.collect::<Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 5);

        // get all prefix
        let entries = store
            .get_by_prefix(namespace.id(), "hello-")?
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
        let entries = store.get_all(namespace.id())?.collect::<Result<Vec<_>>>()?;
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
            let store = Store::new(dbfile.path())?;
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
            tx.delete_table(LATEST_TABLE)?;
            Ok(())
        })?;

        // open the copied db file, which will run the migration.
        let store = Store::new(dbfile_before_migration.path())?;
        let actual = store
            .get_latest_for_each_author(namespace.id())?
            .collect::<Result<Vec<_>>>()?;

        assert_eq!(expected, actual);

        Ok(())
    }
}

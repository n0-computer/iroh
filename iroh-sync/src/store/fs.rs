//! On disk storage for replicas.

use std::{cmp::Ordering, collections::HashSet, ops::Bound, path::Path, sync::Arc};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use derive_more::From;
use ed25519_dalek::{SignatureError, VerifyingKey};
use iroh_bytes::Hash;
use parking_lot::RwLock;
use redb::{
    Database, MultimapTableDefinition, Range as TableRange, ReadOnlyTable, ReadableMultimapTable,
    ReadableTable, StorageError, TableDefinition,
};

use crate::{
    ranger::{Fingerprint, Range, RangeEntry},
    store::Store as _,
    sync::{
        Author, Entry, EntrySignature, Namespace, Record, RecordIdentifier, Replica, SignedEntry,
    },
    AuthorId, NamespaceId, PeerIdBytes,
};

use self::util::TableReader;

use super::{
    pubkeys::MemPublicKeyStore, AuthorMatcher, Direction, KeyMatcher, LimitOffset, OpenError,
    OrderBy, PublicKeyStore, Query, QueryKind,
};

mod util;
use util::TableRangeReader;

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

type RecordsId<'a> = (&'a [u8; 32], &'a [u8; 32], &'a [u8]);
type RecordsIdOwned = ([u8; 32], [u8; 32], Bytes);

type RecordsValue<'a> = (u64, &'a [u8; 64], &'a [u8; 64], u64, &'a [u8; 32]);

type RecordsRange<'a> = TableRange<'a, RecordsId<'static>, RecordsValue<'static>>;
type RecordsTable<'a> = ReadOnlyTable<'a, RecordsId<'static>, RecordsValue<'static>>;
type RecordsReader<'a> = TableRangeReader<'a, RecordsId<'static>, RecordsValue<'static>>;

// Records by key
// Key: (NamespaceId, Key, AuthorId)
// Value: same as in RECORDS_TABLE

const RECORDS_BY_KEY_TABLE: TableDefinition<RecordsByKeyId, RecordsValue> =
    TableDefinition::new("records-by-key-1");
type RecordsByKeyId<'a> = (&'a [u8; 32], &'a [u8], &'a [u8; 32]);
type RecordsByKeyIdOwned = ([u8; 32], Bytes, [u8; 32]);

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

type DbResult<T> = Result<T, StorageError>;

impl Store {
    /// Create or open a store from a `path` to a database file.
    ///
    /// The file will be created if it does not exist, otherwise it will be opened.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path)?;

        // Setup all tables
        let write_tx = db.begin_write()?;
        {
            let _table = write_tx.open_table(RECORDS_TABLE)?;
            let _table = write_tx.open_table(NAMESPACES_TABLE)?;
            let _table = write_tx.open_table(AUTHORS_TABLE)?;
            let _table = write_tx.open_multimap_table(NAMESPACE_PEERS_TABLE)?;
            let _table = write_tx.open_table(RECORDS_BY_KEY_TABLE)?;
        }
        write_tx.commit()?;

        Ok(Store {
            db: Arc::new(db),
            open_replicas: Default::default(),
            pubkeys: Default::default(),
        })
    }

    /// Stores a new namespace
    fn insert_namespace(&self, namespace: Namespace) -> Result<()> {
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
    type GetIter<'a> = QueryIterator<'a>;
    type ContentHashesIter<'a> = ContentHashesIterator<'a>;
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
        let namespace = Namespace::from_bytes(namespace.value());
        let replica = Replica::new(namespace, StoreInstance::new(*namespace_id, self.clone()));
        self.open_replicas.write().insert(*namespace_id);
        Ok(replica)
    }

    fn close_replica(&self, mut replica: Replica<Self::Instance>) {
        self.open_replicas.write().remove(&replica.namespace());
        replica.close();
    }

    fn list_namespaces(&self) -> Result<Self::NamespaceIter<'_>> {
        // TODO: avoid collect
        let read_tx = self.db.begin_read()?;
        let namespace_table = read_tx.open_table(NAMESPACES_TABLE)?;
        let namespaces: Vec<_> = namespace_table
            .iter()?
            .map(|res| match res {
                Ok((_key, value)) => Ok(Namespace::from_bytes(value.value()).id()),
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

    fn import_namespace(&self, namespace: Namespace) -> Result<()> {
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
            {
                let mut table = write_tx.open_table(RECORDS_BY_KEY_TABLE)?;
                let (start, end) = by_key_range(*namespace, &KeyMatcher::Any);
                let start = map_bound(&start, records_by_key_id_as_ref);
                let end = map_bound(&end, records_by_key_id_as_ref);
                let _ = table.drain((start, end));
            }
            let mut namespace_table = write_tx.open_table(NAMESPACES_TABLE)?;
            namespace_table.remove(namespace.as_bytes())?;
        }
        write_tx.commit()?;
        Ok(())
    }

    fn get_many(
        &self,
        namespace: NamespaceId,
        query: impl Into<Query>,
    ) -> Result<Self::GetIter<'_>> {
        QueryIterator::new(&self.db, namespace, query.into())
    }

    fn get_one(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>> {
        let read_tx = self.db.begin_read()?;
        let record_table = read_tx.open_table(RECORDS_TABLE)?;
        get_one(&record_table, namespace, author, key, false)
    }

    fn content_hashes(&self) -> Result<Self::ContentHashesIter<'_>> {
        ContentHashesIterator::new(&self.db)
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
    include_empty: bool,
) -> Result<Option<SignedEntry>> {
    let table_key = (namespace.as_bytes(), author.as_bytes(), key.as_ref());
    let record = record_table.get(table_key)?;
    Ok(record.and_then(|r| {
        let entry = into_entry(table_key, r.value());
        if !include_empty && entry.is_empty() {
            None
        } else {
            Some(entry)
        }
    }))
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

fn increment_by_one_maybe(value: &mut [u8; 32]) -> Option<[u8; 32]> {
    if increment_by_one(value) {
        Some(*value)
    } else {
        None
    }
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

/// [`Namespace`] specific wrapper around the [`Store`].
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
            // let binding is needed
            let hash = e.content_hash();
            let value = (
                e.timestamp(),
                &e.signature().namespace().to_bytes(),
                &e.signature().author().to_bytes(),
                e.content_len(),
                hash.as_bytes(),
            );
            record_table.insert(key, value)?;

            let mut idx_by_key = write_tx.open_table(RECORDS_BY_KEY_TABLE)?;
            let key = (
                &id.namespace().to_bytes(),
                id.key(),
                &id.author().to_bytes(),
            );
            idx_by_key.insert(key, value)?;
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
                let iter =
                    RangeIterator::with_range(&self.store.db, |table| table.range(start..=end))?;
                let empty = RangeIterator::empty(&self.store.db)?;
                iter.chain(empty)
            }
            // regular range: iter1 = x <= t < y, iter2 = none
            Ordering::Less => {
                let start = range.x().as_byte_tuple();
                let end = range.y().as_byte_tuple();
                // iterator for entries from range.x to range.y
                let iter =
                    RangeIterator::with_range(&self.store.db, |table| table.range(start..end))?;
                // wrap-around range: iter1 = y <= t, iter2 = x >= t
                let empty = RangeIterator::empty(&self.store.db)?;
                iter.chain(empty)
            }
            Ordering::Greater => {
                let start = range_start(&self.namespace);
                let end = range.y().as_byte_tuple();
                // iterator for entries start to from range.y
                let iter =
                    RangeIterator::with_range(&self.store.db, |table| table.range(start..end))?;
                let start = range.x().as_byte_tuple();
                let end = range_end(&self.namespace);
                // iterator for entries from range.x to end
                let iter2 =
                    RangeIterator::with_range(&self.store.db, |table| table.range(start..=end))?;
                iter.chain(iter2)
            }
        };
        Ok(iter)
    }

    fn remove(&mut self, k: &RecordIdentifier) -> Result<Option<SignedEntry>> {
        let write_tx = self.store.db.begin_write()?;
        let res = {
            let mut records_table = write_tx.open_table(RECORDS_TABLE)?;
            let mut by_key_table = write_tx.open_table(RECORDS_BY_KEY_TABLE)?;
            let key = (&k.namespace().to_bytes(), &k.author().to_bytes(), k.key());
            let record = records_table.remove(key)?;
            let key2 = (&k.namespace().to_bytes(), k.key(), &k.author().to_bytes());
            by_key_table.remove(key2)?;
            record.map(|record| into_entry(key, record.value()))
        };
        write_tx.commit()?;
        Ok(res)
    }

    fn all(&self) -> Result<Self::RangeIterator<'_>> {
        let iter = RangeIterator::namespace(&self.store.db, &self.namespace)?;
        let iter2 = RangeIterator::empty(&self.store.db)?;
        Ok(iter.chain(iter2))
    }

    type ParentIterator<'a> = ParentIterator<'a>;
    fn prefixes_of(&self, id: &RecordIdentifier) -> Result<Self::ParentIterator<'_>, Self::Error> {
        ParentIterator::new(
            &self.store.db,
            id.namespace(),
            id.author(),
            id.key().to_vec(),
        )
    }

    fn prefixed_by(&self, prefix: &RecordIdentifier) -> Result<Self::RangeIterator<'_>> {
        let start = prefix.as_byte_tuple();
        let end = prefix_range_end(&start);
        let iter = RangeIterator::with_range(&self.store.db, |table| match end {
            Some(end) => table.range(start..(&end.0, &end.1, &end.2)),
            None => table.range(start..),
        })?;
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
pub struct ParentIterator<'a> {
    reader: TableReader<'a, RecordsId<'static>, RecordsValue<'static>>,
    namespace: NamespaceId,
    author: AuthorId,
    key: Vec<u8>,
}

impl<'a> ParentIterator<'a> {
    fn new(
        db: &'a Arc<Database>,
        namespace: NamespaceId,
        author: AuthorId,
        key: Vec<u8>,
    ) -> anyhow::Result<Self> {
        let reader = TableReader::new(db, |tx| tx.open_table(RECORDS_TABLE))?;
        Ok(Self {
            reader,
            namespace,
            author,
            key,
        })
    }
}

impl Iterator for ParentIterator<'_> {
    type Item = Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let records_table = self.reader.table();
        while !self.key.is_empty() {
            let entry = get_one(records_table, self.namespace, self.author, &self.key, false);
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
pub struct ContentHashesIterator<'a> {
    reader: RecordsReader<'a>,
}
impl<'a> ContentHashesIterator<'a> {
    fn new(db: &'a Arc<Database>) -> anyhow::Result<Self> {
        let reader =
            RecordsReader::new(db, |tx| tx.open_table(RECORDS_TABLE), |table| table.iter())?;
        Ok(Self { reader })
    }
}

impl Iterator for ContentHashesIterator<'_> {
    type Item = Result<Hash>;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.with_range(|range| match range.next() {
            None => None,
            Some(Err(err)) => Some(Err(err.into())),
            Some(Ok((_key, value))) => {
                let (_timestamp, _namespace_sig, _author_sig, _len, hash) = value.value();
                Some(Ok(Hash::from(hash)))
            }
        })
    }
}

/// Iterator over a range of replica entries.
pub struct RangeIterator<'a> {
    records: TableRangeReader<'a, RecordsId<'static>, RecordsValue<'static>>,
}

impl<'a> RangeIterator<'a> {
    fn with_range(
        db: &'a Arc<Database>,
        range_fn: impl for<'this> FnOnce(&'this RecordsTable<'this>) -> DbResult<RecordsRange<'this>>,
    ) -> anyhow::Result<Self> {
        let records = TableRangeReader::new(db, |tx| tx.open_table(RECORDS_TABLE), range_fn)?;
        Ok(Self { records })
    }

    fn namespace(db: &'a Arc<Database>, namespace: &NamespaceId) -> anyhow::Result<Self> {
        let start = range_start(namespace);
        let end = range_end(namespace);
        Self::with_range(db, |table| table.range(start..=end))
    }

    fn empty(db: &'a Arc<Database>) -> anyhow::Result<Self> {
        let start = (&[0u8; 32], &[0u8; 32], &[0u8][..]);
        let end = (&[0u8; 32], &[0u8; 32], &[0u8][..]);
        Self::with_range(db, |table| table.range(start..end))
    }
}
impl Iterator for RangeIterator<'_> {
    type Item = Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.records.with_range(|records| match records.next() {
            None => None,
            Some(Err(err)) => Some(Err(err.into())),
            Some(Ok(next)) => Some(Ok(into_entry(next.0.value(), next.1.value()))),
        })
    }
}

/// A query iterator for entry queries.
pub struct QueryIterator<'a> {
    records: QueryRecords<'a>,
    reverse: bool,
    limit: LimitOffset,
    include_empty: bool,
    offset: u64,
    count: u64,
}

enum QueryRecords<'a> {
    AuthorKey {
        filter: KeyMatcher,
        records: TableRangeReader<'a, RecordsId<'static>, RecordsValue<'static>>,
    },
    KeyAuthor {
        filter: AuthorMatcher,
        records: TableRangeReader<'a, RecordsByKeyId<'static>, RecordsValue<'static>>,
        grouper: Option<Grouper>,
    },
}

impl<'a> Iterator for QueryIterator<'a> {
    type Item = Result<SignedEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next()
    }
}

fn map_bound<'a, T, U: 'a>(bound: &'a Bound<T>, f: impl Fn(&'a T) -> U) -> Bound<U> {
    match bound {
        Bound::Unbounded => Bound::Unbounded,
        Bound::Included(t) => Bound::Included(f(t)),
        Bound::Excluded(t) => Bound::Excluded(f(t)),
    }
}

fn by_key_range<'a>(
    ns: NamespaceId,
    matcher: &KeyMatcher,
) -> (Bound<RecordsByKeyIdOwned>, Bound<RecordsByKeyIdOwned>) {
    let ns = ns.as_bytes();
    match matcher {
        KeyMatcher::Any => {
            let start = (*ns, Bytes::new(), [0u8; 32]);
            let mut ns2 = *ns;
            let end = match increment_by_one_maybe(&mut ns2) {
                Some(ns) => Bound::Excluded((ns, Bytes::new(), [0u8; 32])),
                None => Bound::Unbounded,
            };
            (Bound::Included(start), end)
        }
        KeyMatcher::Exact(key) => {
            let start = (*ns, key.clone(), [0u8; 32]);
            let end = (*ns, key.clone(), [255u8; 32]);
            (Bound::Included(start), Bound::Included(end))
        }
        KeyMatcher::Prefix(ref prefix) => {
            let start = (*ns, prefix.clone(), [0u8; 32]);
            let mut key_end = prefix.to_vec();
            let mut ns_end = *ns;
            let end = if increment_by_one(&mut key_end) {
                Bound::Excluded((*ns, key_end.into(), [0u8; 32]))
            } else if increment_by_one(&mut ns_end) {
                Bound::Excluded((ns_end, Bytes::new(), [0u8; 32]))
            } else {
                Bound::Unbounded
            };
            (Bound::Included(start), end)
        }
    }
}

fn by_author_range(
    ns: NamespaceId,
    matcher: &AuthorMatcher,
) -> (Bound<RecordsIdOwned>, Bound<RecordsIdOwned>) {
    let ns = *(ns.as_bytes());
    match matcher {
        AuthorMatcher::Any => {
            let start = (ns, [0u8; 32], Bytes::new());
            let mut ns_end = ns;
            let end = if increment_by_one(&mut ns_end) {
                Bound::Excluded((ns_end, [0u8; 32], Bytes::new()))
            } else {
                Bound::Unbounded
            };
            (Bound::Included(start), end)
        }
        AuthorMatcher::Exact(author) => {
            let author_start = *(author.as_bytes());
            let mut author_end = author_start;
            let mut ns_end = ns;
            let start = (ns, author_start, Bytes::new());
            let end = if increment_by_one(&mut author_end) {
                Bound::Excluded((ns, author_end, Bytes::new()))
            } else if increment_by_one(&mut ns_end) {
                Bound::Excluded((ns_end, [0u8; 32], Bytes::new()))
            } else {
                Bound::Unbounded
            };
            (Bound::Included(start), end)
        }
    }
}

impl<'a> QueryIterator<'a> {
    fn new(db: &'a Arc<Database>, namespace: NamespaceId, query: Query) -> Result<Self> {
        let records = match query.kind {
            QueryKind::Flat(details) => match (&query.filter_author, details.order_by) {
                (AuthorMatcher::Any, OrderBy::Key) => {
                    let (start, end) = by_key_range(namespace, &query.filter_key);
                    let start = map_bound(&start, records_by_key_id_as_ref);
                    let end = map_bound(&end, records_by_key_id_as_ref);
                    let records = TableRangeReader::new(
                        &db,
                        |tx| tx.open_table(RECORDS_BY_KEY_TABLE),
                        |table| table.range((start, end)),
                    )?;
                    QueryRecords::KeyAuthor {
                        filter: AuthorMatcher::Any,
                        records,
                        grouper: None,
                    }
                }
                _ => {
                    let (start, end) = by_author_range(namespace, &query.filter_author);
                    let start = map_bound(&start, records_id_by_ref);
                    let end = map_bound(&end, records_id_by_ref);
                    let records = TableRangeReader::new(
                        &db,
                        |tx| tx.open_table(RECORDS_TABLE),
                        |table| table.range((start, end)),
                    )?;
                    QueryRecords::AuthorKey {
                        records,
                        filter: query.filter_key,
                    }
                }
            },
            QueryKind::SingleLatestPerKey(_) => {
                let (start, end) = by_key_range(namespace, &query.filter_key);
                let start = map_bound(&start, records_by_key_id_as_ref);
                let end = map_bound(&end, records_by_key_id_as_ref);
                let records = TableRangeReader::new(
                    &db,
                    |tx| tx.open_table(RECORDS_BY_KEY_TABLE),
                    |table| table.range((start, end)),
                )?;
                QueryRecords::KeyAuthor {
                    filter: AuthorMatcher::Any,
                    records,
                    grouper: Some(Grouper::default()),
                }
            }
        };
        Ok(QueryIterator {
            records,
            reverse: matches!(query.ordering, Direction::Desc),
            limit: query.limit_offset,
            include_empty: query.include_empty,
            offset: 0,
            count: 0,
        })
    }
    fn next(&mut self) -> Option<Result<SignedEntry>> {
        if let Some(limit) = self.limit.limit() {
            if self.count >= limit {
                return None;
            }
        }
        loop {
            let next = match &mut self.records {
                QueryRecords::AuthorKey {
                    records: iter,
                    filter,
                } => iter.with_range(|records| loop {
                    let mut next = match self.reverse {
                        false => records.next(),
                        true => records.next_back(),
                    };
                    match next.take() {
                        Some(Ok(ref res)) => {
                            let id = res.0.value();
                            let (_namespace, _author, key) = id;
                            if !match_key(filter, key) {
                                continue;
                            }
                            let value = res.1.value();
                            if !self.include_empty && value_is_empty(&value) {
                                continue;
                            }
                            let entry = into_entry(id, value);
                            break Some(Ok(entry));
                        }
                        Some(Err(err)) => break Some(Err(err)),
                        None => break None,
                    }
                }),
                QueryRecords::KeyAuthor {
                    records: iter,
                    filter,
                    grouper,
                } => loop {
                    let next = iter.with_range(|records| loop {
                        let next = match self.reverse {
                            false => records.next(),
                            true => records.next_back(),
                        };
                        match next {
                            Some(Ok(res)) => {
                                let (namespace, key, author) = res.0.value();
                                let value = res.1.value();
                                if !match_author(filter, author) {
                                    continue;
                                }
                                if grouper.is_none()
                                    && !self.include_empty
                                    && value_is_empty(&value)
                                {
                                    continue;
                                }
                                let id = (namespace, author, key);
                                let entry = into_entry(id, value);
                                break Some(Ok(entry));
                            }
                            Some(Err(err)) => break Some(Err(err)),
                            None => break None,
                        }
                    });

                    match grouper.as_mut() {
                        None => break next,
                        Some(grouper) => match next {
                            Some(Err(err)) => break Some(Err(err)),
                            None => break grouper.current.take().map(|x| Ok(x)),
                            Some(Ok(next)) => match grouper.push(next) {
                                Some(next) => {
                                    if !self.include_empty && next.is_empty() {
                                        continue;
                                    } else {
                                        break Some(Ok(next));
                                    }
                                }
                                None => continue,
                            },
                        },
                    }
                },
            };
            match next {
                None => break None,
                Some(Err(err)) => break Some(Err(err.into())),
                Some(Ok(entry)) => {
                    if let Some(offset) = self.limit.limit() {
                        if self.offset < offset {
                            self.offset += 1;
                            continue;
                        }
                    }
                    if let Some(limit) = self.limit.limit() {
                        if self.count >= limit {
                            break None;
                        }
                    }
                    self.count += 1;
                    break Some(Ok(entry));
                }
            }
        }
    }
}

#[derive(Debug, Default)]
struct Grouper {
    current: Option<SignedEntry>,
}

impl Grouper {
    fn push(&mut self, entry: SignedEntry) -> Option<SignedEntry> {
        match self.current.take() {
            None => {
                self.current = Some(entry);
                None
            }
            Some(current) if current.key() == entry.key() => {
                if entry.timestamp() > current.timestamp() {
                    self.current = Some(entry);
                } else {
                    self.current = Some(current);
                }
                None
            }
            Some(current) => {
                self.current = Some(entry);
                Some(current)
            }
        }
    }
}

fn records_by_key_id_as_ref(id: &RecordsByKeyIdOwned) -> RecordsByKeyId {
    (&id.0, &id.1[..], &id.2)
}

fn records_id_by_ref(id: &RecordsIdOwned) -> RecordsId {
    (&id.0, &id.1, &id.2[..])
}

fn value_is_empty(value: &RecordsValue) -> bool {
    let (_timestamp, _namespace_sig, _author_sig, _len, hash) = value;
    *hash == Hash::EMPTY.as_bytes()
}

fn match_key<'a>(matcher: &KeyMatcher, key: &'a [u8]) -> bool {
    match matcher {
        KeyMatcher::Any => true,
        KeyMatcher::Exact(k) => k == &key,
        KeyMatcher::Prefix(k) => key.starts_with(k),
    }
}
fn match_author<'a>(matcher: &AuthorMatcher, author: &'a [u8; 32]) -> bool {
    match matcher {
        AuthorMatcher::Any => true,
        AuthorMatcher::Exact(a) => a.as_bytes() == author,
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
    use crate::store::Store as _;

    use super::*;

    #[test]
    fn test_ranges() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let store = Store::new(dbfile.path())?;

        let author = store.new_author(&mut rand::thread_rng())?;
        let namespace = Namespace::new(&mut rand::thread_rng());
        let mut replica = store.new_replica(namespace)?;

        // test author prefix relation for all-255 keys
        let key1 = vec![255, 255];
        let key2 = vec![255, 255, 255];
        replica.hash_and_insert(&key1, &author, b"v1")?;
        replica.hash_and_insert(&key2, &author, b"v2")?;
        let res = store
            .get_many(
                replica.namespace(),
                Query::author(author.id()).key_prefix([255]),
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
        let namespace = Namespace::new(&mut rand::thread_rng());
        let replica = store.new_replica(namespace.clone())?;
        store.close_replica(replica);
        let replica = store.open_replica(&namespace.id())?;
        assert_eq!(replica.namespace(), namespace.id());

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
            .get_many(namespace.id(), Query::prefix("hello-"))?
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
}

//! On disk storage for replicas.

use std::{cmp::Ordering, collections::HashMap, path::Path, sync::Arc};

use anyhow::Result;
use derive_more::From;
use ed25519_dalek::{SignatureError, VerifyingKey};
use iroh_bytes::Hash;
use ouroboros::self_referencing;
use parking_lot::RwLock;
use redb::{
    Database, Range as TableRange, ReadOnlyTable, ReadTransaction, ReadableTable, StorageError,
    TableDefinition,
};

use crate::{
    ranger::{Fingerprint, Range, RangeEntry},
    store::Store as _,
    sync::{
        Author, Entry, EntrySignature, Namespace, Record, RecordIdentifier, Replica, SignedEntry,
    },
    AuthorId, NamespaceId, PeerIdBytes,
};

use super::{pubkeys::MemPublicKeyStore, PublicKeyStore};

/// Manages the replicas and authors for an instance.
#[derive(Debug, Clone)]
pub struct Store {
    db: Arc<Database>,
    replicas: Arc<RwLock<HashMap<NamespaceId, Replica<StoreInstance>>>>,
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

type RecordsId<'a> = (&'a [u8; 32], &'a [u8; 32], &'a [u8]);
type RecordsValue<'a> = (u64, &'a [u8; 64], &'a [u8; 64], u64, &'a [u8; 32]);
type RecordsRange<'a> = TableRange<'a, RecordsId<'static>, RecordsValue<'static>>;
type RecordsTable<'a> = ReadOnlyTable<'a, RecordsId<'static>, RecordsValue<'static>>;
type DbResult<T> = Result<T, StorageError>;

const RECORDS_TABLE: TableDefinition<RecordsId, RecordsValue> = TableDefinition::new("records-1");

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
        }
        write_tx.commit()?;

        Ok(Store {
            db: Arc::new(db),
            replicas: Default::default(),
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
    type GetIter<'a> = RangeIterator<'a>;
    type ContentHashesIter<'a> = ContentHashesIterator<'a>;
    type AuthorsIter<'a> = std::vec::IntoIter<Result<Author>>;
    type NamespaceIter<'a> = std::vec::IntoIter<Result<NamespaceId>>;
    type PeersIter<'a> = std::vec::IntoIter<Result<PeerIdBytes>>;

    fn open_replica(&self, namespace_id: &NamespaceId) -> Result<Option<Replica<Self::Instance>>> {
        if let Some(replica) = self.replicas.read().get(namespace_id) {
            return Ok(Some(replica.clone()));
        }

        let read_tx = self.db.begin_read()?;
        let namespace_table = read_tx.open_table(NAMESPACES_TABLE)?;
        let Some(namespace) = namespace_table.get(namespace_id.as_bytes())? else {
            return Ok(None);
        };
        let namespace = Namespace::from_bytes(namespace.value());
        let replica = Replica::new(namespace, StoreInstance::new(*namespace_id, self.clone()));
        self.replicas.write().insert(*namespace_id, replica.clone());
        Ok(Some(replica))
    }

    fn close_replica(&self, namespace_id: &NamespaceId) {
        if let Some(replica) = self.replicas.write().remove(namespace_id) {
            replica.unsubscribe();
        }
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

    fn new_replica(&self, namespace: Namespace) -> Result<Replica<Self::Instance>> {
        let id = namespace.id();
        self.insert_namespace(namespace.clone())?;

        let replica = Replica::new(namespace, StoreInstance::new(id, self.clone()));

        self.replicas.write().insert(id, replica.clone());
        Ok(replica)
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

        let db_key = (namespace.as_ref(), author.as_ref(), key.as_ref());
        let record = record_table.get(db_key)?;
        let Some(record) = record else {
            return Ok(None);
        };
        let (timestamp, namespace_sig, author_sig, len, hash) = record.value();

        let record = Record::new(hash.into(), len, timestamp);
        let id = RecordIdentifier::new(namespace, author, key);
        let entry = Entry::new(id, record);
        let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
        let signed_entry = SignedEntry::new(entry_signature, entry);

        Ok(Some(signed_entry))
    }

    fn content_hashes(&self) -> Result<Self::ContentHashesIter<'_>> {
        ContentHashesIterator::create(&self.db)
    }

    fn register_useful_peer(&self, namespace: &NamespaceId, peer: crate::PeerIdBytes) {}

    fn get_sync_peers(&self, namespace: &NamespaceId) -> Result<Self::PeersIter<'_>> {
        Ok(vec![].into_iter())
    }
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
        let write_tx = self.store.db.begin_write()?;
        {
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
                    |table| table.range(start..end),
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
                    |table| table.range(start..end),
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
        let namespace = Namespace::new(&mut rand::thread_rng());
        let replica = store.new_replica(namespace)?;

        // test author prefix relation for all-255 keys
        let key1 = vec![255, 255];
        let key2 = vec![255, 255, 255];
        replica.hash_and_insert(&key1, &author, b"v1")?;
        replica.hash_and_insert(&key2, &author, b"v2")?;
        let res = store
            .get_many(
                replica.namespace(),
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
        let namespace = Namespace::new(&mut rand::thread_rng());
        let replica = store.new_replica(namespace.clone())?;

        let replica_back = store.open_replica(&namespace.id())?.unwrap();
        assert_eq!(
            replica.namespace().as_bytes(),
            replica_back.namespace().as_bytes()
        );

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
}

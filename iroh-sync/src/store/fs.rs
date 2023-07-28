//! On disk storage for replicas.

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::Arc,
};

use anyhow::Result;
use parking_lot::RwLockReadGuard;
use rand_core::CryptoRngCore;
use redb::{
    Database, MultimapRange, MultimapTableDefinition, ReadOnlyMultimapTable, ReadTransaction,
    ReadableMultimapTable, ReadableTable, TableDefinition,
};

use crate::{
    ranger::{AsFingerprint, Fingerprint, Range, RangeKey},
    sync::{
        Author, AuthorId, Entry, EntrySignature, Namespace, NamespaceId, Record, RecordIdentifier,
        Replica as SyncReplica, SignedEntry,
    },
};

pub type Replica = SyncReplica<StoreInstance>;

/// Manages the replicas and authors for an instance.
#[derive(Debug, Clone)]
pub struct Store {
    db: Arc<Database>,
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
// Multimap
// Key: ([u8; 32], [u8; 32], Vec<u8>) # (NamespaceId, AuthorId, Key)
// Values:
//    (u64,  [u8; 32], [u8; 32], u64, [u8; 32])
//  # (timestamp, signature_namespace, signature_author, len, hash)

type RecordsId<'a> = (&'a [u8; 32], &'a [u8; 32], &'a [u8]);
type RecordsValue<'a> = (u64, &'a [u8; 64], &'a [u8; 64], u64, &'a [u8; 32]);

const RECORDS_TABLE: MultimapTableDefinition<RecordsId, RecordsValue> =
    MultimapTableDefinition::new("records-1");

impl Store {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path)?;

        // Setup all tables
        {
            let write_tx = db.begin_write()?;
            let _table = write_tx.open_multimap_table(RECORDS_TABLE)?;
            let _table = write_tx.open_table(NAMESPACES_TABLE)?;
            let _table = write_tx.open_table(AUTHORS_TABLE)?;
        }

        Ok(Store { db: Arc::new(db) })
    }

    pub fn get_replica(&self, namespace_id: &NamespaceId) -> Result<Option<Replica>> {
        let read_tx = self.db.begin_read()?;
        let namespace_table = read_tx.open_table(NAMESPACES_TABLE)?;
        let Some(namespace) = namespace_table.get(namespace_id.as_bytes())? else {
            return Ok(None);
        };
        let namespace = Namespace::from_bytes(namespace.value());
        let replica = Replica::new(namespace, StoreInstance::new(*namespace_id, self.clone()));
        Ok(Some(replica))
    }

    pub fn get_author(&self, author_id: &AuthorId) -> Result<Option<Author>> {
        let read_tx = self.db.begin_read()?;
        let author_table = read_tx.open_table(AUTHORS_TABLE)?;
        let Some(author) = author_table.get(author_id.as_bytes())? else {
            return Ok(None);
        };

        let author = Author::from_bytes(author.value());
        Ok(Some(author))
    }

    /// Inserts a new author.
    pub fn insert_author(&self, author: Author) -> Result<()> {
        let write_tx = self.db.begin_write()?;
        let mut author_table = write_tx.open_table(AUTHORS_TABLE)?;
        author_table.insert(&author.id_bytes(), &author.to_bytes())?;

        Ok(())
    }

    /// Generates a new author, using the passed in randomness.
    pub fn new_author<R: CryptoRngCore + ?Sized>(&self, rng: &mut R) -> Result<Author> {
        let author = Author::new(rng);
        self.insert_author(author.clone())?;
        Ok(author)
    }

    /// Stores a new namespace
    fn insert_namespace(&self, namespace: Namespace) -> Result<()> {
        let write_tx = self.db.begin_write()?;
        let mut namespace_table = write_tx.open_table(NAMESPACES_TABLE)?;
        namespace_table.insert(&namespace.id_bytes(), &namespace.to_bytes())?;

        Ok(())
    }

    /// Creates a new replica for the given [`Namespace`].
    pub fn new_replica(&self, namespace: Namespace) -> Result<Replica> {
        let id = namespace.id();
        self.insert_namespace(namespace.clone())?;

        let replica = Replica::new(namespace, StoreInstance::new(id, self.clone()));

        Ok(replica)
    }

    /// Gets all entries matching this key and author.
    pub fn get_latest_by_key_and_author(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
        author: &AuthorId,
    ) -> Option<SignedEntry> {
        todo!()
    }

    /// Returns the latest version of the matching documents by key.
    pub fn get_latest_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> GetLatestIter<'_> {
        todo!()
    }

    /// Returns the latest version of the matching documents by prefix.
    pub fn get_latest_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> GetLatestIter<'_> {
        todo!()
    }

    /// Returns the latest versions of all documents.
    pub fn get_latest(&self, namespace: NamespaceId) -> GetLatestIter<'_> {
        todo!()
    }

    /// Returns all versions of the matching documents by author.
    pub fn get_all_by_key_and_author<'a, 'b: 'a>(
        &'a self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]> + 'b,
        author: &AuthorId,
    ) -> GetAllIter<'a> {
        todo!()
    }

    /// Returns all versions of the matching documents by key.
    pub fn get_all_by_key(&self, namespace: NamespaceId, key: impl AsRef<[u8]>) -> GetAllIter<'_> {
        todo!()
    }

    /// Returns all versions of the matching documents by prefix.
    pub fn get_all_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> GetAllIter<'_> {
        todo!()
    }

    /// Returns all versions of all documents.
    pub fn get_all(&self, namespace: NamespaceId) -> GetAllIter<'_> {
        todo!()
    }
}

#[derive(Debug)]
enum GetFilter {
    /// All entries.
    All { namespace: NamespaceId },
    /// Filter by key and author.
    KeyAuthor(RecordIdentifier),
    /// Filter by key only.
    Key {
        namespace: NamespaceId,
        key: Vec<u8>,
    },
    /// Filter by prefix only.
    Prefix {
        namespace: NamespaceId,
        prefix: Vec<u8>,
    },
}

impl GetFilter {
    fn namespace(&self) -> &NamespaceId {
        match self {
            GetFilter::All { ref namespace } => namespace,
            GetFilter::KeyAuthor(ref r) => r.namespace(),
            GetFilter::Key { ref namespace, .. } => namespace,
            GetFilter::Prefix { ref namespace, .. } => namespace,
        }
    }
}

#[derive(Debug)]
pub struct GetLatestIter<'a> {
    records: RwLockReadGuard<
        'a,
        HashMap<NamespaceId, BTreeMap<RecordIdentifier, BTreeMap<u64, SignedEntry>>>,
    >,
    filter: GetFilter,
    /// Current iteration index.
    index: usize,
}

impl<'a> Iterator for GetLatestIter<'a> {
    type Item = SignedEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let records = self.records.get(self.filter.namespace())?;
        let res = match self.filter {
            GetFilter::All { namespace } => {
                let (_, res) = records
                    .iter()
                    .filter(|(k, _)| k.namespace() == &namespace)
                    .filter_map(|(_key, value)| value.last_key_value())
                    .nth(self.index)?;
                res.clone()
            }
            GetFilter::KeyAuthor(ref record_id) => {
                let values = records.get(record_id)?;
                let (_, res) = values.iter().nth(self.index)?;
                res.clone()
            }
            GetFilter::Key { namespace, ref key } => {
                let (_, res) = records
                    .iter()
                    .filter(|(k, _)| k.key() == key && k.namespace() == &namespace)
                    .filter_map(|(_key, value)| value.last_key_value())
                    .nth(self.index)?;
                res.clone()
            }
            GetFilter::Prefix {
                namespace,
                ref prefix,
            } => {
                let (_, res) = records
                    .iter()
                    .filter(|(k, _)| k.key().starts_with(prefix) && k.namespace() == &namespace)
                    .filter_map(|(_key, value)| value.last_key_value())
                    .nth(self.index)?;
                res.clone()
            }
        };
        self.index += 1;
        Some(res)
    }
}

#[derive(Debug)]
pub struct GetAllIter<'a> {
    records: RwLockReadGuard<
        'a,
        HashMap<NamespaceId, BTreeMap<RecordIdentifier, BTreeMap<u64, SignedEntry>>>,
    >,
    filter: GetFilter,
    /// Current iteration index.
    index: usize,
}

impl<'a> Iterator for GetAllIter<'a> {
    type Item = (RecordIdentifier, u64, SignedEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let records = self.records.get(self.filter.namespace())?;
        let res = match self.filter {
            GetFilter::All { namespace } => records
                .iter()
                .filter(|(k, _)| k.namespace() == &namespace)
                .flat_map(|(key, value)| {
                    value
                        .iter()
                        .map(|(t, value)| (key.clone(), *t, value.clone()))
                })
                .nth(self.index)?,
            GetFilter::KeyAuthor(ref record_id) => {
                let values = records.get(record_id)?;
                let (t, value) = values.iter().nth(self.index)?;
                (record_id.clone(), *t, value.clone())
            }
            GetFilter::Key { namespace, ref key } => records
                .iter()
                .filter(|(k, _)| k.key() == key && k.namespace() == &namespace)
                .flat_map(|(key, value)| {
                    value
                        .iter()
                        .map(|(t, value)| (key.clone(), *t, value.clone()))
                })
                .nth(self.index)?,
            GetFilter::Prefix {
                namespace,
                ref prefix,
            } => records
                .iter()
                .filter(|(k, _)| k.key().starts_with(prefix) && k.namespace() == &namespace)
                .flat_map(|(key, value)| {
                    value
                        .iter()
                        .map(|(t, value)| (key.clone(), *t, value.clone()))
                })
                .nth(self.index)?,
        };
        self.index += 1;
        Some(res)
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

#[derive(Debug)]
struct RecordsIter<'a> {
    namespace: NamespaceId,
    replica_records: RwLockReadGuard<
        'a,
        HashMap<NamespaceId, BTreeMap<RecordIdentifier, BTreeMap<u64, SignedEntry>>>,
    >,
    i: usize,
}

impl Iterator for RecordsIter<'_> {
    type Item = (RecordIdentifier, BTreeMap<u64, SignedEntry>);

    fn next(&mut self) -> Option<Self::Item> {
        let records = self.replica_records.get(&self.namespace)?;
        let (key, value) = records.iter().nth(self.i)?;
        self.i += 1;
        Some((key.clone(), value.clone()))
    }
}

impl crate::ranger::Store<RecordIdentifier, SignedEntry> for StoreInstance {
    type Error = anyhow::Error;

    /// Get a the first key (or the default if none is available).
    fn get_first(&self) -> Result<RecordIdentifier> {
        let read_tx = self.store.db.begin_read()?;
        let record_table = read_tx.open_multimap_table(RECORDS_TABLE)?;

        // TODO: verify this fetches all keys with this namespace
        let key = (self.namespace.as_bytes(), &[0u8; 32], &[][..]);
        let mut records = record_table.range(key..=key)?;

        let Some(record) = records.next() else {
            return Ok(RecordIdentifier::default());
        };
        let (compound_key, _) = record?;
        let (namespace_id, author_id, key) = compound_key.value();

        let id = RecordIdentifier::from_parts(key, namespace_id, author_id)?;
        Ok(id)
    }

    fn get(&self, id: &RecordIdentifier) -> Result<Option<SignedEntry>> {
        let read_tx = self.store.db.begin_read()?;
        let record_table = read_tx.open_multimap_table(RECORDS_TABLE)?;

        // TODO: verify this fetches all keys with this namespace
        let key = (id.namespace().as_bytes(), id.author().as_bytes(), id.key());
        let records = record_table.get(key)?;
        let Some(record) = records.last() else {
            return Ok(None);
        };
        let record = record?;
        let (timestamp, namespace_sig, author_sig, len, hash) = record.value();
        let record = Record::new(timestamp, len, hash.into());
        let entry = Entry::new(id.clone(), record);
        let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
        let signed_entry = SignedEntry::new(entry_signature, entry);

        Ok(Some(signed_entry))
    }

    fn len(&self) -> Result<usize> {
        let read_tx = self.store.db.begin_read()?;
        let record_table = read_tx.open_multimap_table(RECORDS_TABLE)?;

        // TODO: verify this fetches all keys with this namespace
        let key = (self.namespace.as_bytes(), &[0u8; 32], &[][..]);
        let records = record_table.range(key..=key)?;
        Ok(records.count())
    }

    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    fn get_fingerprint(
        &self,
        range: &Range<RecordIdentifier>,
        limit: Option<&Range<RecordIdentifier>>,
    ) -> Result<Fingerprint> {
        // TODO: optimize?

        let elements = self.get_range(range.clone(), limit.cloned())?;
        let mut fp = Fingerprint::empty();
        for el in elements {
            fp ^= el.0.as_fingerprint();
        }

        Ok(fp)
    }

    fn put(&mut self, k: RecordIdentifier, v: SignedEntry) -> Result<()> {
        // TODO: propagate error/not insertion?
        if v.verify().is_ok() {
            let timestamp = v.entry().record().timestamp();
            // TODO: verify timestamp is "reasonable"

            let write_tx = self.store.db.begin_write()?;
            let mut record_table = write_tx.open_multimap_table(RECORDS_TABLE)?;
            let key = (k.namespace().as_bytes(), k.author().as_bytes(), k.key());
            let record = v.entry().record();
            let value = (
                record.timestamp(),
                &v.signature().namespace_signature().to_bytes(),
                &v.signature().author_signature().to_bytes(),
                record.content_len(),
                record.content_hash().as_bytes(),
            );
            record_table.insert(key, value)?;
        }
        Ok(())
    }

    type RangeIterator<'a> = RangeIterator<'a>;
    fn get_range(
        &self,
        range: Range<RecordIdentifier>,
        limit: Option<Range<RecordIdentifier>>,
    ) -> Result<Self::RangeIterator<'_>> {
        let read_tx = self.store.db.begin_read()?;
        let record_table = read_tx.open_multimap_table(RECORDS_TABLE)?;

        // TODO: implement inverted range
        let range_start = range.x();
        let range_end = range.y();

        let start = (
            range_start.namespace().as_bytes(),
            range_start.author().as_bytes(),
            range_start.key(),
        );
        let end = (
            range_end.namespace().as_bytes(),
            range_end.author().as_bytes(),
            range_end.key(),
        );
        // let records: MultimapRange<
        //     (&[u8; 32], &[u8; 32], &[u8]),
        //     (u64, &[u8; 64], &[u8; 64], u64, &[u8; 32]),
        // > = record_table.range(start..end)?;

        Ok(RangeIterator {
            read_tx,
            record_table,
            records: todo!(),
            limit,
        })
    }

    fn remove(&mut self, key: &RecordIdentifier) -> Result<Option<SignedEntry>> {
        todo!()
    }

    type AllIterator<'a> = RangeIterator<'a>;

    fn all(&self) -> Result<Self::AllIterator<'_>> {
        todo!()
    }
}

#[derive(derive_more::Debug)]
pub struct RangeIterator<'a> {
    read_tx: ReadTransaction<'a>,
    #[debug("ReadOnlyMultimapTable")]
    record_table: ReadOnlyMultimapTable<'a, RecordsId<'static>, RecordsValue<'static>>,
    #[debug("MultimapRange")]
    records: MultimapRange<
        'a,
        (&'static [u8; 32], &'static [u8; 32], &'static [u8]),
        (
            u64,
            &'static [u8; 64],
            &'static [u8; 64],
            u64,
            &'static [u8; 32],
        ),
    >,
    limit: Option<Range<RecordIdentifier>>,
}

impl RangeIterator<'_> {
    fn matches(&self, x: &RecordIdentifier) -> bool {
        self.limit.as_ref().map(|r| x.contains(r)).unwrap_or(true)
    }
}

impl Iterator for RangeIterator<'_> {
    type Item = (RecordIdentifier, SignedEntry);

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: should yield Result<..> instead of just the values

        let mut next = self.records.next()?.ok()?;
        loop {
            let (namespace, author, key) = next.0.value();
            let id = RecordIdentifier::from_parts(key, namespace, author).ok()?;
            if self.matches(&id) {
                let value = next.1.last()?.ok()?;
                let (timestamp, namespace_sig, author_sig, len, hash) = value.value();
                let record = Record::new(timestamp, len, hash.into());
                let entry = Entry::new(id.clone(), record);
                let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
                let signed_entry = SignedEntry::new(entry_signature, entry);

                return Some((id, signed_entry));
            }

            next = self.records.next()?.ok()?;
        }
    }
}

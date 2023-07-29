//! On disk storage for replicas.

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::Arc,
};

use anyhow::Result;
use ouroboros::self_referencing;
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
        Replica, SignedEntry,
    },
};

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
        let write_tx = db.begin_write()?;
        {
            let _table = write_tx.open_multimap_table(RECORDS_TABLE)?;
            let _table = write_tx.open_table(NAMESPACES_TABLE)?;
            let _table = write_tx.open_table(AUTHORS_TABLE)?;
        }
        write_tx.commit()?;

        Ok(Store { db: Arc::new(db) })
    }
    /// Stores a new namespace
    fn insert_namespace(&self, namespace: Namespace) -> Result<()> {
        let write_tx = self.db.begin_write()?;
        {
            let mut namespace_table = write_tx.open_table(NAMESPACES_TABLE)?;
            namespace_table.insert(&namespace.id_bytes(), &namespace.to_bytes())?;
        }
        write_tx.commit()?;

        Ok(())
    }

    fn insert_author(&self, author: Author) -> Result<()> {
        let write_tx = self.db.begin_write()?;
        {
            let mut author_table = write_tx.open_table(AUTHORS_TABLE)?;
            author_table.insert(&author.id_bytes(), &author.to_bytes())?;
        }
        write_tx.commit()?;

        Ok(())
    }
}

impl super::Store for Store {
    type Instance = StoreInstance;
    type GetAllIter<'a> = GetAllIter<'a>;
    type GetLatestIter<'a> = GetLatestIter<'a>;

    fn get_replica(&self, namespace_id: &NamespaceId) -> Result<Option<Replica<Self::Instance>>> {
        let read_tx = self.db.begin_read()?;
        let namespace_table = read_tx.open_table(NAMESPACES_TABLE)?;
        let Some(namespace) = namespace_table.get(namespace_id.as_bytes())? else {
            return Ok(None);
        };
        let namespace = Namespace::from_bytes(namespace.value());
        let replica = Replica::new(namespace, StoreInstance::new(*namespace_id, self.clone()));
        Ok(Some(replica))
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

    /// Generates a new author, using the passed in randomness.
    fn new_author<R: CryptoRngCore + ?Sized>(&self, rng: &mut R) -> Result<Author> {
        let author = Author::new(rng);
        self.insert_author(author.clone())?;
        Ok(author)
    }

    fn new_replica(&self, namespace: Namespace) -> Result<Replica<Self::Instance>> {
        let id = namespace.id();
        self.insert_namespace(namespace.clone())?;

        let replica = Replica::new(namespace, StoreInstance::new(id, self.clone()));

        Ok(replica)
    }

    /// Gets all entries matching this key and author.
    fn get_latest_by_key_and_author(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
        author: AuthorId,
    ) -> Result<Option<SignedEntry>> {
        todo!()
    }

    fn get_latest_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> Result<Self::GetLatestIter<'_>> {
        todo!()
    }

    fn get_latest_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<Self::GetLatestIter<'_>> {
        todo!()
    }

    fn get_latest(&self, namespace: NamespaceId) -> Result<Self::GetLatestIter<'_>> {
        todo!()
    }

    fn get_all_by_key_and_author<'a, 'b: 'a>(
        &'a self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]> + 'b,
        author: AuthorId,
    ) -> Result<Self::GetAllIter<'a>> {
        todo!()
    }

    fn get_all_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> Result<Self::GetAllIter<'_>> {
        todo!()
    }

    fn get_all_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<Self::GetAllIter<'_>> {
        todo!()
    }

    fn get_all(&self, namespace: NamespaceId) -> Result<Self::GetAllIter<'_>> {
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
    type Item = Result<SignedEntry>;

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
        Some(Ok(res))
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
    type Item = Result<(u64, SignedEntry)>;

    fn next(&mut self) -> Option<Self::Item> {
        let records = self.records.get(self.filter.namespace())?;
        let res = match self.filter {
            GetFilter::All { namespace } => records
                .iter()
                .filter(|(k, _)| k.namespace() == &namespace)
                .flat_map(|(_, value)| value.iter().map(|(t, value)| (*t, value.clone())))
                .nth(self.index)?,
            GetFilter::KeyAuthor(ref record_id) => {
                let values = records.get(record_id)?;
                let (t, value) = values.iter().nth(self.index)?;
                (*t, value.clone())
            }
            GetFilter::Key { namespace, ref key } => records
                .iter()
                .filter(|(k, _)| k.key() == key && k.namespace() == &namespace)
                .flat_map(|(_, value)| value.iter().map(|(t, value)| (*t, value.clone())))
                .nth(self.index)?,
            GetFilter::Prefix {
                namespace,
                ref prefix,
            } => records
                .iter()
                .filter(|(k, _)| k.key().starts_with(prefix) && k.namespace() == &namespace)
                .flat_map(|(_, value)| value.iter().map(|(t, value)| (*t, value.clone())))
                .nth(self.index)?,
        };
        self.index += 1;
        Some(Ok(res))
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
        let start = (self.namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (self.namespace.as_bytes(), &[255u8; 32], &[][..]);
        let mut records = record_table.range(start..=end)?;

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
        let start = (self.namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (self.namespace.as_bytes(), &[255u8; 32], &[][..]);
        let records = record_table.range(start..=end)?;
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
            {
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
            write_tx.commit()?;
        }
        Ok(())
    }

    type RangeIterator<'a> = RangeIterator<'a>;
    fn get_range(
        &self,
        range: Range<RecordIdentifier>,
        limit: Option<Range<RecordIdentifier>>,
    ) -> Result<Self::RangeIterator<'_>> {
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
        let iter = RangeIterator::try_new(
            self.store.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| record_table.range(start..=end).map_err(anyhow::Error::from),
            limit,
        )?;

        Ok(iter)
    }

    fn remove(&mut self, key: &RecordIdentifier) -> Result<Option<SignedEntry>> {
        todo!()
    }

    type AllIterator<'a> = RangeIterator<'a>;

    fn all(&self) -> Result<Self::AllIterator<'_>> {
        // TODO: verify this gives all
        let start = (self.namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (self.namespace.as_bytes(), &[255u8; 32], &[][..]);
        let iter = RangeIterator::try_new(
            self.store.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| record_table.range(start..=end).map_err(anyhow::Error::from),
            None,
        )?;

        Ok(iter)
    }
}

#[self_referencing]
pub struct RangeIterator<'a> {
    read_tx: ReadTransaction<'a>,
    #[borrows(read_tx)]
    #[covariant]
    record_table: ReadOnlyMultimapTable<'this, RecordsId<'static>, RecordsValue<'static>>,
    #[covariant]
    #[borrows(record_table)]
    records: MultimapRange<'this, RecordsId<'static>, RecordsValue<'static>>,
    limit: Option<Range<RecordIdentifier>>,
}

impl std::fmt::Debug for RangeIterator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeIterator").finish_non_exhaustive()
    }
}

fn matches(limit: &Option<Range<RecordIdentifier>>, x: &RecordIdentifier) -> bool {
    limit.as_ref().map(|r| x.contains(r)).unwrap_or(true)
}

impl Iterator for RangeIterator<'_> {
    type Item = (RecordIdentifier, SignedEntry);

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: should yield Result<..> instead of just the values

        let limit = self.borrow_limit().clone();
        self.with_records_mut(|records| {
            let mut next = records.next()?.ok()?;

            loop {
                let (namespace, author, key) = next.0.value();
                let id = RecordIdentifier::from_parts(key, namespace, author).ok()?;
                if matches(&limit, &id) {
                    let value = next.1.last()?.ok()?;
                    let (timestamp, namespace_sig, author_sig, len, hash) = value.value();
                    let record = Record::new(timestamp, len, hash.into());
                    let entry = Entry::new(id.clone(), record);
                    let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
                    let signed_entry = SignedEntry::new(entry_signature, entry);

                    return Some((id, signed_entry));
                }

                next = records.next()?.ok()?;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ranger::Store as _;
    use crate::store::Store as _;

    use super::*;

    #[test]
    fn test_basics() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let store = Store::new(dbfile.path())?;

        let author = store.new_author(&mut rand::thread_rng())?;
        let namespace = Namespace::new(&mut rand::thread_rng());
        let replica = store.new_replica(namespace.clone())?;

        let replica_back = store.get_replica(&namespace.id())?.unwrap();
        assert_eq!(
            replica.namespace().as_bytes(),
            replica_back.namespace().as_bytes()
        );

        let author_back = store.get_author(&author.id())?.unwrap();
        assert_eq!(author.to_bytes(), author_back.to_bytes(),);

        let mut wrapper = StoreInstance::new(namespace.id(), store.clone());
        for i in 0..5 {
            let id = RecordIdentifier::new(format!("hello-{i}"), namespace.id(), author.id());
            let entry = Entry::new(
                id.clone(),
                Record::from_data(format!("world-{i}"), namespace.id()),
            );
            let entry = SignedEntry::from_entry(entry, &namespace, &author);
            wrapper.put(id, entry)?;
        }

        // all
        let all: Vec<_> = wrapper.all()?.collect();
        assert_eq!(all.len(), 5);

        Ok(())
    }
}

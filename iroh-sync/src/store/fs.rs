//! On disk storage for replicas.

use std::{collections::HashMap, path::Path, sync::Arc};

use anyhow::Result;
use ouroboros::self_referencing;
use parking_lot::RwLock;
use rand_core::CryptoRngCore;
use redb::{
    AccessGuard, Database, MultimapRange, MultimapTableDefinition, MultimapValue,
    ReadOnlyMultimapTable, ReadTransaction, ReadableMultimapTable, ReadableTable, TableDefinition,
};

use crate::{
    ranger::{AsFingerprint, Fingerprint, Range, RangeKey},
    store::Store as _,
    sync::{
        Author, AuthorId, Entry, EntrySignature, Namespace, NamespaceId, Record, RecordIdentifier,
        Replica, SignedEntry,
    },
};

use self::ouroboros_impl_range_all_iterator::BorrowedMutFields;

/// Manages the replicas and authors for an instance.
#[derive(Debug, Clone)]
pub struct Store {
    db: Arc<Database>,
    replicas: Arc<RwLock<HashMap<NamespaceId, Replica<StoreInstance>>>>,
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

        Ok(Store {
            db: Arc::new(db),
            replicas: Default::default(),
        })
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
    type GetAllIter<'a> = RangeAllIterator<'a>;
    type GetLatestIter<'a> = RangeLatestIterator<'a>;

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

    // TODO: return iterator
    fn list_replicas(&self) -> Result<Vec<NamespaceId>> {
        let read_tx = self.db.begin_read()?;
        let namespace_table = read_tx.open_table(NAMESPACES_TABLE)?;
        let namespaces = namespace_table
            .iter()?
            .filter_map(|entry| entry.ok())
            .map(|(_key, value)| Namespace::from_bytes(value.value()).id());
        Ok(namespaces.collect())
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

    /// Generates a new author, using the passed in randomness.
    fn list_authors(&self) -> Result<Vec<Author>> {
        let read_tx = self.db.begin_read()?;
        let author_table = read_tx.open_table(AUTHORS_TABLE)?;

        let mut authors = vec![];
        let iter = author_table.iter()?;
        for entry in iter {
            let (_key, value) = entry?;
            let author = Author::from_bytes(value.value());
            authors.push(author);
        }
        Ok(authors)
    }

    fn new_replica(&self, namespace: Namespace) -> Result<Replica<Self::Instance>> {
        let id = namespace.id();
        self.insert_namespace(namespace.clone())?;

        let replica = Replica::new(namespace, StoreInstance::new(id, self.clone()));

        self.replicas.write().insert(id, replica.clone());
        Ok(replica)
    }

    /// Gets all entries matching this key and author.
    fn get_latest_by_key_and_author(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>> {
        let read_tx = self.db.begin_read()?;
        let record_table = read_tx.open_multimap_table(RECORDS_TABLE)?;

        let db_key = (namespace.as_bytes(), author.as_bytes(), key.as_ref());
        let records = record_table.get(db_key)?;
        let Some(record) = records.last() else {
            return Ok(None);
        };
        let record = record?;
        let (timestamp, namespace_sig, author_sig, len, hash) = record.value();
        let record = Record::new(timestamp, len, hash.into());
        let id = RecordIdentifier::new(key, namespace, author);
        let entry = Entry::new(id, record);
        let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
        let signed_entry = SignedEntry::new(entry_signature, entry);

        Ok(Some(signed_entry))
    }

    fn get_latest_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> Result<Self::GetLatestIter<'_>> {
        let start = (namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (namespace.as_bytes(), &[255u8; 32], &[][..]);
        let iter = RangeLatestIterator::try_new(
            self.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| record_table.range(start..=end).map_err(anyhow::Error::from),
            None,
            RangeFilter::Key(key.as_ref().to_vec()),
        )?;

        Ok(iter)
    }

    fn get_latest_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<Self::GetLatestIter<'_>> {
        let start = (namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (namespace.as_bytes(), &[255u8; 32], &[][..]);
        let iter = RangeLatestIterator::try_new(
            self.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| record_table.range(start..=end).map_err(anyhow::Error::from),
            None,
            RangeFilter::Prefix(prefix.as_ref().to_vec()),
        )?;

        Ok(iter)
    }

    fn get_latest(&self, namespace: NamespaceId) -> Result<Self::GetLatestIter<'_>> {
        let start = (namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (namespace.as_bytes(), &[255u8; 32], &[][..]);
        let iter = RangeLatestIterator::try_new(
            self.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| record_table.range(start..=end).map_err(anyhow::Error::from),
            None,
            RangeFilter::None,
        )?;

        Ok(iter)
    }

    fn get_all_by_key_and_author<'a, 'b: 'a>(
        &'a self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]> + 'b,
    ) -> Result<Self::GetAllIter<'a>> {
        let start = (namespace.as_bytes(), author.as_bytes(), key.as_ref());
        let end = (namespace.as_bytes(), author.as_bytes(), key.as_ref());
        let iter = RangeAllIterator::try_new(
            self.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| {
                record_table
                    .range(start..=end)
                    .map_err(anyhow::Error::from)
                    .map(|v| (v, None))
            },
            RangeFilter::None,
        )?;

        Ok(iter)
    }

    fn get_all_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> Result<Self::GetAllIter<'_>> {
        let start = (namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (namespace.as_bytes(), &[255u8; 32], &[][..]);
        let iter = RangeAllIterator::try_new(
            self.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| {
                record_table
                    .range(start..=end)
                    .map_err(anyhow::Error::from)
                    .map(|v| (v, None))
            },
            RangeFilter::Key(key.as_ref().to_vec()),
        )?;

        Ok(iter)
    }

    fn get_all_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<Self::GetAllIter<'_>> {
        let start = (namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (namespace.as_bytes(), &[255u8; 32], &[][..]);
        let iter = RangeAllIterator::try_new(
            self.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| {
                record_table
                    .range(start..=end)
                    .map_err(anyhow::Error::from)
                    .map(|v| (v, None))
            },
            RangeFilter::Prefix(prefix.as_ref().to_vec()),
        )?;

        Ok(iter)
    }

    fn get_all(&self, namespace: NamespaceId) -> Result<Self::GetAllIter<'_>> {
        let start = (namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (namespace.as_bytes(), &[255u8; 32], &[][..]);
        let iter = RangeAllIterator::try_new(
            self.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| {
                record_table
                    .range(start..=end)
                    .map_err(anyhow::Error::from)
                    .map(|v| (v, None))
            },
            RangeFilter::None,
        )?;

        Ok(iter)
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
        self.store
            .get_latest_by_key_and_author(id.namespace(), id.author(), id.key())
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
            let el = el?;
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
                let key = (k.namespace_bytes(), k.author_bytes(), k.key());
                let record = v.entry().record();
                let value = (
                    timestamp,
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

    type RangeIterator<'a> = RangeLatestIterator<'a>;
    fn get_range(
        &self,
        range: Range<RecordIdentifier>,
        limit: Option<Range<RecordIdentifier>>,
    ) -> Result<Self::RangeIterator<'_>> {
        // TODO: implement inverted range
        let range_start = range.x();
        let range_end = range.y();

        let start = (
            range_start.namespace_bytes(),
            range_start.author_bytes(),
            range_start.key(),
        );
        let end = (
            range_end.namespace_bytes(),
            range_end.author_bytes(),
            range_end.key(),
        );
        let iter = RangeLatestIterator::try_new(
            self.store.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| record_table.range(start..=end).map_err(anyhow::Error::from),
            limit,
            RangeFilter::None,
        )?;

        Ok(iter)
    }

    fn remove(&mut self, k: &RecordIdentifier) -> Result<Vec<SignedEntry>> {
        let write_tx = self.store.db.begin_write()?;
        let res = {
            let mut records_table = write_tx.open_multimap_table(RECORDS_TABLE)?;
            let key = (k.namespace_bytes(), k.author_bytes(), k.key());
            let records = records_table.remove_all(key)?;
            let mut res = Vec::new();
            for record in records.into_iter() {
                let record = record?;
                let (timestamp, namespace_sig, author_sig, len, hash) = record.value();
                let record = Record::new(timestamp, len, hash.into());
                let entry = Entry::new(k.clone(), record);
                let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
                let signed_entry = SignedEntry::new(entry_signature, entry);
                res.push(signed_entry);
            }
            res
        };
        write_tx.commit()?;
        Ok(res)
    }

    type AllIterator<'a> = RangeLatestIterator<'a>;

    fn all(&self) -> Result<Self::AllIterator<'_>> {
        let start = (self.namespace.as_bytes(), &[0u8; 32], &[][..]);
        let end = (self.namespace.as_bytes(), &[255u8; 32], &[][..]);
        let iter = RangeLatestIterator::try_new(
            self.store.db.begin_read()?,
            |read_tx| {
                read_tx
                    .open_multimap_table(RECORDS_TABLE)
                    .map_err(anyhow::Error::from)
            },
            |record_table| record_table.range(start..=end).map_err(anyhow::Error::from),
            None,
            RangeFilter::None,
        )?;

        Ok(iter)
    }
}

fn matches(limit: &Option<Range<RecordIdentifier>>, x: &RecordIdentifier) -> bool {
    limit.as_ref().map(|r| x.contains(r)).unwrap_or(true)
}

#[self_referencing]
pub struct RangeLatestIterator<'a> {
    read_tx: ReadTransaction<'a>,
    #[borrows(read_tx)]
    #[covariant]
    record_table: ReadOnlyMultimapTable<'this, RecordsId<'static>, RecordsValue<'static>>,
    #[covariant]
    #[borrows(record_table)]
    records: MultimapRange<'this, RecordsId<'static>, RecordsValue<'static>>,
    limit: Option<Range<RecordIdentifier>>,
    filter: RangeFilter,
}

impl std::fmt::Debug for RangeLatestIterator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeLatestIterator")
            .finish_non_exhaustive()
    }
}

impl Iterator for RangeLatestIterator<'_> {
    type Item = Result<(RecordIdentifier, SignedEntry)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.with_mut(|fields| {
            for next in fields.records.by_ref() {
                let next = match next {
                    Ok(next) => next,
                    Err(err) => return Some(Err(err.into())),
                };

                let (namespace, author, key) = next.0.value();
                let id = match RecordIdentifier::from_parts(key, namespace, author) {
                    Ok(id) => id,
                    Err(err) => return Some(Err(err)),
                };
                if fields.filter.matches(&id) && matches(fields.limit, &id) {
                    let last = next.1.last();
                    let value = match last? {
                        Ok(value) => value,
                        Err(err) => return Some(Err(err.into())),
                    };
                    let (timestamp, namespace_sig, author_sig, len, hash) = value.value();
                    let record = Record::new(timestamp, len, hash.into());
                    let entry = Entry::new(id.clone(), record);
                    let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
                    let signed_entry = SignedEntry::new(entry_signature, entry);

                    return Some(Ok((id, signed_entry)));
                }
            }
            None
        })
    }
}

#[self_referencing]
pub struct RangeAllIterator<'a> {
    read_tx: ReadTransaction<'a>,
    #[borrows(read_tx)]
    #[covariant]
    record_table: ReadOnlyMultimapTable<'this, RecordsId<'static>, RecordsValue<'static>>,
    #[covariant]
    #[borrows(record_table)]
    records: (
        MultimapRange<'this, RecordsId<'static>, RecordsValue<'static>>,
        Option<(
            AccessGuard<'this, RecordsId<'static>>,
            MultimapValue<'this, RecordsValue<'static>>,
            RecordIdentifier,
        )>,
    ),
    filter: RangeFilter,
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

impl std::fmt::Debug for RangeAllIterator<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeAllIterator").finish_non_exhaustive()
    }
}

/// Advance the internal iterator to the next set of multimap values
fn next_iter(fields: &mut BorrowedMutFields) -> Result<()> {
    for next_iter in fields.records.0.by_ref() {
        let (id_guard, values_guard) = next_iter?;
        let (namespace, author, key) = id_guard.value();
        let id = RecordIdentifier::from_parts(key, namespace, author)?;
        if fields.filter.matches(&id) {
            fields.records.1 = Some((id_guard, values_guard, id));
            return Ok(());
        }
    }
    Ok(())
}

impl Iterator for RangeAllIterator<'_> {
    type Item = Result<(RecordIdentifier, SignedEntry)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.with_mut(|mut fields| {
            loop {
                if fields.records.1.is_none() {
                    if let Err(err) = next_iter(&mut fields) {
                        return Some(Err(err));
                    }
                }
                // If this is None, nothing is available anymore
                let (_id_guard, values_guard, id) = fields.records.1.as_mut()?;

                match values_guard.next() {
                    Some(Ok(value)) => {
                        let (timestamp, namespace_sig, author_sig, len, hash) = value.value();
                        let record = Record::new(timestamp, len, hash.into());
                        let entry = Entry::new(id.clone(), record);
                        let entry_signature = EntrySignature::from_parts(namespace_sig, author_sig);
                        let signed_entry = SignedEntry::new(entry_signature, entry);
                        return Some(Ok((id.clone(), signed_entry)));
                    }
                    Some(Err(err)) => return Some(Err(err.into())),
                    None => {
                        // clear the current
                        fields.records.1 = None;
                    }
                }
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

        let replica_back = store.open_replica(&namespace.id())?.unwrap();
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

        // add a second version
        for i in 0..5 {
            let id = RecordIdentifier::new(format!("hello-{i}"), namespace.id(), author.id());
            let entry = Entry::new(
                id.clone(),
                Record::from_data(format!("world-{i}-2"), namespace.id()),
            );
            let entry = SignedEntry::from_entry(entry, &namespace, &author);
            wrapper.put(id, entry)?;
        }

        // get all
        let entries = store.get_all(namespace.id())?.collect::<Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 10);

        // get all prefix
        let entries = store
            .get_all_by_prefix(namespace.id(), "hello-")?
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 10);

        // get latest
        let entries = store
            .get_latest(namespace.id())?
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 5);

        // get latest by prefix
        let entries = store
            .get_latest_by_prefix(namespace.id(), "hello-")?
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 5);

        // delete and get
        for i in 0..5 {
            let id = RecordIdentifier::new(format!("hello-{i}"), namespace.id(), author.id());
            let res = wrapper.get(&id)?;
            assert!(res.is_some());
            let out = wrapper.remove(&id)?;
            assert_eq!(out.len(), 2);
            for val in out {
                assert_eq!(val.entry().id(), &id);
            }
            let res = wrapper.get(&id)?;
            assert!(res.is_none());
        }

        // get latest
        let entries = store
            .get_latest(namespace.id())?
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(entries.len(), 0);

        Ok(())
    }
}

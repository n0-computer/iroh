//! In memory storage for replicas.

use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    sync::Arc,
};

use anyhow::Result;
use derive_more::From;
use parking_lot::{RwLock, RwLockReadGuard};

use crate::{
    ranger::{AsFingerprint, Fingerprint, Range},
    sync::{Author, AuthorId, Namespace, NamespaceId, RecordIdentifier, Replica, SignedEntry},
};

/// Manages the replicas and authors for an instance.
#[derive(Debug, Clone, Default)]
pub struct Store {
    replicas: Arc<RwLock<HashMap<NamespaceId, Replica<ReplicaStoreInstance>>>>,
    authors: Arc<RwLock<HashMap<AuthorId, Author>>>,
    /// Stores records by namespace -> identifier + timestamp
    replica_records: Arc<RwLock<ReplicaRecordsOwned>>,
}

type Rid = (AuthorId, Vec<u8>);
type Rvalue = SignedEntry;
type RecordMap = BTreeMap<Rid, Rvalue>;
type ReplicaRecordsOwned = HashMap<NamespaceId, RecordMap>;

impl super::Store for Store {
    type Instance = ReplicaStoreInstance;
    type GetIter<'a> = EntryIterator<'a>;
    type AuthorsIter<'a> = std::vec::IntoIter<Result<Author>>;
    type NamespaceIter<'a> = std::vec::IntoIter<Result<NamespaceId>>;

    fn open_replica(&self, namespace: &NamespaceId) -> Result<Option<Replica<Self::Instance>>> {
        let replicas = &*self.replicas.read();
        Ok(replicas.get(namespace).cloned())
    }

    fn list_namespaces(&self) -> Result<Self::NamespaceIter<'_>> {
        // TODO: avoid collect?
        Ok(self
            .replicas
            .read()
            .keys()
            .cloned()
            .map(Ok)
            .collect::<Vec<_>>()
            .into_iter())
    }

    fn get_author(&self, author: &AuthorId) -> Result<Option<Author>> {
        let authors = &*self.authors.read();
        Ok(authors.get(author).cloned())
    }

    fn import_author(&self, author: Author) -> Result<()> {
        self.authors.write().insert(author.id(), author);
        Ok(())
    }

    fn list_authors(&self) -> Result<Self::AuthorsIter<'_>> {
        // TODO: avoid collect?
        Ok(self
            .authors
            .read()
            .values()
            .cloned()
            .map(Ok)
            .collect::<Vec<_>>()
            .into_iter())
    }

    fn new_replica(&self, namespace: Namespace) -> Result<Replica<ReplicaStoreInstance>> {
        let id = namespace.id();
        let replica = Replica::new(namespace, ReplicaStoreInstance::new(id, self.clone()));
        self.replicas
            .write()
            .insert(replica.namespace(), replica.clone());
        Ok(replica)
    }

    fn get(&self, namespace: NamespaceId, filter: super::GetFilter) -> Result<Self::GetIter<'_>> {
        let iter = match filter {
            super::GetFilter::All => self.get_all(namespace),
            super::GetFilter::Key(key) => self.get_by_key(namespace, key),
            super::GetFilter::Prefix(prefix) => self.get_by_prefix(namespace, &prefix),
            super::GetFilter::Author(author) => self.get_by_author(namespace, author),
            super::GetFilter::AuthorAndPrefix(author, prefix) => {
                self.get_by_author_and_prefix(namespace, author, prefix)
            }
        }?;
        Ok(iter.into())
    }

    fn get_by_key_and_author(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>> {
        let inner = self.replica_records.read();

        let value = inner
            .get(&namespace)
            .and_then(|records| records.get(&(author, key.as_ref().to_vec())));

        Ok(value.cloned())
    }
}

/// Iterator over signed entries
#[derive(From, Debug)]
pub struct EntryIterator<'a>(StoreRangeIterator<'a>);
impl<'a> Iterator for EntryIterator<'a> {
    type Item = Result<SignedEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|res| Ok(res.map(|(_id, entry)| entry).expect("never errors")))
    }
}

impl Store {
    fn get_by_key(
        &self,
        namespace: NamespaceId,
        key: impl AsRef<[u8]>,
    ) -> Result<StoreRangeIterator<'_>> {
        let records = self.replica_records.read();
        let key = key.as_ref().to_vec();
        let filter = GetFilter::Key { namespace, key };

        Ok(StoreRangeIterator {
            records,
            filter,
            index: 0,
        })
    }

    fn get_by_prefix(
        &self,
        namespace: NamespaceId,
        prefix: impl AsRef<[u8]>,
    ) -> Result<StoreRangeIterator<'_>> {
        let records = self.replica_records.read();
        let prefix = prefix.as_ref().to_vec();
        let filter = GetFilter::Prefix { namespace, prefix };

        Ok(StoreRangeIterator {
            records,
            filter,
            index: 0,
        })
    }

    fn get_by_author(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
    ) -> Result<StoreRangeIterator<'_>> {
        let records = self.replica_records.read();
        let filter = GetFilter::Author { namespace, author };

        Ok(StoreRangeIterator {
            records,
            filter,
            index: 0,
        })
    }

    fn get_by_author_and_prefix(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        prefix: Vec<u8>,
    ) -> Result<StoreRangeIterator<'_>> {
        let records = self.replica_records.read();
        let filter = GetFilter::AuthorAndPrefix {
            namespace,
            author,
            prefix,
        };

        Ok(StoreRangeIterator {
            records,
            filter,
            index: 0,
        })
    }

    fn get_all(&self, namespace: NamespaceId) -> Result<StoreRangeIterator<'_>> {
        let records = self.replica_records.read();
        let filter = GetFilter::All { namespace };

        Ok(StoreRangeIterator {
            records,
            filter,
            index: 0,
        })
    }
}

#[derive(Debug)]
enum GetFilter {
    /// All entries.
    All { namespace: NamespaceId },
    /// Filter by author.
    Author {
        namespace: NamespaceId,
        author: AuthorId,
    },
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
    /// Filter by author and prefix.
    AuthorAndPrefix {
        namespace: NamespaceId,
        prefix: Vec<u8>,
        author: AuthorId,
    },
}

impl GetFilter {
    fn namespace(&self) -> NamespaceId {
        match self {
            GetFilter::All { namespace } => *namespace,
            GetFilter::Key { namespace, .. } => *namespace,
            GetFilter::Prefix { namespace, .. } => *namespace,
            GetFilter::Author { namespace, .. } => *namespace,
            GetFilter::AuthorAndPrefix { namespace, .. } => *namespace,
        }
    }
}

#[derive(Debug)]
struct StoreRangeIterator<'a> {
    records: ReplicaRecords<'a>,
    filter: GetFilter,
    /// Current iteration index.
    index: usize,
}

impl<'a> Iterator for StoreRangeIterator<'a> {
    type Item = Result<(RecordIdentifier, SignedEntry)>;

    fn next(&mut self) -> Option<Self::Item> {
        let records = self.records.get(&self.filter.namespace())?;
        let res = match self.filter {
            GetFilter::All { namespace } => records
                .iter()
                .map(|(key_author, value)| {
                    let record_id = RecordIdentifier::new(
                        &key_author.1,
                        namespace,
                        key_author.0,
                        value.timestamp(),
                    );
                    (record_id, value.clone())
                })
                .nth(self.index)?,
            GetFilter::Key { namespace, ref key } => records
                .iter()
                .filter(|((_, k), _)| k == key)
                .map(|(key_author, value)| {
                    let record_id = RecordIdentifier::new(
                        &key_author.1,
                        namespace,
                        key_author.0,
                        value.timestamp(),
                    );
                    (record_id, value.clone())
                })
                .nth(self.index)?,
            GetFilter::Prefix {
                namespace,
                ref prefix,
            } => records
                .iter()
                .filter(|((_, k), _)| k.starts_with(prefix))
                .map(|(key_author, value)| {
                    let record_id = RecordIdentifier::new(
                        &key_author.1,
                        namespace,
                        key_author.0,
                        value.timestamp(),
                    );
                    (record_id, value.clone())
                })
                .nth(self.index)?,
            GetFilter::Author {
                namespace,
                ref author,
            } => records
                .iter()
                .filter(|((a, _), _)| a == author)
                .map(|(key_author, value)| {
                    let record_id = RecordIdentifier::new(
                        &key_author.1,
                        namespace,
                        key_author.0,
                        value.timestamp(),
                    );
                    (record_id, value.clone())
                })
                .nth(self.index)?,
            GetFilter::AuthorAndPrefix {
                namespace,
                ref prefix,
                ref author,
            } => records
                .iter()
                .filter(|((a, k), _)| a == author && k.starts_with(prefix))
                .map(|(key_author, value)| {
                    let record_id = RecordIdentifier::new(
                        &key_author.1,
                        namespace,
                        key_author.0,
                        value.timestamp(),
                    );
                    (record_id, value.clone())
                })
                .nth(self.index)?,
        };
        self.index += 1;
        Some(Ok(res))
    }
}

/// Instance of a [`Store`]
#[derive(Debug, Clone)]
pub struct ReplicaStoreInstance {
    namespace: NamespaceId,
    store: Store,
}

impl ReplicaStoreInstance {
    fn new(namespace: NamespaceId, store: Store) -> Self {
        ReplicaStoreInstance { namespace, store }
    }

    fn with_records<F, T>(&self, f: F) -> T
    where
        F: FnOnce(Option<&RecordMap>) -> T,
    {
        let guard = self.store.replica_records.read();
        let value = guard.get(&self.namespace);
        f(value)
    }

    fn with_records_mut<F, T>(&self, f: F) -> T
    where
        F: FnOnce(Option<&mut RecordMap>) -> T,
    {
        let mut guard = self.store.replica_records.write();
        let value = guard.get_mut(&self.namespace);
        f(value)
    }

    fn with_records_mut_with_default<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut RecordMap) -> T,
    {
        let mut guard = self.store.replica_records.write();
        let value = guard.entry(self.namespace).or_default();
        f(value)
    }

    fn records_iter(&self) -> RecordsIter<'_> {
        RecordsIter {
            namespace: self.namespace,
            replica_records: self.store.replica_records.read(),
            i: 0,
        }
    }
}

type ReplicaRecords<'a> = RwLockReadGuard<'a, ReplicaRecordsOwned>;

#[derive(Debug)]
struct RecordsIter<'a> {
    namespace: NamespaceId,
    replica_records: ReplicaRecords<'a>,
    i: usize,
}

impl Iterator for RecordsIter<'_> {
    type Item = (RecordIdentifier, SignedEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let records = self.replica_records.get(&self.namespace)?;
        let ((author, key), value) = records.iter().nth(self.i)?;
        let id = RecordIdentifier::new(key, self.namespace, *author, value.timestamp());
        self.i += 1;
        Some((id, value.clone()))
    }
}

impl crate::ranger::Store<RecordIdentifier, SignedEntry> for ReplicaStoreInstance {
    type Error = Infallible;

    /// Get a the first key (or the default if none is available).
    fn get_first(&self) -> Result<RecordIdentifier, Self::Error> {
        Ok(self.with_records(|records| {
            records
                .and_then(|r| {
                    r.first_key_value().map(|((author, key), value)| {
                        RecordIdentifier::new(key, self.namespace, *author, value.timestamp())
                    })
                })
                .unwrap_or_default()
        }))
    }

    fn get(&self, key: &RecordIdentifier) -> Result<Option<SignedEntry>, Self::Error> {
        Ok(self.with_records(|records| {
            records.and_then(|r| {
                let v = r.get(&(key.author(), key.key().to_vec()))?;
                if v.timestamp() == key.timestamp() {
                    return Some(v.clone());
                }
                None
            })
        }))
    }

    fn len(&self) -> Result<usize, Self::Error> {
        Ok(self.with_records(|records| records.map(|v| v.len()).unwrap_or_default()))
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.len()? == 0)
    }

    fn get_fingerprint(&self, range: &Range<RecordIdentifier>) -> Result<Fingerprint, Self::Error> {
        let elements = self.get_range(range.clone())?;
        let mut fp = Fingerprint::empty();
        for el in elements {
            let el = el?;
            fp ^= el.0.as_fingerprint();
        }
        Ok(fp)
    }

    fn put(&mut self, k: RecordIdentifier, v: SignedEntry) -> Result<(), Self::Error> {
        assert_eq!(k.timestamp(), v.timestamp(), "inconsistent timestamp"); // TODO: error
                                                                            // TODO: propagate error/not insertion?
        if v.verify().is_ok() {
            // TODO: verify timestamp is "reasonable"
            self.with_records_mut_with_default(|records| {
                match records.entry((k.author(), k.key().to_vec())) {
                    std::collections::btree_map::Entry::Vacant(e) => {
                        e.insert(v);
                    }
                    std::collections::btree_map::Entry::Occupied(mut e) => {
                        // Ignore older timestamp
                        if e.get().timestamp() < v.timestamp() {
                            e.insert(v);
                        }
                    }
                }
            });
        }
        Ok(())
    }

    type RangeIterator<'a> = InstanceRangeIterator<'a>;

    fn get_range(
        &self,
        range: Range<RecordIdentifier>,
    ) -> Result<Self::RangeIterator<'_>, Self::Error> {
        Ok(InstanceRangeIterator {
            iter: self.records_iter(),
            range: Some(range),
        })
    }

    fn remove(&mut self, key: &RecordIdentifier) -> Result<Option<SignedEntry>, Self::Error> {
        // TODO: what if we are trying to remove with the wrong timestamp?
        let res = self.with_records_mut(|records| {
            records.and_then(|records| records.remove(&(key.author(), key.key().to_vec())))
        });
        Ok(res)
    }

    type AllIterator<'a> = InstanceRangeIterator<'a>;

    fn all(&self) -> Result<Self::AllIterator<'_>, Self::Error> {
        Ok(InstanceRangeIterator {
            iter: self.records_iter(),
            range: None,
        })
    }
}

/// Range iterator for a [`ReplicaStoreInstance`]
#[derive(Debug)]
pub struct InstanceRangeIterator<'a> {
    iter: RecordsIter<'a>,
    range: Option<Range<RecordIdentifier>>,
}

impl InstanceRangeIterator<'_> {
    fn matches(&self, x: &RecordIdentifier) -> bool {
        self.range.as_ref().map(|r| r.contains(x)).unwrap_or(true)
    }
}

impl Iterator for InstanceRangeIterator<'_> {
    type Item = Result<(RecordIdentifier, SignedEntry), Infallible>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut next = self.iter.next()?;
        loop {
            let (record_id, v) = next;
            if self.matches(&record_id) {
                return Some(Ok((record_id, v)));
            }

            next = self.iter.next()?;
        }
    }
}

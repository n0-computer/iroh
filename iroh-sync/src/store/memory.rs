//! In memory storage for replicas.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use ed25519_dalek::{SignatureError, VerifyingKey};
use iroh_bytes::Hash;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard};

use crate::{
    keys::{Author, Namespace},
    ranger::{Fingerprint, Range, RangeEntry},
    sync::{RecordIdentifier, Replica, SignedEntry},
    AuthorId, NamespaceId, PeerIdBytes, Record,
};

use super::{
    pubkeys::MemPublicKeyStore,
    util::{LatestPerKeySelector, SelectorRes, UseTable},
    OpenError, PublicKeyStore, Query,
};

type SyncPeersCache = Arc<RwLock<HashMap<NamespaceId, lru::LruCache<PeerIdBytes, ()>>>>;

/// Manages the replicas and authors for an instance.
#[derive(Debug, Clone, Default)]
pub struct Store {
    open_replicas: Arc<RwLock<HashSet<NamespaceId>>>,
    namespaces: Arc<RwLock<HashMap<NamespaceId, Namespace>>>,
    authors: Arc<RwLock<HashMap<AuthorId, Author>>>,
    /// Stores records by namespace -> identifier + timestamp
    replica_records: Arc<RwLock<ReplicaRecordsOwned>>,
    /// Stores the latest entry for each author
    latest: Arc<RwLock<LatestMapOwned>>,
    pubkeys: MemPublicKeyStore,
    /// Cache of peers that have been used for sync.
    peers_per_doc: SyncPeersCache,
}

type Key = Vec<u8>;
type ReplicaRecordsOwned = BTreeMap<NamespaceId, RecordMap>;

#[derive(Debug, Default)]
struct RecordMap {
    by_author: BTreeMap<(AuthorId, Key), SignedEntry>,
    by_key: BTreeMap<(Key, AuthorId), u64>,
}

impl RecordMap {
    fn insert(&mut self, entry: SignedEntry) {
        self.by_key
            .insert((entry.key().to_vec(), entry.author()), entry.timestamp());
        self.by_author
            .insert((entry.author(), entry.key().to_vec()), entry);
    }
    fn remove(&mut self, id: &RecordIdentifier) -> Option<SignedEntry> {
        let entry = self.by_author.remove(&(id.author(), id.key().to_vec()));
        self.by_key.remove(&(id.key().to_vec(), id.author()));
        entry
    }
    fn len(&self) -> usize {
        self.by_author.len()
    }
    fn retain(&mut self, f: impl Fn(&(AuthorId, Key), &mut SignedEntry) -> bool) {
        self.by_author.retain(|key, value| {
            let retain = f(key, value);
            if !retain {
                self.by_key.remove(&(key.1.clone(), key.0));
            }
            retain
        })
    }
}

type LatestByAuthorMapOwned = BTreeMap<AuthorId, (u64, Vec<u8>)>;
type LatestMapOwned = HashMap<NamespaceId, LatestByAuthorMapOwned>;
type LatestByAuthorMap<'a> = MappedRwLockReadGuard<'a, LatestByAuthorMapOwned>;

impl super::Store for Store {
    type Instance = ReplicaStoreInstance;
    type GetIter<'a> = QueryIterator<'a>;
    type ContentHashesIter<'a> = ContentHashesIterator<'a>;
    type AuthorsIter<'a> = std::vec::IntoIter<Result<Author>>;
    type NamespaceIter<'a> = std::vec::IntoIter<Result<NamespaceId>>;
    type PeersIter<'a> = std::vec::IntoIter<PeerIdBytes>;
    type LatestIter<'a> = LatestIterator<'a>;

    fn open_replica(&self, id: &NamespaceId) -> Result<Replica<Self::Instance>, OpenError> {
        if self.open_replicas.read().contains(id) {
            return Err(OpenError::AlreadyOpen);
        }
        let namespace = {
            let namespaces = self.namespaces.read();
            let namespace = namespaces.get(id).ok_or(OpenError::NotFound)?;
            namespace.clone()
        };
        let replica = Replica::new(namespace, ReplicaStoreInstance::new(*id, self.clone()));
        self.open_replicas.write().insert(*id);
        Ok(replica)
    }

    fn close_replica(&self, mut replica: Replica<Self::Instance>) {
        self.open_replicas.write().remove(&replica.namespace());
        replica.close();
    }

    fn list_namespaces(&self) -> Result<Self::NamespaceIter<'_>> {
        // TODO: avoid collect?
        Ok(self
            .namespaces
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

    fn import_namespace(&self, namespace: Namespace) -> Result<()> {
        self.namespaces.write().insert(namespace.id(), namespace);
        Ok(())
    }

    fn remove_replica(&self, namespace: &NamespaceId) -> Result<()> {
        if self.open_replicas.read().contains(namespace) {
            return Err(anyhow!("replica is not closed"));
        }
        self.replica_records.write().remove(namespace);
        self.namespaces.write().remove(namespace);
        Ok(())
    }

    fn get_many(
        &self,
        namespace: NamespaceId,
        query: impl Into<Query>,
    ) -> Result<Self::GetIter<'_>> {
        let query = query.into();
        let records = self.replica_records.read();
        Ok(QueryIterator::new(records, namespace, query))
    }

    fn get_one(
        &self,
        namespace: NamespaceId,
        author: AuthorId,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<SignedEntry>> {
        let inner = self.replica_records.read();
        let Some(records) = inner.get(&namespace) else {
            return Ok(None);
        };
        let entry = records.by_author.get(&(author, key.as_ref().to_vec()));
        Ok(entry.and_then(|entry| match entry.is_empty() {
            true => None,
            false => Some(entry.clone()),
        }))
    }

    /// Get all content hashes of all replicas in the store.
    fn content_hashes(&self) -> Result<Self::ContentHashesIter<'_>> {
        let records = self.replica_records.read();
        Ok(ContentHashesIterator {
            records,
            namespace_i: 0,
            record_i: 0,
        })
    }

    fn get_latest_for_each_author(&self, namespace: NamespaceId) -> Result<LatestIterator<'_>> {
        let records =
            RwLockReadGuard::try_map(self.latest.read(), move |map| map.get(&namespace)).ok();
        Ok(LatestIterator {
            records,
            author_i: 0,
        })
    }

    fn register_useful_peer(&self, namespace: NamespaceId, peer: crate::PeerIdBytes) -> Result<()> {
        let mut per_doc_cache = self.peers_per_doc.write();
        per_doc_cache
            .entry(namespace)
            .or_insert_with(|| lru::LruCache::new(super::PEERS_PER_DOC_CACHE_SIZE))
            .put(peer, ());
        Ok(())
    }

    fn get_sync_peers(&self, namespace: &NamespaceId) -> Result<Option<Self::PeersIter<'_>>> {
        let per_doc_cache = self.peers_per_doc.read();
        let cache = match per_doc_cache.get(namespace) {
            Some(cache) => cache,
            None => return Ok(None),
        };

        let peers: Vec<PeerIdBytes> = cache.iter().map(|(peer_id, _empty_val)| *peer_id).collect();
        Ok(Some(peers.into_iter()))
    }
}

/// Iterator over all content hashes in the memory store.
#[derive(Debug)]
pub struct ContentHashesIterator<'a> {
    records: ReplicaRecords<'a>,
    namespace_i: usize,
    record_i: usize,
}

impl<'a> Iterator for ContentHashesIterator<'a> {
    type Item = Result<Hash>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let records = self.records.values().nth(self.namespace_i)?;
            match records.by_author.values().nth(self.record_i) {
                None => {
                    self.namespace_i += 1;
                    self.record_i = 0;
                }
                Some(record) => {
                    self.record_i += 1;
                    return Some(Ok(record.content_hash()));
                }
            }
        }
    }
}

/// Iterator over the latest timestamp/key for each author
#[derive(Debug)]
pub struct LatestIterator<'a> {
    records: Option<LatestByAuthorMap<'a>>,
    author_i: usize,
}

impl<'a> Iterator for LatestIterator<'a> {
    type Item = Result<(AuthorId, u64, Vec<u8>)>;
    fn next(&mut self) -> Option<Self::Item> {
        let records = self.records.as_ref()?;
        match records.iter().nth(self.author_i) {
            None => None,
            Some((author, (timestamp, key))) => {
                self.author_i += 1;
                Some(Ok((*author, *timestamp, key.to_vec())))
            }
        }
    }
}

/// Iterator over entries in the memory store
#[derive(Debug)]
pub struct QueryIterator<'a> {
    records: ReplicaRecords<'a>,
    namespace: NamespaceId,
    query: Query,
    table: UseTable,
    selector: Option<LatestPerKeySelector>,
    // current iterator index
    position: usize,
    // number of entries returned from the iterator
    count: usize,
    // number of entries skipped at the beginning
    offset: usize,
}

impl<'a> QueryIterator<'a> {
    fn new(records: ReplicaRecords<'a>, namespace: NamespaceId, query: Query) -> Self {
        let table = UseTable::from(&query);
        let selector = match table {
            UseTable::KeyAuthor { latest_per_key, .. } if latest_per_key => {
                Some(LatestPerKeySelector::default())
            }
            _ => None,
        };

        Self {
            records,
            namespace,
            query,
            table,
            selector,
            position: 0,
            offset: 0,
            count: 0,
        }
    }
}

impl<'a> Iterator for QueryIterator<'a> {
    type Item = Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(limit) = self.query.limit_offset.limit() {
                if self.count as u64 >= limit {
                    return None;
                }
            }

            let records = self.records.get(&self.namespace)?;

            let entry = match &self.table {
                UseTable::AuthorKey { range, filter } => records
                    .by_author
                    .iter()
                    .filter(|(_key, entry)| {
                        range.matches(&entry.author())
                            && filter.matches(entry.key())
                            && (self.query.include_empty || !entry.is_empty())
                    })
                    .map(|(_key, entry)| entry)
                    .nth(self.position)
                    .cloned(),
                UseTable::KeyAuthor { range, filter, .. } => loop {
                    let next = records
                        .by_key.keys().flat_map(|k| records.by_author.get(&(k.1, k.0.to_vec())).into_iter())
                        .filter(|entry| {
                            range.matches(entry.key()) && filter.matches(&entry.author())
                        })
                        .nth(self.position)
                        .cloned();

                    let next = match self.selector.as_mut() {
                        None => next,
                        Some(selector) => match selector.push(next) {
                            SelectorRes::Continue => {
                                self.position += 1;
                                continue;
                            }
                            SelectorRes::Finished => None,
                            SelectorRes::Some(res) => Some(res),
                        },
                    };
                    let Some(entry) = next else {
                        break None;
                    };

                    // final check for empty entries: if the selector is active, the latest
                    // entry for a key might be empty, so skip it if no empty entries were
                    // requested
                    if !self.query.include_empty && entry.is_empty() {
                        self.position += 1;
                        continue;
                    } else {
                        break Some(entry);
                    }
                },
            };

            self.position += 1;
            self.offset += 1;
            if (self.offset as u64) <= self.query.limit_offset.offset() {
                continue;
            }
            self.count += 1;
            return entry.map(Result::Ok);
        }
    }
}

/// Instance of a [`Store`]
#[derive(Debug, Clone)]
pub struct ReplicaStoreInstance {
    namespace: NamespaceId,
    store: Store,
}

impl PublicKeyStore for ReplicaStoreInstance {
    fn public_key(&self, id: &[u8; 32]) -> std::result::Result<VerifyingKey, SignatureError> {
        self.store.pubkeys.public_key(id)
    }
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

    fn with_latest_mut_with_default<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut LatestByAuthorMapOwned) -> T,
    {
        let mut guard = self.store.latest.write();
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
        let ((author, key), value) = records.by_author.iter().nth(self.i)?;
        let id = RecordIdentifier::new(self.namespace, *author, key);
        self.i += 1;
        Some((id, value.clone()))
    }
}

impl crate::ranger::Store<SignedEntry> for ReplicaStoreInstance {
    type Error = Infallible;

    /// Get a the first key (or the default if none is available).
    fn get_first(&self) -> Result<RecordIdentifier, Self::Error> {
        Ok(self.with_records(|records| {
            records
                .and_then(|r| {
                    r.by_author
                        .first_key_value()
                        .map(|((author, key), _value)| {
                            RecordIdentifier::new(self.namespace, *author, key.clone())
                        })
                })
                .unwrap_or_default()
        }))
    }

    fn get(&self, key: &RecordIdentifier) -> Result<Option<SignedEntry>, Self::Error> {
        Ok(self.with_records(|records| {
            records.and_then(|r| {
                let v = r.by_author.get(&(key.author(), key.key().to_vec()))?;
                Some(v.clone())
            })
        }))
    }

    fn len(&self) -> Result<usize, Self::Error> {
        Ok(self.with_records(|records| records.map(|v| v.by_author.len()).unwrap_or_default()))
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.len()? == 0)
    }

    fn get_fingerprint(&self, range: &Range<RecordIdentifier>) -> Result<Fingerprint, Self::Error> {
        let elements = self.get_range(range.clone())?;
        let mut fp = Fingerprint::empty();
        for el in elements {
            let el = el?;
            fp ^= el.as_fingerprint();
        }
        Ok(fp)
    }

    fn put(&mut self, e: SignedEntry) -> Result<(), Self::Error> {
        self.with_latest_mut_with_default(|records| {
            records.insert(e.author_bytes(), (e.timestamp(), e.key().to_vec()));
        });
        self.with_records_mut_with_default(|records| {
            records.insert(e);
        });
        Ok(())
    }

    type RangeIterator<'a> = InstanceRangeIterator<'a>;

    fn get_range(
        &self,
        range: Range<RecordIdentifier>,
    ) -> Result<Self::RangeIterator<'_>, Self::Error> {
        Ok(InstanceRangeIterator {
            iter: self.records_iter(),
            filter: InstanceRangeFilter::Range(range),
        })
    }

    fn remove(&mut self, key: &RecordIdentifier) -> Result<Option<SignedEntry>, Self::Error> {
        // TODO: what if we are trying to remove with the wrong timestamp?
        let res = self.with_records_mut(|records| records.and_then(|records| records.remove(key)));
        Ok(res)
    }

    fn all(&self) -> Result<Self::RangeIterator<'_>, Self::Error> {
        Ok(InstanceRangeIterator {
            iter: self.records_iter(),
            filter: InstanceRangeFilter::None,
        })
    }

    // TODO: Not horrible.
    type ParentIterator<'a> = std::vec::IntoIter<Result<SignedEntry, Infallible>>;
    fn prefixes_of(&self, id: &RecordIdentifier) -> Result<Self::ParentIterator<'_>, Self::Error> {
        let mut entries = vec![];
        let mut key = id.key().to_vec();
        while !key.is_empty() {
            let id = RecordIdentifier::new(id.namespace(), id.author(), &key);
            match self.get(&id) {
                Ok(Some(entry)) => entries.push(Ok(entry)),
                Ok(None) => {}
                Err(err) => entries.push(Err(err)),
            }
            key.pop();
        }
        Ok(entries.into_iter())
    }

    fn prefixed_by(
        &self,
        prefix: &RecordIdentifier,
    ) -> std::result::Result<Self::RangeIterator<'_>, Self::Error> {
        Ok(InstanceRangeIterator {
            iter: self.records_iter(),
            filter: InstanceRangeFilter::Prefix(prefix.author(), prefix.key().to_vec()),
        })
    }

    fn remove_prefix_filtered(
        &mut self,
        prefix: &RecordIdentifier,
        predicate: impl Fn(&Record) -> bool,
    ) -> Result<usize, Self::Error> {
        self.with_records_mut(|records| {
            let Some(records) = records else {
                return Ok(0);
            };
            let old_len = records.by_author.len();
            records.retain(|(a, k), v| {
                !(a == &prefix.author() && k.starts_with(prefix.key()) && predicate(v.entry()))
            });
            Ok(old_len - records.len())
        })
    }
}

/// Range iterator for a [`ReplicaStoreInstance`]
#[derive(Debug)]
pub struct InstanceRangeIterator<'a> {
    iter: RecordsIter<'a>,
    filter: InstanceRangeFilter,
}

/// Filter for an [`InstanceRangeIterator`]
#[derive(Debug)]
enum InstanceRangeFilter {
    None,
    Range(Range<RecordIdentifier>),
    Prefix(AuthorId, Vec<u8>),
}

impl InstanceRangeFilter {
    fn matches(&self, x: &RecordIdentifier) -> bool {
        match self {
            Self::None => true,
            Self::Range(range) => range.contains(x),
            Self::Prefix(author, prefix) => x.author() == *author && x.key().starts_with(prefix),
        }
    }
}

impl Iterator for InstanceRangeIterator<'_> {
    type Item = Result<SignedEntry, Infallible>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut next = self.iter.next()?;
        loop {
            let (record_id, v) = next;
            if self.filter.matches(&record_id) {
                return Some(Ok(v));
            }

            next = self.iter.next()?;
        }
    }
}

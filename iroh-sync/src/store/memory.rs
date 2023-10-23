//! In memory storage for replicas.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use ed25519_dalek::{SignatureError, VerifyingKey};
use iroh_bytes::Hash;
use parking_lot::{RwLock, RwLockReadGuard};

use crate::{
    ranger::{Fingerprint, Range, RangeEntry},
    sync::{Author, Namespace, RecordIdentifier, Replica, SignedEntry},
    AuthorId, NamespaceId, PeerIdBytes, Record,
};

use super::{
    pubkeys::MemPublicKeyStore, AuthorMatcher, KeyMatcher, OpenError, PublicKeyStore, Query, View,
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
    pubkeys: MemPublicKeyStore,
    /// Cache of peers that have been used for sync.
    peers_per_doc: SyncPeersCache,
}

type Rid = (AuthorId, Vec<u8>);
type Rvalue = SignedEntry;
type RecordMap = BTreeMap<Rid, Rvalue>;
type ReplicaRecordsOwned = BTreeMap<NamespaceId, RecordMap>;

impl super::Store for Store {
    type Instance = ReplicaStoreInstance;
    type GetIter<'a> = RangeIterator<'a>;
    type ContentHashesIter<'a> = ContentHashesIterator<'a>;
    type AuthorsIter<'a> = std::vec::IntoIter<Result<Author>>;
    type NamespaceIter<'a> = std::vec::IntoIter<Result<NamespaceId>>;
    type PeersIter<'a> = std::vec::IntoIter<PeerIdBytes>;

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
        query: Query,
        view: View,
    ) -> Result<Self::GetIter<'_>> {
        let records = self.replica_records.read();
        let index = usize::try_from(query.range.start())?;

        Ok(RangeIterator {
            records,
            namespace,
            query,
            view,
            index,
        })
    }

    fn get_one(
        &self,
        namespace: NamespaceId,
        author: impl Into<AuthorMatcher>,
        key: impl Into<KeyMatcher>,
    ) -> Result<Option<SignedEntry>> {
        let inner = self.replica_records.read();

        let Some(records) = inner.get(&namespace) else {
            return Ok(None);
        };

        let res = match (author.into(), key.into()) {
            (AuthorMatcher::Any, KeyMatcher::Any) => records.iter().next(),
            (AuthorMatcher::Any, KeyMatcher::Exact(key)) => {
                records.iter().find(|((_, k), _)| k == &key)
            }
            (AuthorMatcher::Any, KeyMatcher::Prefix(key)) => {
                records.iter().find(|((_, k), _)| k.starts_with(&key))
            }

            (AuthorMatcher::Exact(author), KeyMatcher::Any) => {
                records.iter().find(|((a, _), _)| &author == a)
            }
            (AuthorMatcher::Exact(author), KeyMatcher::Exact(key)) => {
                records.iter().find(|((a, k), _)| a == &author && k == &key)
            }

            (AuthorMatcher::Exact(author), KeyMatcher::Prefix(key)) => records
                .iter()
                .find(|((a, k), _)| a == &author && k.starts_with(&key)),
        };

        Ok(res.map(|(_, e)| e.clone()))
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
            match records.values().nth(self.record_i) {
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

/// Iterator over entries in the memory store
#[derive(Debug)]
pub struct RangeIterator<'a> {
    records: ReplicaRecords<'a>,
    namespace: NamespaceId,
    query: Query,
    view: View,
    /// Current iteration index.
    index: usize,
}

impl<'a> Iterator for RangeIterator<'a> {
    type Item = Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(end) = self.query.range.end() {
                if self.index as u64 >= end {
                    return None;
                }
            }

            let records = self.records.get(&self.namespace)?;
            let author_check = match (&self.query.author, &self.view) {
                (AuthorMatcher::Any, View::LatestByKeyAndAuthor) => None,
                (AuthorMatcher::Any, View::LatestByKey) => None,
                (AuthorMatcher::Exact(author), View::LatestByKeyAndAuthor) => Some(author), // TODO: what to do here?
                (AuthorMatcher::Exact(author), View::LatestByKey) => Some(author),
            };

            let offset = self.index;
            let entry = match self.query.key {
                KeyMatcher::Any => records
                    .iter()
                    .filter(|((a, k), _)| author_check.map(|author| author == a).unwrap_or(true))
                    .skip(offset)
                    .next(),
                KeyMatcher::Exact(ref key) => records
                    .iter()
                    .filter(|((a, k), _)| {
                        k == key && author_check.map(|author| author == a).unwrap_or(true)
                    })
                    .skip(offset)
                    .next(),
                KeyMatcher::Prefix(ref prefix) => records
                    .iter()
                    .filter(|((a, k), _)| {
                        k.starts_with(prefix)
                            && author_check.map(|author| author == a).unwrap_or(true)
                    })
                    .skip(offset)
                    .next(),
            }?;
            self.index += 1;
            if entry.1.is_empty() {
                continue;
            } else {
                return Some(Ok(entry.1.clone()));
            }
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
                    r.first_key_value().map(|((author, key), _value)| {
                        RecordIdentifier::new(self.namespace, *author, key.clone())
                    })
                })
                .unwrap_or_default()
        }))
    }

    fn get(&self, key: &RecordIdentifier) -> Result<Option<SignedEntry>, Self::Error> {
        Ok(self.with_records(|records| {
            records.and_then(|r| {
                let v = r.get(&(key.author(), key.key().to_vec()))?;
                Some(v.clone())
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
            fp ^= el.as_fingerprint();
        }
        Ok(fp)
    }

    fn put(&mut self, e: SignedEntry) -> Result<(), Self::Error> {
        self.with_records_mut_with_default(|records| {
            records.insert((e.author_bytes(), e.key().to_vec()), e);
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
        let res = self.with_records_mut(|records| {
            records.and_then(|records| records.remove(&(key.author(), key.key().to_vec())))
        });
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
            let old_len = records.len();
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

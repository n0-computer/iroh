// Names and concepts are roughly based on Willows design at the moment:
//
// https://hackmd.io/DTtck8QOQm6tZaQBBtTf7w
//
// This is going to change!

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    fmt::{Debug, Display},
    str::FromStr,
    sync::Arc,
    time::SystemTime,
};

use parking_lot::RwLock;

use bytes::Bytes;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use iroh_bytes::Hash;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::ranger::{AsFingerprint, Fingerprint, Peer, Range, RangeKey};

pub type ProtocolMessage = crate::ranger::Message<RecordIdentifier, SignedEntry>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Author {
    priv_key: SigningKey,
    id: AuthorId,
}

impl Display for Author {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Author({})", hex::encode(self.priv_key.to_bytes()))
    }
}

impl Author {
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let priv_key = SigningKey::generate(rng);
        let id = AuthorId(priv_key.verifying_key());

        Author { priv_key, id }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    pub fn id(&self) -> &AuthorId {
        &self.id
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.priv_key.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.id.verify(msg, signature)
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct AuthorId(VerifyingKey);

impl Debug for AuthorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthorId({})", hex::encode(self.0.as_bytes()))
    }
}

impl Display for AuthorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl AuthorId {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    priv_key: SigningKey,
    id: NamespaceId,
}

impl Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Namespace({})", hex::encode(self.priv_key.to_bytes()))
    }
}

impl FromStr for Namespace {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let priv_key: [u8; 32] = hex::decode(s).map_err(|_| ())?.try_into().map_err(|_| ())?;
        let priv_key = SigningKey::from_bytes(&priv_key);
        let id = NamespaceId(priv_key.verifying_key());
        Ok(Namespace { priv_key, id })
    }
}

impl FromStr for Author {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let priv_key: [u8; 32] = hex::decode(s).map_err(|_| ())?.try_into().map_err(|_| ())?;
        let priv_key = SigningKey::from_bytes(&priv_key);
        let id = AuthorId(priv_key.verifying_key());
        Ok(Author { priv_key, id })
    }
}

impl From<SigningKey> for Author {
    fn from(priv_key: SigningKey) -> Self {
        let id = AuthorId(priv_key.verifying_key());
        Self { priv_key, id }
    }
}

impl From<SigningKey> for Namespace {
    fn from(priv_key: SigningKey) -> Self {
        let id = NamespaceId(priv_key.verifying_key());
        Self { priv_key, id }
    }
}

impl Namespace {
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let priv_key = SigningKey::generate(rng);
        let id = NamespaceId(priv_key.verifying_key());

        Namespace { priv_key, id }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    pub fn id(&self) -> &NamespaceId {
        &self.id
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.priv_key.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.id.verify(msg, signature)
    }
}

#[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NamespaceId(VerifyingKey);

impl Display for NamespaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NamespaceId({})", hex::encode(self.0.as_bytes()))
    }
}

impl Debug for NamespaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NamespaceId({})", hex::encode(self.0.as_bytes()))
    }
}

impl NamespaceId {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Manages the replicas and authors for an instance.
#[derive(Debug, Clone, Default)]
pub struct ReplicaStore {
    replicas: Arc<RwLock<HashMap<NamespaceId, Replica>>>,
    authors: Arc<RwLock<HashMap<AuthorId, Author>>>,
}

impl ReplicaStore {
    pub fn get_replica(&self, namespace: &NamespaceId) -> Option<Replica> {
        let replicas = &*self.replicas.read();
        replicas.get(namespace).cloned()
    }

    pub fn get_author(&self, author: &AuthorId) -> Option<Author> {
        let authors = &*self.authors.read();
        authors.get(author).cloned()
    }

    pub fn new_author<R: CryptoRngCore + ?Sized>(&self, rng: &mut R) -> Author {
        let author = Author::new(rng);
        self.authors.write().insert(*author.id(), author.clone());
        author
    }

    pub fn new_replica(&self, namespace: Namespace) -> Replica {
        let replica = Replica::new(namespace);
        self.replicas
            .write()
            .insert(replica.namespace(), replica.clone());
        replica
    }

    pub fn open_replica(&self, bytes: &[u8]) -> anyhow::Result<Replica> {
        let replica = Replica::from_bytes(bytes)?;
        self.replicas
            .write()
            .insert(replica.namespace(), replica.clone());
        Ok(replica)
    }
}

/// TODO: Would potentially nice to pass a `&SignedEntry` reference, however that would make
/// everything `!Send`.
/// TODO: Not sure if the `Sync` requirement will be a problem for implementers. It comes from
/// [parking_lot::RwLock] requiring `Sync`.
pub type OnInsertCallback = Box<dyn Fn(InsertOrigin, SignedEntry) + Send + Sync + 'static>;

#[derive(Debug, Clone)]
pub enum InsertOrigin {
    Local,
    Sync,
}

#[derive(derive_more::Debug, Clone)]
pub struct Replica {
    inner: Arc<RwLock<InnerReplica>>,
    #[debug("on_insert: [Box<dyn Fn>; {}]", "self.on_insert.len()")]
    on_insert: Arc<RwLock<Vec<OnInsertCallback>>>,
}

#[derive(derive_more::Debug)]
struct InnerReplica {
    namespace: Namespace,
    peer: Peer<RecordIdentifier, SignedEntry, Store>,
}

#[derive(Default, Debug, Clone)]
pub struct Store {
    /// Stores records by identifier + timestamp
    records: BTreeMap<RecordIdentifier, BTreeMap<u64, SignedEntry>>,
}

impl Store {
    pub fn latest(&self) -> impl Iterator<Item = (&RecordIdentifier, &SignedEntry)> {
        self.records.iter().filter_map(|(k, values)| {
            let (_, v) = values.last_key_value()?;
            Some((k, v))
        })
    }
}

impl crate::ranger::Store<RecordIdentifier, SignedEntry> for Store {
    /// Get a the first key (or the default if none is available).
    fn get_first(&self) -> RecordIdentifier {
        self.records
            .first_key_value()
            .map(|(k, _)| k.clone())
            .unwrap_or_default()
    }

    fn get(&self, key: &RecordIdentifier) -> Option<&SignedEntry> {
        self.records
            .get(key)
            .and_then(|values| values.last_key_value())
            .map(|(_, v)| v)
    }

    fn len(&self) -> usize {
        self.records.len()
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn get_fingerprint(
        &self,
        range: &Range<RecordIdentifier>,
        limit: Option<&Range<RecordIdentifier>>,
    ) -> Fingerprint {
        let elements = self.get_range(range.clone(), limit.cloned());
        let mut fp = Fingerprint::empty();
        for el in elements {
            fp ^= el.0.as_fingerprint();
        }

        fp
    }

    fn put(&mut self, k: RecordIdentifier, v: SignedEntry) {
        // TODO: propagate error/not insertion?
        if v.verify().is_ok() {
            let timestamp = v.entry().record().timestamp();
            // TODO: verify timestamp is "reasonable"

            self.records.entry(k).or_default().insert(timestamp, v);
        }
    }

    type RangeIterator<'a> = RangeIterator<'a>;
    fn get_range(
        &self,
        range: Range<RecordIdentifier>,
        limit: Option<Range<RecordIdentifier>>,
    ) -> Self::RangeIterator<'_> {
        RangeIterator {
            iter: self.records.iter(),
            range: Some(range),
            limit,
        }
    }

    fn remove(&mut self, key: &RecordIdentifier) -> Option<SignedEntry> {
        self.records
            .remove(key)
            .and_then(|mut v| v.last_entry().map(|e| e.remove_entry().1))
    }

    type AllIterator<'a> = RangeIterator<'a>;

    fn all(&self) -> Self::AllIterator<'_> {
        RangeIterator {
            iter: self.records.iter(),
            range: None,
            limit: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ReplicaData {
    entries: Vec<SignedEntry>,
    namespace: Namespace,
}

#[derive(Debug)]
pub struct RangeIterator<'a> {
    iter: std::collections::btree_map::Iter<'a, RecordIdentifier, BTreeMap<u64, SignedEntry>>,
    range: Option<Range<RecordIdentifier>>,
    limit: Option<Range<RecordIdentifier>>,
}

impl<'a> RangeIterator<'a> {
    fn matches(&self, x: &RecordIdentifier) -> bool {
        let range = self.range.as_ref().map(|r| x.contains(r)).unwrap_or(true);
        let limit = self.limit.as_ref().map(|r| x.contains(r)).unwrap_or(true);
        range && limit
    }
}

impl<'a> Iterator for RangeIterator<'a> {
    type Item = (&'a RecordIdentifier, &'a SignedEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let mut next = self.iter.next()?;
        loop {
            if self.matches(next.0) {
                let (k, values) = next;
                let (_, v) = values.last_key_value()?;
                return Some((k, v));
            }

            next = self.iter.next()?;
        }
    }
}

impl Replica {
    pub fn new(namespace: Namespace) -> Self {
        Replica {
            inner: Arc::new(RwLock::new(InnerReplica {
                namespace,
                peer: Peer::default(),
            })),
            on_insert: Default::default(),
        }
    }

    pub fn on_insert(&self, callback: OnInsertCallback) {
        let mut on_insert = self.on_insert.write();
        on_insert.push(callback);
    }

    // TODO: not horrible
    pub fn all(&self) -> Vec<(RecordIdentifier, SignedEntry)> {
        self.inner
            .read()
            .peer
            .all()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    // TODO: not horrible
    pub fn all_for_key(&self, key: impl AsRef<[u8]>) -> Vec<(RecordIdentifier, SignedEntry)> {
        self.all()
            .into_iter()
            .filter(|(id, _entry)| id.key() == key.as_ref())
            .collect()
    }

    // TODO: not horrible
    pub fn all_with_key_prefix(
        &self,
        prefix: impl AsRef<[u8]>,
    ) -> Vec<(RecordIdentifier, SignedEntry)> {
        self.all()
            .into_iter()
            .filter(|(id, _entry)| id.key().starts_with(prefix.as_ref()))
            .collect()
    }

    pub fn to_bytes(&self) -> anyhow::Result<Bytes> {
        let entries = self.all().into_iter().map(|(_id, entry)| entry).collect();
        let data = ReplicaData {
            entries,
            namespace: self.inner.read().namespace.clone(),
        };
        let bytes = postcard::to_stdvec(&data)?;
        Ok(bytes.into())
    }
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let data: ReplicaData = postcard::from_bytes(bytes)?;
        let replica = Self::new(data.namespace);
        for entry in data.entries {
            replica.insert_remote_entry(entry)?;
        }
        Ok(replica)
    }

    /// Inserts a new record at the given key.
    pub fn insert(&self, key: impl AsRef<[u8]>, author: &Author, hash: Hash, len: u64) {
        let mut inner = self.inner.write();

        let id = RecordIdentifier::new(key, inner.namespace.id(), author.id());
        let record = Record::from_hash(hash, len);

        // Store signed entries
        let entry = Entry::new(id.clone(), record);
        let signed_entry = entry.sign(&inner.namespace, author);
        inner.peer.put(id, signed_entry.clone());
        drop(inner);
        let on_insert = self.on_insert.read();
        for cb in &*on_insert {
            cb(InsertOrigin::Local, signed_entry.clone());
        }
    }

    /// Hashes the given data and inserts it.
    /// This does not store the content, just the record of it.
    ///
    /// Returns the calculated hash.
    pub fn hash_and_insert(
        &self,
        key: impl AsRef<[u8]>,
        author: &Author,
        data: impl AsRef<[u8]>,
    ) -> Hash {
        let len = data.as_ref().len() as u64;
        let hash = Hash::new(data);
        self.insert(key, author, hash, len);
        hash
    }

    pub fn id(&self, key: impl AsRef<[u8]>, author: &Author) -> RecordIdentifier {
        let inner = self.inner.read();
        let id = RecordIdentifier::new(key, inner.namespace.id(), author.id());
        id
    }

    pub fn insert_remote_entry(&self, entry: SignedEntry) -> anyhow::Result<()> {
        entry.verify()?;
        let mut inner = self.inner.write();
        let id = entry.entry.id.clone();
        inner.peer.put(id, entry.clone());
        drop(inner);
        let on_insert = self.on_insert.read();
        for cb in &*on_insert {
            cb(InsertOrigin::Sync, entry.clone());
        }
        Ok(())
    }

    /// Gets all entries matching this key and author.
    pub fn get_latest_by_key_and_author(
        &self,
        key: impl AsRef<[u8]>,
        author: &AuthorId,
    ) -> Option<SignedEntry> {
        let inner = self.inner.read();
        inner
            .peer
            .get(&RecordIdentifier::new(key, inner.namespace.id(), author))
            .cloned()
    }

    /// Returns the latest version of the matching documents by key.
    pub fn get_latest_by_key(&self, key: impl AsRef<[u8]>) -> GetLatestIter<'_> {
        let guard: parking_lot::lock_api::RwLockReadGuard<_, _> = self.inner.read();
        let key = key.as_ref().to_vec();
        let namespace = *guard.namespace.id();
        let filter = GetFilter::Key { namespace, key };

        GetLatestIter {
            records: parking_lot::lock_api::RwLockReadGuard::map(guard, move |inner| {
                &inner.peer.store().records
            }),
            filter,
            index: 0,
        }
    }

    /// Returns the latest version of the matching documents by prefix.
    pub fn get_latest_by_prefix(&self, prefix: impl AsRef<[u8]>) -> GetLatestIter<'_> {
        let guard: parking_lot::lock_api::RwLockReadGuard<_, _> = self.inner.read();
        let prefix = prefix.as_ref().to_vec();
        let namespace = *guard.namespace.id();
        let filter = GetFilter::Prefix { namespace, prefix };

        GetLatestIter {
            records: parking_lot::lock_api::RwLockReadGuard::map(guard, move |inner| {
                &inner.peer.store().records
            }),
            filter,
            index: 0,
        }
    }

    /// Returns the latest versions of all documents.
    pub fn get_latest(&self) -> GetLatestIter<'_> {
        let guard: parking_lot::lock_api::RwLockReadGuard<_, _> = self.inner.read();
        let namespace = *guard.namespace.id();
        let filter = GetFilter::All { namespace };

        GetLatestIter {
            records: parking_lot::lock_api::RwLockReadGuard::map(guard, move |inner| {
                &inner.peer.store().records
            }),
            filter,
            index: 0,
        }
    }

    /// Returns all versions of the matching documents by author.
    pub fn get_all_by_key_and_author<'a, 'b: 'a>(
        &'a self,
        key: impl AsRef<[u8]> + 'b,
        author: &AuthorId,
    ) -> GetAllIter<'a> {
        let guard: parking_lot::lock_api::RwLockReadGuard<_, _> = self.inner.read();
        let record_id = RecordIdentifier::new(key, guard.namespace.id(), author);
        let filter = GetFilter::KeyAuthor(record_id);

        GetAllIter {
            records: parking_lot::lock_api::RwLockReadGuard::map(guard, move |inner| {
                &inner.peer.store().records
            }),
            filter,
            index: 0,
        }
    }

    /// Returns all versions of the matching documents by key.
    pub fn get_all_by_key(&self, key: impl AsRef<[u8]>) -> GetAllIter<'_> {
        let guard: parking_lot::lock_api::RwLockReadGuard<_, _> = self.inner.read();
        let key = key.as_ref().to_vec();
        let namespace = *guard.namespace.id();
        let filter = GetFilter::Key { namespace, key };

        GetAllIter {
            records: parking_lot::lock_api::RwLockReadGuard::map(guard, move |inner| {
                &inner.peer.store().records
            }),
            filter,
            index: 0,
        }
    }

    /// Returns all versions of the matching documents by prefix.
    pub fn get_all_by_prefix(&self, prefix: impl AsRef<[u8]>) -> GetAllIter<'_> {
        let guard: parking_lot::lock_api::RwLockReadGuard<_, _> = self.inner.read();
        let prefix = prefix.as_ref().to_vec();
        let namespace = *guard.namespace.id();
        let filter = GetFilter::Prefix { namespace, prefix };

        GetAllIter {
            records: parking_lot::lock_api::RwLockReadGuard::map(guard, move |inner| {
                &inner.peer.store().records
            }),
            filter,
            index: 0,
        }
    }

    /// Returns all versions of all documents.
    pub fn get_all(&self) -> GetAllIter<'_> {
        let guard: parking_lot::lock_api::RwLockReadGuard<_, _> = self.inner.read();
        let namespace = *guard.namespace.id();
        let filter = GetFilter::All { namespace };

        GetAllIter {
            records: parking_lot::lock_api::RwLockReadGuard::map(guard, move |inner| {
                &inner.peer.store().records
            }),
            filter,
            index: 0,
        }
    }

    pub fn sync_initial_message(&self) -> crate::ranger::Message<RecordIdentifier, SignedEntry> {
        self.inner.read().peer.initial_message()
    }

    pub fn sync_process_message(
        &self,
        message: crate::ranger::Message<RecordIdentifier, SignedEntry>,
    ) -> Option<crate::ranger::Message<RecordIdentifier, SignedEntry>> {
        let reply = self
            .inner
            .write()
            .peer
            .process_message(message, |_key, entry| {
                let on_insert = self.on_insert.read();
                for cb in &*on_insert {
                    cb(InsertOrigin::Sync, entry.clone());
                }
            });

        reply
    }

    pub fn namespace(&self) -> NamespaceId {
        *self.inner.read().namespace.id()
    }
}

#[derive(Debug)]
pub enum GetFilter {
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

#[derive(Debug)]
pub struct GetLatestIter<'a> {
    // Oh my god, rust why u do this to me?
    records: parking_lot::lock_api::MappedRwLockReadGuard<
        'a,
        parking_lot::RawRwLock,
        BTreeMap<RecordIdentifier, BTreeMap<u64, SignedEntry>>,
    >,
    filter: GetFilter,
    /// Current iteration index.
    index: usize,
}

impl<'a> Iterator for GetLatestIter<'a> {
    type Item = SignedEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let res = match self.filter {
            GetFilter::All { namespace } => {
                let (_, res) = self
                    .records
                    .iter()
                    .filter(|(k, _)| k.namespace() == &namespace)
                    .filter_map(|(_key, value)| value.last_key_value())
                    .nth(self.index)?;
                res.clone()
            }
            GetFilter::KeyAuthor(ref record_id) => {
                let values = self.records.get(record_id)?;
                let (_, res) = values.iter().nth(self.index)?;
                res.clone()
            }
            GetFilter::Key { namespace, ref key } => {
                let (_, res) = self
                    .records
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
                let (_, res) = self
                    .records
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
    // Oh my god, rust why u do this to me?
    records: parking_lot::lock_api::MappedRwLockReadGuard<
        'a,
        parking_lot::RawRwLock,
        BTreeMap<RecordIdentifier, BTreeMap<u64, SignedEntry>>,
    >,
    filter: GetFilter,
    /// Current iteration index.
    index: usize,
}

impl<'a> Iterator for GetAllIter<'a> {
    type Item = (RecordIdentifier, u64, SignedEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let res = match self.filter {
            GetFilter::All { namespace } => self
                .records
                .iter()
                .filter(|(k, _)| k.namespace() == &namespace)
                .flat_map(|(key, value)| {
                    value
                        .iter()
                        .map(|(t, value)| (key.clone(), *t, value.clone()))
                })
                .nth(self.index)?,
            GetFilter::KeyAuthor(ref record_id) => {
                let values = self.records.get(record_id)?;
                let (t, value) = values.iter().nth(self.index)?;
                (record_id.clone(), *t, value.clone())
            }
            GetFilter::Key { namespace, ref key } => self
                .records
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
            } => self
                .records
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

/// A signed entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEntry {
    signature: EntrySignature,
    entry: Entry,
}

impl SignedEntry {
    pub fn from_entry(entry: Entry, namespace: &Namespace, author: &Author) -> Self {
        let signature = EntrySignature::from_entry(&entry, namespace, author);
        SignedEntry { signature, entry }
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        self.signature
            .verify(&self.entry, &self.entry.id.namespace, &self.entry.id.author)
    }

    pub fn signature(&self) -> &EntrySignature {
        &self.signature
    }

    pub fn entry(&self) -> &Entry {
        &self.entry
    }

    pub fn content_hash(&self) -> &Hash {
        self.entry().record().content_hash()
    }
}

/// Signature over an entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySignature {
    author_signature: Signature,
    namespace_signature: Signature,
}

impl EntrySignature {
    pub fn from_entry(entry: &Entry, namespace: &Namespace, author: &Author) -> Self {
        // TODO: this should probably include a namespace prefix
        // namespace in the cryptographic sense.
        let bytes = entry.to_vec();
        let namespace_signature = namespace.sign(&bytes);
        let author_signature = author.sign(&bytes);

        EntrySignature {
            author_signature,
            namespace_signature,
        }
    }

    pub fn verify(
        &self,
        entry: &Entry,
        namespace: &NamespaceId,
        author: &AuthorId,
    ) -> Result<(), SignatureError> {
        let bytes = entry.to_vec();
        namespace.verify(&bytes, &self.namespace_signature)?;
        author.verify(&bytes, &self.author_signature)?;

        Ok(())
    }
}

/// A single entry in a replica.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    id: RecordIdentifier,
    record: Record,
}

impl Entry {
    pub fn new(id: RecordIdentifier, record: Record) -> Self {
        Entry { id, record }
    }

    pub fn id(&self) -> &RecordIdentifier {
        &self.id
    }

    pub fn record(&self) -> &Record {
        &self.record
    }

    /// Serialize this entry into its canonical byte representation used for signing.
    pub fn into_vec(&self, out: &mut Vec<u8>) {
        self.id.as_bytes(out);
        self.record.as_bytes(out);
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.into_vec(&mut out);
        out
    }

    pub fn sign(self, namespace: &Namespace, author: &Author) -> SignedEntry {
        SignedEntry::from_entry(self, namespace, author)
    }
}

/// The indentifier of a record.
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecordIdentifier {
    /// The key of the record.
    key: Vec<u8>,
    /// The namespace this record belongs to.
    namespace: NamespaceId,
    /// The author that wrote this record.
    author: AuthorId,
}

impl AsFingerprint for RecordIdentifier {
    fn as_fingerprint(&self) -> crate::ranger::Fingerprint {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.namespace.as_bytes());
        hasher.update(self.author.as_bytes());
        hasher.update(&self.key);
        Fingerprint(hasher.finalize().into())
    }
}

impl PartialOrd for NamespaceId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NamespaceId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl PartialOrd for AuthorId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AuthorId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl RangeKey for RecordIdentifier {
    fn contains(&self, range: &crate::ranger::Range<Self>) -> bool {
        use crate::ranger::contains;

        let key_range = range.clone().map(|x, y| (x.key, y.key));
        let namespace_range = range.clone().map(|x, y| (x.namespace, y.namespace));
        let author_range = range.clone().map(|x, y| (x.author, y.author));

        contains(&self.key, &key_range)
            && contains(&self.namespace, &namespace_range)
            && contains(&self.author, &author_range)
    }
}

impl RecordIdentifier {
    pub fn new(key: impl AsRef<[u8]>, namespace: &NamespaceId, author: &AuthorId) -> Self {
        RecordIdentifier {
            key: key.as_ref().to_vec(),
            namespace: *namespace,
            author: *author,
        }
    }

    pub fn as_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.namespace.as_bytes());
        out.extend_from_slice(self.author.as_bytes());
        out.extend_from_slice(&self.key);
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn namespace(&self) -> &NamespaceId {
        &self.namespace
    }

    pub fn author(&self) -> &AuthorId {
        &self.author
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Record creation timestamp. Counted as micros since the Unix epoch.
    timestamp: u64,
    /// Length of the data referenced by `hash`.
    len: u64,
    hash: Hash,
}

impl Record {
    pub fn new(timestamp: u64, len: u64, hash: Hash) -> Self {
        Record {
            timestamp,
            len,
            hash,
        }
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn content_len(&self) -> u64 {
        self.len
    }

    pub fn content_hash(&self) -> &Hash {
        &self.hash
    }

    pub fn from_hash(hash: Hash, len: u64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time drift")
            .as_micros() as u64;
        Self::new(timestamp, len, hash)
    }

    // TODO: remove
    pub fn from_data(data: impl AsRef<[u8]>, namespace: &NamespaceId) -> Self {
        // Salted hash
        // TODO: do we actually want this?
        // TODO: this should probably use a namespace prefix if used
        let mut hasher = blake3::Hasher::new();
        hasher.update(namespace.as_bytes());
        hasher.update(data.as_ref());
        let hash = hasher.finalize();
        Self::from_hash(hash.into(), data.as_ref().len() as u64)
    }

    pub fn as_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.len.to_be_bytes());
        out.extend_from_slice(self.hash.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basics() {
        let mut rng = rand::thread_rng();
        let alice = Author::new(&mut rng);
        let bob = Author::new(&mut rng);
        let myspace = Namespace::new(&mut rng);

        let record_id = RecordIdentifier::new("/my/key", myspace.id(), alice.id());
        let record = Record::from_data(b"this is my cool data", myspace.id());
        let entry = Entry::new(record_id, record);
        let signed_entry = entry.sign(&myspace, &alice);
        signed_entry.verify().expect("failed to verify");

        let my_replica = Replica::new(myspace);
        for i in 0..10 {
            my_replica.hash_and_insert(format!("/{i}"), &alice, format!("{i}: hello from alice"));
        }

        for i in 0..10 {
            let res = my_replica
                .get_latest_by_key_and_author(format!("/{i}"), alice.id())
                .unwrap();
            let len = format!("{i}: hello from alice").as_bytes().len() as u64;
            assert_eq!(res.entry().record().content_len(), len);
            res.verify().expect("invalid signature");
        }

        // Test multiple records for the same key
        my_replica.hash_and_insert("/cool/path", &alice, "round 1");
        let _entry = my_replica
            .get_latest_by_key_and_author("/cool/path", alice.id())
            .unwrap();
        // Second
        my_replica.hash_and_insert("/cool/path", &alice, "round 2");
        let _entry = my_replica
            .get_latest_by_key_and_author("/cool/path", alice.id())
            .unwrap();

        // Get All by author
        let entries: Vec<_> = my_replica
            .get_all_by_key_and_author("/cool/path", alice.id())
            .collect();
        assert_eq!(entries.len(), 2);

        // Get All by key
        let entries: Vec<_> = my_replica.get_all_by_key(b"/cool/path").collect();
        assert_eq!(entries.len(), 2);

        // Get latest by key
        let entries: Vec<_> = my_replica.get_latest_by_key(b"/cool/path").collect();
        assert_eq!(entries.len(), 1);

        // Get latest by prefix
        let entries: Vec<_> = my_replica.get_latest_by_prefix(b"/cool").collect();
        assert_eq!(entries.len(), 1);

        // Get All
        let entries: Vec<_> = my_replica.get_all().collect();
        assert_eq!(entries.len(), 12);

        // Get All latest
        let entries: Vec<_> = my_replica.get_latest().collect();
        assert_eq!(entries.len(), 11);

        // insert record from different author
        let _entry = my_replica.hash_and_insert("/cool/path", &bob, "bob round 1");

        // Get All by author
        let entries: Vec<_> = my_replica
            .get_all_by_key_and_author("/cool/path", alice.id())
            .collect();
        assert_eq!(entries.len(), 2);

        let entries: Vec<_> = my_replica
            .get_all_by_key_and_author("/cool/path", bob.id())
            .collect();
        assert_eq!(entries.len(), 1);

        // Get All by key
        let entries: Vec<_> = my_replica.get_all_by_key(b"/cool/path").collect();
        assert_eq!(entries.len(), 3);

        // Get latest by key
        let entries: Vec<_> = my_replica.get_latest_by_key(b"/cool/path").collect();
        assert_eq!(entries.len(), 2);

        // Get latest by prefix
        let entries: Vec<_> = my_replica.get_latest_by_prefix(b"/cool").collect();
        assert_eq!(entries.len(), 2);

        // Get all by prefix
        let entries: Vec<_> = my_replica.get_all_by_prefix(b"/cool").collect();
        assert_eq!(entries.len(), 3);

        // Get All
        let entries: Vec<_> = my_replica.get_all().collect();
        assert_eq!(entries.len(), 13);

        // Get All latest
        let entries: Vec<_> = my_replica.get_latest().collect();
        assert_eq!(entries.len(), 12);
    }

    #[test]
    fn test_multikey() {
        let mut rng = rand::thread_rng();

        let k = vec!["a", "c", "z"];

        let mut n: Vec<_> = (0..3).map(|_| Namespace::new(&mut rng)).collect();
        n.sort_by_key(|n| *n.id());

        let mut a: Vec<_> = (0..3).map(|_| Author::new(&mut rng)).collect();
        a.sort_by_key(|a| *a.id());

        // Just key
        {
            let ri0 = RecordIdentifier::new(k[0], n[0].id(), a[0].id());
            let ri1 = RecordIdentifier::new(k[1], n[0].id(), a[0].id());
            let ri2 = RecordIdentifier::new(k[2], n[0].id(), a[0].id());

            let range = Range::new(ri0.clone(), ri2.clone());
            assert!(ri0.contains(&range), "start");
            assert!(ri1.contains(&range), "inside");
            assert!(!ri2.contains(&range), "end");
        }

        // Just namespace
        {
            let ri0 = RecordIdentifier::new(k[0], n[0].id(), a[0].id());
            let ri1 = RecordIdentifier::new(k[0], n[1].id(), a[0].id());
            let ri2 = RecordIdentifier::new(k[0], n[2].id(), a[0].id());

            let range = Range::new(ri0.clone(), ri2.clone());
            assert!(ri0.contains(&range), "start");
            assert!(ri1.contains(&range), "inside");
            assert!(!ri2.contains(&range), "end");
        }

        // Just author
        {
            let ri0 = RecordIdentifier::new(k[0], n[0].id(), a[0].id());
            let ri1 = RecordIdentifier::new(k[0], n[0].id(), a[1].id());
            let ri2 = RecordIdentifier::new(k[0], n[0].id(), a[2].id());

            let range = Range::new(ri0.clone(), ri2.clone());
            assert!(ri0.contains(&range), "start");
            assert!(ri1.contains(&range), "inside");
            assert!(!ri2.contains(&range), "end");
        }

        // Just key and namespace
        {
            let ri0 = RecordIdentifier::new(k[0], n[0].id(), a[0].id());
            let ri1 = RecordIdentifier::new(k[1], n[1].id(), a[0].id());
            let ri2 = RecordIdentifier::new(k[2], n[2].id(), a[0].id());

            let range = Range::new(ri0.clone(), ri2.clone());
            assert!(ri0.contains(&range), "start");
            assert!(ri1.contains(&range), "inside");
            assert!(!ri2.contains(&range), "end");
        }
    }

    #[test]
    fn test_replica_sync() {
        let alice_set = ["ape", "eel", "fox", "gnu"];
        let bob_set = ["bee", "cat", "doe", "eel", "fox", "hog"];

        let mut rng = rand::thread_rng();
        let author = Author::new(&mut rng);
        let myspace = Namespace::new(&mut rng);
        let mut alice = Replica::new(myspace.clone());
        for el in &alice_set {
            alice.hash_and_insert(el, &author, el.as_bytes());
        }

        let mut bob = Replica::new(myspace);
        for el in &bob_set {
            bob.hash_and_insert(el, &author, el.as_bytes());
        }

        sync(&author, &mut alice, &mut bob, &alice_set, &bob_set);
    }

    fn sync(
        author: &Author,
        alice: &mut Replica,
        bob: &mut Replica,
        alice_set: &[&str],
        bob_set: &[&str],
    ) {
        // Sync alice - bob
        let mut next_to_bob = Some(alice.sync_initial_message());
        let mut rounds = 0;
        while let Some(msg) = next_to_bob.take() {
            assert!(rounds < 100, "too many rounds");
            rounds += 1;
            println!("round {}", rounds);
            if let Some(msg) = bob.sync_process_message(msg) {
                next_to_bob = alice.sync_process_message(msg);
            }
        }

        // Check result
        for el in alice_set {
            alice.get_latest_by_key_and_author(el, author.id()).unwrap();
            bob.get_latest_by_key_and_author(el, author.id()).unwrap();
        }

        for el in bob_set {
            alice.get_latest_by_key_and_author(el, author.id()).unwrap();
            bob.get_latest_by_key_and_author(el, author.id()).unwrap();
        }
    }
}

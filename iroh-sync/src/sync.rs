// Names and concepts are roughly based on Willows design at the moment:
//
// https://hackmd.io/DTtck8QOQm6tZaQBBtTf7w
//
// This is going to change!

use std::{
    cmp::Ordering,
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

use crate::ranger::{self, AsFingerprint, Fingerprint, Peer, RangeKey};

pub type ProtocolMessage = crate::ranger::Message<RecordIdentifier, SignedEntry>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Author {
    priv_key: SigningKey,
}

impl Display for Author {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Author({})", hex::encode(self.priv_key.to_bytes()))
    }
}

impl Author {
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let priv_key = SigningKey::generate(rng);

        Author { priv_key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Returns the Author byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.priv_key.to_bytes()
    }

    /// Returns the AuthorId byte representation.
    pub fn id_bytes(&self) -> [u8; 32] {
        self.priv_key.verifying_key().to_bytes()
    }

    pub fn id(&self) -> AuthorId {
        AuthorId(self.priv_key.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.priv_key.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.priv_key.verify_strict(msg, signature)
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

    pub fn from_bytes(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        Ok(AuthorId(VerifyingKey::from_bytes(bytes)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    priv_key: SigningKey,
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

        Ok(Namespace { priv_key })
    }
}

impl FromStr for Author {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let priv_key: [u8; 32] = hex::decode(s).map_err(|_| ())?.try_into().map_err(|_| ())?;
        let priv_key = SigningKey::from_bytes(&priv_key);

        Ok(Author { priv_key })
    }
}

impl From<SigningKey> for Author {
    fn from(priv_key: SigningKey) -> Self {
        Self { priv_key }
    }
}

impl From<SigningKey> for Namespace {
    fn from(priv_key: SigningKey) -> Self {
        Self { priv_key }
    }
}

impl Namespace {
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let priv_key = SigningKey::generate(rng);

        Namespace { priv_key }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Returns the Namespace byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.priv_key.to_bytes()
    }

    /// Returns the NamespaceId byte representation.
    pub fn id_bytes(&self) -> [u8; 32] {
        self.priv_key.verifying_key().to_bytes()
    }

    pub fn id(&self) -> NamespaceId {
        NamespaceId(self.priv_key.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.priv_key.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.priv_key.verify_strict(msg, signature)
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

    pub fn from_bytes(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        Ok(NamespaceId(VerifyingKey::from_bytes(bytes)?))
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
pub struct Replica<S: ranger::Store<RecordIdentifier, SignedEntry>> {
    inner: Arc<RwLock<InnerReplica<S>>>,
    #[debug("on_insert: [Box<dyn Fn>; {}]", "self.on_insert.len()")]
    on_insert: Arc<RwLock<Vec<OnInsertCallback>>>,
}

#[derive(derive_more::Debug)]
struct InnerReplica<S: ranger::Store<RecordIdentifier, SignedEntry>> {
    namespace: Namespace,
    peer: Peer<RecordIdentifier, SignedEntry, S>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReplicaData {
    entries: Vec<SignedEntry>,
    namespace: Namespace,
}

impl<S: ranger::Store<RecordIdentifier, SignedEntry>> Replica<S> {
    // TODO: check that read only replicas are possible
    pub fn new(namespace: Namespace, store: S) -> Self {
        Replica {
            inner: Arc::new(RwLock::new(InnerReplica {
                namespace,
                peer: Peer::from_store(store),
            })),
            on_insert: Default::default(),
        }
    }

    pub fn on_insert(&self, callback: OnInsertCallback) {
        let mut on_insert = self.on_insert.write();
        on_insert.push(callback);
    }

    // TODO: not horrible
    pub fn all(&self) -> Result<Vec<(RecordIdentifier, SignedEntry)>, S::Error> {
        let res = self
            .inner
            .read()
            .peer
            .all()?
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Ok(res)
    }

    // TODO: not horrible
    pub fn all_for_key(
        &self,
        key: impl AsRef<[u8]>,
    ) -> Result<Vec<(RecordIdentifier, SignedEntry)>, S::Error> {
        let res = self
            .all()?
            .into_iter()
            .filter(|(id, _entry)| id.key() == key.as_ref())
            .collect();
        Ok(res)
    }

    // TODO: not horrible
    pub fn all_with_key_prefix(
        &self,
        prefix: impl AsRef<[u8]>,
    ) -> Result<Vec<(RecordIdentifier, SignedEntry)>, S::Error> {
        let res = self
            .all()?
            .into_iter()
            .filter(|(id, _entry)| id.key().starts_with(prefix.as_ref()))
            .collect();
        Ok(res)
    }

    pub fn to_bytes(&self) -> anyhow::Result<Bytes> {
        let entries = self
            .all()
            .map_err(Into::into)?
            .into_iter()
            .map(|(_id, entry)| entry)
            .collect();
        let data = ReplicaData {
            entries,
            namespace: self.inner.read().namespace.clone(),
        };
        let bytes = postcard::to_stdvec(&data)?;
        Ok(bytes.into())
    }

    pub fn from_bytes(bytes: &[u8], store: S) -> anyhow::Result<Self> {
        let data: ReplicaData = postcard::from_bytes(bytes)?;
        let replica = Self::new(data.namespace, store);
        for entry in data.entries {
            replica.insert_remote_entry(entry)?;
        }
        Ok(replica)
    }

    /// Inserts a new record at the given key.
    pub fn insert(
        &self,
        key: impl AsRef<[u8]>,
        author: &Author,
        hash: Hash,
        len: u64,
    ) -> Result<(), S::Error> {
        let mut inner = self.inner.write();

        let id = RecordIdentifier::new(key, inner.namespace.id(), author.id());
        let record = Record::from_hash(hash, len);

        // Store signed entries
        let entry = Entry::new(id.clone(), record);
        let signed_entry = entry.sign(&inner.namespace, author);
        inner.peer.put(id, signed_entry.clone())?;
        drop(inner);
        let on_insert = self.on_insert.read();
        for cb in &*on_insert {
            cb(InsertOrigin::Local, signed_entry.clone());
        }
        Ok(())
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
    ) -> Result<Hash, S::Error> {
        let len = data.as_ref().len() as u64;
        let hash = Hash::new(data);
        self.insert(key, author, hash, len)?;
        Ok(hash)
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
        inner.peer.put(id, entry.clone()).map_err(Into::into)?;
        drop(inner);
        let on_insert = self.on_insert.read();
        for cb in &*on_insert {
            cb(InsertOrigin::Sync, entry.clone());
        }
        Ok(())
    }

    pub fn sync_initial_message(
        &self,
    ) -> Result<crate::ranger::Message<RecordIdentifier, SignedEntry>, S::Error> {
        self.inner.read().peer.initial_message()
    }

    pub fn sync_process_message(
        &self,
        message: crate::ranger::Message<RecordIdentifier, SignedEntry>,
    ) -> Result<Option<crate::ranger::Message<RecordIdentifier, SignedEntry>>, S::Error> {
        let reply = self
            .inner
            .write()
            .peer
            .process_message(message, |_key, entry| {
                let on_insert = self.on_insert.read();
                for cb in &*on_insert {
                    cb(InsertOrigin::Sync, entry.clone());
                }
            })?;

        Ok(reply)
    }

    pub fn namespace(&self) -> NamespaceId {
        self.inner.read().namespace.id()
    }
}

/// A signed entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEntry {
    signature: EntrySignature,
    entry: Entry,
}

impl SignedEntry {
    pub fn new(signature: EntrySignature, entry: Entry) -> Self {
        SignedEntry { signature, entry }
    }

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

    pub fn from_parts(namespace_sig: &[u8; 64], author_sig: &[u8; 64]) -> Self {
        let namespace_signature = Signature::from_bytes(namespace_sig);
        let author_signature = Signature::from_bytes(author_sig);

        EntrySignature {
            author_signature,
            namespace_signature,
        }
    }

    pub fn author_signature(&self) -> &Signature {
        &self.author_signature
    }

    pub fn namespace_signature(&self) -> &Signature {
        &self.namespace_signature
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
    pub fn new(key: impl AsRef<[u8]>, namespace: NamespaceId, author: AuthorId) -> Self {
        RecordIdentifier {
            key: key.as_ref().to_vec(),
            namespace,
            author,
        }
    }

    pub fn from_parts(key: &[u8], namespace: &[u8; 32], author: &[u8; 32]) -> anyhow::Result<Self> {
        Ok(RecordIdentifier {
            key: key.to_vec(),
            namespace: NamespaceId::from_bytes(namespace)?,
            author: AuthorId::from_bytes(author)?,
        })
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
    pub fn from_data(data: impl AsRef<[u8]>, namespace: NamespaceId) -> Self {
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
    use anyhow::Result;

    use crate::{ranger::Range, store};

    use super::*;

    #[test]
    fn test_basics_memory() -> Result<()> {
        let store = store::memory::Store::default();
        test_basics(store)?;

        Ok(())
    }

    #[cfg(feature = "fs-store")]
    #[test]
    fn test_basics_fs() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let store = store::fs::Store::new(dbfile.path())?;
        test_basics(store)?;
        Ok(())
    }

    fn test_basics<S: store::Store>(store: S) -> Result<()> {
        let mut rng = rand::thread_rng();
        let alice = Author::new(&mut rng);
        let bob = Author::new(&mut rng);
        let myspace = Namespace::new(&mut rng);

        let record_id = RecordIdentifier::new("/my/key", myspace.id(), alice.id());
        let record = Record::from_data(b"this is my cool data", myspace.id());
        let entry = Entry::new(record_id, record);
        let signed_entry = entry.sign(&myspace, &alice);
        signed_entry.verify().expect("failed to verify");

        let my_replica = store.new_replica(myspace)?;
        for i in 0..10 {
            my_replica
                .hash_and_insert(format!("/{i}"), &alice, format!("{i}: hello from alice"))
                .map_err(Into::into)?;
        }

        for i in 0..10 {
            let res = store
                .get_latest_by_key_and_author(my_replica.namespace(), format!("/{i}"), alice.id())?
                .unwrap();
            let len = format!("{i}: hello from alice").as_bytes().len() as u64;
            assert_eq!(res.entry().record().content_len(), len);
            res.verify()?;
        }

        // Test multiple records for the same key
        my_replica
            .hash_and_insert("/cool/path", &alice, "round 1")
            .map_err(Into::into)?;
        let _entry = store
            .get_latest_by_key_and_author(my_replica.namespace(), "/cool/path", alice.id())?
            .unwrap();
        // Second
        my_replica
            .hash_and_insert("/cool/path", &alice, "round 2")
            .map_err(Into::into)?;
        let _entry = store
            .get_latest_by_key_and_author(my_replica.namespace(), "/cool/path", alice.id())?
            .unwrap();

        // Get All by author
        let entries: Vec<_> = store
            .get_all_by_key_and_author(my_replica.namespace(), "/cool/path", alice.id())?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 2);

        // Get All by key
        let entries: Vec<_> = store
            .get_all_by_key(my_replica.namespace(), b"/cool/path")?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 2);

        // Get latest by key
        let entries: Vec<_> = store
            .get_latest_by_key(my_replica.namespace(), b"/cool/path")?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 1);

        // Get latest by prefix
        let entries: Vec<_> = store
            .get_latest_by_prefix(my_replica.namespace(), b"/cool")?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 1);

        // Get All
        let entries: Vec<_> = store
            .get_all(my_replica.namespace())?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 12);

        // Get All latest
        let entries: Vec<_> = store
            .get_latest(my_replica.namespace())?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 11);

        // insert record from different author
        let _entry = my_replica
            .hash_and_insert("/cool/path", &bob, "bob round 1")
            .map_err(Into::into)?;

        // Get All by author
        let entries: Vec<_> = store
            .get_all_by_key_and_author(my_replica.namespace(), "/cool/path", alice.id())?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 2);

        let entries: Vec<_> = store
            .get_all_by_key_and_author(my_replica.namespace(), "/cool/path", bob.id())?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 1);

        // Get All by key
        let entries: Vec<_> = store
            .get_all_by_key(my_replica.namespace(), b"/cool/path")?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 3);

        // Get latest by key
        let entries: Vec<_> = store
            .get_latest_by_key(my_replica.namespace(), b"/cool/path")?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 2);

        // Get latest by prefix
        let entries: Vec<_> = store
            .get_latest_by_prefix(my_replica.namespace(), b"/cool")?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 2);

        // Get all by prefix
        let entries: Vec<_> = store
            .get_all_by_prefix(my_replica.namespace(), b"/cool")?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 3);

        // Get All
        let entries: Vec<_> = store
            .get_all(my_replica.namespace())?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 13);

        // Get All latest
        let entries: Vec<_> = store
            .get_latest(my_replica.namespace())?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 12);

        Ok(())
    }

    #[test]
    fn test_multikey() {
        let mut rng = rand::thread_rng();

        let k = vec!["a", "c", "z"];

        let mut n: Vec<_> = (0..3).map(|_| Namespace::new(&mut rng)).collect();
        n.sort_by_key(|n| n.id());

        let mut a: Vec<_> = (0..3).map(|_| Author::new(&mut rng)).collect();
        a.sort_by_key(|a| a.id());

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
    fn test_replica_sync_memory() -> Result<()> {
        let alice_store = store::memory::Store::default();
        let bob_store = store::memory::Store::default();

        test_replica_sync(alice_store, bob_store)?;
        Ok(())
    }

    #[cfg(feature = "fs-store")]
    #[test]
    fn test_replica_sync_fs() -> Result<()> {
        let alice_dbfile = tempfile::NamedTempFile::new()?;
        let alice_store = store::fs::Store::new(alice_dbfile.path())?;
        let bob_dbfile = tempfile::NamedTempFile::new()?;
        let bob_store = store::fs::Store::new(bob_dbfile.path())?;
        test_replica_sync(alice_store, bob_store)?;

        Ok(())
    }

    fn test_replica_sync<S: store::Store>(alice_store: S, bob_store: S) -> Result<()> {
        let alice_set = ["ape", "eel", "fox", "gnu"];
        let bob_set = ["bee", "cat", "doe", "eel", "fox", "hog"];

        let mut rng = rand::thread_rng();
        let author = Author::new(&mut rng);
        let myspace = Namespace::new(&mut rng);
        let alice = alice_store.new_replica(myspace.clone())?;
        for el in &alice_set {
            alice
                .hash_and_insert(el, &author, el.as_bytes())
                .map_err(Into::into)?;
        }

        let bob = bob_store.new_replica(myspace)?;
        for el in &bob_set {
            bob.hash_and_insert(el, &author, el.as_bytes())
                .map_err(Into::into)?;
        }

        sync(
            &author,
            &alice,
            &alice_store,
            &bob,
            &bob_store,
            &alice_set,
            &bob_set,
        )?;
        Ok(())
    }

    fn sync<S: store::Store>(
        author: &Author,
        alice: &Replica<S::Instance>,
        alice_store: &S,
        bob: &Replica<S::Instance>,
        bob_store: &S,
        alice_set: &[&str],
        bob_set: &[&str],
    ) -> Result<()> {
        // Sync alice - bob
        let mut next_to_bob = Some(alice.sync_initial_message().map_err(Into::into)?);
        let mut rounds = 0;
        while let Some(msg) = next_to_bob.take() {
            assert!(rounds < 100, "too many rounds");
            rounds += 1;
            println!("round {}", rounds);
            if let Some(msg) = bob.sync_process_message(msg).map_err(Into::into)? {
                next_to_bob = alice.sync_process_message(msg).map_err(Into::into)?;
            }
        }

        // Check result
        for el in alice_set {
            alice_store.get_latest_by_key_and_author(alice.namespace(), el, author.id())?;
            bob_store.get_latest_by_key_and_author(bob.namespace(), el, author.id())?;
        }

        for el in bob_set {
            alice_store.get_latest_by_key_and_author(alice.namespace(), el, author.id())?;
            bob_store.get_latest_by_key_and_author(bob.namespace(), el, author.id())?;
        }
        Ok(())
    }
}

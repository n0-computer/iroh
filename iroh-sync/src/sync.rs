//! API for iroh-sync replicas

// Names and concepts are roughly based on Willows design at the moment:
//
// https://hackmd.io/DTtck8QOQm6tZaQBBtTf7w
//
// This is going to change!

use std::{
    cmp::Ordering,
    fmt::Debug,
    sync::Arc,
    time::{Duration, SystemTime},
};

#[cfg(feature = "metrics")]
use crate::metrics::Metrics;
use bytes::{Bytes, BytesMut};
use derive_more::Deref;
#[cfg(feature = "metrics")]
use iroh_metrics::{inc, inc_by};

use parking_lot::RwLock;

use ed25519_dalek::{Signature, SignatureError};
use iroh_bytes::Hash;
use serde::{Deserialize, Serialize};

use crate::{
    ranger::{self, Fingerprint, Peer, RangeEntry, RangeKey},
    store::PublicKeyStore,
};
use crate::{
    ranger::{InsertOutcome, RangeValue},
    store,
};

pub use crate::keys::*;

/// Protocol message for the set reconciliation protocol.
///
/// Can be serialized to bytes with [serde] to transfer between peers.
pub type ProtocolMessage = crate::ranger::Message<SignedEntry>;

/// Byte represenation of a `PeerId` from `iroh-net`.
// TODO: PeerId is in iroh-net which iroh-sync doesn't depend on. Add iroh-common crate with `PeerId`.
pub type PeerIdBytes = [u8; 32];

/// Max time in the future from our wall clock time that we accept entries for.
/// Value is 10 minutes.
pub const MAX_TIMESTAMP_FUTURE_SHIFT: u64 = 10 * 60 * Duration::from_secs(1).as_millis() as u64;

/// Whether an entry was inserted locally or by a remote peer.
#[derive(Debug, Clone)]
pub enum InsertOrigin {
    /// The entry was inserted locally.
    Local,
    /// The entry was received from the remote peer identified by [`PeerIdBytes`].
    Sync {
        /// The peer from which we received this entry.
        from: PeerIdBytes,
        /// Whether the peer claims to have the content blob for this entry.
        content_status: ContentStatus,
    },
}

/// Whether the content status is available on a node.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContentStatus {
    /// The content is completely available.
    Complete,
    /// The content is partially available.
    Incomplete,
    /// The content is missing.
    Missing,
}

/// Local representation of a mutable, synchronizable key-value store.
#[derive(derive_more::Debug, Clone)]
pub struct Replica<S: ranger::Store<SignedEntry> + PublicKeyStore> {
    inner: Arc<RwLock<InnerReplica<S>>>,
    #[allow(clippy::type_complexity)]
    on_insert_sender: Arc<RwLock<Option<flume::Sender<(InsertOrigin, SignedEntry)>>>>,

    #[allow(clippy::type_complexity)]
    #[debug("ContentStatusCallback")]
    content_status_cb:
        Arc<RwLock<Option<Box<dyn Fn(Hash) -> ContentStatus + Send + Sync + 'static>>>>,
}

#[derive(derive_more::Debug)]
struct InnerReplica<S: ranger::Store<SignedEntry> + PublicKeyStore> {
    namespace: Namespace,
    peer: Peer<SignedEntry, S>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReplicaData {
    entries: Vec<SignedEntry>,
    namespace: Namespace,
}

impl<S: ranger::Store<SignedEntry> + PublicKeyStore + 'static> Replica<S> {
    /// Create a new replica.
    // TODO: make read only replicas possible
    pub fn new(namespace: Namespace, store: S) -> Self {
        Replica {
            inner: Arc::new(RwLock::new(InnerReplica {
                namespace,
                peer: Peer::from_store(store),
            })),
            on_insert_sender: Arc::new(RwLock::new(None)),
            content_status_cb: Arc::new(RwLock::new(None)),
        }
    }

    /// Subscribe to insert events.
    ///
    /// Only one subscription can be active at a time. If a previous subscription was created, this
    /// will return `None`.
    ///
    /// When subscribing to a replica, you must ensure that the returned [`flume::Receiver`] is
    /// received from in a loop. If not receiving, local and remote inserts will hang waiting for
    /// the receiver to be received from.
    // TODO: Allow to clear a previous subscription?
    pub fn subscribe(&self) -> Option<flume::Receiver<(InsertOrigin, SignedEntry)>> {
        let mut on_insert_sender = self.on_insert_sender.write();
        match &*on_insert_sender {
            Some(_sender) => None,
            None => {
                let (s, r) = flume::bounded(16); // TODO: should this be configurable?
                *on_insert_sender = Some(s);
                Some(r)
            }
        }
    }

    /// Remove the subscription.
    pub fn unsubscribe(&self) -> bool {
        self.on_insert_sender.write().take().is_some()
    }

    /// Set the content status callback.
    ///
    /// Only one callback can be active at a time. If a previous callback was registered, this
    /// will return `false`.
    pub fn set_content_status_callback(
        &self,
        cb: Box<dyn Fn(Hash) -> ContentStatus + Send + Sync + 'static>,
    ) -> bool {
        let mut content_status_cb = self.content_status_cb.write();
        match &*content_status_cb {
            Some(_cb) => false,
            None => {
                *content_status_cb = Some(cb);
                true
            }
        }
    }

    /// Insert a new record at the given key.
    ///
    /// The entry will by signed by the provided `author`.
    /// The `len` must be the byte length of the data identified by `hash`.
    ///
    /// Returns the number of entries removed as a consequence of this insertion,
    /// or an error either if the entry failed to validate or if a store operation failed.
    pub fn insert(
        &self,
        key: impl AsRef<[u8]>,
        author: &Author,
        hash: Hash,
        len: u64,
    ) -> Result<usize, InsertError<S>> {
        if len == 0 || hash == Hash::EMPTY {
            return Err(InsertError::EntryIsEmpty);
        }
        let id = RecordIdentifier::new(self.namespace(), author.id(), key);
        let record = Record::new_current(hash, len);
        let entry = Entry::new(id, record);
        let signed_entry = entry.sign(&self.inner.read().namespace, author);
        self.insert_entry(signed_entry, InsertOrigin::Local)
    }

    /// Wipe entries that match the given `author` and key `prefix`.
    ///
    /// This inserts an empty entry with the key set to `prefix`, effectively clearing all other
    /// entries whose key starts with or is equal to the given `prefix`.
    ///
    /// Returns the number of entries removed as a consequence of this insertion,
    pub fn wipe_at_prefix(
        &self,
        prefix: impl AsRef<[u8]>,
        author: &Author,
    ) -> Result<usize, InsertError<S>> {
        let id = RecordIdentifier::new(self.namespace(), author.id(), prefix);
        let entry = Entry::new_empty(id);
        let signed_entry = entry.sign(&self.inner.read().namespace, author);
        self.insert_entry(signed_entry, InsertOrigin::Local)
    }

    /// Insert an entry into this replica which was received from a remote peer.
    ///
    /// This will verify both the namespace and author signatures of the entry, emit an `on_insert`
    /// event, and insert the entry into the replica store.
    ///
    /// Returns the number of entries removed as a consequence of this insertion,
    /// or an error if the entry failed to validate or if a store operation failed.
    pub fn insert_remote_entry(
        &self,
        entry: SignedEntry,
        received_from: PeerIdBytes,
        content_status: ContentStatus,
    ) -> Result<usize, InsertError<S>> {
        let origin = InsertOrigin::Sync {
            from: received_from,
            content_status,
        };
        self.insert_entry(entry, origin)
    }

    /// Insert a signed entry into the database.
    ///
    /// Returns the number of entries removed as a consequence of this insertion.
    fn insert_entry(
        &self,
        entry: SignedEntry,
        origin: InsertOrigin,
    ) -> Result<usize, InsertError<S>> {
        let expected_namespace = self.namespace();

        #[cfg(feature = "metrics")]
        let len = entry.content_len();

        let mut inner = self.inner.write();
        let store = inner.peer.store();
        validate_entry(
            system_time_now(),
            store,
            expected_namespace,
            &entry,
            &origin,
        )?;

        let outcome = inner.peer.put(entry.clone()).map_err(InsertError::Store)?;

        let InsertOutcome::Inserted { removed } = outcome else {
            return Err(InsertError::NewerEntryExists);
        };

        drop(inner);

        if let Some(sender) = self.on_insert_sender.read().as_ref() {
            sender.send((origin.clone(), entry)).ok();
        }

        #[cfg(feature = "metrics")]
        {
            match origin {
                InsertOrigin::Local => {
                    inc!(Metrics, new_entries_local);
                    inc_by!(Metrics, new_entries_local_size, len);
                }
                InsertOrigin::Sync { .. } => {
                    inc!(Metrics, new_entries_remote);
                    inc_by!(Metrics, new_entries_remote_size, len);
                }
            }
        }

        Ok(removed)
    }

    /// Hashes the given data and inserts it.
    ///
    /// This does not store the content, just the record of it.
    /// Returns the calculated hash.
    pub fn hash_and_insert(
        &self,
        key: impl AsRef<[u8]>,
        author: &Author,
        data: impl AsRef<[u8]>,
    ) -> anyhow::Result<Hash> {
        let len = data.as_ref().len() as u64;
        let hash = Hash::new(data);
        self.insert(key, author, hash, len)?;
        Ok(hash)
    }

    /// Get the identifier for an entry in this replica.
    pub fn id(&self, key: impl AsRef<[u8]>, author: &Author) -> RecordIdentifier {
        let inner = self.inner.read();
        RecordIdentifier::new(inner.namespace.id(), author.id(), key)
    }

    /// Create the initial message for the set reconciliation flow with a remote peer.
    pub fn sync_initial_message(&self) -> Result<crate::ranger::Message<SignedEntry>, S::Error> {
        self.inner.read().peer.initial_message()
    }

    /// Process a set reconciliation message from a remote peer.
    ///
    /// Returns the next message to be sent to the peer, if any.
    pub fn sync_process_message(
        &self,
        message: crate::ranger::Message<SignedEntry>,
        from_peer: PeerIdBytes,
    ) -> Result<Option<crate::ranger::Message<SignedEntry>>, S::Error> {
        let expected_namespace = self.namespace();
        let now = system_time_now();
        let reply = self.inner.write().peer.process_message(
            message,
            |store, entry, content_status| {
                let origin = InsertOrigin::Sync {
                    from: from_peer,
                    content_status,
                };
                if validate_entry(now, store, expected_namespace, entry, &origin).is_ok() {
                    if let Some(sender) = self.on_insert_sender.read().as_ref() {
                        sender.send((origin, entry.clone())).ok();
                    }
                    true
                } else {
                    false
                }
            },
            |_store, entry| {
                if let Some(cb) = self.content_status_cb.read().as_ref() {
                    cb(entry.content_hash())
                } else {
                    ContentStatus::Missing
                }
            },
        )?;

        Ok(reply)
    }

    /// Get the namespace identifier for this [`Replica`].
    pub fn namespace(&self) -> NamespaceId {
        self.inner.read().namespace.id()
    }

    /// Get the byte represenation of the [`Namespace`] key for this replica.
    // TODO: Why return [u8; 32] and not `Namespace` here?
    pub fn secret_key(&self) -> [u8; 32] {
        self.inner.read().namespace.to_bytes()
    }
}

/// Validate a [`SignedEntry`] if it's fit to be inserted.
///
/// This validates that
/// * the entry's author and namespace signatures are correct
/// * the entry's namespace matches the current replica
/// * the entry's timestamp is not more than 10 minutes in the future of our system time
/// * the entry is newer than an existing entry for the same key and author, if such exists.
fn validate_entry<S: ranger::Store<SignedEntry> + PublicKeyStore>(
    now: u64,
    store: &S,
    expected_namespace: NamespaceId,
    entry: &SignedEntry,
    origin: &InsertOrigin,
) -> Result<(), ValidationFailure> {
    // Verify the namespace
    if entry.namespace() != expected_namespace {
        return Err(ValidationFailure::InvalidNamespace);
    }

    // Verify signature for non-local entries.
    if !matches!(origin, InsertOrigin::Local) && entry.verify(store).is_err() {
        return Err(ValidationFailure::BadSignature);
    }

    // Verify that the timestamp of the entry is not too far in the future.
    if entry.timestamp() > now + MAX_TIMESTAMP_FUTURE_SHIFT {
        return Err(ValidationFailure::TooFarInTheFuture);
    }
    Ok(())
}

/// Error emitted when inserting entries into a [`Replica`] failed
#[derive(thiserror::Error, derive_more::Debug)]
pub enum InsertError<S: ranger::Store<SignedEntry>> {
    /// Storage error
    #[error("storage error")]
    Store(S::Error),
    /// Validation failure
    #[error("validation failure")]
    Validation(#[from] ValidationFailure),
    /// A newer entry exists for either this entry's key or a prefix of the key.
    #[error("A newer entry exists for either this entry's key or a prefix of the key.")]
    NewerEntryExists,
    /// Attempted to insert an empty entry without calling `delete_prefix`.
    #[error("Attempted to insert an empty entry")]
    EntryIsEmpty,
}

/// Reason why entry validation failed
#[derive(thiserror::Error, Debug)]
pub enum ValidationFailure {
    /// Entry namespace does not match the current replica.
    #[error("Entry namespace does not match the current replica")]
    InvalidNamespace,
    /// Entry signature is invalid.
    #[error("Entry signature is invalid")]
    BadSignature,
    /// Entry timestamp is too far in the future.
    #[error("Entry timestamp is too far in the future.")]
    TooFarInTheFuture,
}

/// A signed entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEntry {
    signature: EntrySignature,
    entry: Entry,
}

impl From<SignedEntry> for Entry {
    fn from(value: SignedEntry) -> Self {
        value.entry
    }
}

impl PartialOrd for SignedEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SignedEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.entry.cmp(&other.entry)
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id
            .cmp(&other.id)
            .then_with(|| self.record.cmp(&other.record))
    }
}

impl SignedEntry {
    #[cfg(feature = "fs-store")]
    pub(crate) fn new(signature: EntrySignature, entry: Entry) -> Self {
        SignedEntry { signature, entry }
    }

    /// Create a new signed entry by signing an entry with the `namespace` and `author`.
    pub fn from_entry(entry: Entry, namespace: &Namespace, author: &Author) -> Self {
        let signature = EntrySignature::from_entry(&entry, namespace, author);
        SignedEntry { signature, entry }
    }

    /// Create a new signed entries from its parts.
    pub fn from_parts(
        namespace: &Namespace,
        author: &Author,
        key: impl AsRef<[u8]>,
        record: Record,
    ) -> Self {
        let id = RecordIdentifier::new(namespace.id(), author.id(), key);
        let entry = Entry::new(id, record);
        Self::from_entry(entry, namespace, author)
    }

    /// Verify the signatures on this entry.
    pub fn verify<S: store::PublicKeyStore>(&self, store: &S) -> Result<(), SignatureError> {
        self.signature.verify(
            &self.entry,
            &self.entry.namespace().public_key(store)?,
            &self.entry.author().public_key(store)?,
        )
    }

    /// Get the signature.
    pub fn signature(&self) -> &EntrySignature {
        &self.signature
    }

    /// Get the [`Entry`].
    pub fn entry(&self) -> &Entry {
        &self.entry
    }

    /// Get the content [`struct@Hash`] of the entry.
    pub fn content_hash(&self) -> Hash {
        self.entry().content_hash()
    }

    /// Get the content length of the entry.
    pub fn content_len(&self) -> u64 {
        self.entry().content_len()
    }

    /// Get the author bytes of this entry.
    pub fn author_bytes(&self) -> AuthorId {
        self.entry().id().author()
    }

    /// Get the key of the entry.
    pub fn key(&self) -> &[u8] {
        self.entry().id().key()
    }

    /// Get the timestamp of the entry.
    pub fn timestamp(&self) -> u64 {
        self.entry().timestamp()
    }
}

impl RangeEntry for SignedEntry {
    type Key = RecordIdentifier;
    type Value = Record;

    fn key(&self) -> &Self::Key {
        &self.entry.id
    }

    fn value(&self) -> &Self::Value {
        &self.entry.record
    }

    fn as_fingerprint(&self) -> crate::ranger::Fingerprint {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.namespace().as_ref());
        hasher.update(self.author_bytes().as_ref());
        hasher.update(self.key());
        hasher.update(&self.timestamp().to_be_bytes());
        hasher.update(self.content_hash().as_bytes());
        Fingerprint(hasher.finalize().into())
    }
}

/// Signature over an entry.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntrySignature {
    author_signature: Signature,
    namespace_signature: Signature,
}

impl Debug for EntrySignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntrySignature")
            .field(
                "namespace_signature",
                &base32::fmt(self.namespace_signature.to_bytes()),
            )
            .field(
                "author_signature",
                &base32::fmt(self.author_signature.to_bytes()),
            )
            .finish()
    }
}

impl EntrySignature {
    /// Create a new signature by signing an entry with the `namespace` and `author`.
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

    /// Verify that this signature was created by signing the `entry` with the
    /// secret keys of the specified `author` and `namespace`.
    pub fn verify(
        &self,
        entry: &Entry,
        namespace: &NamespacePublicKey,
        author: &AuthorPublicKey,
    ) -> Result<(), SignatureError> {
        let bytes = entry.to_vec();
        namespace.verify(&bytes, &self.namespace_signature)?;
        author.verify(&bytes, &self.author_signature)?;

        Ok(())
    }

    #[cfg(feature = "fs-store")]
    pub(crate) fn from_parts(namespace_sig: &[u8; 64], author_sig: &[u8; 64]) -> Self {
        let namespace_signature = Signature::from_bytes(namespace_sig);
        let author_signature = Signature::from_bytes(author_sig);

        EntrySignature {
            author_signature,
            namespace_signature,
        }
    }

    #[cfg(feature = "fs-store")]
    pub(crate) fn author_signature(&self) -> &Signature {
        &self.author_signature
    }

    #[cfg(feature = "fs-store")]
    pub(crate) fn namespace_signature(&self) -> &Signature {
        &self.namespace_signature
    }
}

/// A single entry in a [`Replica`]
///
/// An entry is identified by a key, its [`Author`], and the [`Replica`]'s
/// [`Namespace`]. Its value is the [32-byte BLAKE3 hash](iroh_bytes::Hash)
/// of the entry's content data, the size of this content data, and a timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    id: RecordIdentifier,
    record: Record,
}

impl Entry {
    /// Create a new entry
    pub fn new(id: RecordIdentifier, record: Record) -> Self {
        Entry { id, record }
    }

    /// Create a new empty entry with the current timestamp.
    pub fn new_empty(id: RecordIdentifier) -> Self {
        Entry {
            id,
            record: Record::empty_current(),
        }
    }

    /// Get the [`RecordIdentifier`] for this entry.
    pub fn id(&self) -> &RecordIdentifier {
        &self.id
    }

    /// Get the [`NamespaceId`] of this entry.
    pub fn namespace(&self) -> NamespaceId {
        self.id.namespace()
    }

    /// Get the [`AuthorId`] of this entry.
    pub fn author(&self) -> AuthorId {
        self.id.author()
    }

    /// Get the key of this entry.
    pub fn key(&self) -> &[u8] {
        self.id.key()
    }

    /// Get the [`Record`] contained in this entry.
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// Serialize this entry into its canonical byte representation used for signing.
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.id.encode(out);
        self.record.encode(out);
    }

    /// Serialize this entry into a new vector with its canonical byte representation.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// Sign this entry with a [`Namespace`] and [`Author`].
    pub fn sign(self, namespace: &Namespace, author: &Author) -> SignedEntry {
        SignedEntry::from_entry(self, namespace, author)
    }
}

const NAMESPACE_BYTES: std::ops::Range<usize> = 0..32;
const AUTHOR_BYTES: std::ops::Range<usize> = 32..64;
const KEY_BYTES: std::ops::RangeFrom<usize> = 64..;

/// The indentifier of a record.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordIdentifier(Bytes);

impl Default for RecordIdentifier {
    fn default() -> Self {
        Self::new(NamespaceId::default(), AuthorId::default(), b"")
    }
}

impl Debug for RecordIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordIdentifier")
            .field("namespace", &self.namespace())
            .field("author", &self.author())
            .field("key", &std::string::String::from_utf8_lossy(self.key()))
            .finish()
    }
}

impl RangeKey for RecordIdentifier {
    fn is_prefix_of(&self, other: &Self) -> bool {
        self.as_bytes().starts_with(other.as_bytes())
    }
}

fn system_time_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time drift")
        .as_micros() as u64
}

impl RecordIdentifier {
    /// Create a new [`RecordIdentifier`].
    pub fn new(
        namespace: impl Into<NamespaceId>,
        author: impl Into<AuthorId>,
        key: impl AsRef<[u8]>,
    ) -> Self {
        let mut bytes = BytesMut::with_capacity(32 + 32 + key.as_ref().len());
        bytes.extend_from_slice(namespace.into().as_bytes());
        bytes.extend_from_slice(author.into().as_bytes());
        bytes.extend_from_slice(key.as_ref());
        Self(bytes.freeze())
    }

    /// Serialize this [`RecordIdentifier`] into a mutable byte array.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    /// Get this [`RecordIdentifier`] as a byte slices.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get this [`RecordIdentifier`] as a tuple of byte slices.
    pub fn as_byte_tuple(&self) -> (&[u8; 32], &[u8; 32], &[u8]) {
        (
            self.0[NAMESPACE_BYTES].try_into().unwrap(),
            self.0[AUTHOR_BYTES].try_into().unwrap(),
            &self.0[KEY_BYTES],
        )
    }

    /// Get the key of this record.
    pub fn key(&self) -> &[u8] {
        &self.0[KEY_BYTES]
    }

    /// Get the [`NamespaceId`] of this record as byte array.
    pub fn namespace(&self) -> NamespaceId {
        let value: &[u8; 32] = &self.0[NAMESPACE_BYTES].try_into().unwrap();
        value.into()
    }

    /// Get the [`AuthorId`] of this record as byte array.
    pub fn author(&self) -> AuthorId {
        let value: &[u8; 32] = &self.0[AUTHOR_BYTES].try_into().unwrap();
        value.into()
    }
}

impl Deref for SignedEntry {
    type Target = Entry;
    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

impl Deref for Entry {
    type Target = Record;
    fn deref(&self) -> &Self::Target {
        &self.record
    }
}

/// The data part of an entry in a [`Replica`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    /// Length of the data referenced by `hash`.
    len: u64,
    /// Hash of the content data.
    hash: Hash,
    /// Record creation timestamp. Counted as micros since the Unix epoch.
    timestamp: u64,
}

impl RangeValue for Record {}

/// Ordering for entry values.
///
/// Compares first the timestamp, then the content hash.
impl Ord for Record {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.hash.cmp(&other.hash))
    }
}

impl PartialOrd for Record {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Record {
    /// Create a new record.
    pub fn new(hash: Hash, len: u64, timestamp: u64) -> Self {
        debug_assert!(
            len != 0 || hash == Hash::EMPTY,
            "if `len` is 0 then `hash` must be the hash of the empty byte range"
        );
        Record {
            hash,
            len,
            timestamp,
        }
    }

    /// Create a tombstone record (empty content)
    pub fn empty(timestamp: u64) -> Self {
        Self::new(Hash::EMPTY, 0, timestamp)
    }

    /// Create a tombstone record with the timestamp set to now.
    pub fn empty_current() -> Self {
        Self::new_current(Hash::EMPTY, 0)
    }

    /// Return `true` if the entry is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.hash == Hash::EMPTY
    }

    /// Create a new [`Record`] with the timestamp set to now.
    pub fn new_current(hash: Hash, len: u64) -> Self {
        let timestamp = system_time_now();
        Self::new(hash, len, timestamp)
    }

    /// Get the length of the data addressed by this record's content hash.
    pub fn content_len(&self) -> u64 {
        self.len
    }

    /// Get the [`struct@Hash`] of the content data of this record.
    pub fn content_hash(&self) -> Hash {
        self.hash
    }

    /// Get the timestamp of this record.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    #[cfg(test)]
    pub(crate) fn current_from_data(data: impl AsRef<[u8]>) -> Self {
        let len = data.as_ref().len() as u64;
        let hash = Hash::new(data);
        Self::new_current(hash, len)
    }

    #[cfg(test)]
    pub(crate) fn from_data(data: impl AsRef<[u8]>, timestamp: u64) -> Self {
        let len = data.as_ref().len() as u64;
        let hash = Hash::new(data);
        Self::new(hash, len, timestamp)
    }

    /// Serialize this record into a mutable byte array.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.len.to_be_bytes());
        out.extend_from_slice(self.hash.as_ref());
        out.extend_from_slice(&self.timestamp.to_be_bytes())
    }
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "fs-store")]
    use std::collections::HashSet;

    use anyhow::Result;
    use rand_core::SeedableRng;

    use crate::{
        ranger::{Range, Store as _},
        store::{self, GetFilter, Store},
    };

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

        let record_id = RecordIdentifier::new(myspace.id(), alice.id(), "/my/key");
        let record = Record::current_from_data(b"this is my cool data");
        let entry = Entry::new(record_id, record);
        let signed_entry = entry.sign(&myspace, &alice);
        signed_entry.verify(&()).expect("failed to verify");

        let my_replica = store.new_replica(myspace)?;
        for i in 0..10 {
            my_replica.hash_and_insert(
                format!("/{i}"),
                &alice,
                format!("{i}: hello from alice"),
            )?;
        }

        for i in 0..10 {
            let res = store
                .get_one(my_replica.namespace(), alice.id(), format!("/{i}"))?
                .unwrap();
            let len = format!("{i}: hello from alice").as_bytes().len() as u64;
            assert_eq!(res.entry().record().content_len(), len);
            res.verify(&())?;
        }

        // Test multiple records for the same key
        my_replica.hash_and_insert("/cool/path", &alice, "round 1")?;
        let _entry = store
            .get_one(my_replica.namespace(), alice.id(), "/cool/path")?
            .unwrap();
        // Second
        my_replica.hash_and_insert("/cool/path", &alice, "round 2")?;
        let _entry = store
            .get_one(my_replica.namespace(), alice.id(), "/cool/path")?
            .unwrap();

        // Get All by author
        let entries: Vec<_> = store
            .get_many(my_replica.namespace(), GetFilter::Author(alice.id()))?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 11);

        // Get All by author
        let entries: Vec<_> = store
            .get_many(my_replica.namespace(), GetFilter::Author(bob.id()))?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 0);

        // Get All by key
        let entries: Vec<_> = store
            .get_many(
                my_replica.namespace(),
                GetFilter::Key(b"/cool/path".to_vec()),
            )?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 1);

        // Get All
        let entries: Vec<_> = store
            .get_many(my_replica.namespace(), GetFilter::All)?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 11);

        // insert record from different author
        let _entry = my_replica.hash_and_insert("/cool/path", &bob, "bob round 1")?;

        // Get All by author
        let entries: Vec<_> = store
            .get_many(my_replica.namespace(), GetFilter::Author(alice.id()))?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 11);

        let entries: Vec<_> = store
            .get_many(my_replica.namespace(), GetFilter::Author(bob.id()))?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 1);

        // Get All by key
        let entries: Vec<_> = store
            .get_many(
                my_replica.namespace(),
                GetFilter::Key(b"/cool/path".to_vec()),
            )?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 2);

        // Get all by prefix
        let entries: Vec<_> = store
            .get_many(my_replica.namespace(), GetFilter::Prefix(b"/cool".to_vec()))?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 2);

        // Get All by author and prefix
        let entries: Vec<_> = store
            .get_many(
                my_replica.namespace(),
                GetFilter::AuthorAndPrefix(alice.id(), b"/cool".to_vec()),
            )?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 1);

        let entries: Vec<_> = store
            .get_many(
                my_replica.namespace(),
                GetFilter::AuthorAndPrefix(bob.id(), b"/cool".to_vec()),
            )?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 1);

        // Get All
        let entries: Vec<_> = store
            .get_many(my_replica.namespace(), GetFilter::All)?
            .collect::<Result<_>>()?;
        assert_eq!(entries.len(), 12);

        let replica = store.open_replica(&my_replica.namespace())?.unwrap();
        // Get Range of all should return all latest
        let entries_second: Vec<_> = replica
            .inner
            .read()
            .peer
            .store()
            .get_range(Range::new(
                RecordIdentifier::default(),
                RecordIdentifier::default(),
            ))
            .map_err(Into::into)?
            .collect::<Result<_, _>>()
            .map_err(Into::into)?;

        assert_eq!(entries_second.len(), 12);
        assert_eq!(entries, entries_second.into_iter().collect::<Vec<_>>());

        Ok(())
    }

    #[test]
    fn test_content_hashes_iterator_memory() -> Result<()> {
        let store = store::memory::Store::default();
        test_basics(store)
    }

    #[cfg(feature = "fs-store")]
    #[test]
    fn test_content_hashes_iterator_fs() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let store = store::fs::Store::new(dbfile.path())?;
        test_content_hashes_iterator(store)
    }

    #[cfg(feature = "fs-store")]
    fn test_content_hashes_iterator<S: store::Store>(store: S) -> Result<()> {
        let mut rng = rand::thread_rng();
        let mut expected = HashSet::new();
        let n_replicas = 3;
        let n_entries = 4;
        for i in 0..n_replicas {
            let namespace = Namespace::new(&mut rng);
            let author = store.new_author(&mut rng)?;
            let replica = store.new_replica(namespace)?;
            for j in 0..n_entries {
                let key = format!("{j}");
                let data = format!("{i}:{j}");
                let hash = replica.hash_and_insert(key, &author, data)?;
                expected.insert(hash);
            }
        }
        assert_eq!(expected.len(), n_replicas * n_entries);
        let actual = store.content_hashes()?.collect::<Result<HashSet<Hash>>>()?;
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn test_multikey() {
        let mut rng = rand::thread_rng();

        let k = ["a", "c", "z"];

        let mut n: Vec<_> = (0..3).map(|_| Namespace::new(&mut rng)).collect();
        n.sort_by_key(|n| n.id());

        let mut a: Vec<_> = (0..3).map(|_| Author::new(&mut rng)).collect();
        a.sort_by_key(|a| a.id());

        // Just key
        {
            let ri0 = RecordIdentifier::new(n[0].id(), a[0].id(), k[0]);
            let ri1 = RecordIdentifier::new(n[0].id(), a[0].id(), k[1]);
            let ri2 = RecordIdentifier::new(n[0].id(), a[0].id(), k[2]);

            let range = Range::new(ri0.clone(), ri2.clone());
            assert!(range.contains(&ri0), "start");
            assert!(range.contains(&ri1), "inside");
            assert!(!range.contains(&ri2), "end");

            assert!(ri0 < ri1);
            assert!(ri1 < ri2);
        }

        // Just namespace
        {
            let ri0 = RecordIdentifier::new(n[0].id(), a[0].id(), k[0]);
            let ri1 = RecordIdentifier::new(n[1].id(), a[0].id(), k[1]);
            let ri2 = RecordIdentifier::new(n[2].id(), a[0].id(), k[2]);

            let range = Range::new(ri0.clone(), ri2.clone());
            assert!(range.contains(&ri0), "start");
            assert!(range.contains(&ri1), "inside");
            assert!(!range.contains(&ri2), "end");

            assert!(ri0 < ri1);
            assert!(ri1 < ri2);
        }

        // Just author
        {
            let ri0 = RecordIdentifier::new(n[0].id(), a[0].id(), k[0]);
            let ri1 = RecordIdentifier::new(n[0].id(), a[1].id(), k[0]);
            let ri2 = RecordIdentifier::new(n[0].id(), a[2].id(), k[0]);

            let range = Range::new(ri0.clone(), ri2.clone());
            assert!(range.contains(&ri0), "start");
            assert!(range.contains(&ri1), "inside");
            assert!(!range.contains(&ri2), "end");

            assert!(ri0 < ri1);
            assert!(ri1 < ri2);
        }

        // Just key and namespace
        {
            let ri0 = RecordIdentifier::new(n[0].id(), a[0].id(), k[0]);
            let ri1 = RecordIdentifier::new(n[1].id(), a[0].id(), k[1]);
            let ri2 = RecordIdentifier::new(n[2].id(), a[0].id(), k[2]);

            let range = Range::new(ri0.clone(), ri2.clone());
            assert!(range.contains(&ri0), "start");
            assert!(range.contains(&ri1), "inside");
            assert!(!range.contains(&ri2), "end");

            assert!(ri0 < ri1);
            assert!(ri1 < ri2);
        }

        // Mixed
        {
            // Ord should prioritize namespace - author - key

            let a0 = a[0].id();
            let a1 = a[1].id();
            let n0 = n[0].id();
            let n1 = n[1].id();
            let k0 = k[0];
            let k1 = k[1];

            assert!(RecordIdentifier::new(n0, a0, k0) < RecordIdentifier::new(n1, a1, k1));
            assert!(RecordIdentifier::new(n0, a0, k1) < RecordIdentifier::new(n1, a0, k0));
            assert!(RecordIdentifier::new(n0, a1, k0) < RecordIdentifier::new(n0, a1, k1));
            assert!(RecordIdentifier::new(n1, a1, k0) < RecordIdentifier::new(n1, a1, k1));
        }
    }

    #[test]
    fn test_timestamps_memory() -> Result<()> {
        let store = store::memory::Store::default();
        test_timestamps(store)?;

        Ok(())
    }

    #[cfg(feature = "fs-store")]
    #[test]
    fn test_timestamps_fs() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let store = store::fs::Store::new(dbfile.path())?;
        test_timestamps(store)?;
        Ok(())
    }

    fn test_timestamps<S: store::Store>(store: S) -> Result<()> {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let namespace = Namespace::new(&mut rng);
        let replica = store.new_replica(namespace.clone())?;
        let author = store.new_author(&mut rng)?;

        let key = b"hello";
        let value = b"world";
        let entry = {
            let timestamp = 2;
            let id = RecordIdentifier::new(namespace.id(), author.id(), key);
            let record = Record::from_data(value, timestamp);
            Entry::new(id, record).sign(&namespace, &author)
        };

        replica
            .insert_entry(entry.clone(), InsertOrigin::Local)
            .unwrap();
        let res = store.get_one(namespace.id(), author.id(), key)?.unwrap();
        assert_eq!(res, entry);

        let entry2 = {
            let timestamp = 1;
            let id = RecordIdentifier::new(namespace.id(), author.id(), key);
            let record = Record::from_data(value, timestamp);
            Entry::new(id, record).sign(&namespace, &author)
        };

        let res = replica.insert_entry(entry2, InsertOrigin::Local);
        assert!(matches!(res, Err(InsertError::NewerEntryExists)));
        let res = store.get_one(namespace.id(), author.id(), key)?.unwrap();
        assert_eq!(res, entry);

        Ok(())
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
            alice.hash_and_insert(el, &author, el.as_bytes())?;
        }

        let bob = bob_store.new_replica(myspace.clone())?;
        for el in &bob_set {
            bob.hash_and_insert(el, &author, el.as_bytes())?;
        }

        sync::<S>(&alice, &bob)?;

        check_entries(&alice_store, &myspace.id(), &author, &alice_set)?;
        check_entries(&alice_store, &myspace.id(), &author, &bob_set)?;
        check_entries(&bob_store, &myspace.id(), &author, &alice_set)?;
        check_entries(&bob_store, &myspace.id(), &author, &bob_set)?;

        Ok(())
    }

    #[test]
    fn test_replica_timestamp_sync_memory() -> Result<()> {
        let alice_store = store::memory::Store::default();
        let bob_store = store::memory::Store::default();

        test_replica_timestamp_sync(alice_store, bob_store)?;
        Ok(())
    }

    #[cfg(feature = "fs-store")]
    #[test]
    fn test_replica_timestamp_sync_fs() -> Result<()> {
        let alice_dbfile = tempfile::NamedTempFile::new()?;
        let alice_store = store::fs::Store::new(alice_dbfile.path())?;
        let bob_dbfile = tempfile::NamedTempFile::new()?;
        let bob_store = store::fs::Store::new(bob_dbfile.path())?;
        test_replica_timestamp_sync(alice_store, bob_store)?;

        Ok(())
    }

    fn test_replica_timestamp_sync<S: store::Store>(alice_store: S, bob_store: S) -> Result<()> {
        let mut rng = rand::thread_rng();
        let author = Author::new(&mut rng);
        let namespace = Namespace::new(&mut rng);
        let alice = alice_store.new_replica(namespace.clone())?;
        let bob = bob_store.new_replica(namespace.clone())?;

        let key = b"key";
        let alice_value = b"alice";
        let bob_value = b"bob";
        let _alice_hash = alice.hash_and_insert(key, &author, alice_value)?;
        // system time increased - sync should overwrite
        let bob_hash = bob.hash_and_insert(key, &author, bob_value)?;
        sync::<S>(&alice, &bob)?;
        assert_eq!(
            get_content_hash(&alice_store, namespace.id(), author.id(), key)?,
            Some(bob_hash)
        );
        assert_eq!(
            get_content_hash(&alice_store, namespace.id(), author.id(), key)?,
            Some(bob_hash)
        );

        let alice_value_2 = b"alice2";
        // system time increased - sync should overwrite
        let _bob_hash_2 = bob.hash_and_insert(key, &author, bob_value)?;
        let alice_hash_2 = alice.hash_and_insert(key, &author, alice_value_2)?;
        sync::<S>(&alice, &bob)?;
        assert_eq!(
            get_content_hash(&alice_store, namespace.id(), author.id(), key)?,
            Some(alice_hash_2)
        );
        assert_eq!(
            get_content_hash(&alice_store, namespace.id(), author.id(), key)?,
            Some(alice_hash_2)
        );

        Ok(())
    }

    #[test]
    fn test_future_timestamp() -> Result<()> {
        let mut rng = rand::thread_rng();
        let store = store::memory::Store::default();
        let author = Author::new(&mut rng);
        let namespace = Namespace::new(&mut rng);
        let replica = store.new_replica(namespace.clone())?;

        let key = b"hi";
        let t = system_time_now();
        let record = Record::from_data(b"1", t);
        let entry0 = SignedEntry::from_parts(&namespace, &author, key, record);
        replica.insert_entry(entry0.clone(), InsertOrigin::Local)?;

        assert_eq!(get_entry(&store, namespace.id(), author.id(), key)?, entry0);

        let t = system_time_now() + MAX_TIMESTAMP_FUTURE_SHIFT - 10000;
        let record = Record::from_data(b"2", t);
        let entry1 = SignedEntry::from_parts(&namespace, &author, key, record);
        replica.insert_entry(entry1.clone(), InsertOrigin::Local)?;
        assert_eq!(get_entry(&store, namespace.id(), author.id(), key)?, entry1);

        let t = system_time_now() + MAX_TIMESTAMP_FUTURE_SHIFT;
        let record = Record::from_data(b"2", t);
        let entry2 = SignedEntry::from_parts(&namespace, &author, key, record);
        replica.insert_entry(entry2.clone(), InsertOrigin::Local)?;
        assert_eq!(get_entry(&store, namespace.id(), author.id(), key)?, entry2);

        let t = system_time_now() + MAX_TIMESTAMP_FUTURE_SHIFT + 10000;
        let record = Record::from_data(b"2", t);
        let entry3 = SignedEntry::from_parts(&namespace, &author, key, record);
        let res = replica.insert_entry(entry3, InsertOrigin::Local);
        assert!(matches!(
            res,
            Err(InsertError::Validation(
                ValidationFailure::TooFarInTheFuture
            ))
        ));
        assert_eq!(get_entry(&store, namespace.id(), author.id(), key)?, entry2);

        Ok(())
    }

    #[test]
    fn test_prefix_delete_memory() -> Result<()> {
        let store = store::memory::Store::default();
        test_prefix_delete(store)?;

        Ok(())
    }

    #[cfg(feature = "fs-store")]
    #[test]
    fn test_prefix_delete_fs() -> Result<()> {
        let dbfile = tempfile::NamedTempFile::new()?;
        let store = store::fs::Store::new(dbfile.path())?;
        test_prefix_delete(store)?;
        Ok(())
    }

    fn test_prefix_delete<S: store::Store>(store: S) -> Result<()> {
        let mut rng = rand::thread_rng();
        let alice = Author::new(&mut rng);
        let myspace = Namespace::new(&mut rng);
        let replica = store.new_replica(myspace.clone())?;
        let hash1 = replica.hash_and_insert(b"foobar", &alice, b"hello")?;
        let hash2 = replica.hash_and_insert(b"fooboo", &alice, b"world")?;

        // sanity checks
        assert_eq!(
            get_content_hash(&store, myspace.id(), alice.id(), b"foobar")?,
            Some(hash1)
        );
        assert_eq!(
            get_content_hash(&store, myspace.id(), alice.id(), b"fooboo")?,
            Some(hash2)
        );

        // delete
        let deleted = replica.wipe_at_prefix(b"foo", &alice)?;
        assert_eq!(deleted, 2);
        assert_eq!(store.get_one(myspace.id(), alice.id(), b"foobar")?, None);
        assert_eq!(store.get_one(myspace.id(), alice.id(), b"fooboo")?, None);
        assert_eq!(store.get_one(myspace.id(), alice.id(), b"foo")?, None);

        Ok(())
    }

    fn get_entry<S: store::Store>(
        store: &S,
        namespace: NamespaceId,
        author: AuthorId,
        key: &[u8],
    ) -> anyhow::Result<SignedEntry> {
        let entry = store
            .get_one(namespace, author, key)?
            .ok_or_else(|| anyhow::anyhow!("not found"))?;
        Ok(entry)
    }

    fn get_content_hash<S: store::Store>(
        store: &S,
        namespace: NamespaceId,
        author: AuthorId,
        key: &[u8],
    ) -> anyhow::Result<Option<Hash>> {
        let hash = store
            .get_one(namespace, author, key)?
            .map(|e| e.content_hash());
        Ok(hash)
    }

    fn sync<S: store::Store>(
        alice: &Replica<S::Instance>,
        bob: &Replica<S::Instance>,
    ) -> Result<()> {
        let alice_peer_id = [1u8; 32];
        let bob_peer_id = [2u8; 32];
        // Sync alice - bob
        let mut next_to_bob = Some(alice.sync_initial_message().map_err(Into::into)?);
        let mut rounds = 0;
        while let Some(msg) = next_to_bob.take() {
            assert!(rounds < 100, "too many rounds");
            rounds += 1;
            println!("round {}", rounds);
            if let Some(msg) = bob
                .sync_process_message(msg, alice_peer_id)
                .map_err(Into::into)?
            {
                next_to_bob = alice
                    .sync_process_message(msg, bob_peer_id)
                    .map_err(Into::into)?;
            }
        }
        Ok(())
    }

    fn check_entries<S: store::Store>(
        store: &S,
        namespace: &NamespaceId,
        author: &Author,
        set: &[&str],
    ) -> Result<()> {
        let replica = store.open_replica(namespace)?.unwrap();
        for el in set {
            store.get_one(replica.namespace(), author.id(), el)?;
        }
        Ok(())
    }
}

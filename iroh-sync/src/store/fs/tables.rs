#![allow(missing_docs)]
// Table Definitions

use std::time::Instant;

use bytes::Bytes;
use redb::{
    MultimapTable, MultimapTableDefinition, ReadOnlyMultimapTable, ReadOnlyTable, ReadTransaction,
    ReadableTable, Table, TableDefinition, WriteTransaction,
};

use crate::PeerIdBytes;

/// Table: Authors
/// Key:   `[u8; 32]` # AuthorId
/// Value: `[u8; 32]` # Author
pub const AUTHORS_TABLE: TableDefinition<&[u8; 32], &[u8; 32]> = TableDefinition::new("authors-1");

/// Table: Namespaces v1 (replaced by Namespaces v2 in migration )
/// Key:   `[u8; 32]` # NamespaceId
/// Value: `[u8; 32]` # NamespaceSecret
pub const NAMESPACES_TABLE_V1: TableDefinition<&[u8; 32], &[u8; 32]> =
    TableDefinition::new("namespaces-1");

/// Table: Namespaces v2
/// Key:   `[u8; 32]`       # NamespaceId
/// Value: `(u8, [u8; 32])` # (CapabilityKind, Capability)
pub const NAMESPACES_TABLE: TableDefinition<&[u8; 32], (u8, &[u8; 32])> =
    TableDefinition::new("namespaces-2");

/// Table: Records
/// Key:   `([u8; 32], [u8; 32], &[u8])`
///      # (NamespaceId, AuthorId, Key)
/// Value: `(u64, [u8; 32], [u8; 32], u64, [u8; 32])`
///      # (timestamp, signature_namespace, signature_author, len, hash)
pub const RECORDS_TABLE: TableDefinition<RecordsId, RecordsValue> =
    TableDefinition::new("records-1");
pub type RecordsId<'a> = (&'a [u8; 32], &'a [u8; 32], &'a [u8]);
pub type RecordsIdOwned = ([u8; 32], [u8; 32], Bytes);
pub type RecordsValue<'a> = (u64, &'a [u8; 64], &'a [u8; 64], u64, &'a [u8; 32]);
pub type RecordsTable = ReadOnlyTable<RecordsId<'static>, RecordsValue<'static>>;

/// Table: Latest per author
/// Key:   `([u8; 32], [u8; 32])`    # (NamespaceId, AuthorId)
/// Value: `(u64, Vec<u8>)`          # (Timestamp, Key)
pub const LATEST_PER_AUTHOR_TABLE: TableDefinition<LatestPerAuthorKey, LatestPerAuthorValue> =
    TableDefinition::new("latest-by-author-1");
pub type LatestPerAuthorKey<'a> = (&'a [u8; 32], &'a [u8; 32]);
pub type LatestPerAuthorValue<'a> = (u64, &'a [u8]);

/// Table: Records by key
/// Key:   `([u8; 32], Vec<u8>, [u8; 32]])` # (NamespaceId, Key, AuthorId)
/// Value: `()`
pub const RECORDS_BY_KEY_TABLE: TableDefinition<RecordsByKeyId, ()> =
    TableDefinition::new("records-by-key-1");
pub type RecordsByKeyId<'a> = (&'a [u8; 32], &'a [u8], &'a [u8; 32]);
pub type RecordsByKeyIdOwned = ([u8; 32], Bytes, [u8; 32]);

/// Table: Peers per document.
/// Key:   `[u8; 32]`        # NamespaceId
/// Value: `(u64, [u8; 32])` # ([`Nanos`], &[`PeerIdBytes`]) representing the last time a peer was used.
pub const NAMESPACE_PEERS_TABLE: MultimapTableDefinition<&[u8; 32], (Nanos, &PeerIdBytes)> =
    MultimapTableDefinition::new("sync-peers-1");
/// Number of seconds elapsed since [`std::time::SystemTime::UNIX_EPOCH`]. Used to register the
/// last time a peer was useful in a document.
// NOTE: resolution is nanoseconds, stored as a u64 since this covers ~500years from unix epoch,
// which should be more than enough
pub type Nanos = u64;

/// Table: Download policy
/// Key:   `[u8; 32]`        # NamespaceId
/// Value: `Vec<u8>`         # Postcard encoded download policy
pub const DOWNLOAD_POLICY_TABLE: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("download-policy-1");

pub trait ReadableTables {
    fn records(&self) -> impl ReadableTable<RecordsId<'static>, RecordsValue<'static>>;
    fn records_by_key(&self) -> impl ReadableTable<RecordsByKeyId<'static>, ()>;
    fn namespaces(&self) -> impl ReadableTable<&'static [u8; 32], (u8, &'static [u8; 32])>;
    fn latest_per_author(
        &self,
    ) -> impl ReadableTable<LatestPerAuthorKey<'static>, LatestPerAuthorValue<'static>>;
    // fn namespace_peers(
    //     &self,
    // ) -> impl ReadableMultimapTable<&'static [u8; 32], (Nanos, &'static PeerIdBytes)>;
    fn download_policy(&self) -> impl ReadableTable<&'static [u8; 32], &'static [u8]>;
    fn authors(&self) -> impl ReadableTable<&'static [u8; 32], &'static [u8; 32]>;
}

self_cell::self_cell! {
    struct TransactionAndTablesInner {
        owner: WriteTransaction,
        #[covariant]
        dependent: Tables,
    }
}

#[derive(derive_more::Debug)]
pub struct TransactionAndTables {
    #[debug("TransactionAndTablesInner")]
    inner: TransactionAndTablesInner,
    pub(crate) since: Instant,
}

impl TransactionAndTables {
    pub fn new(tx: WriteTransaction) -> std::result::Result<Self, redb::TableError> {
        Ok(Self {
            inner: TransactionAndTablesInner::try_new(tx, |tx| Tables::new(tx))?,
            since: Instant::now(),
        })
    }

    pub fn tables(&self) -> &Tables {
        self.inner.borrow_dependent()
    }

    pub fn with_tables_mut<T>(
        &mut self,
        f: impl FnOnce(&mut Tables) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.inner.with_dependent_mut(|_, t| f(t))
    }

    pub fn commit(self) -> std::result::Result<(), redb::CommitError> {
        self.inner.into_owner().commit()
    }
}

#[derive(derive_more::Debug)]
pub struct Tables<'tx> {
    pub records: Table<'tx, RecordsId<'static>, RecordsValue<'static>>,
    pub records_by_key: Table<'tx, RecordsByKeyId<'static>, ()>,
    pub namespaces: Table<'tx, &'static [u8; 32], (u8, &'static [u8; 32])>,
    pub latest_per_author: Table<'tx, LatestPerAuthorKey<'static>, LatestPerAuthorValue<'static>>,
    pub namespace_peers: MultimapTable<'tx, &'static [u8; 32], (Nanos, &'static PeerIdBytes)>,
    pub download_policy: Table<'tx, &'static [u8; 32], &'static [u8]>,
    pub authors: Table<'tx, &'static [u8; 32], &'static [u8; 32]>,
}

impl<'tx> Tables<'tx> {
    pub fn new(tx: &'tx WriteTransaction) -> Result<Self, redb::TableError> {
        let records = tx.open_table(RECORDS_TABLE)?;
        let records_by_key = tx.open_table(RECORDS_BY_KEY_TABLE)?;
        let namespaces = tx.open_table(NAMESPACES_TABLE)?;
        let latest_per_author = tx.open_table(LATEST_PER_AUTHOR_TABLE)?;
        let namespace_peers = tx.open_multimap_table(NAMESPACE_PEERS_TABLE)?;
        let download_policy = tx.open_table(DOWNLOAD_POLICY_TABLE)?;
        let authors = tx.open_table(AUTHORS_TABLE)?;
        Ok(Self {
            records,
            records_by_key,
            namespaces,
            latest_per_author,
            namespace_peers,
            download_policy,
            authors,
        })
    }
}
#[derive(derive_more::Debug)]
pub struct ReadOnlyTables {
    pub records: ReadOnlyTable<RecordsId<'static>, RecordsValue<'static>>,
    pub records_by_key: ReadOnlyTable<RecordsByKeyId<'static>, ()>,
    pub namespaces: ReadOnlyTable<&'static [u8; 32], (u8, &'static [u8; 32])>,
    pub latest_per_author:
        ReadOnlyTable<LatestPerAuthorKey<'static>, LatestPerAuthorValue<'static>>,
    #[debug("namespace_peers")]
    pub namespace_peers: ReadOnlyMultimapTable<&'static [u8; 32], (Nanos, &'static PeerIdBytes)>,
    pub download_policy: ReadOnlyTable<&'static [u8; 32], &'static [u8]>,
    pub authors: ReadOnlyTable<&'static [u8; 32], &'static [u8; 32]>,
    tx: ReadTransaction,
}

impl ReadOnlyTables {
    pub fn new(tx: ReadTransaction) -> Result<Self, redb::TableError> {
        let records = tx.open_table(RECORDS_TABLE)?;
        let records_by_key = tx.open_table(RECORDS_BY_KEY_TABLE)?;
        let namespaces = tx.open_table(NAMESPACES_TABLE)?;
        let latest_per_author = tx.open_table(LATEST_PER_AUTHOR_TABLE)?;
        let namespace_peers = tx.open_multimap_table(NAMESPACE_PEERS_TABLE)?;
        let download_policy = tx.open_table(DOWNLOAD_POLICY_TABLE)?;
        let authors = tx.open_table(AUTHORS_TABLE)?;
        Ok(Self {
            records,
            records_by_key,
            namespaces,
            latest_per_author,
            namespace_peers,
            download_policy,
            authors,
            tx,
        })
    }

    /// Create a clone of the records table for use in iterators.
    pub fn records_clone(&self) -> Result<RecordsTable, redb::TableError> {
        self.tx.open_table(RECORDS_TABLE)
    }
}

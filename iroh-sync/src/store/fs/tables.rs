#![allow(missing_docs)]
// Table Definitions

use bytes::Bytes;
use redb::{MultimapTableDefinition, ReadOnlyTable, TableDefinition};

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
pub type RecordsTable<'a> = ReadOnlyTable<RecordsId<'static>, RecordsValue<'static>>;

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

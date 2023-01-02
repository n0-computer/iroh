use bytecheck::CheckBytes;
use redb::TableDefinition;
use rkyv::{with::AsBox, Archive, Deserialize, Serialize};

/// Column family to store actual data.
/// - Maps id (u64) to bytes
pub const CF_BLOBS_V0: TableDefinition<u64, &[u8]> = TableDefinition::new("blobs-v0");
/// Column family that stores metdata about a given blob.
/// - indexed by id (u64)
pub const CF_METADATA_V0: TableDefinition<u64, &[u8]> = TableDefinition::new("metadata-v0");
/// Column familty that stores the graph for a blob
/// - indexed by id (u64)
pub const CF_GRAPH_V0: TableDefinition<u64, &[u8]> = TableDefinition::new("graph-v0");
/// Column family that stores the mapping (multihash, code) to id.
///
/// By storing multihash first we can search for ids either by cid = (multihash, code) or by multihash.
pub const CF_ID_V0: TableDefinition<&[u8], u64> = TableDefinition::new("id-v0");

// This wrapper type serializes the contained value out-of-line so that newer
// versions can be viewed as the older version.
#[derive(Debug, Archive, Deserialize, Serialize)]
#[repr(transparent)]
#[archive_attr(repr(transparent), derive(CheckBytes))]
pub struct Versioned<T>(#[with(AsBox)] pub T);

#[derive(Debug, Archive, Deserialize, Serialize)]
#[repr(C)]
#[archive_attr(repr(C), derive(CheckBytes))]
pub struct MetadataV0 {
    /// The codec of the original CID.
    pub codec: u64,
    #[with(rkyv::with::CopyOptimize)]
    pub multihash: Box<[u8]>,
}

#[derive(Debug, Archive, Deserialize, Serialize)]
#[repr(C)]
#[archive_attr(repr(C), derive(CheckBytes))]
pub struct GraphV0 {
    #[with(rkyv::with::CopyOptimize)]
    pub children: Box<[u64]>,
}

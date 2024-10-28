use std::path::PathBuf;

use bytes::Bytes;
use iroh_base::hash::Hash;
use iroh_blobs::{
    export::ExportProgress,
    format::collection::Collection,
    get::db::DownloadProgress,
    net_protocol::{BatchId, BlobDownloadRequest},
    provider::{AddProgress, BatchAddPathProgress},
    store::{
        BaoBlobSize, ConsistencyCheckProgress, ExportFormat, ExportMode, ImportMode,
        ValidateProgress,
    },
    util::SetTagOption,
    BlobFormat, HashAndFormat, Tag,
};
use nested_enum_utils::enum_conversions;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use super::RpcService;
use crate::{
    client::blobs::{BlobInfo, BlobStatus, IncompleteBlobInfo, ReadAtLen, WrapOption},
    node::{RpcError, RpcResult},
};

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[server_streaming(response = RpcResult<ReadAtResponse>)]
    ReadAt(ReadAtRequest),
    #[bidi_streaming(update = AddStreamUpdate, response = AddStreamResponse)]
    AddStream(AddStreamRequest),
    AddStreamUpdate(AddStreamUpdate),
    #[server_streaming(response = AddPathResponse)]
    AddPath(AddPathRequest),
    #[server_streaming(response = DownloadResponse)]
    Download(BlobDownloadRequest),
    #[server_streaming(response = ExportResponse)]
    Export(ExportRequest),
    #[server_streaming(response = RpcResult<BlobInfo>)]
    List(ListRequest),
    #[server_streaming(response = RpcResult<IncompleteBlobInfo>)]
    ListIncomplete(ListIncompleteRequest),
    #[rpc(response = RpcResult<()>)]
    Delete(DeleteRequest),
    #[server_streaming(response = ValidateProgress)]
    Validate(ValidateRequest),
    #[server_streaming(response = ConsistencyCheckProgress)]
    Fsck(ConsistencyCheckRequest),
    #[rpc(response = RpcResult<CreateCollectionResponse>)]
    CreateCollection(CreateCollectionRequest),
    #[rpc(response = RpcResult<BlobStatusResponse>)]
    BlobStatus(BlobStatusRequest),

    #[bidi_streaming(update = BatchUpdate, response = BatchCreateResponse)]
    BatchCreate(BatchCreateRequest),
    BatchUpdate(BatchUpdate),
    #[bidi_streaming(update = BatchAddStreamUpdate, response = BatchAddStreamResponse)]
    BatchAddStream(BatchAddStreamRequest),
    BatchAddStreamUpdate(BatchAddStreamUpdate),
    #[server_streaming(response = BatchAddPathResponse)]
    BatchAddPath(BatchAddPathRequest),
    #[rpc(response = RpcResult<()>)]
    BatchCreateTempTag(BatchCreateTempTagRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Response)]
pub enum Response {
    ReadAt(RpcResult<ReadAtResponse>),
    AddStream(AddStreamResponse),
    AddPath(AddPathResponse),
    List(RpcResult<BlobInfo>),
    ListIncomplete(RpcResult<IncompleteBlobInfo>),
    Download(DownloadResponse),
    Fsck(ConsistencyCheckProgress),
    Export(ExportResponse),
    Validate(ValidateProgress),
    CreateCollection(RpcResult<CreateCollectionResponse>),
    BlobStatus(RpcResult<BlobStatusResponse>),
    BatchCreate(BatchCreateResponse),
    BatchAddStream(BatchAddStreamResponse),
    BatchAddPath(BatchAddPathResponse),
}

/// A request to the node to provide the data at the given path
///
/// Will produce a stream of [`AddProgress`] messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddPathRequest {
    /// The path to the data to provide.
    ///
    /// This should be an absolute path valid for the file system on which
    /// the node runs. Usually the cli will run on the same machine as the
    /// node, so this should be an absolute path on the cli machine.
    pub path: PathBuf,
    /// True if the provider can assume that the data will not change, so it
    /// can be shared in place.
    pub in_place: bool,
    /// Tag to tag the data with.
    pub tag: SetTagOption,
    /// Whether to wrap the added data in a collection
    pub wrap: WrapOption,
}

/// Wrapper around [`AddProgress`].
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct AddPathResponse(pub AddProgress);

/// Progress response for [`DownloadRequest`]
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::From, derive_more::Into)]
pub struct DownloadResponse(pub DownloadProgress);

/// A request to the node to download and share the data specified by the hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRequest {
    /// The hash of the blob to export.
    pub hash: Hash,
    /// The filepath to where the data should be saved
    ///
    /// This should be an absolute path valid for the file system on which
    /// the node runs.
    pub path: PathBuf,
    /// Set to [`ExportFormat::Collection`] if the `hash` refers to a [`Collection`] and you want
    /// to export all children of the collection into individual files.
    pub format: ExportFormat,
    /// The mode of exporting.
    ///
    /// The default is [`ExportMode::Copy`]. See [`ExportMode`] for details.
    pub mode: ExportMode,
}

/// Progress response for [`ExportRequest`]
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::From, derive_more::Into)]
pub struct ExportResponse(pub ExportProgress);

/// A request to the node to validate the integrity of all provided data
#[derive(Debug, Serialize, Deserialize)]
pub struct ConsistencyCheckRequest {
    /// repair the store by dropping inconsistent blobs
    pub repair: bool,
}

/// A request to the node to validate the integrity of all provided data
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateRequest {
    /// repair the store by downgrading blobs from complete to partial
    pub repair: bool,
}

/// List all blobs, including collections
#[derive(Debug, Serialize, Deserialize)]
pub struct ListRequest;

/// List all blobs, including collections
#[derive(Debug, Serialize, Deserialize)]
pub struct ListIncompleteRequest;

/// Get the bytes for a hash
#[derive(Serialize, Deserialize, Debug)]
pub struct ReadAtRequest {
    /// Hash to get bytes for
    pub hash: Hash,
    /// Offset to start reading at
    pub offset: u64,
    /// Length of the data to get
    pub len: ReadAtLen,
}

/// Response to [`ReadAtRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub enum ReadAtResponse {
    /// The entry header.
    Entry {
        /// The size of the blob
        size: BaoBlobSize,
        /// Whether the blob is complete
        is_complete: bool,
    },
    /// Chunks of entry data.
    Data {
        /// The data chunk
        chunk: Bytes,
    },
}

/// Write a blob from a byte stream
#[derive(Serialize, Deserialize, Debug)]
pub struct AddStreamRequest {
    /// Tag to tag the data with.
    pub tag: SetTagOption,
}

/// Write a blob from a byte stream
#[derive(Serialize, Deserialize, Debug)]
pub enum AddStreamUpdate {
    /// A chunk of stream data
    Chunk(Bytes),
    /// Abort the request due to an error on the client side
    Abort,
}

/// Wrapper around [`AddProgress`].
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct AddStreamResponse(pub AddProgress);

/// Delete a blob
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    /// Name of the tag
    pub hash: Hash,
}

/// Create a collection.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCollectionRequest {
    /// The collection
    pub collection: Collection,
    /// Tag option.
    pub tag: SetTagOption,
    /// Tags that should be deleted after creation.
    pub tags_to_delete: Vec<Tag>,
}

/// A response to a create collection request
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCollectionResponse {
    /// The resulting hash.
    pub hash: Hash,
    /// The resulting tag.
    pub tag: Tag,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlobStatusRequest {
    /// The hash of the blob
    pub hash: Hash,
}

/// The response to a status request
#[derive(Debug, Serialize, Deserialize, derive_more::From, derive_more::Into)]
pub struct BlobStatusResponse(pub BlobStatus);

/// Request to create a new scope for temp tags
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchCreateRequest;

/// Update to a temp tag scope
#[derive(Debug, Serialize, Deserialize)]
pub enum BatchUpdate {
    /// Drop of a remote temp tag
    Drop(HashAndFormat),
    /// Message to check that the connection is still alive
    Ping,
}

/// Response to a temp tag scope request
#[derive(Debug, Serialize, Deserialize)]
pub enum BatchCreateResponse {
    /// We got the id of the scope
    Id(BatchId),
}

/// Create a temp tag with a given hash and format
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchCreateTempTagRequest {
    /// Content to protect
    pub content: HashAndFormat,
    /// Batch to create the temp tag in
    pub batch: BatchId,
}

/// Write a blob from a byte stream
#[derive(Serialize, Deserialize, Debug)]
pub struct BatchAddStreamRequest {
    /// What format to use for the blob
    pub format: BlobFormat,
    /// Batch to create the temp tag in
    pub batch: BatchId,
}

/// Write a blob from a byte stream
#[derive(Serialize, Deserialize, Debug)]
pub enum BatchAddStreamUpdate {
    /// A chunk of stream data
    Chunk(Bytes),
    /// Abort the request due to an error on the client side
    Abort,
}

/// Wrapper around [`AddProgress`].
#[derive(Debug, Serialize, Deserialize)]
pub enum BatchAddStreamResponse {
    Abort(RpcError),
    OutboardProgress { offset: u64 },
    Result { hash: Hash },
}

/// Write a blob from a byte stream
#[derive(Serialize, Deserialize, Debug)]
pub struct BatchAddPathRequest {
    /// The path to the data to provide.
    pub path: PathBuf,
    /// Add the data in place
    pub import_mode: ImportMode,
    /// What format to use for the blob
    pub format: BlobFormat,
    /// Batch to create the temp tag in
    pub batch: BatchId,
}

/// Response to a batch add path request
#[derive(Serialize, Deserialize, Debug)]
pub struct BatchAddPathResponse(pub BatchAddPathProgress);

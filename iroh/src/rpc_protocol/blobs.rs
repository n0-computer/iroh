use std::path::PathBuf;

use bytes::Bytes;
use iroh_base::hash::Hash;
use iroh_base::rpc::RpcResult;
use iroh_blobs::{
    export::ExportProgress,
    format::collection::Collection,
    get::db::DownloadProgress,
    provider::AddProgress,
    store::{BaoBlobSize, ConsistencyCheckProgress, ExportFormat, ExportMode, ValidateProgress},
    util::SetTagOption,
    BlobFormat, Tag,
};
use iroh_net::NodeAddr;
use quic_rpc::message::{
    BidiStreaming, BidiStreamingMsg, Msg, RpcMsg, ServerStreaming, ServerStreamingMsg,
};
use serde::{Deserialize, Serialize};

use crate::client::blobs::{BlobInfo, DownloadMode, IncompleteBlobInfo, WrapOption};

use super::RpcService;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Request)]
pub enum Request {
    ReadAt(BlobReadAtRequest),
    AddStream(BlobAddStreamRequest),
    AddStreamUpdate(BlobAddStreamUpdate),
    AddPath(BlobAddPathRequest),
    Download(BlobDownloadRequest),
    Export(BlobExportRequest),
    List(BlobListRequest),
    ListIncomplete(BlobListIncompleteRequest),
    DeleteBlob(BlobDeleteBlobRequest),
    Validate(BlobValidateRequest),
    Fsck(BlobConsistencyCheckRequest),
    CreateCollection(CreateCollectionRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Response)]
pub enum Response {
    ReadAt(RpcResult<BlobReadAtResponse>),
    AddStream(BlobAddStreamResponse),
    AddPath(BlobAddPathResponse),
    List(RpcResult<BlobInfo>),
    ListIncomplete(RpcResult<IncompleteBlobInfo>),
    Download(BlobDownloadResponse),
    Fsck(ConsistencyCheckProgress),
    Export(BlobExportResponse),
    Validate(ValidateProgress),
    CreateCollection(RpcResult<CreateCollectionResponse>),
}

/// A request to the node to provide the data at the given path
///
/// Will produce a stream of [`AddProgress`] messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobAddPathRequest {
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

impl Msg<RpcService> for BlobAddPathRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for BlobAddPathRequest {
    type Response = BlobAddPathResponse;
}

/// Wrapper around [`AddProgress`].
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct BlobAddPathResponse(pub AddProgress);

/// A request to the node to download and share the data specified by the hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDownloadRequest {
    /// This mandatory field contains the hash of the data to download and share.
    pub hash: Hash,
    /// If the format is [`BlobFormat::HashSeq`], all children are downloaded and shared as
    /// well.
    pub format: BlobFormat,
    /// This mandatory field specifies the nodes to download the data from.
    ///
    /// If set to more than a single node, they will all be tried. If `mode` is set to
    /// [`DownloadMode::Direct`], they will be tried sequentially until a download succeeds.
    /// If `mode` is set to [`DownloadMode::Queued`], the nodes may be dialed in parallel,
    /// if the concurrency limits permit.
    pub nodes: Vec<NodeAddr>,
    /// Optional tag to tag the data with.
    pub tag: SetTagOption,
    /// Whether to directly start the download or add it to the download queue.
    pub mode: DownloadMode,
}

impl Msg<RpcService> for BlobDownloadRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for BlobDownloadRequest {
    type Response = BlobDownloadResponse;
}

/// Progress response for [`BlobDownloadRequest`]
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::From, derive_more::Into)]
pub struct BlobDownloadResponse(pub DownloadProgress);

/// A request to the node to download and share the data specified by the hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobExportRequest {
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

impl Msg<RpcService> for BlobExportRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for BlobExportRequest {
    type Response = BlobExportResponse;
}

/// Progress response for [`BlobExportRequest`]
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::From, derive_more::Into)]
pub struct BlobExportResponse(pub ExportProgress);

/// A request to the node to validate the integrity of all provided data
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobConsistencyCheckRequest {
    /// repair the store by dropping inconsistent blobs
    pub repair: bool,
}

impl Msg<RpcService> for BlobConsistencyCheckRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for BlobConsistencyCheckRequest {
    type Response = ConsistencyCheckProgress;
}

/// A request to the node to validate the integrity of all provided data
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobValidateRequest {
    /// repair the store by downgrading blobs from complete to partial
    pub repair: bool,
}

impl Msg<RpcService> for BlobValidateRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for BlobValidateRequest {
    type Response = ValidateProgress;
}

/// List all blobs, including collections
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobListRequest;

impl Msg<RpcService> for BlobListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for BlobListRequest {
    type Response = RpcResult<BlobInfo>;
}

/// List all blobs, including collections
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobListIncompleteRequest;

impl Msg<RpcService> for BlobListIncompleteRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for BlobListIncompleteRequest {
    type Response = RpcResult<IncompleteBlobInfo>;
}

/// Get the bytes for a hash
#[derive(Serialize, Deserialize, Debug)]
pub struct BlobReadAtRequest {
    /// Hash to get bytes for
    pub hash: Hash,
    /// Offset to start reading at
    pub offset: u64,
    /// Length of the data to get
    pub len: Option<usize>,
}

impl Msg<RpcService> for BlobReadAtRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for BlobReadAtRequest {
    type Response = RpcResult<BlobReadAtResponse>;
}

/// Response to [`BlobReadAtRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub enum BlobReadAtResponse {
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
pub struct BlobAddStreamRequest {
    /// Tag to tag the data with.
    pub tag: SetTagOption,
}

/// Write a blob from a byte stream
#[derive(Serialize, Deserialize, Debug)]
pub enum BlobAddStreamUpdate {
    /// A chunk of stream data
    Chunk(Bytes),
    /// Abort the request due to an error on the client side
    Abort,
}

impl Msg<RpcService> for BlobAddStreamRequest {
    type Pattern = BidiStreaming;
}

impl BidiStreamingMsg<RpcService> for BlobAddStreamRequest {
    type Update = BlobAddStreamUpdate;
    type Response = BlobAddStreamResponse;
}

/// Wrapper around [`AddProgress`].
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct BlobAddStreamResponse(pub AddProgress);

/// Delete a blob
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobDeleteBlobRequest {
    /// Name of the tag
    pub hash: Hash,
}

impl RpcMsg<RpcService> for BlobDeleteBlobRequest {
    type Response = RpcResult<()>;
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

impl RpcMsg<RpcService> for CreateCollectionRequest {
    type Response = RpcResult<CreateCollectionResponse>;
}

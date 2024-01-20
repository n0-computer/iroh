//! This defines the RPC protocol used for communication between a CLI and an iroh node.
//!
//! RPC using the [`quic-rpc`](https://docs.rs/quic-rpc) crate.
//!
//! This file contains request messages, response messages and definitions of
//! the interaction pattern. Some requests like version and shutdown have a single
//! response, while others like provide have a stream of responses.
//!
//! Note that this is subject to change. The RPC protocol is not yet stable.
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

use bytes::Bytes;
use derive_more::{From, TryInto};
use iroh_bytes::{format::collection::Collection, util::Tag};
pub use iroh_bytes::{get::db::DownloadProgress, BlobFormat, Hash};
use iroh_net::{
    key::PublicKey,
    magic_endpoint::{ConnectionInfo, NodeAddr},
};

use iroh_sync::{
    actor::OpenState,
    store::{DownloadPolicy, Query},
    {AuthorId, CapabilityKind, Entry, NamespaceId, SignedEntry},
};
use quic_rpc::{
    message::{BidiStreaming, BidiStreamingMsg, Msg, RpcMsg, ServerStreaming, ServerStreamingMsg},
    Service,
};
use serde::{Deserialize, Serialize};

pub use iroh_base::rpc::{RpcError, RpcResult};
pub use iroh_bytes::{provider::AddProgress, store::ValidateProgress};

use crate::sync_engine::LiveEvent;
pub use crate::ticket::DocTicket;

/// A 32-byte key or token
pub type KeyBytes = [u8; 32];

/// Option for commands that allow setting a tag
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SetTagOption {
    /// A tag will be automatically generated
    Auto,
    /// The tag is explicitly named
    Named(Tag),
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

/// Whether to wrap the added data in a collection.
#[derive(Debug, Serialize, Deserialize)]
pub enum WrapOption {
    /// Do not wrap the file or directory.
    NoWrap,
    /// Wrap the file or directory in a collection.
    Wrap {
        /// Override the filename in the wrapping collection.
        name: Option<String>,
    },
}

impl Msg<ProviderService> for BlobAddPathRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for BlobAddPathRequest {
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
    /// This mandatory field specifies the peer to download the data from.
    pub peer: NodeAddr,
    /// Optional tag to tag the data with.
    pub tag: SetTagOption,
    /// This field contains the location to store the data at.
    pub out: DownloadLocation,
}

/// Location to store a downloaded blob at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DownloadLocation {
    /// Store in the node's blob storage directory.
    Internal,
    /// Store at the provided path.
    External {
        /// The path to store the data at.
        path: PathBuf,
        /// If this flag is true, the data is shared in place, i.e. it is moved to the
        /// out path instead of being copied. The database itself contains only a
        /// reference to the out path of the file.
        ///
        /// If the data is modified in the location specified by the out path,
        /// download attempts for the associated hash will fail.
        in_place: bool,
    },
}

impl Msg<ProviderService> for BlobDownloadRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for BlobDownloadRequest {
    type Response = DownloadProgress;
}

/// A request to the node to validate the integrity of all provided data
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobValidateRequest {
    /// If true, remove invalid data
    pub repair: bool,
}

impl Msg<ProviderService> for BlobValidateRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for BlobValidateRequest {
    type Response = ValidateProgress;
}

/// List all blobs, including collections
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobListRequest;

/// A response to a list blobs request
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobListResponse {
    /// Location of the blob
    pub path: String,
    /// The hash of the blob
    pub hash: Hash,
    /// The size of the blob
    pub size: u64,
}

impl Msg<ProviderService> for BlobListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for BlobListRequest {
    type Response = BlobListResponse;
}

/// List all blobs, including collections
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobListIncompleteRequest;

/// A response to a list blobs request
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobListIncompleteResponse {
    /// The size we got
    pub size: u64,
    /// The size we expect
    pub expected_size: u64,
    /// The hash of the blob
    pub hash: Hash,
}

impl Msg<ProviderService> for BlobListIncompleteRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for BlobListIncompleteRequest {
    type Response = BlobListIncompleteResponse;
}

/// List all collections
///
/// Lists all collections that have been explicitly added to the database.
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobListCollectionsRequest;

/// A response to a list collections request
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobListCollectionsResponse {
    /// Tag of the collection
    pub tag: Tag,

    /// Hash of the collection
    pub hash: Hash,
    /// Number of children in the collection
    ///
    /// This is an optional field, because the data is not always available.
    pub total_blobs_count: Option<u64>,
    /// Total size of the raw data referred to by all links
    ///
    /// This is an optional field, because the data is not always available.
    pub total_blobs_size: Option<u64>,
}

impl Msg<ProviderService> for BlobListCollectionsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for BlobListCollectionsRequest {
    type Response = BlobListCollectionsResponse;
}

/// List all collections
///
/// Lists all collections that have been explicitly added to the database.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListTagsRequest;

/// A response to a list collections request
#[derive(Debug, Serialize, Deserialize)]
pub struct ListTagsResponse {
    /// Name of the tag
    pub name: Tag,
    /// Format of the data
    pub format: BlobFormat,
    /// Hash of the data
    pub hash: Hash,
}

impl Msg<ProviderService> for ListTagsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ListTagsRequest {
    type Response = ListTagsResponse;
}

/// Delete a blob
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobDeleteBlobRequest {
    /// Name of the tag
    pub hash: Hash,
}

impl RpcMsg<ProviderService> for BlobDeleteBlobRequest {
    type Response = RpcResult<()>;
}

/// Delete a tag
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteTagRequest {
    /// Name of the tag
    pub name: Tag,
}

impl RpcMsg<ProviderService> for DeleteTagRequest {
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

impl RpcMsg<ProviderService> for CreateCollectionRequest {
    type Response = RpcResult<CreateCollectionResponse>;
}

/// List connection information about all the nodes we know about
///
/// These can be nodes that we have explicitly connected to or nodes
/// that have initiated connections to us.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConnectionsRequest;

/// A response to a connections request
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConnectionsResponse {
    /// Information about a connection
    pub conn_info: ConnectionInfo,
}

impl Msg<ProviderService> for NodeConnectionsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for NodeConnectionsRequest {
    type Response = RpcResult<NodeConnectionsResponse>;
}

/// Get connection information about a specific node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConnectionInfoRequest {
    /// The node identifier
    pub node_id: PublicKey,
}

/// A response to a connection request
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConnectionInfoResponse {
    /// Information about a connection to a node
    pub conn_info: Option<ConnectionInfo>,
}

impl RpcMsg<ProviderService> for NodeConnectionInfoRequest {
    type Response = RpcResult<NodeConnectionInfoResponse>;
}

/// A request to shutdown the node
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeShutdownRequest {
    /// Force shutdown
    pub force: bool,
}

impl RpcMsg<ProviderService> for NodeShutdownRequest {
    type Response = ();
}

/// A request to get information about the identity of the node
///
/// See [`NodeStatusResponse`] for the response.
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeStatusRequest;

impl RpcMsg<ProviderService> for NodeStatusRequest {
    type Response = RpcResult<NodeStatusResponse>;
}

/// The response to a version request
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeStatusResponse {
    /// The node id and socket addresses of this node.
    pub addr: NodeAddr,
    /// The bound listening addresses of the node
    pub listen_addrs: Vec<SocketAddr>,
    /// The version of the node
    pub version: String,
}

/// A request to watch for the node status
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeWatchRequest;

impl Msg<ProviderService> for NodeWatchRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for NodeWatchRequest {
    type Response = NodeWatchResponse;
}

/// The response to a watch request
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeWatchResponse {
    /// The version of the node
    pub version: String,
}

/// The response to a version request
#[derive(Serialize, Deserialize, Debug)]
pub struct VersionResponse {
    /// The version of the node
    pub version: String,
}

// author

/// List document authors for which we have a secret key.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorListRequest {}

impl Msg<ProviderService> for AuthorListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for AuthorListRequest {
    type Response = RpcResult<AuthorListResponse>;
}

/// Response for [`AuthorListRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorListResponse {
    /// The author id
    pub author_id: AuthorId,
}

/// Create a new document author.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorCreateRequest;

impl RpcMsg<ProviderService> for AuthorCreateRequest {
    type Response = RpcResult<AuthorCreateResponse>;
}

/// Response for [`AuthorCreateRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorCreateResponse {
    /// The id of the created author
    pub author_id: AuthorId,
}

/// Import author from secret key
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorImportRequest {
    /// The secret key for the author
    pub key: KeyBytes,
}

impl RpcMsg<ProviderService> for AuthorImportRequest {
    type Response = RpcResult<AuthorImportResponse>;
}

/// Response to [`AuthorImportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorImportResponse {
    /// The author id of the imported author
    pub author_id: AuthorId,
}

/// Intended capability for document share tickets
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum ShareMode {
    /// Read-only access
    Read,
    /// Write access
    Write,
}

/// Subscribe to events for a document.
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSubscribeRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl Msg<ProviderService> for DocSubscribeRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for DocSubscribeRequest {
    type Response = RpcResult<DocSubscribeResponse>;
}

/// Response to [`DocSubscribeRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSubscribeResponse {
    /// The event that occurred on the document
    pub event: LiveEvent,
}

/// List all documents
#[derive(Serialize, Deserialize, Debug)]
pub struct DocListRequest {}

impl Msg<ProviderService> for DocListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for DocListRequest {
    type Response = RpcResult<DocListResponse>;
}

/// Response to [`DocListRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocListResponse {
    /// The document id
    pub id: NamespaceId,
    /// The capability over the document.
    pub capability: CapabilityKind,
}

/// Create a new document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocCreateRequest {}

impl RpcMsg<ProviderService> for DocCreateRequest {
    type Response = RpcResult<DocCreateResponse>;
}

/// Response to [`DocCreateRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocCreateResponse {
    /// The document id
    pub id: NamespaceId,
}

/// Import a document from a ticket.
#[derive(Serialize, Deserialize, Debug)]
pub struct DocImportRequest(pub DocTicket);

impl RpcMsg<ProviderService> for DocImportRequest {
    type Response = RpcResult<DocImportResponse>;
}

/// Response to [`DocImportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocImportResponse {
    /// the document id
    pub doc_id: NamespaceId,
}

/// Share a document with peers over a ticket.
#[derive(Serialize, Deserialize, Debug)]
pub struct DocShareRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Whether to share read or write access to the document
    pub mode: ShareMode,
}

impl RpcMsg<ProviderService> for DocShareRequest {
    type Response = RpcResult<DocShareResponse>;
}

/// The response to [`DocShareRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocShareResponse(pub DocTicket);

/// Get info on a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocStatusRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<ProviderService> for DocStatusRequest {
    type Response = RpcResult<DocStatusResponse>;
}

/// Response to [`DocStatusRequest`]
// TODO: actually provide info
#[derive(Serialize, Deserialize, Debug)]
pub struct DocStatusResponse {
    /// Live sync status
    pub status: OpenState,
}

/// Open a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocOpenRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<ProviderService> for DocOpenRequest {
    type Response = RpcResult<DocOpenResponse>;
}

/// Response to [`DocOpenRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocOpenResponse {}

/// Open a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocCloseRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<ProviderService> for DocCloseRequest {
    type Response = RpcResult<DocCloseResponse>;
}

/// Response to [`DocCloseRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocCloseResponse {}

/// Start to sync a doc with peers.
#[derive(Serialize, Deserialize, Debug)]
pub struct DocStartSyncRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// List of peers to join
    pub peers: Vec<NodeAddr>,
}

impl RpcMsg<ProviderService> for DocStartSyncRequest {
    type Response = RpcResult<DocStartSyncResponse>;
}

/// Response to [`DocStartSyncRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocStartSyncResponse {}

/// Stop the live sync for a doc, and optionally delete the document.
#[derive(Serialize, Deserialize, Debug)]
pub struct DocLeaveRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<ProviderService> for DocLeaveRequest {
    type Response = RpcResult<DocLeaveResponse>;
}

/// Response to [`DocLeaveRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocLeaveResponse {}

/// Stop the live sync for a doc, and optionally delete the document.
#[derive(Serialize, Deserialize, Debug)]
pub struct DocDropRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<ProviderService> for DocDropRequest {
    type Response = RpcResult<DocDropResponse>;
}

/// Response to [`DocDropRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocDropResponse {}

/// Set an entry in a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSetRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Author of this entry.
    pub author_id: AuthorId,
    /// Key of this entry.
    pub key: Bytes,
    /// Value of this entry.
    // TODO: Allow to provide the hash directly
    // TODO: Add a way to provide content as stream
    pub value: Bytes,
}

impl RpcMsg<ProviderService> for DocSetRequest {
    type Response = RpcResult<DocSetResponse>;
}

/// Response to [`DocSetRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSetResponse {
    /// The newly-created entry.
    pub entry: SignedEntry,
}

/// A request to the node to add the data at the given filepath as an entry to the document
///
/// Will produce a stream of [`DocImportProgress`] messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct DocImportFileRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Author of this entry.
    pub author_id: AuthorId,
    /// Key of this entry.
    pub key: Bytes,
    /// The filepath to the data
    ///
    /// This should be an absolute path valid for the file system on which
    /// the node runs. Usually the cli will run on the same machine as the
    /// node, so this should be an absolute path on the cli machine.
    pub path: PathBuf,
    /// True if the provider can assume that the data will not change, so it
    /// can be shared in place.
    pub in_place: bool,
}

impl Msg<ProviderService> for DocImportFileRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for DocImportFileRequest {
    type Response = DocImportFileResponse;
}

/// Wrapper around [`DocImportProgress`].
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct DocImportFileResponse(pub DocImportProgress);

/// Progress messages for an doc import operation
///
/// An import operation involves computing the outboard of a file, and then
/// either copying or moving the file into the database, then setting the author, hash, size, and tag of that file as an entry in the doc
#[derive(Debug, Serialize, Deserialize)]
pub enum DocImportProgress {
    /// An item was found with name `name`, from now on referred to via `id`
    Found {
        /// A new unique id for this entry.
        id: u64,
        /// The name of the entry.
        name: String,
        /// The size of the entry in bytes.
        size: u64,
    },
    /// We got progress ingesting item `id`.
    Progress {
        /// The unique id of the entry.
        id: u64,
        /// The offset of the progress, in bytes.
        offset: u64,
    },
    /// We are done adding `id` to the data store and the hash is `hash`.
    IngestDone {
        /// The unique id of the entry.
        id: u64,
        /// The hash of the entry.
        hash: Hash,
    },
    /// We are done setting the entry to the doc
    AllDone {
        /// The key of the entry
        key: Bytes,
    },
    /// We got an error and need to abort.
    ///
    /// This will be the last message in the stream.
    Abort(RpcError),
}

/// A request to the node to save the data of the entry to the given filepath
///
/// Will produce a stream of [`DocExportProgress`] messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct DocExportFileRequest {
    /// The entry you want to export
    pub entry: Entry,
    /// The filepath to where the data should be saved
    ///
    /// This should be an absolute path valid for the file system on which
    /// the node runs. Usually the cli will run on the same machine as the
    /// node, so this should be an absolute path on the cli machine.
    pub path: PathBuf,
}

impl Msg<ProviderService> for DocExportFileRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for DocExportFileRequest {
    type Response = DocExportFileResponse;
}

/// Wrapper around [`DocExportProgress`].
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct DocExportFileResponse(pub DocExportProgress);

/// Progress messages for an doc export operation
///
/// An export operation involves reading the entry from the database ans saving the entry to the
/// given `outpath`
#[derive(Debug, Serialize, Deserialize)]
pub enum DocExportProgress {
    /// An item was found with name `name`, from now on referred to via `id`
    Found {
        /// A new unique id for this entry.
        id: u64,
        /// The hash of the entry.
        hash: Hash,
        /// The key to the entry.
        key: Bytes,
        /// The size of the entry in bytes.
        size: u64,
        /// The path to where we are writing the entry
        outpath: PathBuf,
    },
    /// We got progress exporting item `id`.
    Progress {
        /// The unique id of the entry.
        id: u64,
        /// The offset of the progress, in bytes.
        offset: u64,
    },
    /// We are done writing the entry to the filesystem
    AllDone,
    /// We got an error and need to abort.
    ///
    /// This will be the last message in the stream.
    Abort(RpcError),
}

/// Delete entries in a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocDelRequest {
    /// The document id.
    pub doc_id: NamespaceId,
    /// Author of this entry.
    pub author_id: AuthorId,
    /// Prefix to delete.
    pub prefix: Bytes,
}

impl RpcMsg<ProviderService> for DocDelRequest {
    type Response = RpcResult<DocDelResponse>;
}

/// Response to [`DocDelRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocDelResponse {
    /// The number of entries that were removed.
    pub removed: usize,
}

/// Set an entry in a document via its hash
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSetHashRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Author of this entry.
    pub author_id: AuthorId,
    /// Key of this entry.
    pub key: Bytes,
    /// Hash of this entry.
    pub hash: Hash,
    /// Size of this entry.
    pub size: u64,
}

impl RpcMsg<ProviderService> for DocSetHashRequest {
    type Response = RpcResult<DocSetHashResponse>;
}

/// Response to [`DocSetHashRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSetHashResponse {}

/// Get entries from a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetManyRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Query to run
    pub query: Query,
}

impl Msg<ProviderService> for DocGetManyRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for DocGetManyRequest {
    type Response = RpcResult<DocGetManyResponse>;
}

/// Response to [`DocGetManyRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetManyResponse {
    /// The document entry
    pub entry: SignedEntry,
}

/// Get entries from a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetExactRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Key matcher
    pub key: Bytes,
    /// Author matcher
    pub author: AuthorId,
    /// Whether to include empty entries (prefix deletion markers)
    pub include_empty: bool,
}

impl RpcMsg<ProviderService> for DocGetExactRequest {
    type Response = RpcResult<DocGetExactResponse>;
}

/// Response to [`DocGetExactRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetExactResponse {
    /// The document entry
    pub entry: Option<SignedEntry>,
}

/// Set a download policy
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSetDownloadPolicyRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Download policy
    pub policy: DownloadPolicy,
}

impl RpcMsg<ProviderService> for DocSetDownloadPolicyRequest {
    type Response = RpcResult<DocSetDownloadPolicyResponse>;
}

/// Response to [`DocSetDownloadPolicyRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSetDownloadPolicyResponse {}

/// Get a download policy
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetDownloadPolicyRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<ProviderService> for DocGetDownloadPolicyRequest {
    type Response = RpcResult<DocGetDownloadPolicyResponse>;
}

/// Response to [`DocGetDownloadPolicyRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetDownloadPolicyResponse {
    /// The download policy
    pub policy: DownloadPolicy,
}

/// Get the bytes for a hash
#[derive(Serialize, Deserialize, Debug)]
pub struct BlobReadRequest {
    /// Hash to get bytes for
    pub hash: Hash,
}

impl Msg<ProviderService> for BlobReadRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for BlobReadRequest {
    type Response = RpcResult<BlobReadResponse>;
}

/// Response to [`BlobReadRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub enum BlobReadResponse {
    /// The entry header.
    Entry {
        /// The size of the blob
        size: u64,
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

impl Msg<ProviderService> for BlobAddStreamRequest {
    type Pattern = BidiStreaming;
}

impl BidiStreamingMsg<ProviderService> for BlobAddStreamRequest {
    type Update = BlobAddStreamUpdate;
    type Response = BlobAddStreamResponse;
}

/// Wrapper around [`AddProgress`].
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct BlobAddStreamResponse(pub AddProgress);

/// Get stats for the running Iroh node
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeStatsRequest {}

impl RpcMsg<ProviderService> for NodeStatsRequest {
    type Response = RpcResult<NodeStatsResponse>;
}

/// Counter stats
#[derive(Serialize, Deserialize, Debug)]
pub struct CounterStats {
    /// The counter value
    pub value: u64,
    /// The counter description
    pub description: String,
}

/// Response to [`NodeStatsRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeStatsResponse {
    /// Map of statistics
    pub stats: BTreeMap<String, CounterStats>,
}

/// The RPC service for the iroh provider process.
#[derive(Debug, Clone)]
pub struct ProviderService;

/// The request enum, listing all possible requests.
#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize, From, TryInto)]
pub enum ProviderRequest {
    NodeStatus(NodeStatusRequest),
    NodeStats(NodeStatsRequest),
    NodeShutdown(NodeShutdownRequest),
    NodeConnections(NodeConnectionsRequest),
    NodeConnectionInfo(NodeConnectionInfoRequest),
    NodeWatch(NodeWatchRequest),

    BlobRead(BlobReadRequest),
    BlobAddStream(BlobAddStreamRequest),
    BlobAddStreamUpdate(BlobAddStreamUpdate),
    BlobAddPath(BlobAddPathRequest),
    BlobDownload(BlobDownloadRequest),
    BlobList(BlobListRequest),
    BlobListIncomplete(BlobListIncompleteRequest),
    BlobListCollections(BlobListCollectionsRequest),
    BlobDeleteBlob(BlobDeleteBlobRequest),
    BlobValidate(BlobValidateRequest),
    CreateCollection(CreateCollectionRequest),

    DeleteTag(DeleteTagRequest),
    ListTags(ListTagsRequest),

    DocOpen(DocOpenRequest),
    DocClose(DocCloseRequest),
    DocStatus(DocStatusRequest),
    DocList(DocListRequest),
    DocCreate(DocCreateRequest),
    DocDrop(DocDropRequest),
    DocImport(DocImportRequest),
    DocSet(DocSetRequest),
    DocSetHash(DocSetHashRequest),
    DocGet(DocGetManyRequest),
    DocGetExact(DocGetExactRequest),
    DocImportFile(DocImportFileRequest),
    DocExportFile(DocExportFileRequest),
    DocDel(DocDelRequest),
    DocStartSync(DocStartSyncRequest),
    DocLeave(DocLeaveRequest),
    DocShare(DocShareRequest),
    DocSubscribe(DocSubscribeRequest),
    DocGetDownloadPolicy(DocGetDownloadPolicyRequest),
    DocSetDownloadPolicy(DocSetDownloadPolicyRequest),

    AuthorList(AuthorListRequest),
    AuthorCreate(AuthorCreateRequest),
    AuthorImport(AuthorImportRequest),
}

/// The response enum, listing all possible responses.
#[allow(missing_docs, clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize, From, TryInto)]
pub enum ProviderResponse {
    NodeStatus(RpcResult<NodeStatusResponse>),
    NodeStats(RpcResult<NodeStatsResponse>),
    NodeConnections(RpcResult<NodeConnectionsResponse>),
    NodeConnectionInfo(RpcResult<NodeConnectionInfoResponse>),
    NodeShutdown(()),
    NodeWatch(NodeWatchResponse),

    BlobRead(RpcResult<BlobReadResponse>),
    BlobAddStream(BlobAddStreamResponse),
    BlobAddPath(BlobAddPathResponse),
    BlobDownload(DownloadProgress),
    BlobList(BlobListResponse),
    BlobListIncomplete(BlobListIncompleteResponse),
    BlobListCollections(BlobListCollectionsResponse),
    BlobValidate(ValidateProgress),
    CreateCollection(RpcResult<CreateCollectionResponse>),

    ListTags(ListTagsResponse),
    DeleteTag(RpcResult<()>),

    DocOpen(RpcResult<DocOpenResponse>),
    DocClose(RpcResult<DocCloseResponse>),
    DocStatus(RpcResult<DocStatusResponse>),
    DocList(RpcResult<DocListResponse>),
    DocCreate(RpcResult<DocCreateResponse>),
    DocDrop(RpcResult<DocDropResponse>),
    DocImport(RpcResult<DocImportResponse>),
    DocSet(RpcResult<DocSetResponse>),
    DocSetHash(RpcResult<DocSetHashResponse>),
    DocGet(RpcResult<DocGetManyResponse>),
    DocGetExact(RpcResult<DocGetExactResponse>),
    DocImportFile(DocImportFileResponse),
    DocExportFile(DocExportFileResponse),
    DocDel(RpcResult<DocDelResponse>),
    DocShare(RpcResult<DocShareResponse>),
    DocStartSync(RpcResult<DocStartSyncResponse>),
    DocLeave(RpcResult<DocLeaveResponse>),
    DocSubscribe(RpcResult<DocSubscribeResponse>),
    DocGetDownloadPolicy(RpcResult<DocGetDownloadPolicyResponse>),
    DocSetDownloadPolicy(RpcResult<DocSetDownloadPolicyResponse>),

    AuthorList(RpcResult<AuthorListResponse>),
    AuthorCreate(RpcResult<AuthorCreateResponse>),
    AuthorImport(RpcResult<AuthorImportResponse>),
}

impl Service for ProviderService {
    type Req = ProviderRequest;
    type Res = ProviderResponse;
}

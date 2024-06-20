//! This defines the RPC protocol used for communication between a CLI and an iroh node.
//!
//! RPC using the [`quic-rpc`](https://docs.rs/quic-rpc) crate.
//!
//! This file contains request messages, response messages and definitions of
//! the interaction pattern. Some requests like version and shutdown have a single
//! response, while others like provide have a stream of responses.
//!
//! Note that this is subject to change. The RPC protocol is not yet stable.
use std::{collections::BTreeMap, path::PathBuf};

use bytes::Bytes;
use derive_more::{From, TryInto};
use iroh_base::node_addr::AddrInfoOptions;
pub use iroh_blobs::{export::ExportProgress, get::db::DownloadProgress, BlobFormat, Hash};
use iroh_blobs::{
    format::collection::Collection,
    store::{BaoBlobSize, ConsistencyCheckProgress},
    util::Tag,
};
use iroh_net::{
    endpoint::{ConnectionInfo, NodeAddr},
    key::PublicKey,
    relay::RelayUrl,
    NodeId,
};

use iroh_docs::{
    actor::OpenState,
    store::{DownloadPolicy, Query},
    Author, AuthorId, Capability, CapabilityKind, DocTicket, Entry, NamespaceId, PeerIdBytes,
    SignedEntry,
};
use quic_rpc::{
    message::{BidiStreaming, BidiStreamingMsg, Msg, RpcMsg, ServerStreaming, ServerStreamingMsg},
    pattern::try_server_streaming::{StreamCreated, TryServerStreaming, TryServerStreamingMsg},
    Service,
};
use serde::{Deserialize, Serialize};

pub use iroh_base::rpc::{RpcError, RpcResult};
use iroh_blobs::store::{ExportFormat, ExportMode};
pub use iroh_blobs::{provider::AddProgress, store::ValidateProgress};
use iroh_docs::engine::LiveEvent;

use crate::client::{
    blobs::{BlobInfo, DownloadMode, IncompleteBlobInfo, WrapOption},
    docs::{ImportProgress, ShareMode},
    tags::TagInfo,
    NodeStatus,
};
pub use iroh_blobs::util::SetTagOption;

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

/// Progress resposne for [`BlobDownloadRequest`]
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

/// Progress resposne for [`BlobExportRequest`]
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

/// List all collections
///
/// Lists all collections that have been explicitly added to the database.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListTagsRequest {
    /// List raw tags
    pub raw: bool,
    /// List hash seq tags
    pub hash_seq: bool,
}

impl ListTagsRequest {
    /// List all tags
    pub fn all() -> Self {
        Self {
            raw: true,
            hash_seq: true,
        }
    }

    /// List raw tags
    pub fn raw() -> Self {
        Self {
            raw: true,
            hash_seq: false,
        }
    }

    /// List hash seq tags
    pub fn hash_seq() -> Self {
        Self {
            raw: false,
            hash_seq: true,
        }
    }
}

impl Msg<RpcService> for ListTagsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for ListTagsRequest {
    type Response = TagInfo;
}

/// Delete a blob
#[derive(Debug, Serialize, Deserialize)]
pub struct BlobDeleteBlobRequest {
    /// Name of the tag
    pub hash: Hash,
}

impl RpcMsg<RpcService> for BlobDeleteBlobRequest {
    type Response = RpcResult<()>;
}

/// Delete a tag
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteTagRequest {
    /// Name of the tag
    pub name: Tag,
}

impl RpcMsg<RpcService> for DeleteTagRequest {
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

impl Msg<RpcService> for NodeConnectionsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for NodeConnectionsRequest {
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

impl RpcMsg<RpcService> for NodeConnectionInfoRequest {
    type Response = RpcResult<NodeConnectionInfoResponse>;
}

/// A request to shutdown the node
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeShutdownRequest {
    /// Force shutdown
    pub force: bool,
}

impl RpcMsg<RpcService> for NodeShutdownRequest {
    type Response = ();
}

/// A request to get information about the status of the node.
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeStatusRequest;

impl RpcMsg<RpcService> for NodeStatusRequest {
    type Response = RpcResult<NodeStatus>;
}

/// A request to get information the identity of the node.
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeIdRequest;

impl RpcMsg<RpcService> for NodeIdRequest {
    type Response = RpcResult<NodeId>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeAddrRequest;

impl RpcMsg<RpcService> for NodeAddrRequest {
    type Response = RpcResult<NodeAddr>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeRelayRequest;

impl RpcMsg<RpcService> for NodeRelayRequest {
    type Response = RpcResult<Option<RelayUrl>>;
}

/// A request to watch for the node status
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeWatchRequest;

impl Msg<RpcService> for NodeWatchRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for NodeWatchRequest {
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

impl Msg<RpcService> for AuthorListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for AuthorListRequest {
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

impl RpcMsg<RpcService> for AuthorCreateRequest {
    type Response = RpcResult<AuthorCreateResponse>;
}

/// Response for [`AuthorCreateRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorCreateResponse {
    /// The id of the created author
    pub author_id: AuthorId,
}

/// Get the default author.
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorGetDefaultRequest;

impl RpcMsg<RpcService> for AuthorGetDefaultRequest {
    type Response = RpcResult<AuthorGetDefaultResponse>;
}

/// Response for [`AuthorGetDefaultRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorGetDefaultResponse {
    /// The id of the author
    pub author_id: AuthorId,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorSetDefaultRequest {
    /// The id of the author
    pub author_id: AuthorId,
}

impl RpcMsg<RpcService> for AuthorSetDefaultRequest {
    type Response = RpcResult<AuthorSetDefaultResponse>;
}

/// Response for [`AuthorGetDefaultRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorSetDefaultResponse;

/// Delete an author
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorDeleteRequest {
    /// The id of the author to delete
    pub author: AuthorId,
}

impl RpcMsg<RpcService> for AuthorDeleteRequest {
    type Response = RpcResult<AuthorDeleteResponse>;
}

/// Response for [`AuthorDeleteRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorDeleteResponse;

/// Exports an author
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorExportRequest {
    /// The id of the author to delete
    pub author: AuthorId,
}

impl RpcMsg<RpcService> for AuthorExportRequest {
    type Response = RpcResult<AuthorExportResponse>;
}

/// Response for [`AuthorExportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorExportResponse {
    /// The author
    pub author: Option<Author>,
}

/// Import author from secret key
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorImportRequest {
    /// The author to import
    pub author: Author,
}

impl RpcMsg<RpcService> for AuthorImportRequest {
    type Response = RpcResult<AuthorImportResponse>;
}

/// Response to [`AuthorImportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorImportResponse {
    /// The author id of the imported author
    pub author_id: AuthorId,
}

/// Subscribe to events for a document.
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSubscribeRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl Msg<RpcService> for DocSubscribeRequest {
    type Pattern = TryServerStreaming;
}

impl TryServerStreamingMsg<RpcService> for DocSubscribeRequest {
    type Item = DocSubscribeResponse;
    type ItemError = RpcError;
    type CreateError = RpcError;
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

impl Msg<RpcService> for DocListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for DocListRequest {
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

impl RpcMsg<RpcService> for DocCreateRequest {
    type Response = RpcResult<DocCreateResponse>;
}

/// Response to [`DocCreateRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocCreateResponse {
    /// The document id
    pub id: NamespaceId,
}

/// Import a document from a capability.
#[derive(Serialize, Deserialize, Debug)]
pub struct DocImportRequest {
    /// The namespace capability.
    pub capability: Capability,
}

impl RpcMsg<RpcService> for DocImportRequest {
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
    /// Configuration of the addresses in the ticket.
    pub addr_options: AddrInfoOptions,
}

impl RpcMsg<RpcService> for DocShareRequest {
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

impl RpcMsg<RpcService> for DocStatusRequest {
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

impl RpcMsg<RpcService> for DocOpenRequest {
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

impl RpcMsg<RpcService> for DocCloseRequest {
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

impl RpcMsg<RpcService> for DocStartSyncRequest {
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

impl RpcMsg<RpcService> for DocLeaveRequest {
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

impl RpcMsg<RpcService> for DocDropRequest {
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

impl RpcMsg<RpcService> for DocSetRequest {
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
/// Will produce a stream of [`ImportProgress`] messages.
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

impl Msg<RpcService> for DocImportFileRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for DocImportFileRequest {
    type Response = DocImportFileResponse;
}

/// Wrapper around [`ImportProgress`].
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct DocImportFileResponse(pub ImportProgress);

/// A request to the node to save the data of the entry to the given filepath
///
/// Will produce a stream of [`DocExportFileResponse`] messages.
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
    /// The mode of exporting. Setting to `ExportMode::TryReference` means attempting
    /// to use references for keeping file
    pub mode: ExportMode,
}

impl Msg<RpcService> for DocExportFileRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for DocExportFileRequest {
    type Response = DocExportFileResponse;
}

/// Progress messages for an doc export operation
///
/// An export operation involves reading the entry from the database ans saving the entry to the
/// given `outpath`
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct DocExportFileResponse(pub ExportProgress);

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

impl RpcMsg<RpcService> for DocDelRequest {
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

impl RpcMsg<RpcService> for DocSetHashRequest {
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

impl Msg<RpcService> for DocGetManyRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for DocGetManyRequest {
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

impl RpcMsg<RpcService> for DocGetExactRequest {
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

impl RpcMsg<RpcService> for DocSetDownloadPolicyRequest {
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

impl RpcMsg<RpcService> for DocGetDownloadPolicyRequest {
    type Response = RpcResult<DocGetDownloadPolicyResponse>;
}

/// Response to [`DocGetDownloadPolicyRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetDownloadPolicyResponse {
    /// The download policy
    pub policy: DownloadPolicy,
}

/// Get peers for document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetSyncPeersRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<RpcService> for DocGetSyncPeersRequest {
    type Response = RpcResult<DocGetSyncPeersResponse>;
}

/// Response to [`DocGetSyncPeersRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetSyncPeersResponse {
    /// List of peers ids
    pub peers: Option<Vec<PeerIdBytes>>,
}

/// Get the bytes for a hash
#[derive(Serialize, Deserialize, Debug)]
pub struct BlobReadAtRequest {
    /// Hash to get bytes for
    pub hash: Hash,
    /// Offset to start reading at
    pub offset: u64,
    /// Lenghth of the data to get
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

/// Get stats for the running Iroh node
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeStatsRequest {}

impl RpcMsg<RpcService> for NodeStatsRequest {
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
pub struct RpcService;

/// The request enum, listing all possible requests.
#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize, From, TryInto)]
pub enum Request {
    NodeStatus(NodeStatusRequest),
    NodeId(NodeIdRequest),
    NodeAddr(NodeAddrRequest),
    NodeRelay(NodeRelayRequest),
    NodeStats(NodeStatsRequest),
    NodeShutdown(NodeShutdownRequest),
    NodeConnections(NodeConnectionsRequest),
    NodeConnectionInfo(NodeConnectionInfoRequest),
    NodeWatch(NodeWatchRequest),

    BlobReadAt(BlobReadAtRequest),
    BlobAddStream(BlobAddStreamRequest),
    BlobAddStreamUpdate(BlobAddStreamUpdate),
    BlobAddPath(BlobAddPathRequest),
    BlobDownload(BlobDownloadRequest),
    BlobExport(BlobExportRequest),
    BlobList(BlobListRequest),
    BlobListIncomplete(BlobListIncompleteRequest),
    BlobDeleteBlob(BlobDeleteBlobRequest),
    BlobValidate(BlobValidateRequest),
    BlobFsck(BlobConsistencyCheckRequest),
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
    DocGetSyncPeers(DocGetSyncPeersRequest),

    AuthorList(AuthorListRequest),
    AuthorCreate(AuthorCreateRequest),
    AuthorGetDefault(AuthorGetDefaultRequest),
    AuthorSetDefault(AuthorSetDefaultRequest),
    AuthorImport(AuthorImportRequest),
    AuthorExport(AuthorExportRequest),
    AuthorDelete(AuthorDeleteRequest),
}

/// The response enum, listing all possible responses.
#[allow(missing_docs, clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize, From, TryInto)]
pub enum Response {
    NodeStatus(RpcResult<NodeStatus>),
    NodeId(RpcResult<NodeId>),
    NodeAddr(RpcResult<NodeAddr>),
    NodeRelay(RpcResult<Option<RelayUrl>>),
    NodeStats(RpcResult<NodeStatsResponse>),
    NodeConnections(RpcResult<NodeConnectionsResponse>),
    NodeConnectionInfo(RpcResult<NodeConnectionInfoResponse>),
    NodeShutdown(()),
    NodeWatch(NodeWatchResponse),

    BlobReadAt(RpcResult<BlobReadAtResponse>),
    BlobAddStream(BlobAddStreamResponse),
    BlobAddPath(BlobAddPathResponse),
    BlobList(RpcResult<BlobInfo>),
    BlobListIncomplete(RpcResult<IncompleteBlobInfo>),
    BlobDownload(BlobDownloadResponse),
    BlobFsck(ConsistencyCheckProgress),
    BlobExport(BlobExportResponse),
    BlobValidate(ValidateProgress),
    CreateCollection(RpcResult<CreateCollectionResponse>),

    ListTags(TagInfo),
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
    DocGetSyncPeers(RpcResult<DocGetSyncPeersResponse>),
    StreamCreated(RpcResult<StreamCreated>),

    AuthorList(RpcResult<AuthorListResponse>),
    AuthorCreate(RpcResult<AuthorCreateResponse>),
    AuthorGetDefault(RpcResult<AuthorGetDefaultResponse>),
    AuthorSetDefault(RpcResult<AuthorSetDefaultResponse>),
    AuthorImport(RpcResult<AuthorImportResponse>),
    AuthorExport(RpcResult<AuthorExportResponse>),
    AuthorDelete(RpcResult<AuthorDeleteResponse>),
}

impl Service for RpcService {
    type Req = Request;
    type Res = Response;
}

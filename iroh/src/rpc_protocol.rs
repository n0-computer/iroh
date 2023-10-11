//! This defines the RPC protocol used for communication between a CLI and an iroh node.
//!
//! RPC using the [`quic-rpc`](https://docs.rs/quic-rpc) crate.
//!
//! This file contains request messages, response messages and definitions of
//! the interaction pattern. Some requests like version and shutdown have a single
//! response, while others like provide have a stream of responses.
//!
//! Note that this is subject to change. The RPC protocol is not yet stable.
use std::{collections::HashMap, fmt, net::SocketAddr, path::PathBuf, str::FromStr};

use bytes::Bytes;
use derive_more::{From, TryInto};
use iroh_bytes::util::{BlobFormat, SetTagOption, Tag};
pub use iroh_bytes::{protocol::RequestToken, provider::GetProgress, Hash};
use iroh_gossip::proto::util::base32;
use iroh_net::{
    key::PublicKey,
    magic_endpoint::{ConnectionInfo, PeerAddr},
};

use iroh_sync::{
    store::GetFilter,
    sync::{NamespaceId, SignedEntry},
    AuthorId,
};
use quic_rpc::{
    message::{BidiStreaming, BidiStreamingMsg, Msg, RpcMsg, ServerStreaming, ServerStreamingMsg},
    Service,
};
use serde::{Deserialize, Serialize};

pub use iroh_bytes::{baomap::ValidateProgress, provider::AddProgress, util::RpcResult};

use crate::sync_engine::{LiveEvent, LiveStatus};

/// A 32-byte key or token
pub type KeyBytes = [u8; 32];

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
    /// Wrap the file or directory in a colletion.
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
    pub peer: PeerAddr,
    /// This optional field contains a request token that can be used to authorize
    /// the download request.
    pub token: Option<RequestToken>,
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
        path: String,
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
    type Response = GetProgress;
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
    /// The peer id and socket addresses of this node.
    pub addr: PeerAddr,
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
    /// The event that occured on the document
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

/// Contains both a key (either secret or public) to a document, and a list of peers to join.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DocTicket {
    /// either a public or private key
    pub key: KeyBytes,
    /// a list of peers
    pub peers: Vec<PeerAddr>,
}
impl DocTicket {
    /// Create a new doc ticket
    pub fn new(key: KeyBytes, peers: Vec<PeerAddr>) -> Self {
        Self { key, peers }
    }
    /// Serialize the ticket to a byte array.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let bytes = postcard::to_stdvec(&self)?;
        Ok(bytes)
    }
    /// Parse ticket from a byte array.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let slf = postcard::from_bytes(bytes)?;
        Ok(slf)
    }
}
impl FromStr for DocTicket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&base32::parse_vec(s)?)
    }
}
impl fmt::Display for DocTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            base32::fmt(self.to_bytes().expect("failed to serialize"))
        )
    }
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
pub struct DocInfoRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<ProviderService> for DocInfoRequest {
    type Response = RpcResult<DocInfoResponse>;
}

/// Response to [`DocInfoRequest`]
// TODO: actually provide info
#[derive(Serialize, Deserialize, Debug)]
pub struct DocInfoResponse {
    /// Live sync status
    pub status: LiveStatus,
}

/// Start to sync a doc with peers.
#[derive(Serialize, Deserialize, Debug)]
pub struct DocStartSyncRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// List of peers to join
    pub peers: Vec<PeerAddr>,
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
    pub key: Vec<u8>,
    /// Value of this entry.
    // TODO: Allow to provide the hash directly
    // TODO: Add a way to provide content as stream
    pub value: Vec<u8>,
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

/// Delete entries in a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocDelRequest {
    /// The document id.
    pub doc_id: NamespaceId,
    /// Author of this entry.
    pub author_id: AuthorId,
    /// Prefix to delete.
    pub prefix: Vec<u8>,
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

/// Get entries from a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetManyRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Filter entries by this [`GetFilter`]
    pub filter: GetFilter,
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
pub struct DocGetOneRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Key
    pub key: Vec<u8>,
    /// Author
    pub author: AuthorId,
}

impl RpcMsg<ProviderService> for DocGetOneRequest {
    type Response = RpcResult<DocGetOneResponse>;
}

/// Response to [`DocGetOneRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetOneResponse {
    /// The document entry
    pub entry: Option<SignedEntry>,
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
        /// Wether the blob is complete
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
    pub stats: HashMap<String, CounterStats>,
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

    DeleteTag(DeleteTagRequest),
    ListTags(ListTagsRequest),

    DocInfo(DocInfoRequest),
    DocList(DocListRequest),
    DocCreate(DocCreateRequest),
    DocDrop(DocDropRequest),
    DocImport(DocImportRequest),
    DocSet(DocSetRequest),
    DocGet(DocGetManyRequest),
    DocGetOne(DocGetOneRequest),
    DocDel(DocDelRequest),
    DocStartSync(DocStartSyncRequest),
    DocLeave(DocLeaveRequest),
    DocShare(DocShareRequest),
    DocSubscribe(DocSubscribeRequest),

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
    BlobDownload(GetProgress),
    BlobList(BlobListResponse),
    BlobListIncomplete(BlobListIncompleteResponse),
    BlobListCollections(BlobListCollectionsResponse),
    BlobValidate(ValidateProgress),

    ListTags(ListTagsResponse),
    DeleteTag(RpcResult<()>),

    DocInfo(RpcResult<DocInfoResponse>),
    DocList(RpcResult<DocListResponse>),
    DocCreate(RpcResult<DocCreateResponse>),
    DocDrop(RpcResult<DocDropResponse>),
    DocImport(RpcResult<DocImportResponse>),
    DocSet(RpcResult<DocSetResponse>),
    DocGet(RpcResult<DocGetManyResponse>),
    DocGetOne(RpcResult<DocGetOneResponse>),
    DocDel(RpcResult<DocDelResponse>),
    DocShare(RpcResult<DocShareResponse>),
    DocStartSync(RpcResult<DocStartSyncResponse>),
    DocLeave(RpcResult<DocLeaveResponse>),
    DocSubscribe(RpcResult<DocSubscribeResponse>),

    AuthorList(RpcResult<AuthorListResponse>),
    AuthorCreate(RpcResult<AuthorCreateResponse>),
    AuthorImport(RpcResult<AuthorImportResponse>),
}

impl Service for ProviderService {
    type Req = ProviderRequest;
    type Res = ProviderResponse;
}

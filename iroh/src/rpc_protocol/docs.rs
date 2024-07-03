use std::path::PathBuf;

use bytes::Bytes;
use iroh_base::{
    node_addr::AddrInfoOptions,
    rpc::{RpcError, RpcResult},
};
use iroh_blobs::{export::ExportProgress, store::ExportMode, Hash};
use iroh_docs::{
    actor::OpenState, engine::LiveEvent, store::DownloadPolicy, store::Query, AuthorId, Capability,
    CapabilityKind, DocTicket, Entry, NamespaceId, PeerIdBytes, SignedEntry,
};
use iroh_net::NodeAddr;
use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming, ServerStreamingMsg},
    pattern::try_server_streaming::StreamCreated,
    pattern::try_server_streaming::{TryServerStreaming, TryServerStreamingMsg},
};
use serde::{Deserialize, Serialize};

use super::RpcService;
use crate::client::docs::{ImportProgress, ShareMode};

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Request)]
pub enum Request {
    Open(OpenRequest),
    Close(CloseRequest),
    Status(StatusRequest),
    List(DocListRequest),
    Create(CreateRequest),
    Drop(DropRequest),
    Import(ImportRequest),
    Set(SetRequest),
    SetHash(SetHashRequest),
    Get(GetManyRequest),
    GetExact(GetExactRequest),
    ImportFile(ImportFileRequest),
    ExportFile(ExportFileRequest),
    Del(DelRequest),
    StartSync(StartSyncRequest),
    Leave(LeaveRequest),
    Share(ShareRequest),
    Subscribe(DocSubscribeRequest),
    GetDownloadPolicy(GetDownloadPolicyRequest),
    SetDownloadPolicy(SetDownloadPolicyRequest),
    GetSyncPeers(GetSyncPeersRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Response)]
pub enum Response {
    Open(RpcResult<OpenResponse>),
    Close(RpcResult<CloseResponse>),
    Status(RpcResult<StatusResponse>),
    List(RpcResult<ListResponse>),
    Create(RpcResult<CreateResponse>),
    Drop(RpcResult<DropResponse>),
    Import(RpcResult<ImportResponse>),
    Set(RpcResult<SetResponse>),
    SetHash(RpcResult<SetHashResponse>),
    Get(RpcResult<GetManyResponse>),
    GetExact(RpcResult<GetExactResponse>),
    ImportFile(ImportFileResponse),
    ExportFile(ExportFileResponse),
    Del(RpcResult<DelResponse>),
    Share(RpcResult<ShareResponse>),
    StartSync(RpcResult<StartSyncResponse>),
    Leave(RpcResult<LeaveResponse>),
    Subscribe(RpcResult<DocSubscribeResponse>),
    GetDownloadPolicy(RpcResult<GetDownloadPolicyResponse>),
    SetDownloadPolicy(RpcResult<SetDownloadPolicyResponse>),
    GetSyncPeers(RpcResult<GetSyncPeersResponse>),
    StreamCreated(RpcResult<StreamCreated>),
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
    type Response = RpcResult<ListResponse>;
}

/// Response to [`DocListRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ListResponse {
    /// The document id
    pub id: NamespaceId,
    /// The capability over the document.
    pub capability: CapabilityKind,
}

/// Create a new document
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateRequest {}

impl RpcMsg<RpcService> for CreateRequest {
    type Response = RpcResult<CreateResponse>;
}

/// Response to [`DocCreateRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateResponse {
    /// The document id
    pub id: NamespaceId,
}

/// Import a document from a capability.
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportRequest {
    /// The namespace capability.
    pub capability: Capability,
}

impl RpcMsg<RpcService> for ImportRequest {
    type Response = RpcResult<ImportResponse>;
}

/// Response to [`DocImportRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportResponse {
    /// the document id
    pub doc_id: NamespaceId,
}

/// Share a document with peers over a ticket.
#[derive(Serialize, Deserialize, Debug)]
pub struct ShareRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Whether to share read or write access to the document
    pub mode: ShareMode,
    /// Configuration of the addresses in the ticket.
    pub addr_options: AddrInfoOptions,
}

impl RpcMsg<RpcService> for ShareRequest {
    type Response = RpcResult<ShareResponse>;
}

/// The response to [`ShareRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ShareResponse(pub DocTicket);

/// Get info on a document
#[derive(Serialize, Deserialize, Debug)]
pub struct StatusRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<RpcService> for StatusRequest {
    type Response = RpcResult<StatusResponse>;
}

/// Response to [`StatusRequest`]
// TODO: actually provide info
#[derive(Serialize, Deserialize, Debug)]
pub struct StatusResponse {
    /// Live sync status
    pub status: OpenState,
}

/// Open a document
#[derive(Serialize, Deserialize, Debug)]
pub struct OpenRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<RpcService> for OpenRequest {
    type Response = RpcResult<OpenResponse>;
}

/// Response to [`OpenRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct OpenResponse {}

/// Open a document
#[derive(Serialize, Deserialize, Debug)]
pub struct CloseRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<RpcService> for CloseRequest {
    type Response = RpcResult<CloseResponse>;
}

/// Response to [`CloseRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct CloseResponse {}

/// Start to sync a doc with peers.
#[derive(Serialize, Deserialize, Debug)]
pub struct StartSyncRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// List of peers to join
    pub peers: Vec<NodeAddr>,
}

impl RpcMsg<RpcService> for StartSyncRequest {
    type Response = RpcResult<StartSyncResponse>;
}

/// Response to [`StartSyncRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct StartSyncResponse {}

/// Stop the live sync for a doc, and optionally delete the document.
#[derive(Serialize, Deserialize, Debug)]
pub struct LeaveRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<RpcService> for LeaveRequest {
    type Response = RpcResult<LeaveResponse>;
}

/// Response to [`LeaveRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct LeaveResponse {}

/// Stop the live sync for a doc, and optionally delete the document.
#[derive(Serialize, Deserialize, Debug)]
pub struct DropRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<RpcService> for DropRequest {
    type Response = RpcResult<DropResponse>;
}

/// Response to [`DropRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DropResponse {}

/// Set an entry in a document
#[derive(Serialize, Deserialize, Debug)]
pub struct SetRequest {
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

impl RpcMsg<RpcService> for SetRequest {
    type Response = RpcResult<SetResponse>;
}

/// Response to [`SetRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct SetResponse {
    /// The newly-created entry.
    pub entry: SignedEntry,
}

/// A request to the node to add the data at the given filepath as an entry to the document
///
/// Will produce a stream of [`ImportProgress`] messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportFileRequest {
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

impl Msg<RpcService> for ImportFileRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for ImportFileRequest {
    type Response = ImportFileResponse;
}

/// Wrapper around [`ImportProgress`].
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct ImportFileResponse(pub ImportProgress);

/// A request to the node to save the data of the entry to the given filepath
///
/// Will produce a stream of [`ExportFileResponse`] messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportFileRequest {
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

impl Msg<RpcService> for ExportFileRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for ExportFileRequest {
    type Response = ExportFileResponse;
}

/// Progress messages for an doc export operation
///
/// An export operation involves reading the entry from the database ans saving the entry to the
/// given `outpath`
#[derive(Debug, Serialize, Deserialize, derive_more::Into)]
pub struct ExportFileResponse(pub ExportProgress);

/// Delete entries in a document
#[derive(Serialize, Deserialize, Debug)]
pub struct DelRequest {
    /// The document id.
    pub doc_id: NamespaceId,
    /// Author of this entry.
    pub author_id: AuthorId,
    /// Prefix to delete.
    pub prefix: Bytes,
}

impl RpcMsg<RpcService> for DelRequest {
    type Response = RpcResult<DelResponse>;
}

/// Response to [`DelRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DelResponse {
    /// The number of entries that were removed.
    pub removed: usize,
}

/// Set an entry in a document via its hash
#[derive(Serialize, Deserialize, Debug)]
pub struct SetHashRequest {
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

impl RpcMsg<RpcService> for SetHashRequest {
    type Response = RpcResult<SetHashResponse>;
}

/// Response to [`SetHashRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct SetHashResponse {}

/// Get entries from a document
#[derive(Serialize, Deserialize, Debug)]
pub struct GetManyRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Query to run
    pub query: Query,
}

impl Msg<RpcService> for GetManyRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for GetManyRequest {
    type Response = RpcResult<GetManyResponse>;
}

/// Response to [`GetManyRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct GetManyResponse {
    /// The document entry
    pub entry: SignedEntry,
}

/// Get entries from a document
#[derive(Serialize, Deserialize, Debug)]
pub struct GetExactRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Key matcher
    pub key: Bytes,
    /// Author matcher
    pub author: AuthorId,
    /// Whether to include empty entries (prefix deletion markers)
    pub include_empty: bool,
}

impl RpcMsg<RpcService> for GetExactRequest {
    type Response = RpcResult<GetExactResponse>;
}

/// Response to [`GetExactRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct GetExactResponse {
    /// The document entry
    pub entry: Option<SignedEntry>,
}

/// Set a download policy
#[derive(Serialize, Deserialize, Debug)]
pub struct SetDownloadPolicyRequest {
    /// The document id
    pub doc_id: NamespaceId,
    /// Download policy
    pub policy: DownloadPolicy,
}

impl RpcMsg<RpcService> for SetDownloadPolicyRequest {
    type Response = RpcResult<SetDownloadPolicyResponse>;
}

/// Response to [`SetDownloadPolicyRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct SetDownloadPolicyResponse {}

/// Get a download policy
#[derive(Serialize, Deserialize, Debug)]
pub struct GetDownloadPolicyRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<RpcService> for GetDownloadPolicyRequest {
    type Response = RpcResult<GetDownloadPolicyResponse>;
}

/// Response to [`GetDownloadPolicyRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct GetDownloadPolicyResponse {
    /// The download policy
    pub policy: DownloadPolicy,
}

/// Get peers for document
#[derive(Serialize, Deserialize, Debug)]
pub struct GetSyncPeersRequest {
    /// The document id
    pub doc_id: NamespaceId,
}

impl RpcMsg<RpcService> for GetSyncPeersRequest {
    type Response = RpcResult<GetSyncPeersResponse>;
}

/// Response to [`GetSyncPeersRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct GetSyncPeersResponse {
    /// List of peers ids
    pub peers: Option<Vec<PeerIdBytes>>,
}

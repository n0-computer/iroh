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
use nested_enum_utils::enum_conversions;
use quic_rpc::pattern::try_server_streaming::StreamCreated;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use super::RpcService;
use crate::client::docs::{ImportProgress, ShareMode};

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[rpc(response = RpcResult<OpenResponse>)]
    Open(OpenRequest),
    #[rpc(response = RpcResult<CloseResponse>)]
    Close(CloseRequest),
    #[rpc(response = RpcResult<StatusResponse>)]
    Status(StatusRequest),
    #[server_streaming(response = RpcResult<ListResponse>)]
    List(DocListRequest),
    #[rpc(response = RpcResult<CreateResponse>)]
    Create(CreateRequest),
    #[rpc(response = RpcResult<DropResponse>)]
    Drop(DropRequest),
    #[rpc(response = RpcResult<ImportResponse>)]
    Import(ImportRequest),
    #[rpc(response = RpcResult<SetResponse>)]
    Set(SetRequest),
    #[rpc(response = RpcResult<SetHashResponse>)]
    SetHash(SetHashRequest),
    #[server_streaming(response = RpcResult<GetManyResponse>)]
    Get(GetManyRequest),
    #[rpc(response = RpcResult<GetExactResponse>)]
    GetExact(GetExactRequest),
    #[server_streaming(response = ImportFileResponse)]
    ImportFile(ImportFileRequest),
    #[server_streaming(response = ExportFileResponse)]
    ExportFile(ExportFileRequest),
    #[rpc(response = RpcResult<DelResponse>)]
    Del(DelRequest),
    #[rpc(response = RpcResult<StartSyncResponse>)]
    StartSync(StartSyncRequest),
    #[rpc(response = RpcResult<LeaveResponse>)]
    Leave(LeaveRequest),
    #[rpc(response = RpcResult<ShareResponse>)]
    Share(ShareRequest),
    #[try_server_streaming(create_error = RpcError, item_error = RpcError, item = DocSubscribeResponse)]
    Subscribe(DocSubscribeRequest),
    #[rpc(response = RpcResult<GetDownloadPolicyResponse>)]
    GetDownloadPolicy(GetDownloadPolicyRequest),
    #[rpc(response = RpcResult<SetDownloadPolicyResponse>)]
    SetDownloadPolicy(SetDownloadPolicyRequest),
    #[rpc(response = RpcResult<GetSyncPeersResponse>)]
    GetSyncPeers(GetSyncPeersRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Response)]
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

/// Response to [`DocSubscribeRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSubscribeResponse {
    /// The event that occurred on the document
    pub event: LiveEvent,
}

/// List all documents
#[derive(Serialize, Deserialize, Debug)]
pub struct DocListRequest {}

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

/// Response to [`CreateRequest`]
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

/// Response to [`ImportRequest`]
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

/// The response to [`ShareRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct ShareResponse(pub DocTicket);

/// Get info on a document
#[derive(Serialize, Deserialize, Debug)]
pub struct StatusRequest {
    /// The document id
    pub doc_id: NamespaceId,
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

/// Response to [`OpenRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct OpenResponse {}

/// Open a document
#[derive(Serialize, Deserialize, Debug)]
pub struct CloseRequest {
    /// The document id
    pub doc_id: NamespaceId,
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

/// Response to [`StartSyncRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct StartSyncResponse {}

/// Stop the live sync for a doc, and optionally delete the document.
#[derive(Serialize, Deserialize, Debug)]
pub struct LeaveRequest {
    /// The document id
    pub doc_id: NamespaceId,
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

/// Response to [`SetDownloadPolicyRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct SetDownloadPolicyResponse {}

/// Get a download policy
#[derive(Serialize, Deserialize, Debug)]
pub struct GetDownloadPolicyRequest {
    /// The document id
    pub doc_id: NamespaceId,
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

/// Response to [`GetSyncPeersRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct GetSyncPeersResponse {
    /// List of peers ids
    pub peers: Option<Vec<PeerIdBytes>>,
}

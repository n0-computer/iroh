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
    Open(DocOpenRequest),
    Close(DocCloseRequest),
    Status(DocStatusRequest),
    List(DocListRequest),
    Create(DocCreateRequest),
    Drop(DocDropRequest),
    Import(DocImportRequest),
    Set(DocSetRequest),
    SetHash(DocSetHashRequest),
    Get(DocGetManyRequest),
    GetExact(DocGetExactRequest),
    ImportFile(DocImportFileRequest),
    ExportFile(DocExportFileRequest),
    Del(DocDelRequest),
    StartSync(DocStartSyncRequest),
    Leave(DocLeaveRequest),
    Share(DocShareRequest),
    Subscribe(DocSubscribeRequest),
    GetDownloadPolicy(DocGetDownloadPolicyRequest),
    SetDownloadPolicy(DocSetDownloadPolicyRequest),
    GetSyncPeers(DocGetSyncPeersRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Response)]
pub enum Response {
    Open(RpcResult<DocOpenResponse>),
    Close(RpcResult<DocCloseResponse>),
    Status(RpcResult<DocStatusResponse>),
    List(RpcResult<DocListResponse>),
    Create(RpcResult<DocCreateResponse>),
    Drop(RpcResult<DocDropResponse>),
    Import(RpcResult<DocImportResponse>),
    Set(RpcResult<DocSetResponse>),
    SetHash(RpcResult<DocSetHashResponse>),
    Get(RpcResult<DocGetManyResponse>),
    GetExact(RpcResult<DocGetExactResponse>),
    ImportFile(DocImportFileResponse),
    ExportFile(DocExportFileResponse),
    Del(RpcResult<DocDelResponse>),
    Share(RpcResult<DocShareResponse>),
    StartSync(RpcResult<DocStartSyncResponse>),
    Leave(RpcResult<DocLeaveResponse>),
    Subscribe(RpcResult<DocSubscribeResponse>),
    GetDownloadPolicy(RpcResult<DocGetDownloadPolicyResponse>),
    SetDownloadPolicy(RpcResult<DocSetDownloadPolicyResponse>),
    GetSyncPeers(RpcResult<DocGetSyncPeersResponse>),
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

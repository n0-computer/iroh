#![allow(missing_docs)]

//! This defines the RPC protocol used for communication between a CLI and an iroh node.
//!
//! RPC using the [`quic-rpc`](https://docs.rs/quic-rpc) crate.
//!
//! This file contains request messages, response messages and definitions of
//! the interaction pattern. Some requests like version and shutdown have a single
//! response, while others like provide have a stream of responses.
//!
//! Note that this is subject to change. The RPC protocol is not yet stable.
use std::{net::SocketAddr, path::PathBuf};

use bytes::Bytes;
use derive_more::{From, TryInto};
use iroh_bytes::Hash;
use iroh_net::tls::PeerId;

use iroh_sync::{
    store::GetFilter,
    sync::{AuthorId, NamespaceId, SignedEntry},
};
use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming, ServerStreamingMsg},
    Service,
};
use serde::{Deserialize, Serialize};

pub use iroh_bytes::{
    provider::{ProvideProgress, ValidateProgress},
    util::RpcResult,
};

use crate::sync::PeerSource;

/// A 32-byte key or token
pub type KeyBytes = [u8; 32];

/// A request to the node to provide the data at the given path
///
/// Will produce a stream of [`ProvideProgress`] messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvideRequest {
    /// The path to the data to provide.
    ///
    /// This should be an absolute path valid for the file system on which
    /// the node runs. Usually the cli will run on the same machine as the
    /// node, so this should be an absolute path on the cli machine.
    pub path: PathBuf,
}

impl Msg<ProviderService> for ProvideRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ProvideRequest {
    type Response = ProvideProgress;
}

/// A request to the node to validate the integrity of all provided data
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateRequest;

impl Msg<ProviderService> for ValidateRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ValidateRequest {
    type Response = ValidateProgress;
}

/// List all blobs, including collections
#[derive(Debug, Serialize, Deserialize)]
pub struct ListBlobsRequest;

/// A response to a list blobs request
#[derive(Debug, Serialize, Deserialize)]
pub struct ListBlobsResponse {
    /// Location of the blob
    pub path: String,
    /// The hash of the blob
    pub hash: Hash,
    /// The size of the blob
    pub size: u64,
}

impl Msg<ProviderService> for ListBlobsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ListBlobsRequest {
    type Response = ListBlobsResponse;
}

/// List all collections
///
/// Lists all collections that have been explicitly added to the database.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListCollectionsRequest;

/// A response to a list collections request
#[derive(Debug, Serialize, Deserialize)]
pub struct ListCollectionsResponse {
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

impl Msg<ProviderService> for ListCollectionsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ListCollectionsRequest {
    type Response = ListCollectionsResponse;
}

/// A request to watch for the node status
#[derive(Serialize, Deserialize, Debug)]
pub struct WatchRequest;

/// A request to get the version of the node
#[derive(Serialize, Deserialize, Debug)]
pub struct VersionRequest;

impl RpcMsg<ProviderService> for VersionRequest {
    type Response = VersionResponse;
}

/// A request to shutdown the node
#[derive(Serialize, Deserialize, Debug)]
pub struct ShutdownRequest {
    /// Force shutdown
    pub force: bool,
}

impl RpcMsg<ProviderService> for ShutdownRequest {
    type Response = ();
}

/// A request to get information about the identity of the node
///
/// See [`IdResponse`] for the response.
#[derive(Serialize, Deserialize, Debug)]
pub struct IdRequest;

impl RpcMsg<ProviderService> for IdRequest {
    type Response = IdResponse;
}

/// A request to get the addresses of the node
#[derive(Serialize, Deserialize, Debug)]
pub struct AddrsRequest;

impl RpcMsg<ProviderService> for AddrsRequest {
    type Response = AddrsResponse;
}

/// The response to a watch request
#[derive(Serialize, Deserialize, Debug)]
pub struct WatchResponse {
    /// The version of the node
    pub version: String,
}

/// The response to a version request
#[derive(Serialize, Deserialize, Debug)]
pub struct IdResponse {
    /// The peer id of the node
    pub peer_id: Box<PeerId>,
    /// The addresses of the node
    pub listen_addrs: Vec<SocketAddr>,
    /// The version of the node
    pub version: String,
}

/// The response to an addrs request
#[derive(Serialize, Deserialize, Debug)]
pub struct AddrsResponse {
    /// The addresses of the node
    pub addrs: Vec<SocketAddr>,
}

impl Msg<ProviderService> for WatchRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for WatchRequest {
    type Response = WatchResponse;
}

/// The response to a version request
#[derive(Serialize, Deserialize, Debug)]
pub struct VersionResponse {
    /// The version of the node
    pub version: String,
}

// peer

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct PeerAddRequest {
    pub peer_id: PeerId,
    pub addrs: Vec<SocketAddr>,
    pub region: Option<u16>,
}

impl RpcMsg<ProviderService> for PeerAddRequest {
    type Response = RpcResult<PeerAddResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct PeerAddResponse {}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct PeerListRequest {}

impl Msg<ProviderService> for PeerListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for PeerListRequest {
    type Response = RpcResult<PeerListResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct PeerListResponse {
    pub peer_id: PeerId,
}

// author

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorListRequest {}

impl Msg<ProviderService> for AuthorListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for AuthorListRequest {
    type Response = RpcResult<AuthorListResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorListResponse {
    pub author_id: AuthorId,
    pub writable: bool,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorCreateRequest;

impl RpcMsg<ProviderService> for AuthorCreateRequest {
    type Response = RpcResult<AuthorCreateResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorCreateResponse {
    pub author_id: AuthorId,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorImportRequest {
    // either a public or private key
    pub key: KeyBytes,
}

impl RpcMsg<ProviderService> for AuthorImportRequest {
    type Response = RpcResult<AuthorImportResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorImportResponse {
    pub author_id: AuthorId,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorShareRequest {
    pub author: AuthorId,
    pub mode: ShareMode,
}

/// todo
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "cli", clap::ValueEnum)]
pub enum ShareMode {
    /// Read-only access
    Read,
    /// Write access
    Write,
}

impl RpcMsg<ProviderService> for AuthorShareRequest {
    type Response = RpcResult<AuthorShareResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorShareResponse {
    pub key: KeyBytes,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocsListRequest {}

impl Msg<ProviderService> for DocsListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for DocsListRequest {
    type Response = RpcResult<DocsListResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocsListResponse {
    pub id: NamespaceId,
    // pub writable: bool,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocsCreateRequest {}

impl RpcMsg<ProviderService> for DocsCreateRequest {
    type Response = RpcResult<DocsCreateResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocsCreateResponse {
    pub id: NamespaceId,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocImportRequest {
    // either a public or private key
    pub key: KeyBytes,
    pub peers: Vec<PeerSource>,
}

impl RpcMsg<ProviderService> for DocImportRequest {
    type Response = RpcResult<DocImportResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocImportResponse {
    pub doc_id: NamespaceId,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocShareRequest {
    pub doc_id: NamespaceId,
    pub mode: ShareMode,
}

impl RpcMsg<ProviderService> for DocShareRequest {
    type Response = RpcResult<DocShareResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocShareResponse {
    pub key: KeyBytes,
    pub peer: PeerSource,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocStartSyncRequest {
    pub doc_id: NamespaceId,
    pub peers: Vec<PeerSource>,
}

impl RpcMsg<ProviderService> for DocStartSyncRequest {
    type Response = RpcResult<DocStartSyncResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocStartSyncResponse {}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSetRequest {
    pub doc_id: NamespaceId,
    pub author_id: AuthorId,
    pub key: Vec<u8>,
    // todo: different forms to supply value
    pub value: Vec<u8>,
}

impl RpcMsg<ProviderService> for DocSetRequest {
    type Response = RpcResult<DocSetResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocSetResponse {
    pub entry: SignedEntry,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetRequest {
    pub doc_id: NamespaceId,
    pub filter: GetFilter,
}

impl Msg<ProviderService> for DocGetRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for DocGetRequest {
    type Response = RpcResult<DocGetResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct DocGetResponse {
    pub entry: SignedEntry,
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct BytesGetRequest {
    pub hash: Hash,
}

impl RpcMsg<ProviderService> for BytesGetRequest {
    type Response = RpcResult<BytesGetResponse>;
}

/// todo
#[derive(Serialize, Deserialize, Debug)]
pub struct BytesGetResponse {
    pub data: Bytes,
}

/// The RPC service for the iroh provider process.
#[derive(Debug, Clone)]
pub struct ProviderService;

/// The request enum, listing all possible requests.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize, From, TryInto)]
pub enum ProviderRequest {
    Watch(WatchRequest),
    Version(VersionRequest),
    ListBlobs(ListBlobsRequest),
    ListCollections(ListCollectionsRequest),
    Provide(ProvideRequest),
    Id(IdRequest),
    Addrs(AddrsRequest),
    Shutdown(ShutdownRequest),
    Validate(ValidateRequest),

    PeerAdd(PeerAddRequest),
    PeerList(PeerListRequest),

    AuthorList(AuthorListRequest),
    AuthorCreate(AuthorCreateRequest),
    AuthorImport(AuthorImportRequest),
    AuthorShare(AuthorShareRequest),

    DocsList(DocsListRequest),
    DocsCreate(DocsCreateRequest),
    DocsImport(DocImportRequest),

    DocSet(DocSetRequest),
    DocGet(DocGetRequest),
    DocStartSync(DocStartSyncRequest), // DocGetContent(DocGetContentRequest),
    DocShare(DocShareRequest),         // DocGetContent(DocGetContentRequest),

    BytesGet(BytesGetRequest),
}

/// The response enum, listing all possible responses.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize, From, TryInto)]
pub enum ProviderResponse {
    Watch(WatchResponse),
    Version(VersionResponse),
    ListBlobs(ListBlobsResponse),
    ListCollections(ListCollectionsResponse),
    Provide(ProvideProgress),
    Id(IdResponse),
    Addrs(AddrsResponse),
    Validate(ValidateProgress),
    Shutdown(()),

    // TODO: I see I changed naming convention here but at least to me it becomes easier to parse
    // with the subject in front if there's many commands
    PeerAdd(RpcResult<PeerAddResponse>),
    PeerList(RpcResult<PeerListResponse>),

    AuthorList(RpcResult<AuthorListResponse>),
    AuthorCreate(RpcResult<AuthorCreateResponse>),
    AuthorImport(RpcResult<AuthorImportResponse>),
    AuthorShare(RpcResult<AuthorShareResponse>),

    DocsList(RpcResult<DocsListResponse>),
    DocsCreate(RpcResult<DocsCreateResponse>),
    DocsImport(RpcResult<DocImportResponse>),

    DocSet(RpcResult<DocSetResponse>),
    DocGet(RpcResult<DocGetResponse>),
    DocJoin(RpcResult<DocStartSyncResponse>),
    DocShare(RpcResult<DocShareResponse>),

    BytesGet(RpcResult<BytesGetResponse>), // DocGetContent(DocGetContentResponse),
}

impl Service for ProviderService {
    type Req = ProviderRequest;
    type Res = ProviderResponse;
}

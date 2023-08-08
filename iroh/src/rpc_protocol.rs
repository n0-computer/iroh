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

use derive_more::{From, TryInto};
use iroh_bytes::{protocol::RequestToken, provider::ShareProgress, Hash};
use iroh_net::tls::PeerId;

use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming, ServerStreamingMsg},
    Service,
};
use serde::{Deserialize, Serialize};

pub use iroh_bytes::provider::{ProvideProgress, ValidateProgress};

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
    /// True if the provider can assume that the data will not change, so it
    /// can be shared in place.
    pub in_place: bool,
}

impl Msg<ProviderService> for ProvideRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ProvideRequest {
    type Response = ProvideProgress;
}

/// A request to the node to download and share the data specified by the hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRequest {
    /// This mandatory field contains the hash of the data to download and share.
    pub hash: Hash,
    /// If this flag is true, the hash is assumed to be a collection and all
    /// children are downloaded and shared as well.
    pub recursive: bool,
    /// This mandatory field specifies the peer to download the data from.
    pub peer: PeerId,
    /// This vec contains possible candidate addresses of the peer.
    pub addrs: Vec<SocketAddr>,
    /// If this flag is true, the data is downloaded even if it is already
    /// available locally.
    pub force: bool,
    /// This optional field contains a request token that can be used to authorize
    /// the download request.
    pub token: Option<RequestToken>,
    /// This optional field contains the derp region to use for contacting the peer
    /// over the DERP protocol.
    pub derp_region: Option<u16>,
    /// This optional field contains the path to store the data to. If it is not
    /// set, the data is dumped to stdout.
    pub out: Option<String>,
    /// If this flag is true, the data is shared in place, i.e. it is moved to the
    /// out path instead of being copied. The database itself contains only a
    /// reference to the out path of the file.
    ///
    /// If the data is modified in the location specified by the out path,
    /// download attempts for the associated hash will fail.
    ///
    /// This flag is only relevant if the out path is set.
    pub in_place: bool,
}

impl Msg<ProviderService> for ShareRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ShareRequest {
    type Response = ShareProgress;
}

/// A request to the node to validate the integrity of all provided data
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateRequest {
    /// If true, remove invalid data
    pub repair: bool,
}

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

/// List all blobs, including collections
#[derive(Debug, Serialize, Deserialize)]
pub struct ListIncompleteBlobsRequest;

/// A response to a list blobs request
#[derive(Debug, Serialize, Deserialize)]
pub struct ListIncompleteBlobsResponse {
    /// Location of the blob
    pub path: String,
    /// The size we got
    pub size: u64,
    /// The size we expect
    pub expected_size: u64,
    /// The hash of the blob
    pub hash: Hash,
}

impl Msg<ProviderService> for ListIncompleteBlobsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ListIncompleteBlobsRequest {
    type Response = ListIncompleteBlobsResponse;
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
    ListIncompleteBlobs(ListIncompleteBlobsRequest),
    ListCollections(ListCollectionsRequest),
    Provide(ProvideRequest),
    Share(ShareRequest),
    Id(IdRequest),
    Addrs(AddrsRequest),
    Shutdown(ShutdownRequest),
    Validate(ValidateRequest),
}

/// The response enum, listing all possible responses.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize, From, TryInto)]
pub enum ProviderResponse {
    Watch(WatchResponse),
    Version(VersionResponse),
    ListBlobs(ListBlobsResponse),
    ListIncompleteBlobs(ListIncompleteBlobsResponse),
    ListCollections(ListCollectionsResponse),
    Provide(ProvideProgress),
    Share(ShareProgress),
    Id(IdResponse),
    Addrs(AddrsResponse),
    Validate(ValidateProgress),
    Shutdown(()),
}

impl Service for ProviderService {
    type Req = ProviderRequest;
    type Res = ProviderResponse;
}

#![allow(missing_docs)]
use std::{net::SocketAddr, path::PathBuf};

use derive_more::{From, TryInto};
use iroh_bytes::Hash;
use iroh_net::tls::PeerId;

use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming, ServerStreamingMsg},
    Service,
};
use serde::{Deserialize, Serialize};

pub use iroh_bytes::provider::{ProvideProgress, ValidateProgress};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvideRequest {
    pub path: PathBuf,
}

impl Msg<ProviderService> for ProvideRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ProvideRequest {
    type Response = ProvideProgress;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateRequest;

impl Msg<ProviderService> for ValidateRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ValidateRequest {
    type Response = ValidateProgress;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListBlobsRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ListBlobsResponse {
    pub path: String,
    pub hash: Hash,
    pub size: u64,
}

impl Msg<ProviderService> for ListBlobsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ListBlobsRequest {
    type Response = ListBlobsResponse;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListCollectionsRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ListCollectionsResponse {
    pub hash: Hash,
    pub total_blobs_count: u64,
    pub total_blobs_size: u64,
}

impl Msg<ProviderService> for ListCollectionsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ListCollectionsRequest {
    type Response = ListCollectionsResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WatchRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionRequest;

impl RpcMsg<ProviderService> for VersionRequest {
    type Response = VersionResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShutdownRequest {
    pub force: bool,
}

impl RpcMsg<ProviderService> for ShutdownRequest {
    type Response = ();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IdRequest;

impl RpcMsg<ProviderService> for IdRequest {
    type Response = IdResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddrsRequest;

impl RpcMsg<ProviderService> for AddrsRequest {
    type Response = AddrsResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WatchResponse {
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IdResponse {
    pub peer_id: Box<PeerId>,
    pub listen_addrs: Vec<SocketAddr>,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddrsResponse {
    pub addrs: Vec<SocketAddr>,
}

impl Msg<ProviderService> for WatchRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for WatchRequest {
    type Response = WatchResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionResponse {
    pub version: String,
}

/// The RPC service for the iroh provider process.
#[derive(Debug, Clone)]
pub struct ProviderService;

/// Request enum
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
}

/// Response enum
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
}

impl Service for ProviderService {
    type Req = ProviderRequest;
    type Res = ProviderResponse;
}

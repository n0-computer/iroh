#![allow(missing_docs)]
use std::{net::SocketAddr, path::PathBuf};

use crate::{util::RpcError, Hash, PeerId};
use derive_more::{From, TryInto};
use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming, ServerStreamingMsg},
    Service,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvideRequest {
    pub path: PathBuf,
}

/// Progress updates for the provide operation
#[derive(Debug, Serialize, Deserialize)]
pub enum ProvideProgress {
    /// An item was found with name `name`, from now on referred to via `id`
    Found { name: String, id: u64, size: u64 },
    /// We got progress ingesting item `id`
    Progress { id: u64, offset: u64 },
    /// We are done with `id`, and the hash is `hash`
    Done { id: u64, hash: Hash },
    /// We are done with the whole operation
    AllDone { hash: Hash },
    /// We got an error and need to abort
    Abort(RpcError),
}

impl Msg<ProviderService> for ProvideRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ProvideRequest {
    type Response = ProvideProgress;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateRequest;

/// Progress updates for the provide operation
#[derive(Debug, Serialize, Deserialize)]
pub enum ValidateProgress {
    /// started validating
    Starting { total: u64 },
    /// We started validating an entry
    Entry {
        id: u64,
        hash: Hash,
        path: Option<PathBuf>,
        size: u64,
    },
    /// We got progress ingesting item `id`
    Progress { id: u64, offset: u64 },
    /// We are done with `id`
    Done { id: u64, error: Option<String> },
    /// We are done with the whole operation
    AllDone,
    /// We got an error and need to abort
    Abort(RpcError),
}

impl Msg<ProviderService> for ValidateRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ValidateRequest {
    type Response = ValidateProgress;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ListResponse {
    pub path: PathBuf,
    pub hash: Hash,
    pub size: u64,
}

impl Msg<ProviderService> for ListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<ProviderService> for ListRequest {
    type Response = ListResponse;
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
    pub listen_addr: Box<SocketAddr>,
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
    List(ListRequest),
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
    List(ListResponse),
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

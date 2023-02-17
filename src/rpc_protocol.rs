#![allow(missing_docs)]
use std::path::PathBuf;

use crate::{util::RpcResult, Hash};
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvideResponse {
    pub hash: Hash,
}

impl RpcMsg<SendmeService> for ProvideRequest {
    type Response = RpcResult<ProvideResponse>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct ListResponse {
    pub path: PathBuf,
    pub hash: Hash,
    pub size: u64,
}

impl Msg<SendmeService> for ListRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<SendmeService> for ListRequest {
    type Response = ListResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WatchRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionRequest;

impl RpcMsg<SendmeService> for VersionRequest {
    type Response = VersionResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WatchResponse {
    pub version: String,
}

impl Msg<SendmeService> for WatchRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<SendmeService> for WatchRequest {
    type Response = WatchResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionResponse {
    pub version: String,
}

/// The RPC service for sendme.
#[derive(Debug, Clone)]
pub struct SendmeService;

/// Request enum
#[derive(Debug, Serialize, Deserialize, From, TryInto)]
pub enum SendmeRequest {
    Watch(WatchRequest),
    Version(VersionRequest),
    List(ListRequest),
    Provide(ProvideRequest),
}

/// Response enum
#[derive(Debug, Serialize, Deserialize, From, TryInto)]
pub enum SendmeResponse {
    Watch(WatchResponse),
    Version(VersionResponse),
    List(ListResponse),
    Provide(RpcResult<ProvideResponse>),
}

impl Service for SendmeService {
    type Req = SendmeRequest;
    type Res = SendmeResponse;
}

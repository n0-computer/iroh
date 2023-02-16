//!
use std::path::PathBuf;

use crate::Hash;
use derive_more::{From, TryInto};
use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming},
    Service,
};
use serde::{Deserialize, Serialize};

///
#[derive(Debug, Clone)]
pub struct SendmeService;

impl Service for SendmeService {
    type Req = SendmeRequest;
    type Res = SendmeResponse;
}

///
#[derive(Debug, Serialize, Deserialize, From, TryInto)]
pub enum SendmeRequest {
    ///
    List(ListRequest),
    ///
    Provide(ProvideRequest),
}

///
#[derive(Debug, Serialize, Deserialize)]
pub struct ListRequest;

///
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvideRequest {
    ///
    pub path: PathBuf,
}

///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProvideResponse {
    ///
    pub hash: Hash,
}

impl Msg<SendmeService> for ListRequest {
    type Pattern = ServerStreaming;
    type Update = Self;
    type Response = ListResponse;
}

impl RpcMsg<SendmeService> for ProvideRequest {
    type Response = ProvideResponse;
}

///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    ///
    pub path: PathBuf,
    ///
    pub hash: Hash,
    ///
    pub size: u64,
}

///
#[derive(Debug, Clone, Serialize, Deserialize, From, TryInto)]
pub enum SendmeResponse {
    ///
    List(ListResponse),
    ///
    Provide(ProvideResponse),
}

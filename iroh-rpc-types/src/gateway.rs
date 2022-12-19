use derive_more::{From, TryInto};
use quic_rpc::{
    message::{Msg, RpcMsg, ServerStreaming},
    Service,
};
use serde::{Deserialize, Serialize};

use crate::{RpcResult, VersionRequest, VersionResponse, WatchRequest, WatchResponse};

/// Gateway address
pub type GatewayAddr = crate::addr::Addr<GatewayService>;

#[derive(Serialize, Deserialize, Debug, From, TryInto)]
pub enum GatewayRequest {
    Watch(WatchRequest),
    Version(VersionRequest),
}

#[derive(Serialize, Deserialize, Debug, From, TryInto)]
pub enum GatewayResponse {
    Watch(WatchResponse),
    Version(VersionResponse),
    UnitResult(RpcResult<()>),
}

#[derive(Debug, Clone, Copy)]
pub struct GatewayService;

impl Service for GatewayService {
    type Req = GatewayRequest;
    type Res = GatewayResponse;
}

impl RpcMsg<GatewayService> for VersionRequest {
    type Response = VersionResponse;
}

impl Msg<GatewayService> for WatchRequest {
    type Response = WatchResponse;

    type Update = Self;

    type Pattern = ServerStreaming;
}

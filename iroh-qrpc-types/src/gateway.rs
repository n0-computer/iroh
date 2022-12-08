use derive_more::{From, TryInto};
use quic_rpc::{message::RpcMsg, Service};
use serde::{Deserialize, Serialize};

/// Gateway client address
pub type GatewayClientAddr = crate::addr::Addr<GatewayResponse, GatewayRequest>;
/// Gateway server address
pub type GatewayServerAddr = crate::addr::Addr<GatewayRequest, GatewayResponse>;

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionResponse {
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, From, TryInto)]
pub enum GatewayRequest {
    Version(VersionRequest),
}

#[derive(Serialize, Deserialize, Debug, From, TryInto)]
pub enum GatewayResponse {
    Version(VersionResponse),
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

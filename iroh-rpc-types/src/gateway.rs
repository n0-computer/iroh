use derive_more::{From, TryInto};
use quic_rpc::{message::RpcMsg, Service};
use serde::{Deserialize, Serialize};

pub type GatewayClientAddr = super::addr::Addr<GatewayResponse, GatewayRequest>;
pub type GatewayServerAddr = super::addr::Addr<GatewayRequest, GatewayResponse>;

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

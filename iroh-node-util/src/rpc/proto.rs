use nested_enum_utils::enum_conversions;
use serde::{Deserialize, Serialize};

pub mod net;
pub mod node;

pub(crate) type RpcError = serde_error::Error;
pub(crate) type RpcResult<T> = Result<T, RpcError>;

#[derive(Debug, Serialize, Deserialize)]
#[enum_conversions]
pub enum Request {
    Net(net::Request),
    Node(node::Request),
}

#[derive(Debug, Serialize, Deserialize)]
#[enum_conversions]
pub enum Response {
    Net(net::Response),
    Node(node::Response),
}

#[derive(Debug, Clone, Copy)]
pub struct RpcService {}

impl quic_rpc::Service for RpcService {
    type Req = Request;
    type Res = Response;
}

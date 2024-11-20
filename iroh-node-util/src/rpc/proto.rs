//! RPC protocol definitions for controlling iroh-net endpoints and iroh nodes
use nested_enum_utils::enum_conversions;
use serde::{Deserialize, Serialize};

pub mod net;
pub mod node;

pub(crate) type RpcError = serde_error::Error;
pub(crate) type RpcResult<T> = Result<T, RpcError>;

/// Request, either net or node
#[derive(Debug, Serialize, Deserialize)]
#[enum_conversions]
#[allow(missing_docs)]
pub enum Request {
    Net(net::Request),
    Node(node::Request),
}

/// Response, either net or node
#[derive(Debug, Serialize, Deserialize)]
#[enum_conversions]
#[allow(missing_docs)]
pub enum Response {
    Net(net::Response),
    Node(node::Response),
}

/// The RPC service
#[derive(Debug, Clone, Copy)]
pub struct RpcService {}

impl quic_rpc::Service for RpcService {
    type Req = Request;
    type Res = Response;
}

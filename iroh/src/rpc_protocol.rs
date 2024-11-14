//! This defines the RPC protocol used for communication between a CLI and an iroh node.
//!
//! RPC is done using the [`quic-rpc`](https://docs.rs/quic-rpc) crate.
//!
//! The RPC protocol is split into subsystems. In each subsystem, there is an
//! enum for the requests and an enum for the responses. The top level request
//! and response enums have a variant for each subsystem.
//!
//! Request and response enums for each subsystem derive conversions to the
//! top level enums using the
//! [`enum_conversions``](https://docs.rs/nested_enum_utils/0.1.0/nested_enum_utils/attr.enum_conversions.html)
//! macro.
//!
//! For each rpc request, the quic-rpc interaction pattern is defined using
//! attributes provided by the
//! [`rpc_requests`](https://docs.rs/quic-rpc-derive/latest/quic_rpc_derive/attr.rpc_requests.html)
//! macro.
use serde::{Deserialize, Serialize};

/// The RPC service for the iroh provider process.
#[derive(Debug, Clone)]
pub struct RpcService;

/// The request enum, listing all possible requests.
#[allow(missing_docs, clippy::large_enum_variant)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions()]
pub enum Request {
    Node(iroh_node_util::rpc::proto::Request),
    Gossip(iroh_gossip::RpcRequest),
    Docs(iroh_docs::rpc::proto::Request),
    BlobsAndTags(iroh_blobs::rpc::proto::Request),
}

/// The response enum, listing all possible responses.
#[allow(missing_docs, clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions()]
pub enum Response {
    Node(iroh_node_util::rpc::proto::Response),
    Gossip(iroh_gossip::RpcResponse),
    Docs(iroh_docs::rpc::proto::Response),
    BlobsAndTags(iroh_blobs::rpc::proto::Response),
}

impl quic_rpc::Service for RpcService {
    type Req = Request;
    type Res = Response;
}

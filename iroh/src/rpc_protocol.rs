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

pub mod authors;
pub mod blobs;
pub mod docs;
pub mod gossip;
pub mod net;
pub mod node;
pub mod spaces;
pub mod tags;

/// The RPC service for the iroh provider process.
#[derive(Debug, Clone)]
pub struct RpcService;

/// The request enum, listing all possible requests.
#[allow(missing_docs, clippy::large_enum_variant)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions()]
pub enum Request {
    Node(node::Request),
    Net(net::Request),
    Blobs(blobs::Request),
    Docs(docs::Request),
    Tags(tags::Request),
    Authors(authors::Request),
    Gossip(gossip::Request),
    Spaces(spaces::Request),
}

/// The response enum, listing all possible responses.
#[allow(missing_docs, clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions()]
pub enum Response {
    Node(node::Response),
    Net(net::Response),
    Blobs(blobs::Response),
    Tags(tags::Response),
    Docs(docs::Response),
    Authors(authors::Response),
    Gossip(gossip::Response),
    Spaces(spaces::Response),
}

impl quic_rpc::Service for RpcService {
    type Req = Request;
    type Res = Response;
}

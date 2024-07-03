//! This defines the RPC protocol used for communication between a CLI and an iroh node.
//!
//! RPC using the [`quic-rpc`](https://docs.rs/quic-rpc) crate.
//!
//! This file contains request messages, response messages and definitions of
//! the interaction pattern. Some requests like version and shutdown have a single
//! response, while others like provide have a stream of responses.
//!
//! Note that this is subject to change. The RPC protocol is not yet stable.
use derive_more::From;

use quic_rpc::Service;
use serde::{Deserialize, Serialize};

pub use iroh_base::rpc::RpcResult;

pub mod authors;
pub mod blobs;
pub mod docs;
pub mod node;
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
    Blobs(blobs::Request),
    Docs(docs::Request),
    Tags(tags::Request),
    Authors(authors::Request),
}

/// The response enum, listing all possible responses.
#[allow(missing_docs, clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions()]
pub enum Response {
    Node(node::Response),
    Blobs(blobs::Response),
    Tags(tags::Response),
    Docs(docs::Response),
    Authors(authors::Response),
}

impl Service for RpcService {
    type Req = Request;
    type Res = Response;
}

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

pub mod node;
pub use node::*;
mod tags;
pub use tags::*;
pub mod authors;
pub use authors::*;
pub mod docs;
pub use docs::*;
pub mod blobs;
pub use blobs::*;

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
    Tags(TagsRequest),
    Authors(authors::Request),
}

/// The response enum, listing all possible responses.
#[allow(missing_docs, clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions()]
pub enum Response {
    Node(node::Response),
    Blobs(blobs::Response),
    Tags(TagsResponse),
    Docs(docs::Response),
    Authors(authors::Response),
}

impl Service for RpcService {
    type Req = Request;
    type Res = Response;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_protocol_sizes() {
        if std::mem::size_of::<usize>() == 8 {
            assert_eq!(std::mem::size_of::<Request>(), 240);
            assert_eq!(std::mem::size_of::<Response>(), 344);
            assert_eq!(std::mem::size_of::<authors::Request>(), 232);
            assert_eq!(std::mem::size_of::<authors::Response>(), 232);
            assert_eq!(std::mem::size_of::<docs::Request>(), 232);
            assert_eq!(std::mem::size_of::<docs::Response>(), 256);
            assert_eq!(std::mem::size_of::<blobs::Request>(), 96);
            assert_eq!(std::mem::size_of::<blobs::Response>(), 232);
            assert_eq!(std::mem::size_of::<node::Request>(), 144);
            assert_eq!(std::mem::size_of::<node::Response>(), 344);
            assert_eq!(std::mem::size_of::<TagsRequest>(), 32);
            assert_eq!(std::mem::size_of::<TagsResponse>(), 72);
        }
    }
}

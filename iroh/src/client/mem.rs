//! Type declarations for an in-memory client to an iroh node running in the same process.
//!
//! The in-memory client is obtained directly from a running node through
//! [`crate::node::Node::client`]

use crate::rpc_protocol::RpcService;
use quic_rpc::transport::boxed::Connection as BoxedConnection;

/// RPC client to an iroh node running in the same process.
pub type RpcClient = quic_rpc::RpcClient<RpcService, BoxedConnection<RpcService>>;

/// In-memory client to an iroh node running in the same process.
///
/// This is obtained from [`crate::node::Node::client`].
pub type Iroh = super::Iroh;

/// In-memory document client to an iroh node running in the same process.
pub type Doc = super::docs::Doc;

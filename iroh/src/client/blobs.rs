//! Reexport of iroh-blobs rpc client

use quic_rpc::client::BoxedServiceConnection;

use super::RpcService;
/// Reexport of iroh-blobs rpc client
pub type Client =
    iroh_blobs::rpc::client::blobs::Client<BoxedServiceConnection<RpcService>, RpcService>;

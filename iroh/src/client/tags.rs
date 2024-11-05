//! Reexport of iroh-blobs rpc client
use quic_rpc::server::BoxedListener;

use super::RpcService;
/// Reexport of iroh-blobs rpc client
pub type Client =
    iroh_blobs::rpc::client::tags::Client<BoxedListener<RpcService>, RpcService>;

pub use iroh_blobs::rpc::client::tags::TagInfo;

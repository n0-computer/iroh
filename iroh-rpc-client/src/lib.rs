#[cfg(any(feature = "grpc", feature = "mem"))]
#[macro_use]
mod macros;

#[cfg(any(feature = "grpc", feature = "mem"))]
mod client;
#[cfg(any(feature = "grpc", feature = "mem"))]
mod config;
#[cfg(any(feature = "grpc", feature = "mem"))]
mod gateway;
#[cfg(any(feature = "grpc", feature = "mem"))]
mod network;
#[cfg(feature = "grpc")]
mod status;
#[cfg(any(feature = "grpc", feature = "mem"))]
mod store;

#[cfg(any(feature = "grpc", feature = "mem"))]
pub use crate::client::Client;

#[cfg(any(feature = "grpc", feature = "mem"))]
pub use crate::config::Config;

#[cfg(any(feature = "grpc", feature = "mem"))]
pub use crate::network::{Lookup, P2pClient};

#[cfg(feature = "grpc")]
pub use crate::status::{ServiceStatus, StatusRow, StatusTable};

#[cfg(any(feature = "grpc", feature = "mem"))]
pub use crate::store::StoreClient;

#[cfg(feature = "qrpc")]
mod qrpc_config;

#[cfg(feature = "qrpc")]
use qrpc_config as config;
#[cfg(feature = "qrpc")]
mod qrpc_gateway;
#[cfg(feature = "qrpc")]
use qrpc_gateway as gateway;
#[cfg(feature = "qrpc")]
mod qrpc_network;
#[cfg(feature = "qrpc")]
use qrpc_network as network;
#[cfg(feature = "qrpc")]
mod qrpc_store;
#[cfg(feature = "qrpc")]
use qrpc_store as store;
#[cfg(feature = "qrpc")]
mod qrpc_status;
#[cfg(feature = "qrpc")]
use qrpc_status as status;

#[cfg(feature = "qrpc")]
pub use crate::status::{ServiceStatus, StatusRow, StatusTable};

#[cfg(feature = "qrpc")]
pub use crate::qrpc_config::Config;

#[cfg(feature = "qrpc")]
pub use crate::qrpc_gateway::GatewayClient;

#[cfg(feature = "qrpc")]
pub use crate::qrpc_store::StoreClient;

#[cfg(feature = "qrpc")]
pub use crate::qrpc_network::P2pClient;

#[cfg(feature = "qrpc")]
pub type ChannelTypes = quic_rpc::combined::CombinedChannelTypes<
    quic_rpc::mem::MemChannelTypes,
    quic_rpc::quinn::QuinnChannelTypes,
>;

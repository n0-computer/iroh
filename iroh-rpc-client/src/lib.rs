#[macro_use]
mod macros;

mod client;
mod config;
mod gateway;
mod network;
#[cfg(feature = "grpc")]
mod status;
mod store;

pub use crate::client::Client;
pub use crate::config::Config;
pub use crate::network::{Lookup, P2pClient};
#[cfg(feature = "grpc")]
pub use crate::status::{ServiceStatus, StatusRow, StatusTable};
pub use crate::store::StoreClient;

pub type ChannelTypes = quic_rpc::combined::CombinedChannelTypes<
    quic_rpc::mem::MemChannelTypes,
    quic_rpc::quinn::QuinnChannelTypes,
>;

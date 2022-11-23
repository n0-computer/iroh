pub mod client;
pub mod config;
pub mod gateway;
pub mod network;
pub mod status;
pub mod store;

pub type ChannelTypes = quic_rpc::combined::CombinedChannelTypes<
    quic_rpc::mem::MemChannelTypes,
    quic_rpc::quinn::QuinnChannelTypes,
>;

pub use self::config::Config;
pub use client::Client;
pub use network::{Lookup, P2pClient};
pub use status::{ServiceStatus, StatusRow, StatusTable};
pub use store::StoreClient;

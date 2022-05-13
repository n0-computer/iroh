mod behaviour;
mod commands;
mod server;

pub mod builder;
pub mod client;
pub mod error;
pub mod handler;
pub mod serde;
pub mod stream;
pub mod swarm;

pub use crate::behaviour::Behaviour;
pub use crate::builder::RpcBuilder;
pub use crate::client::Client;
pub use crate::error::RpcError;
pub use crate::handler::State;
pub use crate::server::Server;
pub use crate::swarm::{new_mem_swarm, new_tcp_swarm};

pub const DEFAULT_STREAM_CAPACITY: usize = 64;
pub const DEFAULT_RPC_CAPACITY: usize = 64;

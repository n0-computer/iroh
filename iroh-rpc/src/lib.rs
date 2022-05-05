mod behaviour;
mod commands;
mod server;

pub mod client;
pub mod config;
pub mod error;
pub mod handler;
pub mod serde;
pub mod stream;
pub mod swarm;

use futures::channel::mpsc;

use crate::client::Client;
use crate::config::RpcConfig;
use crate::error::RpcError;
use crate::server::Server;

pub fn rpc_from_config<T>(cfg: RpcConfig<T>) -> Result<(Client, Server<T>), RpcError> {
    let (sender, receiver) = mpsc::channel(0);
    let server = Server::server_from_config(receiver, cfg.server)?;
    let mut client = Client::new(sender);
    for (namespace, addrs) in cfg.client.addrs.iter() {
        client.with_addrs(namespace.to_owned(), addrs.0.clone(), addrs.1);
    }
    Ok((client, server))
}

//! Implements handling of the [bitswap protocol]((https://github.com/ipfs/specs/blob/master/BITSWAP.md)). Based on go-ipfs.
//!
//! Supports the versions `1.0.0`, `1.1.0` and `1.2.0`.

use anyhow::Result;
use cid::Cid;
use libp2p::PeerId;
use message::BitswapMessage;
use tracing::info;

use self::block::Block;
use self::client::{Client, Config as ClientConfig};
use self::network::Network;
use self::server::{Config as ServerConfig, Server};

mod block;
mod client;
mod message;
mod network;
mod prefix;
mod server;

#[derive(Debug)]
pub struct Bitswap {
    client: Client,
    server: Server,
    network: Network,
}

#[derive(Debug)]
pub struct Config {
    pub client: ClientConfig,
    pub server: ServerConfig,
}

#[derive(Debug, Clone)]
pub struct Store {}

impl Bitswap {
    pub fn new(network: Network, store: Store, config: Config) -> Self {
        let server = Server::new(network.clone(), store.clone(), config.server);
        let client = Client::new(network.clone(), store, config.client);

        Bitswap {
            server,
            client,
            network,
        }
    }

    pub fn close(self) -> Result<()> {
        self.network.stop();

        self.client.close()?;
        self.server.close()?;

        Ok(())
    }

    pub fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        self.client.notify_new_blocks(blocks)?;
        self.server.notify_new_blocks(blocks)?;

        Ok(())
    }

    pub fn stat(&self) -> Result<Stat> {
        let client_stat = self.client.stat()?;
        let server_stat = self.server.stat()?;

        Ok(Stat {
            wantlist: client_stat.wantlist,
            blocks_received: client_stat.blocks_received,
            data_received: client_stat.data_received,
            dup_blks_received: client_stat.dup_blks_received,
            dup_data_received: client_stat.dup_data_received,
            messages_received: client_stat.messages_received,
            peers: server_stat.peers,
            blocks_sent: server_stat.blocks_sent,
            data_sent: server_stat.data_sent,
            provide_buf_len: server_stat.provide_buf_len,
        })
    }

    pub fn wantlist_for_peer(&self, peer: &PeerId) -> Vec<Cid> {
        if peer == self.network.self_id() {
            return self.client.get_wantlist();
        }

        self.server.wantlist_for_peer(peer)
    }

    pub fn peer_connected(&self, peer: &PeerId) {
        self.client.peer_connected(peer);
        self.server.peer_connected(peer);
    }

    pub fn peer_disconnected(&self, peer: &PeerId) {
        self.client.peer_disconnected(peer);
        self.server.peer_disconnected(peer);
    }

    pub fn receive_error(&self, error: anyhow::Error) {
        info!("Bitswap client receive error: {:?}", error);
    }

    pub fn receive_message(&self, peer: &PeerId, message: &BitswapMessage) {
        self.client.receive_message(peer, &message);
        self.server.receive_message(peer, &message);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub wantlist: Vec<Cid>,
    pub peers: Vec<PeerId>,
    pub blocks_received: u64,
    pub data_received: u64,
    pub dup_blks_received: u64,
    pub dup_data_received: u64,
    pub messages_received: u64,
    pub blocks_sent: u64,
    pub data_sent: u64,
    pub provide_buf_len: usize,
}

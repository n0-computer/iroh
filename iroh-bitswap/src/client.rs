use std::time::Duration;

use anyhow::Result;
use cid::Cid;
use libp2p::PeerId;

use crate::{block::Block, message::BitswapMessage, network::Network, Store};

mod block_presence_manager;
mod message_queue;
mod peer_manager;
mod peer_want_manager;
mod provider_query_manager;
mod session;
mod session_interest_manager;
mod session_manager;
mod session_peer_manager;
pub(crate) mod wantlist;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Overwrites the global provider search delay
    pub provider_search_delay: Duration,
    /// Overwrites the global rebroadcast delay
    pub rebroadcast_delay: Duration,
    pub simluate_donthaves_on_timeout: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            provider_search_delay: Duration::from_secs(1),
            rebroadcast_delay: Duration::from_secs(60),
            simluate_donthaves_on_timeout: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub wantlist: Vec<Cid>,
    pub blocks_received: u64,
    pub data_received: u64,
    pub dup_blks_received: u64,
    pub dup_data_received: u64,
    pub messages_received: u64,
}

#[derive(Debug)]
pub struct Client<S: Store> {
    network: Network,
    store: S,
}

impl<S: Store> Client<S> {
    pub fn new(network: Network, store: S, config: Config) -> Self {
        Client { network, store }
    }

    pub fn close(self) -> Result<()> {
        // TODO
        Ok(())
    }

    pub fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        // TODO
        Ok(())
    }

    pub fn stat(&self) -> Result<Stat> {
        todo!()
    }

    pub fn get_wantlist(&self) -> Vec<Cid> {
        todo!()
    }

    pub fn peer_connected(&self, peer: &PeerId) {
        // TODO
    }

    pub fn peer_disconnected(&self, peer: &PeerId) {
        // TODO
    }

    pub fn receive_message(&self, peer: &PeerId, message: &BitswapMessage) {
        // todo!()
    }
}

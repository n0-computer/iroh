use anyhow::Result;
use cid::Cid;
use libp2p::PeerId;

use crate::{block::Block, message::BitswapMessage, network::Network, Store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {}

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
pub struct Client {}

impl Client {
    pub fn new(network: Network, store: Store, config: Config) -> Self {
        todo!()
    }

    pub fn close(self) -> Result<()> {
        todo!()
    }

    pub fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        todo!()
    }

    pub fn stat(&self) -> Result<Stat> {
        todo!()
    }

    pub fn get_wantlist(&self) -> Vec<Cid> {
        todo!()
    }

    pub fn peer_connected(&self, peer: &PeerId) {
        todo!()
    }

    pub fn peer_disconnected(&self, peer: &PeerId) {
        todo!()
    }

    pub fn receive_message(&self, peer: &PeerId, message: &BitswapMessage) {
        todo!()
    }
}

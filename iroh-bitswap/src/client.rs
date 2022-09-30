use std::{sync::Mutex, time::Duration};

use anyhow::Result;
use cid::Cid;
use libp2p::PeerId;

use crate::{block::Block, message::BitswapMessage, network::Network, Store};

use self::{
    block_presence_manager::BlockPresenceManager, peer_manager::PeerManager,
    provider_query_manager::ProviderQueryManager, session::Session,
    session_interest_manager::SessionInterestManager, session_manager::SessionManager,
};

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

#[derive(Default, Debug, Clone, PartialEq, Eq)]
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
    peer_manager: PeerManager,
    provider_query_manager: ProviderQueryManager,
    network: Network,
    store: S,
    counters: Mutex<Stat>,
    session_manager: SessionManager,
    session_interest_manager: SessionInterestManager,
    provider_search_delay: Duration,
    rebroadcast_delay: Duration,
    simulate_dont_haves_on_timeout: bool,
}

impl<S: Store> Client<S> {
    pub fn new(network: Network, store: S, config: Config) -> Self {
        let self_id = *network.self_id();

        let session_interest_manager = SessionInterestManager::new();
        let block_presence_manager = BlockPresenceManager::new();
        let peer_manager = PeerManager::new(self_id, network.clone());
        // TODO: resolve cycle
        // let peer_manager = PeerManager::with_cb(
        //     self_id,
        //     network.clone(),
        //     move |peer: &PeerId, dont_haves: &[Cid]| {
        //         sm.receive_from(peer, &[][..], &[][..], dont_haves)
        //     },
        // );
        let provider_query_manager = ProviderQueryManager::new(network.clone());

        let session_manager = SessionManager::new(
            self_id,
            session_interest_manager,
            block_presence_manager,
            peer_manager.clone(),
            provider_query_manager.clone(),
            network.clone(),
        );
        let counters = Mutex::new(Stat::default());

        let session_interest_manager = SessionInterestManager::new();

        Client {
            peer_manager,
            provider_query_manager,
            network,
            store,
            counters,
            session_manager,
            session_interest_manager,
            provider_search_delay: config.provider_search_delay,
            rebroadcast_delay: config.rebroadcast_delay,
            simulate_dont_haves_on_timeout: config.simluate_donthaves_on_timeout,
        }
    }

    pub fn get_block(&self, key: &Cid) -> Result<Block> {
        todo!()
    }

    pub fn get_blocks(&self, keys: &[Cid]) -> Result<Block> {
        todo!()
    }

    pub fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        // TODO
        Ok(())
    }

    fn receive_blocks_from(
        &self,
        from: &PeerId,
        blocks: &[Block],
        haves: &[Cid],
        dont_haves: &[Cid],
    ) -> Result<()> {
        todo!();
    }

    pub fn receive_message(&self, peer: &PeerId, message: &BitswapMessage) {
        // todo!()
    }

    fn update_receive_counters(&self, blocks: &[Block]) {
        todo!()
    }

    fn store_has(&self, blocks: &[Cid]) -> Vec<bool> {
        todo!()
    }

    pub fn peer_connected(&self, peer: &PeerId) {
        todo!()
    }

    pub fn peer_disconnected(&self, peer: &PeerId) {
        todo!()
    }

    pub fn close(self) -> Result<()> {
        // TODO
        Ok(())
    }

    pub fn get_wantlist(&self) -> Vec<Cid> {
        todo!()
    }

    pub fn get_want_blocks(&self) -> Vec<Cid> {
        todo!()
    }

    pub fn get_want_haves(&self) -> Vec<Cid> {
        todo!()
    }

    pub fn new_session(&self) -> Session {
        todo!()
    }

    pub fn stat(&self) -> Result<Stat> {
        todo!()
    }
}

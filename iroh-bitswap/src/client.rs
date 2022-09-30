use std::{sync::Mutex, time::Duration};

use ahash::AHashSet;
use anyhow::Result;
use cid::Cid;
use crossbeam::channel::Receiver;
use derivative::Derivative;
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

#[derive(Derivative)]
#[derivative(Debug)]
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
    #[derivative(Debug = "ignore")]
    notify: Mutex<bus::Bus<Block>>,
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
        let notify = bus::Bus::new(64);

        let session_manager = SessionManager::new(
            self_id,
            session_interest_manager,
            block_presence_manager,
            peer_manager.clone(),
            provider_query_manager.clone(),
            network.clone(),
            notify.read_handle(),
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
            notify: Mutex::new(notify),
        }
    }

    /// Attempts to retrieve a particular block from peers.
    pub fn get_block(&self, key: &Cid) -> Result<Block> {
        let session = self.new_session();
        session.get_block(key)
    }

    /// Returns a channel where the caller may receive blocks that correspond to the
    /// provided `keys`.
    pub fn get_blocks(&self, keys: &[Cid]) -> Result<Receiver<Block>> {
        let session = self.new_session();
        session.get_blocks(keys)
    }

    /// Announces the existence of blocks to this bitswap service.
    /// Bitswap itself doesn't store new blocks. It's the caller responsibility to ensure
    /// that those blocks are available in the blockstore before calling this function.
    pub fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        let block_cids: Vec<Cid> = blocks.iter().map(|b| *b.cid()).collect();
        // Send all block keys (including duplicates) to any session that wants them.
        self.session_manager
            .receive_from(None, &block_cids, &[][..], &[][..]);

        // Publish the block to any Bitswap clients that had requested blocks.
        // (the sessions use this pubsub mechanism to inform clients of incoming blocks)
        let notify = &mut *self.notify.lock().unwrap();
        for block in blocks {
            notify.broadcast(block.clone());
        }

        Ok(())
    }

    /// Process blocks received from the network.
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

    /// Called by the network interface when a peer initiates a new connection to bitswap.
    pub fn peer_connected(&self, peer: &PeerId) {
        self.peer_manager.connected(peer);
    }

    /// Called by the network interface when a peer closes a connection.
    pub fn peer_disconnected(&self, peer: &PeerId) {
        self.peer_manager.disconnected(peer);
    }

    /// Returns the current local wantlist (both want-blocks and want-haves).
    pub fn get_wantlist(&self) -> AHashSet<Cid> {
        self.peer_manager.current_wants()
    }

    /// Returns the current list of want-blocks.
    pub fn get_want_blocks(&self) -> AHashSet<Cid> {
        self.peer_manager.current_want_blocks()
    }

    /// Returns the current list of want-haves.
    pub fn get_want_haves(&self) -> AHashSet<Cid> {
        self.peer_manager.current_want_haves()
    }

    /// Creates a new Bitswap session. You should use this, rather
    /// that calling `get_blocks`. Any time you intend to do several related
    /// block requests in a row. The session returned will have it's own `get_blocks`
    /// method, but the session will use the fact that the requests are related to
    /// be more efficient in its requests to peers.
    pub fn new_session(&self) -> Session {
        self.session_manager
            .new_session(self.provider_search_delay, self.rebroadcast_delay)
    }

    /// Returns aggregated statistics about bitswap operations.
    pub fn stat(&self) -> Result<Stat> {
        let mut counters = self.counters.lock().unwrap().clone();
        counters.wantlist = self.get_wantlist().into_iter().collect();

        Ok(counters)
    }
}

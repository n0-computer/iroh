use std::{sync::Arc, time::Duration};

use ahash::AHashSet;
use anyhow::Result;
use cid::Cid;
use derivative::Derivative;
use futures::{future::BoxFuture, FutureExt};
use libp2p::PeerId;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, warn};

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
#[derive(Clone)]
pub struct Client<S: Store> {
    peer_manager: PeerManager,
    provider_query_manager: ProviderQueryManager,
    network: Network,
    store: S,
    counters: Arc<Mutex<Stat>>,
    session_manager: SessionManager,
    session_interest_manager: SessionInterestManager,
    provider_search_delay: Duration,
    rebroadcast_delay: Duration,
    simulate_dont_haves_on_timeout: bool,
    #[derivative(Debug = "ignore")]
    blocks_received_cb:
        Arc<Box<dyn Fn(PeerId, Vec<Block>) -> BoxFuture<'static, ()> + 'static + Send + Sync>>,
    notify: broadcast::Sender<Block>,
}

impl<S: Store> Client<S> {
    pub async fn new(
        network: Network,
        store: S,
        blocks_received_cb: Box<
            dyn Fn(PeerId, Vec<Block>) -> BoxFuture<'static, ()> + 'static + Send + Sync,
        >,
        config: Config,
    ) -> Self {
        let self_id = *network.self_id();

        let session_interest_manager = SessionInterestManager::new();
        let block_presence_manager = BlockPresenceManager::new();
        let peer_manager = PeerManager::new(self_id, network.clone());
        let provider_query_manager = ProviderQueryManager::new(network.clone()).await;
        let (notify, mut default_receiver): (broadcast::Sender<Block>, broadcast::Receiver<Block>) =
            broadcast::channel(64);

        // TODO: track task
        tokio::task::spawn(async move {
            while let Ok(block) = default_receiver.recv().await {
                debug!("received block {}", block.cid());
            }
        });

        let session_manager = SessionManager::new(
            self_id,
            session_interest_manager.clone(),
            block_presence_manager,
            peer_manager.clone(),
            provider_query_manager.clone(),
            network.clone(),
            notify.clone(),
        );
        peer_manager
            .set_cb({
                let sm = session_manager.clone();
                move |peer: PeerId, dont_haves: Vec<Cid>| {
                    let sm = sm.clone();
                    async move {
                        sm.receive_from(Some(peer), &[][..], &[][..], &dont_haves)
                            .await
                    }
                    .boxed()
                }
            })
            .await;
        let counters = Mutex::new(Stat::default());

        Client {
            peer_manager,
            provider_query_manager,
            network,
            store,
            counters: Arc::new(counters),
            session_manager,
            session_interest_manager,
            provider_search_delay: config.provider_search_delay,
            rebroadcast_delay: config.rebroadcast_delay,
            simulate_dont_haves_on_timeout: config.simluate_donthaves_on_timeout,
            blocks_received_cb: Arc::new(blocks_received_cb),
            notify,
        }
    }

    pub async fn stop(self) -> Result<()> {
        self.session_manager.stop().await?;
        self.provider_query_manager.stop().await?;
        self.peer_manager.stop().await?;

        Ok(())
    }

    /// Attempts to retrieve a particular block from peers.
    pub async fn get_block(&self, key: &Cid) -> Result<Block> {
        let session = self.new_session().await;
        let block = session.get_block(key).await;
        session.stop().await?;
        block
    }

    /// Returns a channel where the caller may receive blocks that correspond to the
    /// provided `keys`.
    pub async fn get_blocks(&self, keys: &[Cid]) -> Result<async_channel::Receiver<Block>> {
        let session = self.new_session().await;
        session.get_blocks(keys).await
    }

    /// Announces the existence of blocks to this bitswap service.
    /// Bitswap itself doesn't store new blocks. It's the caller responsibility to ensure
    /// that those blocks are available in the blockstore before calling this function.
    pub async fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        let block_cids: Vec<Cid> = blocks.iter().map(|b| *b.cid()).collect();
        // Send all block keys (including duplicates) to any session that wants them.
        self.session_manager
            .receive_from(None, &block_cids, &[][..], &[][..])
            .await;

        // Publish the block to any Bitswap clients that had requested blocks.
        // (the sessions use this pubsub mechanism to inform clients of incoming blocks)
        for block in blocks {
            self.notify.send(block.clone())?;
        }

        Ok(())
    }

    /// Process blocks received from the network.
    async fn receive_blocks_from(
        &self,
        from: &PeerId,
        blocks: &[Block],
        haves: &[Cid],
        dont_haves: &[Cid],
    ) -> Result<()> {
        let (wanted, not_wanted) = self
            .session_interest_manager
            .split_wanted_unwanted(blocks)
            .await;
        for block in not_wanted {
            debug!("recv block not in wantlist: {} from {}", block.cid(), from);
        }
        let all_keys: Vec<Cid> = blocks.iter().map(|b| *b.cid()).collect();

        // Inform the PeerManager so that we can calculate per-peer latency.
        let mut combined = all_keys.clone();
        combined.extend_from_slice(haves);
        combined.extend_from_slice(dont_haves);

        self.peer_manager.response_received(from, &combined).await;

        // Send all block keys (including duplicates to any sessions that want them for accounting purposes).
        self.session_manager
            .receive_from(Some(*from), &all_keys, haves, dont_haves)
            .await;

        // Publish the block
        for block in &wanted {
            self.notify.send((*block).clone())?;
        }
        (self.blocks_received_cb)(*from, wanted.into_iter().cloned().collect());

        Ok(())
    }

    /// Called by the network interface when a new message is received.
    pub async fn receive_message(&self, peer: &PeerId, incoming: &BitswapMessage) {
        self.counters.lock().await.messages_received += 1;

        if incoming.blocks_len() > 0 {
            debug!("client::receive_message {} blocks", incoming.blocks_len());

            self.update_receive_counters(incoming.blocks()).await;
            for block in incoming.blocks() {
                debug!("recv block; {} from {}", block.cid(), peer);
            }
        }

        // TODO: investigate if the allocations below can be avoided.

        let haves: Vec<Cid> = incoming.haves().copied().collect();
        let dont_haves: Vec<Cid> = incoming.dont_haves().copied().collect();

        if incoming.blocks_len() > 0 || !haves.is_empty() || !dont_haves.is_empty() {
            let incoming_blocks: Vec<Block> = incoming.blocks().cloned().collect();
            // Process blocks
            if let Err(err) = self
                .receive_blocks_from(peer, &incoming_blocks, &haves, &dont_haves)
                .await
            {
                warn!("ReceiveMessage recvBlockFrom error: {:?}", err);
            }
        }
    }

    async fn update_receive_counters<'a>(&self, blocks: impl Iterator<Item = &'a Block>) {
        // Check which blocks are in the datastore
        // (Note: any errors from the blockstore are simply logged out in store_has())
        // let store = &self.store;
        for block in blocks {
            // TODO: this is a call to the store for each block just to update metrics, should be avoided.
            let has_block = false;
            // TODO:
            /*
            let has_block = tokio::runtime::Handle::current()
                .block_on(async { store.has(block.cid()).await.unwrap_or_default() });
            */
            let block_len = block.data().len();
            // TODO: bs.allMetric.Observe(float64(blkLen))
            if has_block {
                // TODO: bs.dupMetric.Observe(float64(blkLen))
            }

            let counters = &mut *self.counters.lock().await;
            counters.blocks_received += 1;
            counters.data_received += block_len as u64;
            if has_block {
                counters.dup_blks_received += 1;
                counters.dup_data_received += block_len as u64;
            }
        }
    }

    /// Called by the network interface when a peer initiates a new connection to bitswap.
    pub async fn peer_connected(&self, peer: &PeerId) {
        self.peer_manager.connected(peer).await;
    }

    /// Called by the network interface when a peer closes a connection.
    pub async fn peer_disconnected(&self, peer: &PeerId) {
        self.peer_manager.disconnected(peer).await;
    }

    /// Returns the current local wantlist (both want-blocks and want-haves).
    pub async fn get_wantlist(&self) -> AHashSet<Cid> {
        self.peer_manager.current_wants().await
    }

    /// Returns the current list of want-blocks.
    pub async fn get_want_blocks(&self) -> AHashSet<Cid> {
        self.peer_manager.current_want_blocks().await
    }

    /// Returns the current list of want-haves.
    pub async fn get_want_haves(&self) -> AHashSet<Cid> {
        self.peer_manager.current_want_haves().await
    }

    /// Creates a new Bitswap session. You should use this, rather
    /// that calling `get_blocks`. Any time you intend to do several related
    /// block requests in a row. The session returned will have it's own `get_blocks`
    /// method, but the session will use the fact that the requests are related to
    /// be more efficient in its requests to peers.
    pub async fn new_session(&self) -> Session {
        self.session_manager
            .new_session(self.provider_search_delay, self.rebroadcast_delay)
            .await
    }

    /// Returns aggregated statistics about bitswap operations.
    pub async fn stat(&self) -> Result<Stat> {
        let mut counters = self.counters.lock().await.clone();
        counters.wantlist = self.get_wantlist().await.into_iter().collect();

        Ok(counters)
    }
}

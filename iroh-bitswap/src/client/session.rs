use std::{pin::Pin, sync::Arc, time::Duration};

use ahash::AHashSet;
use anyhow::{anyhow, ensure, Result};
use cid::Cid;
use futures::FutureExt;
use libp2p::PeerId;
use tokio::{
    sync::{broadcast, oneshot},
    task::JoinHandle,
    time::{Instant, Sleep},
};
use tracing::{debug, error, info, warn};

use crate::Block;

use self::{session_want_sender::SessionWantSender, session_wants::SessionWants};

use super::{
    block_presence_manager::BlockPresenceManager, peer_manager::PeerManager,
    provider_query_manager::ProviderQueryManager, session_interest_manager::SessionInterestManager,
    session_manager::SessionManager, session_peer_manager::SessionPeerManager,
};

mod cid_queue;
mod peer_response_tracker;
mod sent_want_blocks_tracker;
mod session_want_sender;
mod session_wants;

pub use self::session_want_sender::Signaler;

const BROADCAST_LIVE_WANTS_LIMIT: usize = 64;

/// The kind of operation being executed in the event loop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Receive(Vec<Cid>),
    Want(Vec<Cid>),
    Cancel(Vec<Cid>),
    Broadcast(AHashSet<Cid>),
    WantsSent(Vec<Cid>),
}

/// Holds state for an individual bitswap transfer operation.
/// Allows bitswap to make smarter decisions about who to send what.
#[derive(Debug, Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    self_id: PeerId,
    id: u64,
    session_manager: SessionManager,
    provider_finder: ProviderQueryManager,
    session_interest_manager: SessionInterestManager,
    session_want_sender: SessionWantSender,
    incoming: async_channel::Sender<Op>,
    closer: oneshot::Sender<()>,
    worker: Option<JoinHandle<()>>,
    notify: broadcast::Sender<Block>,
}

impl Session {
    pub async fn new(
        self_id: PeerId,
        id: u64,
        session_manager: SessionManager,
        peer_manager: PeerManager,
        session_peer_manager: SessionPeerManager,
        provider_finder: ProviderQueryManager,
        session_interest_manager: SessionInterestManager,
        block_presence_manager: BlockPresenceManager,
        provider_query_manager: ProviderQueryManager,
        notify: broadcast::Sender<Block>,
        initial_search_delay: Duration,
        periodic_search_delay: Duration,
    ) -> Self {
        info!("creating session {}", id);
        let (incoming_s, incoming_r) = async_channel::bounded(128);

        let session_want_sender = SessionWantSender::new(
            id,
            peer_manager.clone(),
            session_peer_manager.clone(),
            session_manager.clone(),
            block_presence_manager,
            {
                let incoming = incoming_s.clone();
                Box::new(
                    move |_peer_id: PeerId, mut want_blocks: Vec<Cid>, want_haves: Vec<Cid>| {
                        let incoming = incoming.clone();
                        async move {
                            want_blocks.extend(want_haves);
                            incoming.send(Op::WantsSent(want_blocks)).await.ok();
                        }
                        .boxed()
                    },
                )
            },
            {
                let incoming = incoming_s.clone();
                Box::new(move |keys: Vec<Cid>| {
                    let incoming = incoming.clone();
                    async move {
                        incoming
                            .send(Op::Broadcast(keys.into_iter().collect()))
                            .await
                            .ok();
                    }
                    .boxed()
                })
            },
        );

        let session_wants = SessionWants::new(BROADCAST_LIVE_WANTS_LIMIT);
        let (closer_s, mut closer_r) = oneshot::channel();

        let mut loop_state = LoopState::new(
            id,
            session_wants,
            session_want_sender.clone(),
            session_interest_manager.clone(),
            provider_query_manager,
            session_peer_manager,
            peer_manager,
            initial_search_delay,
        );

        let rt = tokio::runtime::Handle::current();
        let worker = rt.spawn(async move {
            // Session run loop

            let mut periodic_search_timer = tokio::time::interval(periodic_search_delay);

            loop {
                debug!("session {} tick", loop_state.id);
                tokio::select! {
                    oper = incoming_r.recv() => {
                        match oper {
                            Ok(Op::Receive(keys)) => {
                                loop_state.handle_receive(keys).await;
                            },
                            Ok(Op::Want(keys)) => {
                                loop_state.want_blocks(keys).await;
                            },
                            Ok(Op::Cancel(keys)) => {
                                loop_state.session_wants.cancel_pending(&keys);
                                loop_state.session_want_sender.cancel(keys).await;
                            }
                            Ok(Op::WantsSent(keys)) => {
                                loop_state.session_wants.wants_sent(&keys);
                            },
                            Ok(Op::Broadcast(keys)) => {
                                loop_state.broadcast(Some(keys)).await;
                            },
                            Err(err) => {
                                // incoming channel gone, shutdown/panic
                                warn!("incoming channel error: {:?}", err);
                                break;
                            }
                        }
                    }
                    _ = &mut loop_state.idle_tick => {
                        // The session hasn't received blocks for a while, broadcast
                        loop_state.broadcast(None).await;
                    }
                    _ = periodic_search_timer.tick() => {
                        // Periodically search for a random live want
                        loop_state.handle_periodic_search().await;
                    }
                    _ = &mut closer_r => {
                        // Shutdown
                        break;
                    }
                }
            }
            if let Err(err) = loop_state.stop().await {
                error!("failed to shutdown session loop: {:?}", err);
            }
        });

        let inner = Arc::new(Inner {
            self_id,
            id,
            session_manager,
            provider_finder,
            session_interest_manager,
            session_want_sender,
            incoming: incoming_s,
            notify,
            closer: closer_s,
            worker: Some(worker),
        });

        Session { inner }
    }

    pub async fn stop(self) -> Result<()> {
        info!("stopping session {}", self.inner.id);
        let mut inner =
            Arc::try_unwrap(self.inner).map_err(|_| anyhow!("session refs not shutdown"))?;
        inner
            .closer
            .send(())
            .map_err(|e| anyhow!("failed to stop worker: {:?}", e))?;
        inner
            .worker
            .take()
            .ok_or_else(|| anyhow!("missing worker"))?
            .await?;

        //  Signal to the SessionManager that the session has been shutdown
        inner.session_manager.remove_session(inner.id).await;
        inner.session_want_sender.stop().await?;

        Ok(())
    }

    pub fn id(&self) -> u64 {
        self.inner.id
    }

    /// Receives incoming blocks from the given peer.
    pub async fn receive_from(
        &self,
        from: Option<PeerId>,
        keys: &[Cid],
        haves: &[Cid],
        dont_haves: &[Cid],
    ) {
        // The SessionManager tells each Session about all keys that it may be
        // interested in. Here the Session filters the keys to the ones that this
        // particular Session is interested in.
        let mut interested_res = self
            .inner
            .session_interest_manager
            .filter_session_interested(self.inner.id, &[keys, haves, dont_haves][..])
            .await;
        let dont_haves = interested_res.pop().unwrap();
        let haves = interested_res.pop().unwrap();
        let keys = interested_res.pop().unwrap();

        // Inform the session want sender that a message has been received
        if let Some(from) = from {
            self.inner
                .session_want_sender
                .update(from, keys.clone(), haves, dont_haves)
                .await;
        }

        if keys.is_empty() {
            return;
        }

        // Inform the session that blocks have been received.
        self.inner.incoming.send(Op::Receive(keys)).await.ok();
    }

    // Fetches a single block.
    pub async fn get_block(&self, key: &Cid) -> Result<Block> {
        let r = self.get_blocks(&[*key][..]).await?;
        let block = r.recv().await?;
        Ok(block)
    }

    // Fetches a set of blocks within the context of this session and
    // returns a channel that found blocks will be returned on. No order is
    // guaranteed on the returned blocks.
    pub async fn get_blocks(&self, keys: &[Cid]) -> Result<async_channel::Receiver<Block>> {
        ensure!(!keys.is_empty(), "missing keys");
        debug!("get blocks: {:?}", keys);

        let (s, r) = async_channel::bounded(8);
        let mut remaining: AHashSet<Cid> = keys.iter().copied().collect();
        let mut block_channel = self.inner.notify.subscribe();
        let incoming = self.inner.incoming.clone();
        let rt = tokio::runtime::Handle::current();
        rt.spawn(async move {
            while let Ok(block) = block_channel.recv().await {
                let cid = *block.cid();
                debug!("received wanted block {}", cid);
                if remaining.contains(&cid) {
                    match s.send(block).await {
                        Ok(_) => {
                            remaining.remove(&cid);
                        }
                        Err(_) => {
                            // receiver dropped, shutdown
                            break;
                        }
                    }
                }

                if remaining.is_empty() {
                    break;
                }
            }

            // cancel all remaining
            incoming
                .send(Op::Cancel(remaining.into_iter().collect()))
                .await
                .ok();
        });

        self.inner.incoming.send(Op::Want(keys.to_vec())).await?;

        Ok(r)
    }
}

#[derive(Debug)]
struct LoopState {
    id: u64,
    consecutive_ticks: usize,
    session_wants: SessionWants,
    session_interest_manager: SessionInterestManager,
    session_want_sender: SessionWantSender,
    provider_query_manager: ProviderQueryManager,
    session_peer_manager: SessionPeerManager,
    peer_manager: PeerManager,
    latency_tracker: LatencyTracker,
    idle_tick: Pin<Box<Sleep>>,
    base_tick_delay: Duration,
    initial_search_delay: Duration,
}

impl LoopState {
    fn new(
        id: u64,
        session_wants: SessionWants,
        session_want_sender: SessionWantSender,
        session_interest_manager: SessionInterestManager,
        provider_query_manager: ProviderQueryManager,
        session_peer_manager: SessionPeerManager,
        peer_manager: PeerManager,
        initial_search_delay: Duration,
    ) -> Self {
        let idle_tick = Box::pin(tokio::time::sleep(initial_search_delay));

        LoopState {
            id,
            consecutive_ticks: 0,
            session_wants,
            session_want_sender,
            session_interest_manager,
            provider_query_manager,
            session_peer_manager,
            peer_manager,
            latency_tracker: Default::default(),
            base_tick_delay: Duration::from_millis(500),
            initial_search_delay,
            idle_tick,
        }
    }

    async fn stop(self) -> Result<()> {
        self.session_peer_manager.stop().await?;
        Ok(())
    }

    /// Called when the session hasn't received any blocks for some time, or when
    /// all peers in the session have sent DONT_HAVE for a particular set of CIDs.
    /// Send want-haves to all connected peers, and search for new peers with the CID.
    async fn broadcast(&mut self, wants: Option<AHashSet<Cid>>) {
        // If this broadcast is because of an idle timeout (we haven't received
        // any blocks for a while) then broadcast all pending wants.
        let wants = wants.unwrap_or_else(|| self.session_wants.prepare_broadcast());

        // Broadcast a want-have for the live wants to everyone we're connected to.
        if !wants.is_empty() {
            self.broadcast_want_haves(&wants).await;
        }

        // Do not find providers on consecutive ticks -- just rely on periodic search widening.
        if !wants.is_empty() && (self.consecutive_ticks == 0) {
            // Search for providers who have the first want in the list.
            // Typically if the provider has the first block they will have
            // the rest of the blocks also.
            self.find_more_peers(wants.iter().next().unwrap()).await;
        }

        self.reset_idle_tick();

        // If we have live wants record a consecutive tick
        if self.session_wants.has_live_wants() {
            self.consecutive_ticks += 1;
        }
    }

    /// Called periodically to search for providers of a randomly chosen CID in the sesssion.
    async fn handle_periodic_search(&self) {
        if let Some(random_want) = self.session_wants.random_live_want() {
            // TODO: come up with a better strategy for determining when to search
            // for new providers for blocks.
            self.find_more_peers(&random_want).await;
            self.broadcast_want_haves(&[random_want].into_iter().collect())
                .await;
        }
    }

    /// Attempts to find more peers for a session by searching for providers for the given cid.
    async fn find_more_peers(&self, cid: &Cid) {
        debug!("find_more_peers");
        // TODO: track thread
        let sws = self.session_want_sender.clone();
        let cid = *cid;
        let provider_query_manager = self.provider_query_manager.clone();
        let _worker = tokio::runtime::Handle::current().spawn(async move {
            let mut num_providers = 0;
            match provider_query_manager.find_providers_async(&cid).await {
                Ok(r) => {
                    while let Ok(provider) = r.recv().await {
                        match provider {
                            Ok(provider) => {
                                num_providers += 1;
                                debug!("found provider for {}: {}", cid, provider);
                                // When a provider indicates that it has a cid, it's equivalent to
                                // the providing peer sending a HAVE.
                                sws.update(provider, Vec::new(), vec![cid], Vec::new())
                                    .await;

                                if num_providers >= 10 {
                                    break;
                                }
                            }
                            Err(err) => {
                                warn!("provider error: {:?}", err);
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!("failed to start finding providers: {:?}", err);
                }
            }
        });
    }

    /// Called when the session receives blocks from a peer.
    async fn handle_receive(&mut self, keys: Vec<Cid>) {
        debug!(
            "received keys: {:?}",
            keys.iter().map(|k| k.to_string()).collect::<Vec<String>>()
        );
        // Record which blocks have been received and figure out the total latency
        // for fetching the blocks
        let (wanted, total_latency) = self.session_wants.blocks_received(&keys);
        if wanted.is_empty() {
            return;
        }

        // Record latency
        self.latency_tracker
            .receive_update(wanted.len(), total_latency);

        // Inform the SessionInterestManager that this session is no longer
        // expecting to receive the wanted keys
        self.session_interest_manager
            .remove_session_wants(self.id, &wanted)
            .await;

        // We've received new wanted blocks, so reset the number of ticks
        // that have occurred since the last new block
        self.consecutive_ticks = 0;

        self.reset_idle_tick();
    }

    /// Called when blocks are requested by the client.
    async fn want_blocks(&mut self, new_keys: Vec<Cid>) {
        if !new_keys.is_empty() {
            // Inform the SessionInterestManager that this session is interested in the keys
            self.session_interest_manager
                .record_session_interest(self.id, &new_keys)
                .await;
            // Tell the sessionWants tracker that that the wants have been requested
            self.session_wants.blocks_requested(&new_keys);
            // Tell the sessionWantSender that the blocks have been requested
            self.session_want_sender.add(new_keys).await;
        }

        // If we have discovered peers already, the sessionWantSender will
        // send wants to them.
        if self.session_peer_manager.peers_discovered().await {
            return;
        }

        // No peers discovered yet, broadcast some want-haves
        let keys = self.session_wants.get_next_wants();
        if !keys.is_empty() {
            self.broadcast_want_haves(&keys).await;
        }
    }

    // Send want-haves to all connected peers
    async fn broadcast_want_haves(&self, wants: &AHashSet<Cid>) {
        debug!(
            "broadacasting wants: {:?}",
            wants.iter().map(|w| w.to_string()).collect::<Vec<_>>()
        );
        self.peer_manager.broadcast_want_haves(wants).await;
    }

    /// The session will broadcast if it has outstanding wants and doesn't receive
    /// any blocks for some time. The length of time is calculated
    ///   - initially
    ///     as a fixed delay
    ///   - once some blocks are received
    ///     from a base delay and average latency, with a backoff
    fn reset_idle_tick(&mut self) {
        let tick_delay = if !self.latency_tracker.has_latency() {
            self.initial_search_delay
        } else {
            let average_latency = self.latency_tracker.average_latency();
            self.base_tick_delay + (3 * average_latency)
        };
        let tick_delay = Duration::from_secs_f64(
            tick_delay.as_secs_f64() * (1. + self.consecutive_ticks as f64),
        );
        dbg!(
            tick_delay,
            self.initial_search_delay,
            self.consecutive_ticks,
            &self.latency_tracker,
        );

        self.idle_tick.as_mut().reset(Instant::now() + tick_delay);
    }
}

#[derive(Debug, Default)]
struct LatencyTracker {
    total_latency: Duration,
    count: usize,
}

impl LatencyTracker {
    fn has_latency(&self) -> bool {
        !self.total_latency.is_zero() && self.count > 0
    }

    fn average_latency(&self) -> Duration {
        Duration::from_secs_f64(self.total_latency.as_secs_f64() / self.count as f64)
    }

    fn receive_update(&mut self, count: usize, latency: Duration) {
        self.count += count;
        self.total_latency += latency;
    }
}

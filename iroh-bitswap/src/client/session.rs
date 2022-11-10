use std::{ops::Deref, pin::Pin, sync::Arc, time::Duration};

use ahash::AHashSet;
use anyhow::{anyhow, ensure, Result};
use cid::Cid;
use futures::{future, stream, StreamExt};
use iroh_metrics::{bitswap::BitswapMetrics, core::MRecorder, inc, record};
use libp2p::PeerId;
use tokio::{
    sync::oneshot,
    task::JoinHandle,
    time::{Instant, Sleep},
};
use tracing::{debug, error, info, warn};

use crate::{network::Network, Block};

use self::{session_want_sender::SessionWantSender, session_wants::SessionWants};

use super::{
    block_presence_manager::BlockPresenceManager, peer_manager::PeerManager,
    session_interest_manager::SessionInterestManager, session_manager::SessionManager,
};

mod cid_queue;
mod peer_response_tracker;
mod sent_want_blocks_tracker;
mod session_want_sender;
mod session_wants;

pub use self::session_want_sender::Signaler;

const BROADCAST_LIVE_WANTS_LIMIT: usize = 64;
const MAX_IN_PROCESS_REQUESTS: usize = 6;
const MAX_PROVIDERS: usize = 10;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The kind of operation being executed in the event loop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Receive(Vec<Cid>),
    Want(Vec<Cid>),
    Cancel(Vec<Cid>),
    Broadcast(AHashSet<Cid>),
    WantsSent(Vec<Cid>),
    UpdateWantSender {
        from: PeerId,
        keys: Vec<Cid>,
        haves: Vec<Cid>,
        dont_haves: Vec<Cid>,
    },
}

/// Holds state for an individual bitswap transfer operation.
/// Allows bitswap to make smarter decisions about who to send what.
#[derive(Debug, Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    id: u64,
    session_manager: SessionManager,
    session_interest_manager: SessionInterestManager,
    incoming: async_channel::Sender<Op>,
    closer: oneshot::Sender<()>,
    worker: JoinHandle<()>,
    notify: async_broadcast::Sender<Block>,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        id: u64,
        session_manager: SessionManager,
        peer_manager: PeerManager,
        session_interest_manager: SessionInterestManager,
        block_presence_manager: BlockPresenceManager,
        network: Network,
        notify: async_broadcast::Sender<Block>,
        initial_search_delay: Duration,
        periodic_search_delay: Duration,
    ) -> Self {
        info!("creating session {}", id);
        let (incoming_s, incoming_r) = async_channel::bounded(128);

        let session_want_sender = SessionWantSender::new(
            id,
            peer_manager.clone(),
            session_manager.clone(),
            block_presence_manager,
            incoming_s.clone(),
        );

        let session_wants = SessionWants::new(BROADCAST_LIVE_WANTS_LIMIT);
        let (closer_s, mut closer_r) = oneshot::channel();

        let mut loop_state = LoopState::new(
            id,
            session_wants,
            session_want_sender,
            session_interest_manager.clone(),
            network,
            peer_manager,
            initial_search_delay,
            incoming_s.clone(),
        );

        let rt = tokio::runtime::Handle::current();
        let worker = rt.spawn(async move {
            // Session run loop

            let mut periodic_search_timer = tokio::time::interval(periodic_search_delay);

            loop {
                inc!(BitswapMetrics::SessionLoopTick);
                tokio::select! {
                    biased;
                    _ = &mut closer_r => {
                        // Shutdown
                        debug!("shutting down loop");
                        break;
                    }
                    oper = incoming_r.recv() => {
                        match oper {
                            Ok(Op::Receive(keys)) => {
                                loop_state.handle_receive(keys).await;
                            },
                            Ok(Op::Want(keys)) => {
                                loop_state.want_blocks(keys).await;
                            },
                            Ok(Op::Cancel(keys)) => {
                                record!(BitswapMetrics::CancelBlocks, keys.len() as u64);
                                loop_state.session_wants.cancel_pending(&keys);
                                loop_state.session_want_sender.cancel(keys).await;
                            }
                            Ok(Op::WantsSent(keys)) => {
                                loop_state.session_wants.wants_sent(&keys);
                            },
                            Ok(Op::Broadcast(keys)) => {
                                loop_state.broadcast(Some(keys)).await;
                            },
                            Ok(Op::UpdateWantSender { from, keys, haves, dont_haves, }) => {
                                loop_state
                                    .session_want_sender
                                    .update(from, keys, haves, dont_haves)
                                    .await;
                            }
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
                }
            }
            if let Err(err) = loop_state.stop().await {
                error!("failed to shutdown session loop: {:?}", err);
            }
        });

        let inner = Arc::new(Inner {
            id,
            session_manager,
            session_interest_manager,
            incoming: incoming_s,
            notify,
            closer: closer_s,
            worker,
        });

        Session { inner }
    }

    pub async fn stop(self) -> Result<()> {
        let count = Arc::strong_count(&self.inner);
        info!("stopping session {} ({})", self.inner.id, count,);
        ensure!(
            count == 2,
            "session {}: too many session refs",
            self.inner.id
        );

        // Remove from the session manager list, to ensure this is the last ref.
        self.inner
            .session_manager
            .remove_session(self.inner.id)
            .await?;

        let inner = Arc::try_unwrap(self.inner).map_err(|inner| {
            anyhow!("session refs not shutdown ({})", Arc::strong_count(&inner))
        })?;
        inner
            .closer
            .send(())
            .map_err(|e| anyhow!("failed to stop worker: {:?}", e))?;
        inner.worker.await?;

        inc!(BitswapMetrics::SessionsDestroyed);

        debug!("session stopped");
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
        debug!(
            "session:{}: received updates from: {:?} keys: {:?}\n  haves: {:?}\n  dont_haves: {:?}",
            self.inner.id,
            from.map(|s| s.to_string()),
            keys.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            haves.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            dont_haves.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );

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
            if let Err(err) = self
                .inner
                .incoming
                .send(Op::UpdateWantSender {
                    from,
                    keys: keys.clone(),
                    haves,
                    dont_haves,
                })
                .await
            {
                warn!("failed to send update want sender: {:?}", err);
            }
        }

        if keys.is_empty() {
            return;
        }

        // Inform the session that blocks have been received.
        if let Err(err) = self.inner.incoming.send(Op::Receive(keys)).await {
            warn!("failed to send receive: {:?}", err);
        }
    }

    /// Fetches a single block.
    pub async fn get_block(&self, key: &Cid) -> Result<Block> {
        let r = self.get_blocks(&[*key][..]).await?;
        let block = r.recv().await?;
        Ok(block)
    }

    pub async fn add_provider(&self, cid: &Cid, provider: PeerId) {
        let _ = self
            .inner
            .incoming
            .send(Op::UpdateWantSender {
                from: provider,
                keys: Vec::new(),
                haves: vec![*cid],
                dont_haves: Vec::new(),
            })
            .await;
    }

    /// Fetches a set of blocks within the context of this session and
    /// returns a channel that found blocks will be returned on. No order is
    /// guaranteed on the returned blocks.
    pub async fn get_blocks(&self, keys: &[Cid]) -> Result<BlockReceiver> {
        ensure!(!keys.is_empty(), "missing keys");
        debug!("get blocks: {:?}", keys);

        let (s, r) = async_channel::bounded(8);
        let mut remaining: AHashSet<Cid> = keys.iter().copied().collect();
        let mut block_channel = self.inner.notify.new_receiver();
        let incoming = self.inner.incoming.clone();
        let (closer_s, mut closer_r) = oneshot::channel();
        let worker = tokio::task::spawn(async move {
            loop {
                inc!(BitswapMetrics::SessionGetBlockLoopTick);
                tokio::select! {
                    biased;
                    _ = &mut closer_r => {
                        // shutting down
                        break;
                    }
                    maybe_block = block_channel.recv() => {
                        match maybe_block {
                            Ok(block) => {
                                let cid = *block.cid();
                                if remaining.contains(&cid) {
                                    debug!("received wanted block {}", cid);
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
                                    debug!("found all requested blocks");
                                    break;
                                }
                            }
                            Err(async_broadcast::RecvError::Closed) => {
                                break;
                            }
                            Err(async_broadcast::RecvError::Overflowed(n)) => {
                                warn!("receiver is overflowing by {}", n);
                                continue;
                            }
                        }
                    }
                }
            }

            // cancel all remaining
            if !remaining.is_empty() {
                if let Err(err) = incoming
                    .send(Op::Cancel(remaining.into_iter().collect()))
                    .await
                {
                    warn!("failed to send cancel: {:?}", err);
                }
            }
        });

        self.inner.incoming.send(Op::Want(keys.to_vec())).await?;

        Ok(BlockReceiver {
            receiver: r,
            guard: BlockReceiverGuard {
                closer: Some(closer_s),
                _worker: worker,
            },
        })
    }
}

struct LoopState {
    id: u64,
    consecutive_ticks: usize,
    session_wants: SessionWants,
    session_interest_manager: SessionInterestManager,
    session_want_sender: SessionWantSender,
    peer_manager: PeerManager,
    latency_tracker: LatencyTracker,
    idle_tick: Pin<Box<Sleep>>,
    base_tick_delay: Duration,
    initial_search_delay: Duration,
    workers: Vec<JoinHandle<Option<()>>>,
    task_controller: tokio_context::task::TaskController,
    provider_search_queue: Arc<deadqueue::limited::Queue<Cid>>,
}

impl LoopState {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: u64,
        session_wants: SessionWants,
        session_want_sender: SessionWantSender,
        session_interest_manager: SessionInterestManager,
        network: Network,
        peer_manager: PeerManager,
        initial_search_delay: Duration,
        incoming: async_channel::Sender<Op>,
    ) -> Self {
        let idle_tick = Box::pin(tokio::time::sleep(initial_search_delay));
        let mut task_controller = tokio_context::task::TaskController::new();

        let mut workers = Vec::new();
        let queue = Arc::new(deadqueue::limited::Queue::new(128));

        for _ in 0..MAX_IN_PROCESS_REQUESTS {
            let network = network.clone();
            let incoming = incoming.clone();
            let queue = queue.clone();

            workers.push(task_controller.spawn(async move {
                loop {
                    let cid = queue.pop().await;
                    if let Ok(chan) = network.find_providers(cid, MAX_PROVIDERS).await {
                        let stream = tokio_stream::wrappers::ReceiverStream::new(chan);
                        stream
                            // Remove intermitten failures.
                            .filter_map(|providers_result| future::ready(providers_result.ok()))
                            // Flatten.
                            .flat_map_unordered(None, stream::iter)
                            // Attempt to dial the provider.
                            .filter_map(|provider| {
                                let network = network.clone();
                                async move {
                                    network
                                        .dial(provider, DEFAULT_TIMEOUT)
                                        .await
                                        .ok()
                                        .map(|_| provider)
                                }
                            })
                            // Notify the session about successfull ones.
                            .for_each_concurrent(None, |provider| {
                                inc!(BitswapMetrics::ProvidersTotal);
                                debug!("found provider for {}: {}", cid, provider);
                                // When a provider indicates that it has a cid, it's equivalent to
                                // the providing peer sending a HAVE.
                                let incoming = incoming.clone();
                                async move {
                                    let _ = incoming
                                        .send(Op::UpdateWantSender {
                                            from: provider,
                                            keys: Vec::new(),
                                            haves: vec![cid],
                                            dont_haves: Vec::new(),
                                        })
                                        .await;
                                }
                            })
                            .await;
                    }
                }
            }));
        }

        LoopState {
            id,
            consecutive_ticks: 0,
            session_wants,
            session_want_sender,
            session_interest_manager,
            peer_manager,
            latency_tracker: Default::default(),
            base_tick_delay: Duration::from_millis(500),
            initial_search_delay,
            idle_tick,
            workers,
            task_controller,
            provider_search_queue: queue,
        }
    }

    async fn stop(mut self) -> Result<()> {
        debug!(
            "seesion loop stopping {} (workers {})",
            self.id,
            self.workers.len(),
        );
        self.task_controller.cancel();
        while let Some(worker) = self.workers.pop() {
            worker.await?;
        }

        self.session_want_sender.stop().await?;

        Ok(())
    }

    /// Called when the session hasn't received any blocks for some time, or when
    /// all peers in the session have sent DONT_HAVE for a particular set of CIDs.
    /// Send want-haves to all connected peers, and search for new peers with the CID.
    async fn broadcast(&mut self, wants: Option<AHashSet<Cid>>) {
        debug!(
            "sesion:{}: broadcast: {:?}",
            self.id,
            wants.as_ref().map(|w| w.len())
        );
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
    async fn handle_periodic_search(&mut self) {
        debug!("session:{}: periodic search", self.id);
        if let Some(random_want) = self.session_wants.random_live_want() {
            // TODO: come up with a better strategy for determining when to search
            // for new providers for blocks.
            self.find_more_peers(&random_want).await;
            self.broadcast_want_haves(&[random_want].into_iter().collect())
                .await;
        }
    }

    /// Attempts to find more peers for a session by searching for providers for the given cid.
    async fn find_more_peers(&mut self, cid: &Cid) {
        debug!("session:{}: find_more_peers {}", self.id, cid);
        inc!(BitswapMetrics::ProviderQueryCreated);
        self.provider_search_queue.push(*cid).await;
    }

    /// Called when the session receives blocks from a peer.
    async fn handle_receive(&mut self, keys: Vec<Cid>) {
        debug!(
            "session:{}: received keys: {:?}",
            self.id,
            keys.iter().map(|k| k.to_string()).collect::<Vec<String>>()
        );
        // Record which blocks have been received and figure out the total latency
        // for fetching the blocks
        let (wanted, total_latency) = self.session_wants.blocks_received(&keys);
        if wanted.is_empty() {
            return;
        }
        record!(BitswapMetrics::WantedBlocksReceived, wanted.len() as u64);

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
        record!(BitswapMetrics::WantedBlocks, new_keys.len() as u64);
        if !new_keys.is_empty() {
            // Inform the SessionInterestManager that this session is interested in the keys.
            self.session_interest_manager
                .record_session_interest(self.id, &new_keys)
                .await;
            // Tell the SessionWants tracker that that the wants have been requested.
            self.session_wants.blocks_requested(&new_keys);
            // Tell the SessionWantSender that the blocks have been requested.
            self.session_want_sender.add(new_keys).await;
        }

        // If we have discovered peers already, the sessionWantSender will
        // send wants to them.
        if self
            .peer_manager
            .peers_discovered_for_session(self.id)
            .await
        {
            return;
        }

        // No peers discovered yet, broadcast some want-haves
        let keys = self.session_wants.get_next_wants();
        debug!(
            "session:{}: initial broadcast, as no peers discovered yet {}",
            self.id,
            keys.len()
        );

        if !keys.is_empty() {
            self.broadcast_want_haves(&keys).await;
        }
    }

    /// Send want-haves to all connected peers
    async fn broadcast_want_haves(&self, wants: &AHashSet<Cid>) {
        debug!(
            "session:{}: broadcasting wants: {:?}",
            self.id,
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

        debug!("session:{}: reset_idle_tick {:?}", self.id, tick_delay);
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

#[derive(Debug)]
pub struct BlockReceiver {
    /// Receives the results.
    receiver: async_channel::Receiver<Block>,
    guard: BlockReceiverGuard,
}
#[derive(Debug)]
pub struct BlockReceiverGuard {
    /// Used to cancel the work, when this is dropped.
    closer: Option<oneshot::Sender<()>>,
    _worker: JoinHandle<()>,
}

impl Drop for BlockReceiverGuard {
    fn drop(&mut self) {
        debug!("shutting down get block loop");
        if let Some(closer) = self.closer.take() {
            let _ = closer.send(());
        }
    }
}

impl BlockReceiver {
    pub fn into_parts(self) -> (async_channel::Receiver<Block>, BlockReceiverGuard) {
        (self.receiver, self.guard)
    }
}

impl Deref for BlockReceiver {
    type Target = async_channel::Receiver<Block>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

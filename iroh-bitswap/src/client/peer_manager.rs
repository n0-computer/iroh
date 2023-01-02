use std::{fmt::Debug, sync::Arc};

use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Result};
use cid::Cid;
use derivative::Derivative;
use futures::{future::BoxFuture, FutureExt};
use iroh_metrics::{bitswap::BitswapMetrics, core::MRecorder, inc};
use libp2p::PeerId;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, trace, warn};

use crate::network::Network;

use super::{message_queue::MessageQueue, peer_want_manager::PeerWantManager, session::Signaler};

#[derive(Debug, Clone)]
pub struct PeerManager {
    sender: mpsc::Sender<Message>,
}

#[derive(Derivative)]
#[derivative(Debug)]
enum Message {
    GetConnectedPeers(oneshot::Sender<Vec<PeerId>>),
    GetCurrentWants(oneshot::Sender<AHashSet<Cid>>),
    GetCurrentWantBlocks(oneshot::Sender<AHashSet<Cid>>),
    GetCurrentWantHaves(oneshot::Sender<AHashSet<Cid>>),
    Connected(PeerId),
    Disconnected(PeerId),
    ResponseReceived(PeerId, Vec<Cid>),
    BroadcastWantHaves(AHashSet<Cid>),
    SendWants {
        peer: PeerId,
        want_blocks: Vec<Cid>,
        want_haves: Vec<Cid>,
    },
    SendCancels(Vec<Cid>),
    RegisterSession {
        peer: PeerId,
        signaler: Signaler,
        response: oneshot::Sender<bool>,
    },
    UnregisterSession(u64, oneshot::Sender<()>),
    AddPeerToSession {
        session: u64,
        peer: PeerId,
        response: oneshot::Sender<bool>,
    },
    RemovePeerFromSession {
        session: u64,
        peer: PeerId,
        response: oneshot::Sender<bool>,
    },
    ProtectConnection {
        session: u64,
        peer: PeerId,
        response: oneshot::Sender<()>,
    },
    PeersDiscoveredForSession {
        session: u64,
        response: oneshot::Sender<bool>,
    },
    PeersForSession {
        session: u64,
        response: oneshot::Sender<Vec<PeerId>>,
    },
    SessionHasPeers {
        session: u64,
        response: oneshot::Sender<bool>,
    },
    SessionHasPeer {
        session: u64,
        peer: PeerId,
        response: oneshot::Sender<bool>,
    },
    SetCb(#[derivative(Debug = "ignore")] Arc<dyn DontHaveTimeout>),
}

pub trait DontHaveTimeout:
    Fn(PeerId, Vec<Cid>) -> BoxFuture<'static, ()> + 'static + Sync + Send
{
}

impl<F: Fn(PeerId, Vec<Cid>) -> BoxFuture<'static, ()> + 'static + Sync + Send> DontHaveTimeout
    for F
{
}

impl PeerManager {
    pub async fn new(self_id: PeerId, network: Network) -> Self {
        let (sender, receiver) = mpsc::channel(2048);
        let actor = PeerManagerActor::new(self_id, network, receiver).await;

        let _worker = tokio::task::spawn(async move {
            run(actor).await;
        });

        Self { sender }
    }

    pub async fn set_cb<F>(&self, on_dont_have_timeout: F)
    where
        F: DontHaveTimeout,
    {
        self.send(Message::SetCb(Arc::new(on_dont_have_timeout)))
            .await;
    }

    async fn send(&self, message: Message) {
        if let Err(err) = self.sender.send(message).await {
            warn!("failed to send message: {:?}", err);
        }
    }

    pub async fn available_peers(&self) -> Vec<PeerId> {
        self.connected_peers().await
    }

    /// Returns a list of peers this peer manager is managing.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        let (s, r) = oneshot::channel();
        self.send(Message::GetConnectedPeers(s)).await;
        r.await.unwrap_or_default()
    }

    /// Called to a new peer to the pool, and send it an initial set of wants.
    pub async fn connected(&self, peer: &PeerId) {
        self.send(Message::Connected(*peer)).await;
    }

    /// Called to remove a peer from the pool.
    pub async fn disconnected(&self, peer: &PeerId) {
        self.send(Message::Disconnected(*peer)).await;
    }

    /// Called when a message is received from the network.
    /// The set of blocks, HAVEs and DONT_HAVEs, is `cids`.
    /// Currently only used to calculate latency.
    pub async fn response_received(&self, peer: &PeerId, cids: &[Cid]) {
        self.send(Message::ResponseReceived(*peer, cids.to_vec()))
            .await;
    }

    /// Broadcasts want-haves to all peers
    /// (used by the session to discover seeds).
    /// For each peer it filters out want-haves that have previously been sent to the peer.
    pub async fn broadcast_want_haves(&self, want_haves: &AHashSet<Cid>) {
        self.send(Message::BroadcastWantHaves(want_haves.to_owned()))
            .await
    }

    /// Sends the given want-blocks and want-haves to the given peer.
    /// It filters out wants that have been previously sent to the peer.
    pub async fn send_wants(&self, peer: &PeerId, want_blocks: &[Cid], want_haves: &[Cid]) {
        self.send(Message::SendWants {
            peer: *peer,
            want_blocks: want_blocks.to_vec(),
            want_haves: want_haves.to_vec(),
        })
        .await;
    }

    /// Sends cancels for the given keys to all peers who had previously received a want for those keys.
    pub async fn send_cancels(&self, cancels: &[Cid]) {
        self.send(Message::SendCancels(cancels.to_vec())).await;
    }

    /// Returns a list of pending wants (both want-haves and want-blocks).
    pub async fn current_wants(&self) -> AHashSet<Cid> {
        let (s, r) = oneshot::channel();
        self.send(Message::GetCurrentWants(s)).await;
        r.await.unwrap_or_default()
    }

    /// Returns a list of pending want-blocks.
    pub async fn current_want_blocks(&self) -> AHashSet<Cid> {
        let (s, r) = oneshot::channel();
        self.send(Message::GetCurrentWantBlocks(s)).await;
        r.await.unwrap_or_default()
    }

    /// Returns a list of pending want-haves
    pub async fn current_want_haves(&self) -> AHashSet<Cid> {
        let (s, r) = oneshot::channel();
        self.send(Message::GetCurrentWantHaves(s)).await;
        r.await.unwrap_or_default()
    }

    /// Informs the `PeerManager` that the given session is interested in events about the given peer.
    pub async fn register_session(&self, peer: &PeerId, signaler: Signaler) -> bool {
        let (s, r) = oneshot::channel();
        self.send(Message::RegisterSession {
            peer: *peer,
            signaler,
            response: s,
        })
        .await;
        r.await.unwrap_or_default()
    }

    pub async fn unregister_session(&self, session_id: u64) {
        let (s, r) = oneshot::channel();
        self.send(Message::UnregisterSession(session_id, s)).await;
        let _ = r.await;
    }

    /// Shutdown this peer manager.
    pub async fn stop(self) -> Result<()> {
        debug!("stopping peer manager");
        // dropping will stop the loop

        Ok(())
    }

    /// Adds the peer to the session.
    /// Returns true if the peer is new.
    pub async fn add_peer_to_session(&self, session: u64, peer: PeerId) -> bool {
        let (s, r) = oneshot::channel();
        self.send(Message::AddPeerToSession {
            session,
            peer,
            response: s,
        })
        .await;

        r.await.unwrap_or_default()
    }

    /// Removes the peer from the sessoin.
    /// Returns true if the peer existed.
    pub async fn remove_peer_from_session(&self, session: u64, peer: PeerId) -> bool {
        let (s, r) = oneshot::channel();
        self.send(Message::RemovePeerFromSession {
            session,
            peer,
            response: s,
        })
        .await;

        r.await.unwrap_or_default()
    }

    /// Protects this connection.
    pub async fn protect_connection(&self, session: u64, peer: PeerId) {
        let (s, r) = oneshot::channel();
        self.send(Message::ProtectConnection {
            session,
            peer,
            response: s,
        })
        .await;

        let _ = r.await;
    }

    /// Indicates wether peers have been discovered yet.
    pub async fn peers_discovered_for_session(&self, session: u64) -> bool {
        let (s, r) = oneshot::channel();
        self.send(Message::PeersDiscoveredForSession {
            session,
            response: s,
        })
        .await;

        r.await.unwrap_or_default()
    }

    pub async fn peers_for_session(&self, session: u64) -> Vec<PeerId> {
        let (s, r) = oneshot::channel();
        self.send(Message::PeersForSession {
            session,
            response: s,
        })
        .await;

        r.await.unwrap_or_default()
    }

    pub async fn session_has_peers(&self, session: u64) -> bool {
        let (s, r) = oneshot::channel();
        self.send(Message::SessionHasPeers {
            session,
            response: s,
        })
        .await;

        r.await.unwrap_or_default()
    }

    pub async fn session_has_peer(&self, session: u64, peer: PeerId) -> bool {
        let (s, r) = oneshot::channel();
        self.send(Message::SessionHasPeer {
            session,
            peer,
            response: s,
        })
        .await;

        r.await.unwrap_or_default()
    }
}

async fn run(mut actor: PeerManagerActor) {
    loop {
        inc!(BitswapMetrics::PeerManagerLoopTick);

        tokio::select! {
            message = actor.receiver.recv() => {
                match message {
                    Some(Message::GetConnectedPeers(r)) => {
                        let _= r.send(actor.connected_peers().await);
                    },
                    Some(Message::GetCurrentWants(r)) => {
                        let _ = r.send(actor.current_wants());
                    },
                    Some(Message::GetCurrentWantBlocks(r)) => {
                        let _ = r.send(actor.current_want_blocks());
                    },
                    Some(Message::GetCurrentWantHaves(r)) => {
                        let _ = r.send(actor.current_want_haves());
                    },
                    Some(Message::Connected(peer)) => {
                        actor.connected(peer).await;
                    },
                    Some(Message::Disconnected(peer)) => {
                        actor.disconnected(peer).await;
                    },
                    Some(Message::ResponseReceived(peer, responses)) => {
                        actor.response_received(peer, responses).await;
                    },
                    Some(Message::BroadcastWantHaves(list)) => {
                        actor.broadcast_want_haves(list).await;
                    },
                    Some(Message::SendWants {
                        peer,
                        want_blocks,
                        want_haves,
                    }) => {
                        actor.send_wants(peer, want_blocks, want_haves).await;
                    },
                    Some(Message::SendCancels(cancels)) => {
                        actor.send_cancels(cancels).await;
                    },
                    Some(Message::RegisterSession { peer, signaler, response }) => {
                        let _ = response.send(actor.register_session(peer, signaler).await);
                    },
                    Some(Message::UnregisterSession(session, response)) => {
                        actor.unregister_session(session, response).await;
                    },
                    Some(Message::SetCb(cb)) => {
                        actor.on_dont_have_timeout = cb;
                    }
                    Some(Message::AddPeerToSession{
                        session,
                        peer,
                        response,
                    }) => {
                        actor.add_peer_to_session(session, peer, response).await;
                    },
                    Some(Message::RemovePeerFromSession{
                        session,
                        peer,
                        response,
                    }) => {
                        actor.remove_peer_from_session(session, peer, response).await;
                    },
                    Some(Message::ProtectConnection{
                        session,
                        peer,
                        response,
                    }) => {
                        actor.protect_connection(session, peer, response).await;
                    },
                    Some(Message::PeersDiscoveredForSession{
                        session,
                        response,
                    }) => {
                        actor.peers_discovered_for_session(session, response).await;
                    },
                    Some(Message::PeersForSession{
                        session,
                        response,
                    }) => {
                        actor.peers_for_session(session, response).await;
                    },
                    Some(Message::SessionHasPeers{
                        session,
                        response,
                    }) => {
                        actor.session_has_peers(session, response).await;
                    },
                    Some(Message::SessionHasPeer{
                        session,
                        peer,
                        response,
                    }) => {
                        actor.session_has_peer(session, peer, response).await;
                    },
                    None => {
                        break;
                    }
                }
            }
        }
    }

    if let Err(err) = actor.stop().await {
        warn!("failed to shutdown peer manager: {:?}", err);
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
struct PeerManagerActor {
    receiver: mpsc::Receiver<Message>,
    peers: AHashMap<PeerId, PeerState>,
    peer_want_manager: PeerWantManager,
    sessions: AHashMap<u64, SessionState>,
    self_id: PeerId,
    network: Network,
    #[derivative(Debug = "ignore")]
    on_dont_have_timeout: Arc<dyn DontHaveTimeout>,
}

#[derive(Debug)]
pub(super) struct PeerState {
    pub(super) message_queue: MessageQueue,
    pub(super) sessions: AHashSet<u64>,
}

#[derive(Debug)]
struct SessionState {
    signaler: Signaler,
    // TODO: can this be merged into `peers`?
    peers: AHashSet<PeerId>,
    /// Have we ever discovered a peer for this session?
    peers_discovered: bool,
}

impl PeerManagerActor {
    async fn new(self_id: PeerId, network: Network, receiver: mpsc::Receiver<Message>) -> Self {
        Self {
            self_id,
            receiver,
            network,
            peers: Default::default(),
            peer_want_manager: Default::default(),
            sessions: Default::default(),
            on_dont_have_timeout: Arc::new(|_, _| async move {}.boxed()),
        }
    }

    async fn stop(self) -> Result<()> {
        let results = futures::future::join_all(
            self.peers
                .into_iter()
                .map(|(_, state)| async move { state.message_queue.stop().await }),
        )
        .await;
        for r in results {
            r?;
        }
        Ok(())
    }

    /// Returns a list of peers this peer manager is managing.
    async fn connected_peers(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }

    /// Called to a new peer to the pool, and send it an initial set of wants.
    async fn connected(&mut self, peer: PeerId) {
        self.insert_peer(peer, None).await;

        let peer_state = self.peers.get_mut(&peer).unwrap();
        if !peer_state.message_queue.is_running() {
            trace!("found stopped peer_queue, restarting: {}", peer);
            inc!(BitswapMetrics::MessageQueuesCreated);
            // Restart if the queue was stopped, but not yet cleaned up.
            peer_state.message_queue = MessageQueue::new(
                peer,
                self.network.clone(),
                self.on_dont_have_timeout.clone(),
            )
            .await;
        }

        // Inform the peer want manager that there's a new peer.
        self.peer_want_manager
            .add_peer(&peer_state.message_queue, &peer)
            .await;

        // Inform the session that the peer has connected
        self.signal_availability(peer, true).await;
    }

    async fn disconnected(&mut self, peer: PeerId) {
        if let Some(peer_state) = self.peers.remove(&peer) {
            inc!(BitswapMetrics::MessageQueuesDestroyed);
            // inform the sessions that the peer has disconnected

            self.peer_want_manager.remove_peer(&peer);

            if let Err(err) = peer_state.message_queue.stop().await {
                error!("failed to shutdown message queue for {}: {:?}", peer, err);
            }
        }
    }

    async fn response_received(&self, peer: PeerId, cids: Vec<Cid>) {
        if let Some(peer_state) = self.peers.get(&peer) {
            peer_state.message_queue.response_received(cids).await;
        }
    }

    async fn broadcast_want_haves(&mut self, want_haves: AHashSet<Cid>) {
        self.peer_want_manager
            .broadcast_want_haves(&want_haves, &self.peers)
            .await;
    }

    async fn send_wants(&mut self, peer: PeerId, want_blocks: Vec<Cid>, want_haves: Vec<Cid>) {
        debug!(
            "send_wants to {}: {}, {} {:?}, {:?}",
            peer,
            want_blocks.len(),
            want_haves.len(),
            want_blocks,
            want_haves
        );
        if let Some(peer_state) = self.peers.get(&peer) {
            self.peer_want_manager
                .send_wants(&peer, &want_blocks, &want_haves, &peer_state.message_queue)
                .await;
        }
    }

    async fn send_cancels(&mut self, cancels: Vec<Cid>) {
        self.peer_want_manager
            .send_cancels(&cancels, &self.peers)
            .await;
    }

    fn current_wants(&self) -> AHashSet<Cid> {
        self.peer_want_manager.get_wants()
    }

    fn current_want_blocks(&self) -> AHashSet<Cid> {
        self.peer_want_manager.get_want_blocks()
    }

    fn current_want_haves(&self) -> AHashSet<Cid> {
        self.peer_want_manager.get_want_haves()
    }

    /// Returns true if the peer is new..
    async fn register_session(&mut self, peer: PeerId, signaler: Signaler) -> bool {
        debug!("register session {}: {}", peer, signaler.id());
        let id = signaler.id();

        match self.sessions.entry(id) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().peers_discovered = true;
                entry.get_mut().peers.insert(peer)
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(SessionState {
                    signaler,
                    peers: [peer].into_iter().collect(),
                    peers_discovered: true,
                });
                true
            }
        }
    }

    async fn insert_peer(&mut self, peer: PeerId, session: Option<u64>) {
        match self.peers.entry(peer) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if let Some(id) = session {
                    entry.get_mut().sessions.insert(id);
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                inc!(BitswapMetrics::MessageQueuesCreated);
                let message_queue = MessageQueue::new(
                    peer,
                    self.network.clone(),
                    self.on_dont_have_timeout.clone(),
                )
                .await;
                let sessions = session
                    .map(|id| [id].into_iter().collect())
                    .unwrap_or_default();
                entry.insert(PeerState {
                    message_queue,
                    sessions,
                });
            }
        }
    }

    async fn unregister_session(&mut self, session_id: u64, response: oneshot::Sender<()>) {
        for peer_state in self.peers.values_mut() {
            peer_state.sessions.remove(&session_id);
        }

        if let Some(session) = self.sessions.remove(&session_id) {
            for peer in session.peers {
                self.network.unprotect_peer(peer).await;
            }
        }
        let _ = response.send(());
    }

    /// Called when a peers connectivity changes, informs the interested sessions.
    async fn signal_availability(&self, peer: PeerId, is_connected: bool) {
        if let Some(peer_state) = self.peers.get(&peer) {
            for session_id in &peer_state.sessions {
                if let Some(session) = self.sessions.get(session_id) {
                    session.signaler.signal_availability(peer, is_connected);
                }
            }
        }
    }

    async fn add_peer_to_session(
        &mut self,
        session_id: u64,
        peer: PeerId,
        response: oneshot::Sender<bool>,
    ) {
        debug!("add peer to session {}: {}", peer, session_id);
        if let Some(session) = self.sessions.get_mut(&session_id) {
            debug!("found session: {}: {}", peer, session_id);
            if session.peers.contains(&peer) {
                let _ = response.send(false);
                return;
            }

            session.peers.insert(peer);
            session.peers_discovered = true;

            let _ = response.send(true);
        } else {
            debug!("found no session: {}: {}", peer, session_id);
            // TODO: better handling
            let _ = response.send(true);
        }
    }

    async fn protect_connection(
        &mut self,
        session: u64,
        peer: PeerId,
        response: oneshot::Sender<()>,
    ) {
        if let Some(session) = self.sessions.get(&session) {
            if session.peers.contains(&peer) {
                self.network
                    .protect_peer(peer)
                    .await
                    .context("Failed to protect connection")
                    .map_err(|err| error!("{err:#}"))
                    .ok();
            }
        }
        response.send(()).ok();
    }

    async fn remove_peer_from_session(
        &mut self,
        session: u64,
        peer: PeerId,
        response: oneshot::Sender<bool>,
    ) {
        if let Some(session) = self.sessions.get_mut(&session) {
            let existed = session.peers.remove(&peer);
            let _ = response.send(existed);

            if existed {
                self.network.unprotect_peer(peer).await;
            }
        } else {
            let _ = response.send(false);
        }
    }

    /// Indicates wether peers have been discovered yet.
    async fn peers_discovered_for_session(&self, session: u64, response: oneshot::Sender<bool>) {
        if let Some(session) = self.sessions.get(&session) {
            let _ = response.send(session.peers_discovered);
        } else {
            let _ = response.send(false);
        }
    }

    async fn peers_for_session(&self, session: u64, response: oneshot::Sender<Vec<PeerId>>) {
        if let Some(session) = self.sessions.get(&session) {
            let _ = response.send(session.peers.iter().copied().collect());
        } else {
            let _ = response.send(Vec::new());
        }
    }

    async fn session_has_peers(&self, session: u64, response: oneshot::Sender<bool>) {
        if let Some(session) = self.sessions.get(&session) {
            let _ = response.send(!session.peers.is_empty());
        } else {
            let _ = response.send(false);
        }
    }

    async fn session_has_peer(&self, session: u64, peer: PeerId, response: oneshot::Sender<bool>) {
        if let Some(session) = self.sessions.get(&session) {
            let _ = response.send(session.peers.contains(&peer));
        } else {
            let _ = response.send(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::block::tests::create_random_block_v1;

    use super::*;

    #[tokio::test]
    async fn test_adding_removing_peers() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        let peer4 = PeerId::random();
        let peer5 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network).await;
        peer_manager.connected(&peer1).await;
        peer_manager.connected(&peer2).await;
        peer_manager.connected(&peer3).await;

        let connected_peers = peer_manager.connected_peers().await;
        assert!(connected_peers.contains(&peer1));
        assert!(connected_peers.contains(&peer2));
        assert!(connected_peers.contains(&peer3));

        assert!(!connected_peers.contains(&peer4));
        assert!(!connected_peers.contains(&peer5));

        // disconnect
        peer_manager.disconnected(&peer1).await;
        let connected_peers = peer_manager.connected_peers().await;
        assert!(!connected_peers.contains(&peer1));

        // reconnect
        peer_manager.connected(&peer1).await;
        let connected_peers = peer_manager.connected_peers().await;
        assert!(connected_peers.contains(&peer1));
        peer_manager.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_broadcast_on_connect() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network).await;
        let cids: AHashSet<_> = gen_cids(2).into_iter().collect();

        peer_manager.broadcast_want_haves(&cids).await;

        // connect with peer, which should send out the broadcast
        peer_manager.connected(&peer1).await;

        // check messages in MessageQueue
        {
            // TODO:
            // let mut peers = &peer_manager.peers;
            // let mq = peers.get(&peer1).unwrap();
            // let mq = mq.wants().await.unwrap();
            // assert_eq!(mq.bcst_wants.pending.len(), 2);
            // for cid in &cids {
            //     assert!(mq.bcst_wants.pending.get(cid).is_some());
            // }
        }
        peer_manager.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_broadcast_want_haves() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network).await;
        let cids = gen_cids(3);

        // broadcast 2
        peer_manager
            .broadcast_want_haves(&cids[..2].iter().copied().collect::<AHashSet<_>>())
            .await;

        peer_manager.connected(&peer1).await;

        {
            // TODO:
            // let peers = &peer_manager.peers;
            // let mq = peers.get(&peer1).unwrap();
            // let mq = mq.wants().await.unwrap();
            // assert_eq!(mq.bcst_wants.pending.len(), 2);
            // for cid in &cids[..2] {
            //     assert!(mq.bcst_wants.pending.get(cid).is_some());
            // }
        }

        // second peer
        peer_manager.connected(&peer2).await;

        // broadcast to all peers, including an already sent cid
        peer_manager
            .broadcast_want_haves(&[cids[0], cids[2]].into_iter().collect::<AHashSet<_>>())
            .await;

        {
            // TODO:
            // let peers = &peer_manager.inner.peers;
            // // peer 1 now has all three
            // {
            //     let mq = peers.get(&peer1).unwrap();
            //     let mq = mq.wants().await.unwrap();
            //     assert_eq!(mq.bcst_wants.pending.len(), 3);
            //     for cid in &cids {
            //         assert!(mq.bcst_wants.pending.get(cid).is_some());
            //     }
            // }
            // // peer 2 now has all three
            // {
            //     let mq = peers.get(&peer2).unwrap();
            //     let mq = mq.wants().await.unwrap();
            //     assert_eq!(mq.bcst_wants.pending.len(), 3);
            //     for cid in &cids {
            //         assert!(mq.bcst_wants.pending.get(cid).is_some());
            //     }
            // }
        }
        peer_manager.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_send_wants() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network).await;
        let cids = gen_cids(4);

        peer_manager.connected(&peer1).await;
        peer_manager
            .send_wants(&peer1, &[cids[0]][..], &[cids[2]][..])
            .await;

        {
            // TODO.
            // let peers = &peer_manager.inner.peers;
            // let mq = peers.get_mut(&peer1).unwrap();
            // let mq = mq.wants().await.unwrap();
            // assert!(mq.bcst_wants.pending.is_empty());
            // assert_eq!(mq.peer_wants.pending.len(), 2);
            // assert_eq!(
            //     mq.peer_wants.pending.get(&cids[0]).unwrap().want_type,
            //     WantType::Block
            // );
            // assert_eq!(
            //     mq.peer_wants.pending.get(&cids[2]).unwrap().want_type,
            //     WantType::Have
            // );
        }

        peer_manager
            .send_wants(&peer1, &[cids[0], cids[1]][..], &[cids[2], cids[3]][..])
            .await;

        {
            // TODO:
            // let peers = &peer_manager.inner.peers;
            // let mq = peers.get(&peer1).unwrap();
            // let mq = mq.wants().await.unwrap();
            // assert!(mq.bcst_wants.pending.is_empty());
            // assert_eq!(mq.peer_wants.pending.len(), 4);
            // assert_eq!(
            //     mq.peer_wants.pending.get(&cids[0]).unwrap().want_type,
            //     WantType::Block
            // );
            // assert_eq!(
            //     mq.peer_wants.pending.get(&cids[1]).unwrap().want_type,
            //     WantType::Block
            // );
            // assert_eq!(
            //     mq.peer_wants.pending.get(&cids[2]).unwrap().want_type,
            //     WantType::Have
            // );
            // assert_eq!(
            //     mq.peer_wants.pending.get(&cids[3]).unwrap().want_type,
            //     WantType::Have
            // );
        }
        peer_manager.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_send_cancels() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network).await;
        let cids = gen_cids(4);

        peer_manager.connected(&peer1).await;
        peer_manager.connected(&peer2).await;

        peer_manager
            .send_wants(&peer1, &[cids[0], cids[1]][..], &[cids[2]][..])
            .await;
        std::thread::sleep(Duration::from_millis(100));

        {
            // TODO:
            // let peers = &peer_manager.inner.peers;
            // let mq = peers.get(&peer1).unwrap();
            // let mq = mq.wants().await.unwrap();
            // assert!(mq.bcst_wants.pending.is_empty());
            // assert!(mq.bcst_wants.sent.is_empty());
            // // TODO: doesn't work because dialing fails
            // // assert!(mq.peer_wants.pending.is_empty());
            // // assert_eq!(mq.peer_wants.sent.len(), 3);
            // assert!(mq.cancels.is_empty());
        }

        peer_manager.send_cancels(&[cids[0], cids[2]][..]).await;
        std::thread::sleep(Duration::from_millis(100));
        {
            // TODO:
            // let peers = &peer_manager.inner.peers;

            // // check that no cancels went to peer2
            // {
            //     let mq = peers.get(&peer2).unwrap();
            //     let mq = mq.wants().await.unwrap();
            //     assert!(mq.cancels.is_empty());
            // }

            // TODO: doesn't work because dialing fails
            // {
            //     let mq = peers.0.get(&peer1).unwrap();
            //     let mq = mq.wants().await.unwrap();
            //     assert!(mq.bcst_wants.pending.is_empty());
            //     assert_eq!(mq.peer_wants.pending.len(), 1);
            //     assert_eq!(mq.cancels.len(), 2);
            // }
        }
        peer_manager.stop().await.unwrap();
    }

    fn gen_cids(n: usize) -> Vec<Cid> {
        (0..n).map(|_| *create_random_block_v1().cid()).collect()
    }
}

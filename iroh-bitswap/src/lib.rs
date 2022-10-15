//! Implements handling of the [bitswap protocol]((https://github.com/ipfs/specs/blob/master/BITSWAP.md)). Based on go-ipfs.
//!
//! Supports the versions `1.0.0`, `1.1.0` and `1.2.0`.

use std::collections::HashSet;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ahash::AHashMap;
use anyhow::Result;
use async_trait::async_trait;
use cid::Cid;
use handler::{BitswapHandler, HandlerEvent};
use iroh_metrics::bitswap::BitswapMetrics;
use iroh_metrics::core::MRecorder;
use iroh_metrics::inc;
use libp2p::core::connection::ConnectionId;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    CloseConnection, DialError, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
    NotifyHandler, PollParameters,
};
use libp2p::{Multiaddr, PeerId};
use message::BitswapMessage;
use network::OutEvent;
use protocol::{ProtocolConfig, ProtocolId};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use self::client::{Client, Config as ClientConfig};
use self::network::Network;
use self::server::{Config as ServerConfig, Server};

mod block;
mod client;
mod error;
mod handler;
mod message;
mod network;
mod prefix;
mod protocol;
mod server;

pub mod peer_task_queue;
pub use self::block::Block;
pub use self::message::Priority;

#[derive(Debug, Clone)]
pub struct Bitswap<S: Store> {
    network: Network,
    protocol_config: ProtocolConfig,
    idle_timeout: Duration,
    peers: Arc<Mutex<AHashMap<PeerId, PeerState>>>,
    dials: Arc<
        Mutex<
            AHashMap<
                PeerId,
                Vec<(
                    usize,
                    oneshot::Sender<
                        std::result::Result<(ConnectionId, Option<ProtocolId>), String>,
                    >,
                )>,
            >,
        >,
    >,
    /// Set to true when dialing should be disabled because we have reached the conn limit.
    pause_dialing: bool,
    client: Client<S>,
    server: Server<S>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerState {
    Connected(ConnectionId),
    Responsive(ConnectionId, ProtocolId),
    Unresponsive,
    Disconnected,
}

impl Default for PeerState {
    fn default() -> Self {
        PeerState::Disconnected
    }
}

#[derive(Debug)]
pub struct Config {
    pub client: ClientConfig,
    pub server: ServerConfig,
    pub protocol: ProtocolConfig,
    pub idle_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            client: ClientConfig::default(),
            server: ServerConfig::default(),
            protocol: ProtocolConfig::default(),
            idle_timeout: Duration::from_secs(30),
        }
    }
}

#[async_trait]
pub trait Store: Debug + Clone + Send + Sync + 'static {
    async fn get_size(&self, cid: &Cid) -> Result<usize>;
    async fn get(&self, cid: &Cid) -> Result<Block>;
    async fn has(&self, cid: &Cid) -> Result<bool>;
}

impl<S: Store> Bitswap<S> {
    pub async fn new(self_id: PeerId, store: S, config: Config) -> Self {
        let network = Network::new(self_id);
        let server = Server::new(network.clone(), store.clone(), config.server).await;
        let client = Client::new(
            network.clone(),
            store,
            server.received_blocks_cb(),
            config.client,
        )
        .await;

        Bitswap {
            network,
            protocol_config: config.protocol,
            idle_timeout: config.idle_timeout,
            peers: Default::default(),
            dials: Default::default(),
            pause_dialing: false,
            server,
            client,
        }
    }

    pub fn server(&self) -> &Server<S> {
        &self.server
    }

    pub fn client(&self) -> &Client<S> {
        &self.client
    }

    pub async fn stop(self) -> Result<()> {
        self.network.stop();
        let (a, b) = futures::future::join(self.client.stop(), self.server.stop()).await;
        a?;
        b?;

        Ok(())
    }

    pub async fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        self.client.notify_new_blocks(blocks).await?;
        self.server.notify_new_blocks(blocks).await?;

        Ok(())
    }

    pub async fn stat(&self) -> Result<Stat> {
        let client_stat = self.client.stat().await?;
        let server_stat = self.server.stat().await?;

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

    pub async fn wantlist_for_peer(&self, peer: &PeerId) -> Vec<Cid> {
        if peer == self.network.self_id() {
            return self.client.get_wantlist().await.into_iter().collect();
        }

        self.server.wantlist_for_peer(peer).await
    }

    fn peer_connected(&self, peer: PeerId) {
        debug!("peer {} connected", peer);
        let client = self.client.clone();
        let server = self.server.clone();
        tokio::task::spawn(async move {
            client.peer_connected(&peer).await;
            server.peer_connected(&peer).await;
        });
    }

    fn peer_disconnected(&self, peer: PeerId) {
        debug!("peer {} disconnected", peer);
        let client = self.client.clone();
        let server = self.server.clone();
        tokio::task::spawn(async move {
            client.peer_disconnected(&peer).await;
            server.peer_disconnected(&peer).await;
        });
    }

    fn receive_message(&self, peer: PeerId, message: BitswapMessage) {
        let client = self.client.clone();
        let server = self.server.clone();
        tokio::task::spawn(async move {
            client.receive_message(&peer, &message).await;
            server.receive_message(&peer, &message).await;
        });
    }

    fn get_peer_state(&self, peer: &PeerId) -> PeerState {
        self.peers
            .lock()
            .unwrap()
            .get(peer)
            .copied()
            .unwrap_or(PeerState::Disconnected)
    }

    fn set_peer_state(&mut self, peer: &PeerId, new_state: PeerState) {
        let peers = &mut *self.peers.lock().unwrap();
        let peer_state = peers.entry(*peer).or_default();
        let old_state = *peer_state;
        *peer_state = new_state;
        let peer = *peer;

        match peer_state {
            PeerState::Disconnected => {
                peers.remove(&peer);
                if matches!(old_state, PeerState::Responsive(_, _)) {
                    self.peer_disconnected(peer);
                }
            }
            PeerState::Unresponsive => {
                if matches!(old_state, PeerState::Responsive(_, _)) {
                    self.peer_disconnected(peer);
                }
            }
            PeerState::Connected(_) => {
                // we only connected, might not speak bitswap
                // TODO: this is tricky
                self.peer_connected(peer);
            }
            PeerState::Responsive(_, _) => {
                if !matches!(old_state, PeerState::Connected(_)) {
                    // Only trigger if not already triggered before
                    self.peer_connected(peer);
                }
            }
        }
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

#[derive(Debug)]
pub enum BitswapEvent {
    /// We have this content, and want it to be provided.
    Provide { key: Cid },
    FindProviders {
        key: Cid,
        response: tokio::sync::mpsc::Sender<std::result::Result<HashSet<PeerId>, String>>,
    },
    Ping {
        peer: PeerId,
        response: oneshot::Sender<Option<Duration>>,
    },
}

impl<S: Store> NetworkBehaviour for Bitswap<S> {
    type ConnectionHandler = BitswapHandler;
    type OutEvent = BitswapEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        let protocol_config = self.protocol_config.clone();
        BitswapHandler::new(protocol_config, self.idle_timeout)
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Default::default()
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        connection: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        other_established: usize,
    ) {
        debug!("connection established {} ({})", peer_id, other_established);
        if self.get_peer_state(peer_id) == PeerState::Disconnected {
            self.set_peer_state(peer_id, PeerState::Connected(*connection));
        }
        self.pause_dialing = false;
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        _conn: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _handler: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        remaining_established: usize,
    ) {
        self.pause_dialing = false;
        if remaining_established == 0 {
            // debug!("connection closed {}", peer_id);
            if self.get_peer_state(peer_id) == PeerState::Disconnected {
                return;
            }
            self.set_peer_state(peer_id, PeerState::Disconnected)
        }
    }

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        error: &DialError,
    ) {
        if let Some(peer_id) = peer_id {
            if let DialError::ConnectionLimit(_) = error {
                self.pause_dialing = true;
            }
            debug!("inject_dial_failure {}, {:?}", peer_id, error);
            let dials = &mut self.dials.lock().unwrap();
            if let Some(mut dials) = dials.remove(&peer_id) {
                while let Some((id, sender)) = dials.pop() {
                    if let Err(err) = sender.send(Err(error.to_string())) {
                        warn!("dial:{}: failed to send dial response {:?}", id, err)
                    }
                }
            }
        }
    }

    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, event: HandlerEvent) {
        // trace!("inject_event from {}, event: {:?}", peer_id, event);
        match event {
            HandlerEvent::Connected { protocol } => {
                self.peer_connected(peer_id);
                {
                    let dials = &mut *self.dials.lock().unwrap();
                    if let Some(mut dials) = dials.remove(&peer_id) {
                        while let Some((id, sender)) = dials.pop() {
                            if let Err(err) = sender.send(Ok((connection, Some(protocol)))) {
                                warn!("dial:{}: failed to send dial response {:?}", id, err)
                            }
                        }
                    }
                }

                self.set_peer_state(&peer_id, PeerState::Responsive(connection, protocol));
            }
            HandlerEvent::ProtocolNotSuppported => {
                if matches!(self.get_peer_state(&peer_id), PeerState::Responsive(_, _)) {
                    self.set_peer_state(&peer_id, PeerState::Unresponsive);
                }

                let dials = &mut *self.dials.lock().unwrap();
                if let Some(mut dials) = dials.remove(&peer_id) {
                    while let Some((id, sender)) = dials.pop() {
                        if let Err(err) = sender.send(Err("protocol not supported".into())) {
                            warn!("dial:{} failed to send dial response {:?}", id, err)
                        }
                    }
                }
            }
            HandlerEvent::Message {
                mut message,
                protocol,
            } => {
                // mark peer as responsive
                if self.get_peer_state(&peer_id) == PeerState::Unresponsive {
                    self.set_peer_state(&peer_id, PeerState::Responsive(connection, protocol));
                }

                message.verify_blocks();
                self.receive_message(peer_id, message);
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        inc!(BitswapMetrics::NetworkBehaviourActionPollTick);
        // limit work
        for _ in 0..100 {
            match Pin::new(&mut self.network).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(ev) => match ev {
                    OutEvent::Disconnect(peer_id, response) => {
                        if let Err(err) = response.send(()) {
                            warn!("failed to send disconnect response {:?}", err)
                        }
                        return Poll::Ready(NetworkBehaviourAction::CloseConnection {
                            peer_id,
                            connection: CloseConnection::All,
                        });
                    }
                    OutEvent::Dial { peer, response, id } => {
                        if self.pause_dialing {
                            // already connected
                            if let Err(err) =
                                response.send(Err(format!("dial:{}: dialing paused", id)))
                            {
                                warn!("dial:{}: failed to send dial response {:?}", id, err)
                            }
                            continue;
                        }
                        match self.get_peer_state(&peer) {
                            PeerState::Responsive(conn, protocol_id) => {
                                // already connected
                                if let Err(err) = response.send(Ok((conn, Some(protocol_id)))) {
                                    debug!("dial:{}: failed to send dial response {:?}", id, err)
                                }
                                continue;
                            }
                            PeerState::Connected(conn) => {
                                // already connected
                                if let Err(err) = response.send(Ok((conn, None))) {
                                    debug!("dial:{}: failed to send dial response {:?}", id, err)
                                }
                                continue;
                            }
                            _ => {
                                self.dials
                                    .lock()
                                    .unwrap()
                                    .entry(peer)
                                    .or_default()
                                    .push((id, response));

                                return Poll::Ready(NetworkBehaviourAction::Dial {
                                    opts: DialOpts::peer_id(peer)
                                        .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
                                        .build(),
                                    handler: self.new_handler(),
                                });
                            }
                        }
                    }
                    OutEvent::GenerateEvent(ev) => {
                        return Poll::Ready(NetworkBehaviourAction::GenerateEvent(ev))
                    }
                    OutEvent::SendMessage {
                        peer,
                        message,
                        response,
                        connection_id,
                    } => {
                        tracing::debug!("send message {}", peer);
                        return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                            peer_id: peer,
                            handler: NotifyHandler::One(connection_id),
                            event: handler::BitswapHandlerIn::Message(message, response),
                        });
                    }
                },
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::anyhow;
    use futures::prelude::*;
    use libp2p::core::muxing::StreamMuxerBox;
    use libp2p::core::transport::upgrade::Version;
    use libp2p::core::transport::Boxed;
    use libp2p::identity::Keypair;
    use libp2p::swarm::SwarmBuilder;
    use libp2p::tcp::{GenTcpConfig, TokioTcpTransport};
    use libp2p::yamux::YamuxConfig;
    use libp2p::{noise, PeerId, Swarm, Transport};
    use tokio::sync::{mpsc, RwLock};
    use tracing::{info, trace};
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    use super::*;
    use crate::block::tests::*;
    use crate::Block;

    fn assert_send<T: Send + Sync>() {}

    #[derive(Debug, Clone)]
    struct DummyStore;

    #[async_trait]
    impl Store for DummyStore {
        async fn get_size(&self, _: &Cid) -> Result<usize> {
            todo!()
        }
        async fn get(&self, _: &Cid) -> Result<Block> {
            todo!()
        }
        async fn has(&self, _: &Cid) -> Result<bool> {
            todo!()
        }
    }

    #[test]
    fn test_traits() {
        assert_send::<Bitswap<DummyStore>>();
        assert_send::<&Bitswap<DummyStore>>();
    }

    fn mk_transport() -> (PeerId, Boxed<(PeerId, StreamMuxerBox)>) {
        let local_key = Keypair::generate_ed25519();

        let auth_config = {
            let dh_keys = noise::Keypair::<noise::X25519Spec>::new()
                .into_authentic(&local_key)
                .expect("Noise key generation failed");

            noise::NoiseConfig::xx(dh_keys).into_authenticated()
        };

        let peer_id = local_key.public().to_peer_id();
        let transport = TokioTcpTransport::new(GenTcpConfig::default().nodelay(true))
            .upgrade(Version::V1)
            .authenticate(auth_config)
            .multiplex(YamuxConfig::default())
            .timeout(Duration::from_secs(20))
            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
            .map_err(|err| Error::new(ErrorKind::Other, err))
            .boxed();
        (peer_id, transport)
    }

    #[derive(Debug, Clone, Default)]
    struct TestStore {
        store: Arc<RwLock<AHashMap<Cid, Block>>>,
    }

    #[async_trait]
    impl Store for TestStore {
        async fn get_size(&self, cid: &Cid) -> Result<usize> {
            self.store
                .read()
                .await
                .get(cid)
                .map(|block| block.data().len())
                .ok_or_else(|| anyhow!("missing"))
        }

        async fn get(&self, cid: &Cid) -> Result<Block> {
            self.store
                .read()
                .await
                .get(cid)
                .cloned()
                .ok_or_else(|| anyhow!("missing"))
        }

        async fn has(&self, cid: &Cid) -> Result<bool> {
            Ok(self.store.read().await.contains_key(cid))
        }
    }

    #[tokio::test]
    async fn test_get_1_block() {
        tracing_subscriber::registry()
            .with(fmt::layer().pretty())
            .with(EnvFilter::from_default_env())
            .init();

        get_block::<1>().await;
    }

    #[tokio::test]
    async fn test_get_2_block() {
        get_block::<2>().await;
    }

    #[tokio::test]
    async fn test_get_4_block() {
        get_block::<4>().await;
    }

    #[tokio::test]
    async fn test_get_64_block() {
        get_block::<64>().await;
    }

    #[tokio::test]
    async fn test_get_65_block() {
        get_block::<65>().await;
    }

    #[tokio::test]
    async fn test_get_66_block() {
        get_block::<66>().await;
    }

    #[tokio::test]
    async fn test_get_128_block() {
        get_block::<128>().await;
    }

    #[tokio::test]
    async fn test_get_1024_block() {
        get_block::<1024>().await;
    }

    async fn get_block<const N: usize>() {
        let (peer1_id, trans) = mk_transport();
        let store1 = TestStore::default();
        let bs1 = Bitswap::new(peer1_id, store1.clone(), Config::default()).await;
        let mut swarm1 = SwarmBuilder::new(trans, bs1, peer1_id)
            .executor(Box::new(|fut| {
                tokio::task::spawn(fut);
            }))
            .build();

        let blocks = (0..N).map(|_| create_random_block_v1()).collect::<Vec<_>>();

        for block in &blocks {
            store1
                .store
                .write()
                .await
                .insert(*block.cid(), block.clone());
        }

        let (tx, mut rx) = mpsc::channel::<Multiaddr>(1);

        Swarm::listen_on(&mut swarm1, "/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

        let peer1 = tokio::task::spawn(async move {
            while swarm1.next().now_or_never().is_some() {}
            let listeners: Vec<_> = Swarm::listeners(&swarm1).collect();
            for l in listeners {
                tx.send(l.clone()).await.unwrap();
            }

            loop {
                match swarm1.next().await {
                    ev => trace!("peer1: {:?}", ev),
                }
            }
        });

        info!("peer2: startup");
        let (peer2_id, trans) = mk_transport();
        let store2 = TestStore::default();
        let bs2 = Bitswap::new(peer2_id, store2.clone(), Config::default()).await;

        let mut swarm2 = SwarmBuilder::new(trans, bs2, peer2_id)
            .executor(Box::new(|fut| {
                tokio::task::spawn(fut);
            }))
            .build();

        let swarm2_bs = swarm2.behaviour().clone();
        let peer2 = tokio::task::spawn(async move {
            let addr = rx.recv().await.unwrap();
            info!("peer2: dialing peer1 at {}", addr);
            Swarm::dial(&mut swarm2, addr).unwrap();

            loop {
                match swarm2.next().await {
                    ev => trace!("peer2: {:?}", ev),
                }
            }
        });

        {
            info!("peer2: fetching block - ordered");
            let blocks = blocks.clone();
            let mut futs = Vec::new();
            for block in &blocks {
                let client = swarm2_bs.client().clone();
                futs.push(async move {
                    // Should work, because retrieved
                    let received_block = client.get_block(block.cid()).await?;

                    info!("peer2: received block");
                    Ok::<Block, anyhow::Error>(received_block)
                });
            }

            let results = futures::future::join_all(futs).await;
            for (block, result) in blocks.into_iter().zip(results.into_iter()) {
                let received_block = result.unwrap();
                assert_eq!(block, received_block);
            }
        }

        {
            info!("peer2: fetching block - unordered");
            let mut blocks = blocks.clone();
            let futs = futures::stream::FuturesUnordered::new();
            for block in &blocks {
                let client = swarm2_bs.client().clone();
                futs.push(async move {
                    // Should work, because retrieved
                    let received_block = client.get_block(block.cid()).await?;

                    info!("peer2: received block");
                    Ok::<Block, anyhow::Error>(received_block)
                });
            }

            let mut results = futs.try_collect::<Vec<_>>().await.unwrap();
            results.sort();
            blocks.sort();
            for (block, received_block) in blocks.into_iter().zip(results.into_iter()) {
                assert_eq!(block, received_block);
            }
        }

        info!("--shutting down peer1");
        peer1.abort();
        peer1.await.ok();

        info!("--shutting down peer2");
        peer2.abort();
        peer2.await.ok();
    }
}

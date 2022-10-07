//! Implements handling of the [bitswap protocol]((https://github.com/ipfs/specs/blob/master/BITSWAP.md)). Based on go-ipfs.
//!
//! Supports the versions `1.0.0`, `1.1.0` and `1.2.0`.

use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

use ahash::AHashMap;
use anyhow::Result;
use async_trait::async_trait;
use cid::Cid;
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use handler::{BitswapHandler, HandlerEvent};
use libp2p::core::connection::ConnectionId;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    DialError, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
    PollParameters,
};
use libp2p::{Multiaddr, PeerId};
use message::BitswapMessage;
use network::OutEvent;
use protocol::{ProtocolConfig, ProtocolId};
use tokio::sync::oneshot;
use tracing::trace;

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

use iroh_metrics::core::MRecorder;

#[derive(Debug)]
pub struct Bitswap<S: Store> {
    network: Network,
    protocol_config: ProtocolConfig,
    idle_timeout: Duration,
    peers: AHashMap<PeerId, PeerState>,
    dials: AHashMap<
        PeerId,
        Vec<oneshot::Sender<std::result::Result<(ConnectionId, ProtocolId), String>>>,
    >,
    client: Client<S>,
    server: Server<S>,
    futures: Mutex<FuturesUnordered<BoxFuture<'static, ()>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerState {
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
            server,
            client,
            futures: Mutex::new(FuturesUnordered::new()),
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
        let client = self.client.clone();
        let server = self.server.clone();
        // self.futures.lock().unwrap().push(
        tokio::task::spawn(
            async move {
                client.peer_connected(&peer).await;
                server.peer_connected(&peer).await;
            }, // .boxed(),
        );
    }

    fn peer_disconnected(&self, peer: PeerId) {
        let client = self.client.clone();
        let server = self.server.clone();
        // self.futures.lock().unwrap().push(
        tokio::task::spawn(
            async move {
                client.peer_disconnected(&peer).await;
                server.peer_disconnected(&peer).await;
            }, //.boxed(),
        );
    }

    fn receive_message(&self, peer: PeerId, message: BitswapMessage) {
        let client = self.client.clone();
        let server = self.server.clone();
        tokio::task::spawn(
            // self.futures.lock().unwrap().push(
            async move {
                client.receive_message(&peer, &message).await;
                server.receive_message(&peer, &message).await;
            }, //.boxed(),
        );
    }

    fn get_peer_state(&self, peer: &PeerId) -> PeerState {
        self.peers
            .get(peer)
            .copied()
            .unwrap_or(PeerState::Disconnected)
    }

    fn set_peer_state(&mut self, peer: &PeerId, new_state: PeerState) {
        let peer_state = self.peers.entry(*peer).or_default();
        let old_state = *peer_state;
        *peer_state = new_state;
        let peer = *peer;

        match peer_state {
            PeerState::Disconnected => {
                self.peers.remove(&peer);
                if matches!(old_state, PeerState::Responsive(_, _)) {
                    self.peer_disconnected(peer);
                }
            }
            PeerState::Unresponsive => {
                if matches!(old_state, PeerState::Responsive(_, _)) {
                    self.peer_disconnected(peer);
                }
            }
            PeerState::Responsive(_, _) => {
                self.peer_connected(peer);
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
        if other_established == 0 {
            // debug!("connection established {}", peer_id);
        }
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        _conn: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _handler: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        remaining_established: usize,
    ) {
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
            if let Some(mut dials) = self.dials.remove(&peer_id) {
                while let Some(sender) = dials.pop() {
                    sender.send(Err(error.to_string())).ok();
                }
            }
        }
    }

    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, event: HandlerEvent) {
        // debug!("inject_event from {}, event: {:?}", peer_id, event);
        match event {
            HandlerEvent::Connected { protocol } => {
                self.peer_connected(peer_id);
                if let Some(mut dials) = self.dials.remove(&peer_id) {
                    while let Some(sender) = dials.pop() {
                        sender.send(Ok((connection, protocol))).ok();
                    }
                }

                self.set_peer_state(&peer_id, PeerState::Responsive(connection, protocol));
            }
            HandlerEvent::ProtocolNotSuppported => {
                if matches!(self.get_peer_state(&peer_id), PeerState::Responsive(_, _)) {
                    self.set_peer_state(&peer_id, PeerState::Unresponsive);
                }

                if let Some(mut dials) = self.dials.remove(&peer_id) {
                    while let Some(sender) = dials.pop() {
                        sender.send(Err("protocol not supported".into())).ok();
                    }
                }
            }
            HandlerEvent::Message { message, protocol } => {
                // mark peer as responsive
                if self.get_peer_state(&peer_id) == PeerState::Unresponsive {
                    self.set_peer_state(&peer_id, PeerState::Responsive(connection, protocol));
                }

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
        // poll local futures
        let _r = self.futures.lock().unwrap().poll_next_unpin(cx);

        loop {
            match self.network.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(ev) => match ev {
                    OutEvent::Dial(peer, response) => {
                        tracing::debug!("{} dials, {} peers", self.dials.len(), self.peers.len());

                        if let PeerState::Responsive(conn, protocol_id) = self.get_peer_state(&peer)
                        {
                            // already connected
                            response.send(Ok((conn, protocol_id))).ok();
                            continue;
                        } else {
                            self.dials.entry(peer).or_default().push(response);

                            return Poll::Ready(NetworkBehaviourAction::Dial {
                                opts: DialOpts::peer_id(peer).build(),
                                handler: self.new_handler(),
                            });
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[derive(Debug, Clone)]
    struct DummyStore;

    #[async_trait]
    impl Store for DummyStore {
        async fn get_size(&self, cid: &Cid) -> Result<usize> {
            todo!()
        }
        async fn get(&self, cid: &Cid) -> Result<Block> {
            todo!()
        }
        async fn has(&self, cid: &Cid) -> Result<bool> {
            todo!()
        }
    }

    #[test]
    fn test_traits() {
        assert_send::<Bitswap<DummyStore>>();
        assert_send::<&Bitswap<DummyStore>>();
    }
}

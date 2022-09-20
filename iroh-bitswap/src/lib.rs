//! Implements handling of the [bitswap protocol]((https://github.com/ipfs/specs/blob/master/BITSWAP.md)). Based on go-ipfs.
//!
//! Supports the versions `1.0.0`, `1.1.0` and `1.2.0`.

use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use cid::Cid;
use handler::{BitswapHandler, HandlerEvent};
use libp2p::core::connection::ConnectionId;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::{
    DialError, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use libp2p::{Multiaddr, PeerId};
use message::BitswapMessage;
use protocol::ProtocolConfig;
use tracing::info;

use self::block::Block;
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

#[derive(Debug)]
pub struct Bitswap {
    client: Client,
    server: Server,
    network: Network,
    protocol_config: ProtocolConfig,
    idle_timeout: Duration,
}

#[derive(Debug)]
pub struct Config {
    pub client: ClientConfig,
    pub server: ServerConfig,
    pub protocol: ProtocolConfig,
    pub idle_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct Store {}
impl Store {
    pub fn get_size(&self, cid: &Cid) -> Result<usize> {
        todo!()
    }

    pub fn get(&self, cid: &Cid) -> Result<Block> {
        todo!()
    }
}

impl Bitswap {
    pub fn new(self_id: PeerId, store: Store, config: Config) -> Self {
        // Default options from go-ipfs
        // DefaultEngineBlockstoreWorkerCount = 128
        // DefaultTaskWorkerCount             = 8
        // DefaultEngineTaskWorkerCount       = 8
        // DefaultMaxOutstandingBytesPerPeer  = 1 << 20

        // Options passed on from go-ipfs
        // ProvideEnabled
        // EngineBlockstoreWorkerCount
        // TaskWorkerCount
        // EngineTaskWorkerCount
        // MaxOutstandingBytesPerPeer

        let network = Network::new(self_id);
        let server = Server::new(network.clone(), store.clone(), config.server);
        let client = Client::new(network.clone(), store, config.client);

        Bitswap {
            server,
            client,
            network,
            protocol_config: config.protocol,
            idle_timeout: config.idle_timeout,
        }
    }

    pub fn close(self) -> Result<()> {
        self.network.stop();

        self.client.close()?;
        self.server.close()?;

        Ok(())
    }

    pub fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        self.client.notify_new_blocks(blocks)?;
        self.server.notify_new_blocks(blocks)?;

        Ok(())
    }

    pub fn stat(&self) -> Result<Stat> {
        let client_stat = self.client.stat()?;
        let server_stat = self.server.stat()?;

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

    pub fn wantlist_for_peer(&self, peer: &PeerId) -> Vec<Cid> {
        if peer == self.network.self_id() {
            return self.client.get_wantlist();
        }

        self.server.wantlist_for_peer(peer)
    }

    pub fn peer_connected(&self, peer: &PeerId) {
        self.client.peer_connected(peer);
        self.server.peer_connected(peer);
    }

    pub fn peer_disconnected(&self, peer: &PeerId) {
        self.client.peer_disconnected(peer);
        self.server.peer_disconnected(peer);
    }

    pub fn receive_error(&self, error: anyhow::Error) {
        info!("Bitswap client receive error: {:?}", error);
    }

    pub fn receive_message(&self, peer: &PeerId, message: &BitswapMessage) {
        self.client.receive_message(peer, &message);
        self.server.receive_message(peer, &message);
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
pub enum BitswapEvent {}

impl NetworkBehaviour for Bitswap {
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
        _peer_id: &PeerId,
        _conn: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        _other_established: usize,
    ) {
        todo!()
    }

    fn inject_connection_closed(
        &mut self,
        _peer_id: &PeerId,
        _conn: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _handler: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        _remaining_established: usize,
    ) {
        todo!()
    }

    fn inject_dial_failure(
        &mut self,
        _peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        _error: &DialError,
    ) {
        todo!()
    }

    fn inject_event(&mut self, peer_id: PeerId, _connection: ConnectionId, event: HandlerEvent) {
        match event {
            HandlerEvent::Connected { protocol: _ } => {
                // TODO
            }
            HandlerEvent::ProtocolNotSuppported => {
                // TODO
            }
            HandlerEvent::Message { message } => {
                self.server.receive_message(&peer_id, &message);
                self.client.receive_message(&peer_id, &message);
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        self.network.poll(cx)
    }
}

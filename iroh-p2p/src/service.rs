use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_channel::{bounded as channel, Receiver, Sender};
use cid::Cid;
use futures::channel::oneshot::Sender as OneShotSender;
use futures_util::stream::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::core::Multiaddr;
pub use libp2p::gossipsub::{IdentTopic, Topic};
use libp2p::identity::Keypair;
use libp2p::kad::record::Key;
use libp2p::multiaddr::Protocol;
use libp2p::multihash::Multihash;
use libp2p::swarm::{
    ConnectionHandler, ConnectionLimits, IntoConnectionHandler, NetworkBehaviour, SwarmBuilder,
    SwarmEvent,
};
use libp2p::yamux::WindowUpdateMode;
use libp2p::{core, mplex, noise, yamux, PeerId, Swarm, Transport};
use tokio::{select, time};
use tracing::{debug, info, trace, warn};

use super::{
    behaviour::{NodeBehaviour, NodeBehaviourEvent},
    Libp2pConfig,
};

/// Events emitted by this Service.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum NetworkEvent {
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    BitswapBlock { cid: Cid },
}

/// Messages into the service to handle.
#[derive(Debug)]
pub enum NetworkMessage {
    BitswapRequest {
        cids: Vec<Cid>,
        response_channels: Vec<OneShotSender<()>>,
        providers: Option<HashSet<PeerId>>,
    },
    JSONRPCRequest {
        method: NetRPCMethods,
    },
    ProviderRequest {
        key: Key,
        response_channel: OneShotSender<Option<Result<HashSet<PeerId>, String>>>,
    },
}

/// Network RPC API methods used to gather data from libp2p node.
#[derive(Debug)]
pub enum NetRPCMethods {
    NetAddrsListen(OneShotSender<(PeerId, Vec<Multiaddr>)>),
    NetPeers(OneShotSender<HashMap<PeerId, Vec<Multiaddr>>>),
    NetConnect(OneShotSender<bool>, PeerId, Vec<Multiaddr>),
    NetDisconnect(OneShotSender<()>, PeerId),
}

/// The Libp2pService listens to events from the Libp2p swarm.
pub struct Libp2pService {
    swarm: Swarm<NodeBehaviour>,

    net_receiver_in: Receiver<NetworkMessage>,
    net_sender_in: Sender<NetworkMessage>,
    net_receiver_out: Receiver<NetworkEvent>,
    net_sender_out: Sender<NetworkEvent>,
    bitswap_response_channels: HashMap<Cid, Vec<OneShotSender<()>>>,
}

impl Libp2pService {
    pub async fn new(config: Libp2pConfig, net_keypair: Keypair) -> Self {
        let peer_id = PeerId::from(net_keypair.public());

        let transport = build_transport(net_keypair.clone()).await;

        let limits = ConnectionLimits::default()
            .with_max_pending_incoming(Some(10)) // TODO: configurable
            .with_max_pending_outgoing(Some(30)) // TODO: configurable
            .with_max_established_incoming(Some(config.target_peer_count))
            .with_max_established_outgoing(Some(config.target_peer_count))
            .with_max_established_per_peer(Some(5)); // TODO: configurable

        let mut swarm = SwarmBuilder::new(
            transport,
            NodeBehaviour::new(&net_keypair, &config).await,
            peer_id,
        )
        .connection_limits(limits)
        .notify_handler_buffer_size(std::num::NonZeroUsize::new(20).expect("Not zero")) // TODO: configurable
        .connection_event_buffer_size(64)
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();

        Swarm::listen_on(&mut swarm, config.listening_multiaddr).unwrap();

        // Bootstrap with Kademlia
        if let Err(e) = swarm.behaviour_mut().bootstrap() {
            warn!("Failed to bootstrap with Kademlia: {}", e);
        }

        let (network_sender_in, network_receiver_in) = channel(1_000); // TODO: configurable
        let (network_sender_out, network_receiver_out) = channel(1_000); // TODO: configurable

        Libp2pService {
            swarm,
            net_receiver_in: network_receiver_in,
            net_sender_in: network_sender_in,
            net_receiver_out: network_receiver_out,
            net_sender_out: network_sender_out,
            bitswap_response_channels: Default::default(),
        }
    }

    /// Starts the libp2p service networking stack. This Future resolves when shutdown occurs.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("Local Peer ID: {}", self.swarm.local_peer_id());
        let mut interval = time::interval(Duration::from_secs(15)); // TODO: configurable

        loop {
            select! {
                swarm_event = self.swarm.select_next_some() => {
                    if let Err(err) = self.handle_swarm_event(swarm_event).await {
                        warn!("swarm: {:?}", err);
                    }
                }
                rpc_message = self.net_receiver_in.recv() => {
                    if let Err(err) = self.handle_rpc_message(rpc_message?).await {
                        warn!("rpc: {:?}", err);
                    }
                }
                _interval_event = interval.tick() => {
                    // Print peer count on an interval.
                    info!("Peers connected: {}", self.swarm.behaviour_mut().peer_addresses().len());
                }
            }
        }
    }

    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<
            <NodeBehaviour as NetworkBehaviour>::OutEvent,
            <<<NodeBehaviour as NetworkBehaviour>::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::Error>,
    ) -> Result<()> {
        match event {
            // outbound events
            SwarmEvent::Behaviour(event) => self.handle_node_behaviour_event(event).await,
            _ => Ok(()),
        }
    }

    async fn handle_node_behaviour_event(&mut self, event: NodeBehaviourEvent) -> Result<()> {
        match event {
            NodeBehaviourEvent::PeerConnected(peer_id) => {
                self.net_sender_out
                    .send(NetworkEvent::PeerConnected(peer_id))
                    .await?;
            }
            NodeBehaviourEvent::PeerDisconnected(peer_id) => {
                self.net_sender_out
                    .send(NetworkEvent::PeerDisconnected(peer_id))
                    .await?;
            }
            NodeBehaviourEvent::BitswapReceivedBlock(_peer_id, cid, _block) => {
                // TODO: verify cid hash
                // TODO: process data in the storage node

                if let Some(chans) = self.bitswap_response_channels.remove(&cid) {
                    for chan in chans.into_iter() {
                        if chan.send(()).is_err() {
                            debug!("Bitswap response channel send failed");
                        }
                        trace!("Saved Bitswap block with cid {:?}", cid);
                    }
                } else {
                    debug!("Received Bitswap response, but response channel cannot be found");
                }
                self.net_sender_out
                    .send(NetworkEvent::BitswapBlock { cid })
                    .await?;
            }
            NodeBehaviourEvent::BitswapReceivedWant(_peer_id, cid) => {
                // TODO: try to load data from the storage node
                trace!("Don't have data for: {}", cid);
            }
        }

        Ok(())
    }

    async fn handle_rpc_message(&mut self, message: NetworkMessage) -> Result<()> {
        // Inbound messages
        match message {
            NetworkMessage::BitswapRequest {
                cids,
                response_channels,
                providers,
            } => {
                if let Some(providers) = providers {
                    for peer_id in providers.into_iter() {
                        let mut addrs = self.swarm.behaviour_mut().addresses_of_peer(&peer_id);
                        for multiaddr in addrs.iter_mut() {
                            multiaddr.push(Protocol::P2p(
                                Multihash::from_bytes(&peer_id.to_bytes()).unwrap(),
                            ));
                            Swarm::dial(&mut self.swarm, multiaddr.clone())
                                .with_context(|| format!("Failed to dial peer: {}", multiaddr))?;
                        }
                    }
                }

                self.swarm
                    .behaviour_mut()
                    .want_blocks(cids.clone(), 1000) // TODO: priority?
                    .await
                    .map_err(|err| anyhow!("Failed to send a bitswap want_block: {:?}", err))?;

                for (cid, response_channel) in cids.into_iter().zip(response_channels.into_iter()) {
                    if let Some(chans) = self.bitswap_response_channels.get_mut(&cid) {
                        chans.push(response_channel);
                    } else {
                        self.bitswap_response_channels
                            .insert(cid, vec![response_channel]);
                    }
                }
            }
            NetworkMessage::ProviderRequest {
                key,
                response_channel,
            } => {
                self.swarm.behaviour_mut().providers(key, response_channel);
            }
            NetworkMessage::JSONRPCRequest { method } => {
                self.handle_jsonrpc_request(method).await?;
            }
        }

        Ok(())
    }

    // TODO: actually use iroh-rpc
    async fn handle_jsonrpc_request(&mut self, method: NetRPCMethods) -> Result<()> {
        match method {
            NetRPCMethods::NetAddrsListen(response_channel) => {
                let listeners: Vec<_> = Swarm::listeners(&self.swarm).cloned().collect();
                let peer_id = Swarm::local_peer_id(&self.swarm);

                response_channel
                    .send((*peer_id, listeners))
                    .map_err(|_| anyhow!("Failed to get Libp2p listeners"))?;
            }
            NetRPCMethods::NetPeers(response_channel) => {
                let peer_addresses: &HashMap<PeerId, Vec<Multiaddr>> =
                    self.swarm.behaviour_mut().peer_addresses();

                response_channel
                    .send(peer_addresses.to_owned())
                    .map_err(|_| anyhow!("Failed to get Libp2p peers"))?;
            }
            NetRPCMethods::NetConnect(response_channel, peer_id, mut addresses) => {
                let mut success = false;

                for multiaddr in addresses.iter_mut() {
                    self.swarm
                        .behaviour_mut()
                        .add_address(&peer_id, multiaddr.clone());

                    multiaddr.push(Protocol::P2p(
                        Multihash::from_bytes(&peer_id.to_bytes()).unwrap(),
                    ));
                    if Swarm::dial(&mut self.swarm, multiaddr.clone()).is_ok() {
                        success = true;
                        break;
                    }
                }

                response_channel
                    .send(success)
                    .map_err(|_| anyhow!("Failed to connect to a peer"))?;
            }
            NetRPCMethods::NetDisconnect(response_channel, _peer_id) => {
                warn!("NetDisconnect API not yet implmeneted"); // TODO: implement NetDisconnect - See #1181

                response_channel
                    .send(())
                    .map_err(|_| anyhow!("Failed to disconnect from a peer"))?;
            }
        }

        Ok(())
    }

    /// Returns a sender which allows sending messages to the libp2p service.
    pub fn network_sender(&self) -> Sender<NetworkMessage> {
        self.net_sender_in.clone()
    }

    /// Returns a receiver to listen to network events emitted from the service.
    pub fn network_receiver(&self) -> Receiver<NetworkEvent> {
        self.net_receiver_out.clone()
    }
}

/// Builds the transport stack that LibP2P will communicate over.
pub async fn build_transport(local_key: Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
    // TODO: make transports configurable

    let transport = libp2p::tcp::TokioTcpConfig::new().nodelay(true);
    let transport = libp2p::websocket::WsConfig::new(transport.clone()).or_transport(transport);
    let transport = libp2p::dns::TokioDnsConfig::system(transport).unwrap();
    let auth_config = {
        let dh_keys = noise::Keypair::<noise::X25519Spec>::new()
            .into_authentic(&local_key)
            .expect("Noise key generation failed");

        noise::NoiseConfig::xx(dh_keys).into_authenticated()
    };

    let mplex_config = {
        let mut mplex_config = mplex::MplexConfig::new();
        mplex_config.set_max_buffer_size(usize::MAX);

        let mut yamux_config = yamux::YamuxConfig::default();
        yamux_config.set_max_buffer_size(16 * 1024 * 1024); // TODO: configurable
        yamux_config.set_receive_window_size(16 * 1024 * 1024); // TODO: configurable
        yamux_config.set_window_update_mode(WindowUpdateMode::on_receive());
        core::upgrade::SelectUpgrade::new(yamux_config, mplex_config)
    };

    transport
        .upgrade(core::upgrade::Version::V1Lazy)
        .authenticate(auth_config)
        .multiplex(mplex_config)
        .timeout(Duration::from_secs(20)) // TODO: configurable
        .boxed()
}

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use ahash::AHashMap;
use anyhow::{anyhow, Result};
use async_channel::{bounded as channel, Receiver};
use cid::Cid;
use futures::channel::oneshot::{self, Sender as OneShotSender};
use futures_util::stream::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::core::Multiaddr;
pub use libp2p::gossipsub::{IdentTopic, Topic};
use libp2p::identify::{IdentifyEvent, IdentifyInfo};
use libp2p::identity::Keypair;
use libp2p::kad::{self, GetProvidersError, GetProvidersOk, KademliaEvent, QueryId, QueryResult};
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

use iroh_bitswap::{BitswapEvent, Block};

use crate::{
    behaviour::{Event, NodeBehaviour},
    rpc::{self, RpcMessage},
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

/// The Libp2pService listens to events from the Libp2p swarm.
pub struct Libp2pService {
    swarm: Swarm<NodeBehaviour>,
    net_receiver_in: Receiver<RpcMessage>,
    bitswap_response_channels: HashMap<Cid, Vec<OneShotSender<Block>>>,
    kad_queries: AHashMap<QueryId, QueryChannel>,
}

enum QueryChannel {
    GetProviders(oneshot::Sender<Result<HashSet<PeerId>, String>>),
}

impl Libp2pService {
    pub async fn new(config: Libp2pConfig, net_keypair: Keypair) -> Result<Self> {
        let peer_id = PeerId::from(net_keypair.public());

        let transport = build_transport(net_keypair.clone()).await;

        let limits = ConnectionLimits::default()
            .with_max_pending_incoming(Some(10)) // TODO: configurable
            .with_max_pending_outgoing(Some(30)) // TODO: configurable
            .with_max_established_incoming(Some(config.target_peer_count))
            .with_max_established_outgoing(Some(config.target_peer_count))
            .with_max_established_per_peer(Some(5)); // TODO: configurable

        let node = NodeBehaviour::new(&net_keypair, &config).await?;
        let mut swarm = SwarmBuilder::new(transport, node, peer_id)
            .connection_limits(limits)
            .notify_handler_buffer_size(std::num::NonZeroUsize::new(20).expect("Not zero")) // TODO: configurable
            .connection_event_buffer_size(128)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build();

        Swarm::listen_on(&mut swarm, config.listening_multiaddr).unwrap();

        let (network_sender_in, network_receiver_in) = channel(1_000); // TODO: configurable

        tokio::spawn(async move {
            // TODO: handle error
            rpc::new(config.rpc_addr, network_sender_in).await.unwrap()
        });

        Ok(Libp2pService {
            swarm,
            net_receiver_in: network_receiver_in,
            bitswap_response_channels: Default::default(),
            kad_queries: Default::default(),
        })
    }

    /// Starts the libp2p service networking stack. This Future resolves when shutdown occurs.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("Local Peer ID: {}", self.swarm.local_peer_id());
        let mut interval = time::interval(Duration::from_secs(15)); // TODO: configurable

        // TODO: add kad random queries if necessary

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
                    info!("Peers connected: {:?}", self.swarm.connected_peers().count());
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
            SwarmEvent::Behaviour(event) => self.handle_node_event(event).await,
            _ => Ok(()),
        }
    }

    async fn handle_node_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Bitswap(BitswapEvent::ReceivedBlock(_peer_id, cid, block)) => {
                info!("got block {}", cid);
                // TODO: verify cid hash

                let b = Block::new(block, cid);
                if let Some(chans) = self.bitswap_response_channels.remove(&cid) {
                    for chan in chans.into_iter() {
                        // TODO: send cid and block
                        if chan.send(b.clone()).is_err() {
                            debug!("Bitswap response channel send failed");
                        }
                        trace!("Saved Bitswap block with cid {:?}", cid);
                    }
                } else {
                    debug!("Received Bitswap response, but response channel cannot be found");
                }
            }
            Event::Bitswap(BitswapEvent::ReceivedWant(_peer_id, cid, _prio)) => {
                // TODO: try to load data from the storage node
                // rpc_client.call("storage", "get", cid)
                trace!("Don't have data for: {}", cid);
            }
            Event::Kademlia(KademliaEvent::OutboundQueryCompleted { id, result, .. }) => {
                info!("kad: {:?}", result);
                match result {
                    QueryResult::GetProviders(Ok(GetProvidersOk { providers, .. })) => {
                        if let Some(QueryChannel::GetProviders(ch)) = self.kad_queries.remove(&id) {
                            ch.send(Ok(providers)).ok();
                        }
                    }
                    QueryResult::GetProviders(Err(err)) => {
                        if let Some(QueryChannel::GetProviders(ch)) = self.kad_queries.remove(&id) {
                            match err {
                                GetProvidersError::Timeout { key, providers, .. } => {
                                    debug!("GetProviders timeout {:?}", key);
                                    ch.send(Ok(providers)).ok();
                                }
                            }
                        }
                    }
                    other => {
                        debug!("Libp2p => Unhandled Kademlia query result: {:?}", other)
                    }
                }
            }
            Event::Identify(e) => {
                if let IdentifyEvent::Received {
                    peer_id,
                    info:
                        IdentifyInfo {
                            listen_addrs,
                            protocols,
                            ..
                        },
                } = *e
                {
                    // Inform kademlia about identified peers
                    if protocols
                        .iter()
                        .any(|p| p.as_bytes() == kad::protocol::DEFAULT_PROTO_NAME)
                    {
                        for addr in listen_addrs {
                            self.swarm
                                .behaviour_mut()
                                .kad
                                .as_mut()
                                .map(|k| k.add_address(&peer_id, addr));
                        }
                    }
                }
            }
            _ => {
                // TODO: check all important events are handled
            }
        }

        Ok(())
    }

    async fn handle_rpc_message(&mut self, message: RpcMessage) -> Result<()> {
        info!("rpc message {:?}", message);
        // Inbound messages
        match message {
            RpcMessage::BitswapRequest {
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
                            if let Err(e) = Swarm::dial(&mut self.swarm, multiaddr.clone()) {
                                trace!("failed to dial peer {}: {:?}", multiaddr, e);
                            }
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
            RpcMessage::ProviderRequest {
                key,
                response_channel,
            } => {
                if let Some(kad) = self.swarm.behaviour_mut().kad.as_mut() {
                    let id = kad.get_providers(key);
                    self.kad_queries
                        .insert(id, QueryChannel::GetProviders(response_channel));
                } else {
                    response_channel.send(Ok(Default::default())).ok();
                }
            }
            RpcMessage::NetListeningAddrs(response_channel) => {
                let listeners: Vec<_> = Swarm::listeners(&self.swarm).cloned().collect();
                let peer_id = Swarm::local_peer_id(&self.swarm);

                response_channel
                    .send((*peer_id, listeners))
                    .map_err(|_| anyhow!("Failed to get Libp2p listeners"))?;
            }
            RpcMessage::NetPeers(response_channel) => {
                #[allow(clippy::needless_collect)]
                let peers = self.swarm.connected_peers().copied().collect::<Vec<_>>();
                let peer_addresses: HashMap<PeerId, Vec<Multiaddr>> = peers
                    .into_iter()
                    .map(|pid| (pid, self.swarm.behaviour_mut().addresses_of_peer(&pid)))
                    .collect();

                response_channel
                    .send(peer_addresses)
                    .map_err(|_| anyhow!("Failed to get Libp2p peers"))?;
            }
            RpcMessage::NetConnect(response_channel, peer_id, mut addresses) => {
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
            RpcMessage::NetDisconnect(response_channel, _peer_id) => {
                warn!("NetDisconnect API not yet implemented"); // TODO: implement NetDisconnect - See #1181

                response_channel
                    .send(())
                    .map_err(|_| anyhow!("Failed to disconnect from a peer"))?;
            }
        }

        Ok(())
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

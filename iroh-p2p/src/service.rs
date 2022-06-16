use std::collections::HashMap;
use std::num::NonZeroU8;
use std::time::Duration;

use ahash::AHashMap;
use anyhow::{anyhow, Context, Result};
use async_channel::{bounded as channel, Receiver};
use cid::Cid;
use futures::channel::oneshot::Sender as OneShotSender;
use futures_util::stream::StreamExt;
use iroh_rpc_client::Client as RpcClient;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::timeout::TransportTimeout;
use libp2p::core::transport::Boxed;
use libp2p::core::Multiaddr;
pub use libp2p::gossipsub::{IdentTopic, Topic};
use libp2p::identify::{IdentifyEvent, IdentifyInfo};
use libp2p::identity::Keypair;
use libp2p::kad::{
    self, record::Key, GetProvidersError, GetProvidersOk, GetProvidersProgress, KademliaEvent,
    QueryProgress, QueryResult,
};
use libp2p::metrics::{Metrics, Recorder};
use libp2p::multiaddr::Protocol;
use libp2p::multihash::Multihash;
use libp2p::swarm::{
    ConnectionHandler, ConnectionLimits, IntoConnectionHandler, NetworkBehaviour, SwarmBuilder,
    SwarmEvent,
};
use libp2p::yamux::WindowUpdateMode;
use libp2p::{core, mplex, noise, yamux, PeerId, Swarm, Transport};
use prometheus_client::registry::Registry;
use tokio::{select, sync::mpsc, time};
use tracing::{debug, info, trace, warn};

use iroh_bitswap::{
    BitswapEvent, Block, InboundRequest, QueryError, QueryId as BitswapQueryId,
    QueryResult as BitswapQueryResult, WantResult,
};

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
    bitswap_queries: AHashMap<BitswapQueryId, OneShotSender<Result<Block, QueryError>>>,
    kad_queries: AHashMap<QueryKey, QueryChannel>,
    metrics: Metrics,
    rpc_client: RpcClient,
}

enum QueryChannel {
    GetProviders(Vec<mpsc::Sender<Result<PeerId, String>>>),
}

#[derive(Debug, Hash, PartialEq, Eq)]
enum QueryKey {
    ProviderKey(Key),
}

const PROVIDER_LIMIT: usize = 20;

impl Libp2pService {
    pub async fn new(
        config: Libp2pConfig,
        net_keypair: Keypair,
        registry: &mut Registry,
        metrics: Metrics,
    ) -> Result<Self> {
        let peer_id = PeerId::from(net_keypair.public());

        let transport = build_transport(net_keypair.clone()).await;

        let limits = ConnectionLimits::default()
            .with_max_pending_incoming(Some(10)) // TODO: configurable
            .with_max_pending_outgoing(Some(30)) // TODO: configurable
            .with_max_established_incoming(Some(config.target_peer_count))
            .with_max_established_outgoing(Some(config.target_peer_count))
            .with_max_established_per_peer(Some(5)); // TODO: configurable

        let node = NodeBehaviour::new(&net_keypair, &config, registry).await?;
        let mut swarm = SwarmBuilder::new(transport, node, peer_id)
            .connection_limits(limits)
            .notify_handler_buffer_size(20.try_into().unwrap()) // TODO: configurable
            .connection_event_buffer_size(128)
            .dial_concurrency_factor(NonZeroU8::new(16).unwrap())
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

        let rpc_client = RpcClient::new(&config.rpc_client)
            .await
            .context("failed to create rpc client")?;

        Ok(Libp2pService {
            swarm,
            net_receiver_in: network_receiver_in,
            bitswap_queries: Default::default(),
            kad_queries: Default::default(),
            metrics,
            rpc_client,
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
        self.metrics.record(&event);
        match event {
            // outbound events
            SwarmEvent::Behaviour(event) => self.handle_node_event(event).await,
            _ => Ok(()),
        }
    }

    async fn handle_node_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Bitswap(e) => {
                match e {
                    BitswapEvent::InboundRequest { request } => match request {
                        InboundRequest::Want { cid, sender, .. } => {
                            if let Ok(Some(data)) = self.rpc_client.store.get(cid).await {
                                trace!("Found data for: {}", cid);
                                if let Err(e) =
                                    self.swarm.behaviour_mut().send_block(&sender, cid, data)
                                {
                                    warn!(
                                        "failed to send block for {} to {}: {:?}",
                                        cid, sender, e
                                    );
                                }
                            } else {
                                trace!("Don't have data for: {}", cid);
                            }
                        }
                        InboundRequest::Cancel { .. } => {
                            // nothing to do atm
                        }
                    },
                    BitswapEvent::OutboundQueryCompleted { id, result } => match result {
                        BitswapQueryResult::Want(WantResult::Ok { sender, cid, data }) => {
                            info!("got block {} from {}", cid, sender);
                            // TODO: verify cid hash
                            let b = Block::new(data, cid);
                            if let Some(chan) = self.bitswap_queries.remove(&id) {
                                // TODO: send cid and block
                                if chan.send(Ok(b)).is_err() {
                                    debug!("Bitswap response channel send failed");
                                }
                                trace!("Saved Bitswap block with cid {:?}", cid);
                            } else {
                                debug!("Received Bitswap response, but response channel cannot be found");
                            }
                        }
                        BitswapQueryResult::Want(WantResult::Err(e)) => {
                            if let Some(chan) = self.bitswap_queries.remove(&id) {
                                if chan.send(Err(e)).is_err() {
                                    debug!("Bitswap response channel send failed");
                                }
                            }
                        }
                        BitswapQueryResult::Send(_) => {
                            // Nothing to do yet
                        }
                        BitswapQueryResult::Cancel(_) => {
                            // Nothing to do yet
                        }
                    },
                }
            }
            Event::Kademlia(e) => {
                self.metrics.record(&e);
                if let KademliaEvent::OutboundQueryCompleted { result, .. } = e {
                    debug!("kad completed: {:?}", result);
                    match result {
                        QueryResult::GetProviders(Ok(GetProvidersOk { key, .. })) => {
                            let _ = self.kad_queries.remove(&QueryKey::ProviderKey(key));
                        }

                        QueryResult::GetProviders(Err(err)) => {
                            let key = match err {
                                GetProvidersError::Timeout { key, .. } => key,
                            };
                            debug!("GetProviders timeout {:?}", key);
                            if let Some(QueryChannel::GetProviders(chans)) =
                                self.kad_queries.remove(&QueryKey::ProviderKey(key))
                            {
                                for chan in chans.into_iter() {
                                    chan.send(Err("Timeout".into())).await.ok();
                                }
                            }
                        }
                        other => {
                            debug!("Libp2p => Unhandled Kademlia query result: {:?}", other)
                        }
                    }
                } else if let KademliaEvent::OutboundQueryProgressed {
                    id, result, count, ..
                } = e
                {
                    debug!("kad progressed: {:?}", result);
                    match result {
                        QueryProgress::GetProviders(GetProvidersProgress {
                            key, provider, ..
                        }) => {
                            if count >= PROVIDER_LIMIT {
                                debug!("finish provider query {}/{}", count, PROVIDER_LIMIT);
                                // Finish query if we have enough providers.
                                self.swarm.behaviour_mut().finish_query(&id);
                            }

                            if let Some(QueryChannel::GetProviders(chans)) = self
                                .kad_queries
                                .get_mut(&QueryKey::ProviderKey(key.clone()))
                            {
                                for chan in chans.iter_mut() {
                                    chan.send(Ok(provider)).await.ok();
                                }
                            } else {
                                debug!("No listeners");
                            }
                        }
                    }
                }
            }
            Event::Identify(e) => {
                self.metrics.record(&*e);
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
            Event::Ping(e) => {
                self.metrics.record(&e);
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
                for (cid, response_channel) in cids.into_iter().zip(response_channels.into_iter()) {
                    let query_id = self
                        .swarm
                        .behaviour_mut()
                        .want_block(cid, 1000, providers.clone()) // TODO: priority?
                        .map_err(|err| anyhow!("Failed to send a bitswap want_block: {:?}", err))?;

                    self.bitswap_queries.insert(query_id, response_channel);
                }
            }
            RpcMessage::ProviderRequest {
                key,
                response_channel,
            } => {
                if let Some(kad) = self.swarm.behaviour_mut().kad.as_mut() {
                    if let Some(QueryChannel::GetProviders(chans)) = self
                        .kad_queries
                        .get_mut(&QueryKey::ProviderKey(key.clone()))
                    {
                        debug!(
                            "RpcMessage::ProviderRequest: already fetching providers for {:?}",
                            key
                        );
                        chans.push(response_channel);
                    } else {
                        debug!(
                            "RpcMessage::ProviderRequest: getting providers for {:?}",
                            key
                        );
                        let _ = kad.get_providers(key.clone());
                        self.kad_queries.insert(
                            QueryKey::ProviderKey(key),
                            QueryChannel::GetProviders(vec![response_channel]),
                        );
                    }
                } else {
                    response_channel
                        .send(Err("kademlia is not available".into()))
                        .await
                        .ok();
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
                warn!("NetDisconnect API not yet implemented"); // TODO: implement NetDisconnect

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
    let transport =
        libp2p::websocket::WsConfig::new(libp2p::tcp::TokioTcpConfig::new().nodelay(true))
            .or_transport(transport);

    // TODO: configurable
    let transport = TransportTimeout::new(transport, Duration::from_secs(5));

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

#[cfg(test)]
mod tests {
    use crate::metrics;

    use super::*;
    use anyhow::Result;
    use libp2p::identity::ed25519;

    #[tokio::test]
    async fn test_fetch_providers() -> Result<()> {
        let mut prom_registry = Registry::default();
        let libp2p_metrics = Metrics::new(&mut prom_registry);
        let net_keypair = {
            let gen_keypair = ed25519::Keypair::generate();
            Keypair::Ed25519(gen_keypair)
        };

        let mut network_config = Libp2pConfig::default();
        network_config.metrics.debug = true;
        let metrics_config = network_config.metrics.clone();

        let mut p2p_service = Libp2pService::new(
            network_config,
            net_keypair,
            &mut prom_registry,
            libp2p_metrics,
        )
        .await?;

        let metrics_handle = iroh_metrics::init_with_registry(
            metrics::metrics_config_with_compile_time_info(metrics_config),
            prom_registry,
        )
        .await
        .expect("failed to initialize metrics");

        let cfg = iroh_rpc_client::Config::default();
        let p2p_task = tokio::task::spawn(async move {
            p2p_service.run().await.unwrap();
        });

        {
            let client = RpcClient::new(&cfg).await?;
            let c = "QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR"
                .parse()
                .unwrap();
            let providers = client.p2p.fetch_providers(&c).await?;
            assert!(providers.len() >= PROVIDER_LIMIT);
        }

        p2p_task.abort();
        metrics_handle.shutdown();
        Ok(())
    }
}

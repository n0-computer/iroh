use std::collections::HashMap;
use std::time::Duration;

use ahash::AHashMap;
use anyhow::{anyhow, Context, Result};
use async_channel::{bounded as channel, Receiver, Sender};
use futures::channel::oneshot::Sender as OneShotSender;
use futures_util::stream::StreamExt;
use iroh_rpc_client::Client as RpcClient;
use libp2p::core::Multiaddr;
use libp2p::gossipsub::{GossipsubMessage, MessageId, TopicHash};
pub use libp2p::gossipsub::{IdentTopic, Topic};
use libp2p::identify::{IdentifyEvent, IdentifyInfo};
use libp2p::identity::Keypair;
use libp2p::kad::kbucket::{Distance, NodeStatus};
use libp2p::kad::BootstrapOk;
use libp2p::kad::{
    self, record::Key, GetProvidersError, GetProvidersOk, GetProvidersProgress, KademliaEvent,
    QueryProgress, QueryResult,
};
use libp2p::metrics::{Metrics, Recorder};
use libp2p::multiaddr::Protocol;
use libp2p::multihash::Multihash;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{ConnectionHandler, IntoConnectionHandler, NetworkBehaviour, SwarmEvent};
use libp2p::{PeerId, Swarm};
use prometheus_client::registry::Registry;
use tokio::{select, sync::mpsc, time};
use tracing::{debug, info, trace, warn};

use iroh_bitswap::{
    BitswapEvent, Block, InboundRequest, QueryError, QueryId as BitswapQueryId,
    QueryResult as BitswapQueryResult, WantResult,
};

use crate::keys::{Keychain, Storage};
use crate::swarm::build_swarm;
use crate::{
    behaviour::{Event, NodeBehaviour},
    rpc::{self, RpcMessage},
    Libp2pConfig,
};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    Gossipsub(GossipsubEvent),
}

#[derive(Debug, Clone)]
pub enum GossipsubEvent {
    Subscribed {
        peer_id: PeerId,
        topic: TopicHash,
    },
    Unsubscribed {
        peer_id: PeerId,
        topic: TopicHash,
    },
    Message {
        from: PeerId,
        id: MessageId,
        message: GossipsubMessage,
    },
}

pub struct Node<KeyStorage: Storage> {
    swarm: Swarm<NodeBehaviour>,
    net_receiver_in: Receiver<RpcMessage>,
    bitswap_queries: AHashMap<BitswapQueryId, OneShotSender<Result<Block, QueryError>>>,
    kad_queries: AHashMap<QueryKey, QueryChannel>,
    network_events: Vec<Sender<NetworkEvent>>,
    metrics: Metrics,
    rpc_client: RpcClient,
    _keychain: Keychain<KeyStorage>,
    kad_last_range: Option<(Distance, Distance)>,
}

enum QueryChannel {
    GetProviders(Vec<mpsc::Sender<Result<PeerId, String>>>),
}

#[derive(Debug, Hash, PartialEq, Eq)]
enum QueryKey {
    ProviderKey(Key),
}

const PROVIDER_LIMIT: usize = 20;

const NICE_INTERVAL: Duration = Duration::from_secs(6);
const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

impl<KeyStorage: Storage> Node<KeyStorage> {
    pub async fn new(
        config: Libp2pConfig,
        mut keychain: Keychain<KeyStorage>,
        registry: &mut Registry,
    ) -> Result<Self> {
        let metrics = Metrics::new(registry);
        let (network_sender_in, network_receiver_in) = channel(1024); // TODO: configurable

        tokio::spawn(async move {
            // TODO: handle error
            rpc::new(config.rpc_addr, network_sender_in).await.unwrap()
        });

        let rpc_client = RpcClient::new(&config.rpc_client)
            .await
            .context("failed to create rpc client")?;

        let keypair = load_identity(&mut keychain).await?;
        let mut swarm = build_swarm(&config, &keypair, registry).await?;
        Swarm::listen_on(&mut swarm, config.listening_multiaddr).unwrap();

        Ok(Node {
            swarm,
            net_receiver_in: network_receiver_in,
            bitswap_queries: Default::default(),
            kad_queries: Default::default(),
            network_events: Vec::new(),
            metrics,
            rpc_client,
            _keychain: keychain,
            kad_last_range: None,
        })
    }

    /// Starts the libp2p service networking stack. This Future resolves when shutdown occurs.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("Local Peer ID: {}", self.swarm.local_peer_id());
        let mut nice_interval = time::interval(NICE_INTERVAL);
        let mut bootstrap_interval = time::interval(BOOTSTRAP_INTERVAL);

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
                _interval_event = nice_interval.tick() => {
                    // Print peer count on an interval.
                    info!("Peers connected: {:?}", self.swarm.connected_peers().count());

                    self.dht_nice_tick().await;
                }
                _interval_event = bootstrap_interval.tick() => {
                    if let Err(e) = self.swarm.behaviour_mut().kad_bootstrap() {
                        warn!("kad bootstrap failed: {:?}", e);
                    }
                }
            }
        }
    }

    /// Check the next node in the DHT.
    async fn dht_nice_tick(&mut self) {
        let mut to_dial = None;
        if let Some(kad) = self.swarm.behaviour_mut().kad.as_mut() {
            for kbucket in kad.kbuckets() {
                if let Some(range) = self.kad_last_range {
                    if kbucket.range() == range {
                        continue;
                    }
                }

                // find the first disconnected node
                for entry in kbucket.iter() {
                    if entry.status == NodeStatus::Disconnected {
                        let peer_id = entry.node.key.preimage();

                        let dial_opts = DialOpts::peer_id(*peer_id)
                            .condition(PeerCondition::Disconnected)
                            .addresses(entry.node.value.clone().into_vec())
                            .extend_addresses_through_behaviour()
                            .build();
                        to_dial = Some((dial_opts, kbucket.range()));
                        break;
                    }
                }
            }
        }

        if let Some((dial_opts, range)) = to_dial {
            debug!(
                "checking node {:?} in bucket range ({:?})",
                dial_opts.get_peer_id().unwrap(),
                range
            );

            if let Err(e) = self.swarm.dial(dial_opts) {
                warn!("failed to dial: {:?}", e);
            }
            self.kad_last_range = Some(range);
        }
    }

    /// Subscribe to [`NetworkEvent`]s.
    pub fn network_events(&mut self) -> Receiver<NetworkEvent> {
        let (s, r) = channel(512);
        self.network_events.push(s);
        r
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
            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                ..
            } => {
                if num_established == 1.try_into().unwrap() {
                    self.emit_network_event(NetworkEvent::PeerConnected(peer_id))
                        .await;
                }
                Ok(())
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                if num_established == 0 {
                    self.emit_network_event(NetworkEvent::PeerDisconnected(peer_id))
                        .await;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn emit_network_event(&mut self, ev: NetworkEvent) {
        for sender in &mut self.network_events {
            if let Err(e) = sender.send(ev.clone()).await {
                warn!("failed to send network event: {:?}", e);
            }
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
                        QueryResult::Bootstrap(Ok(BootstrapOk {
                            peer,
                            num_remaining,
                        })) => {
                            debug!(
                                "kad bootstrap done {:?}, remaining: {}",
                                peer, num_remaining
                            );
                        }
                        QueryResult::Bootstrap(Err(e)) => {
                            warn!("kad bootstrap error: {:?}", e);
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
                        for addr in &listen_addrs {
                            if let Some(kad) = self.swarm.behaviour_mut().kad.as_mut() {
                                kad.add_address(&peer_id, addr.clone());
                            }
                        }
                    }

                    // Inform autonat about identified peers
                    // TODO: expose protocol name on `libp2p::autonat`.
                    // TODO: should we remove them at some point?
                    if protocols
                        .iter()
                        .any(|p| p.as_bytes() == b"/libp2p/autonat/1.0.0")
                    {
                        for addr in listen_addrs {
                            if let Some(autonat) = self.swarm.behaviour_mut().autonat.as_mut() {
                                autonat.add_server(peer_id, Some(addr));
                            }
                        }
                    }
                }
            }
            Event::Ping(e) => {
                self.metrics.record(&e);
            }
            Event::Relay(e) => {
                self.metrics.record(&e);
            }
            Event::Dcutr(e) => {
                self.metrics.record(&e);
            }
            Event::Gossipsub(e) => {
                self.metrics.record(&e);
                if let libp2p::gossipsub::GossipsubEvent::Message {
                    propagation_source,
                    message_id,
                    message,
                } = e
                {
                    self.emit_network_event(NetworkEvent::Gossipsub(GossipsubEvent::Message {
                        from: propagation_source,
                        id: message_id,
                        message,
                    }))
                    .await;
                } else if let libp2p::gossipsub::GossipsubEvent::Subscribed { peer_id, topic } = e {
                    self.emit_network_event(NetworkEvent::Gossipsub(GossipsubEvent::Subscribed {
                        peer_id,
                        topic,
                    }))
                    .await;
                } else if let libp2p::gossipsub::GossipsubEvent::Unsubscribed { peer_id, topic } = e
                {
                    self.emit_network_event(NetworkEvent::Gossipsub(
                        GossipsubEvent::Unsubscribed { peer_id, topic },
                    ))
                    .await;
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
                    .map_err(|_| anyhow!("sender dropped"))?;
            }
            RpcMessage::Gossipsub(g) => match g {
                rpc::GossipsubMessage::AddExplicitPeer(response_channel, peer_id) => {
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                    response_channel
                        .send(())
                        .map_err(|_| anyhow!("sender dropped"))?;
                }
                rpc::GossipsubMessage::AllMeshPeers(response_channel) => {
                    let peers = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .all_mesh_peers()
                        .copied()
                        .collect();
                    response_channel
                        .send(peers)
                        .map_err(|_| anyhow!("sender dropped"))?;
                }
                rpc::GossipsubMessage::AllPeers(response_channel) => {
                    let all_peers = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .all_peers()
                        .map(|(p, t)| (*p, t.into_iter().cloned().collect()))
                        .collect();
                    response_channel
                        .send(all_peers)
                        .map_err(|_| anyhow!("sender dropped"))?;
                }
                rpc::GossipsubMessage::MeshPeers(response_channel, topic_hash) => {
                    let peers = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .mesh_peers(&topic_hash)
                        .copied()
                        .collect();
                    response_channel
                        .send(peers)
                        .map_err(|_| anyhow!("sender dropped"))?;
                }
                rpc::GossipsubMessage::Publish(response_channel, topic_hash, bytes) => {
                    let res = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(IdentTopic::new(topic_hash.into_string()), bytes.to_vec());
                    response_channel
                        .send(res)
                        .map_err(|_| anyhow!("sender dropped"))?;
                }
                rpc::GossipsubMessage::RemoveExplicitPeer(response_channel, peer_id) => {
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer_id);
                    response_channel
                        .send(())
                        .map_err(|_| anyhow!("sender dropped"))?;
                }
                rpc::GossipsubMessage::Subscribe(response_channel, topic_hash) => {
                    let res = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .subscribe(&IdentTopic::new(topic_hash.into_string()));
                    response_channel
                        .send(res)
                        .map_err(|_| anyhow!("sender dropped"))?;
                }
                rpc::GossipsubMessage::Topics(response_channel) => {
                    let topics = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .topics()
                        .cloned()
                        .collect();
                    response_channel
                        .send(topics)
                        .map_err(|_| anyhow!("sender dropped"))?;
                }
                rpc::GossipsubMessage::Unsubscribe(response_channel, topic_hash) => {
                    let res = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .unsubscribe(&IdentTopic::new(topic_hash.into_string()));
                    response_channel
                        .send(res)
                        .map_err(|_| anyhow!("sender dropped"))?;
                }
            },
        }

        Ok(())
    }
}

async fn load_identity<S: Storage>(kc: &mut Keychain<S>) -> Result<Keypair> {
    if kc.is_empty().await? {
        info!("no identity found, creating",);
        kc.create_ed25519_key().await?;
    }

    // for now we just use the first key
    let first_key = kc.keys().next().await;
    if let Some(keypair) = first_key {
        let keypair: Keypair = keypair?.into();
        info!("identity loaded: {}", PeerId::from(keypair.public()));
        return Ok(keypair);
    }

    Err(anyhow!("inconsistent keystate"))
}

#[cfg(test)]
mod tests {
    use crate::{keys::MemoryStorage, metrics};

    use super::*;
    use anyhow::Result;

    #[tokio::test]
    async fn test_fetch_providers() -> Result<()> {
        let mut prom_registry = Registry::default();
        let mut network_config = Libp2pConfig::default();
        network_config.metrics.debug = true;
        let metrics_config = network_config.metrics.clone();

        let kc = Keychain::<MemoryStorage>::new();
        let mut p2p = Node::new(network_config, kc, &mut prom_registry).await?;

        let metrics_handle = iroh_metrics::MetricsHandle::from_registry_with_tracer(
            metrics::metrics_config_with_compile_time_info(metrics_config),
            prom_registry,
        )
        .await
        .expect("failed to initialize metrics");

        let cfg = iroh_rpc_client::Config::default();
        let p2p_task = tokio::task::spawn(async move {
            p2p.run().await.unwrap();
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

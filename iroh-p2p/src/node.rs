use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ahash::AHashMap;
use anyhow::{anyhow, Context, Result};
use cid::Cid;
use futures::channel::oneshot::Sender as OneShotSender;
use futures_util::stream::StreamExt;
use iroh_metrics::{core::MRecorder, inc, libp2p_metrics, p2p::P2PMetrics};
use iroh_rpc_client::Client as RpcClient;
use iroh_rpc_types::p2p::P2pServerAddr;
use libp2p::core::{Multiaddr, ProtocolName};
use libp2p::gossipsub::{GossipsubMessage, MessageId, TopicHash};
pub use libp2p::gossipsub::{IdentTopic, Topic};
use libp2p::identify::{IdentifyEvent, IdentifyInfo};
use libp2p::identity::Keypair;
use libp2p::kad::kbucket::{Distance, NodeStatus};
use libp2p::kad::BootstrapOk;
use libp2p::kad::{
    self, record::Key, GetProvidersError, GetProvidersOk, KademliaEvent, QueryResult,
};
use libp2p::metrics::Recorder;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{ConnectionHandler, IntoConnectionHandler, NetworkBehaviour, SwarmEvent};
use libp2p::{PeerId, Swarm};
use tokio::sync::mpsc;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use iroh_bitswap::{
    BitswapEvent, Block, FindProvidersResult, InboundRequest, QueryError,
    QueryResult as BitswapQueryResult, WantResult,
};

use crate::keys::{Keychain, Storage};
use crate::rpc::ProviderRequestKey;
use crate::swarm::build_swarm;
use crate::{
    behaviour::{Event, NodeBehaviour},
    rpc::{self, RpcMessage},
    Config, Libp2pConfig,
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
    bitswap_queries: AHashMap<BitswapQueryKey, BitswapQueryChannel>,
    kad_queries: AHashMap<QueryKey, KadQueryChannel>,
    dial_queries: AHashMap<PeerId, Vec<OneShotSender<bool>>>,
    network_events: Vec<Sender<NetworkEvent>>,
    rpc_client: RpcClient,
    _keychain: Keychain<KeyStorage>,
    kad_last_range: Option<(Distance, Distance)>,
    rpc_task: JoinHandle<()>,
}

enum BitswapQueryChannel {
    Want {
        timeout: Instant,
        chan: OneShotSender<Result<Block, QueryError>>,
    },
    FindProviders {
        timeout: Instant,
        provider_count: usize,
        expected_provider_count: usize,
        chan: mpsc::Sender<Result<HashSet<PeerId>, String>>,
    },
}

enum KadQueryChannel {
    GetProviders {
        provider_count: usize,
        channels: Vec<mpsc::Sender<Result<HashSet<PeerId>, String>>>,
    },
}

#[derive(Debug, Hash, PartialEq, Eq)]
enum QueryKey {
    ProviderKey(Key),
}

#[derive(Debug, Hash, PartialEq, Eq)]
enum BitswapQueryKey {
    Want(Cid),
    FindProviders(Cid),
}

const PROVIDER_LIMIT: usize = 20;
const NICE_INTERVAL: Duration = Duration::from_secs(6);
const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

impl<KeyStorage: Storage> Drop for Node<KeyStorage> {
    fn drop(&mut self) {
        self.rpc_task.abort();
    }
}

impl<KeyStorage: Storage> Node<KeyStorage> {
    pub async fn new(
        config: Config,
        rpc_addr: P2pServerAddr,
        mut keychain: Keychain<KeyStorage>,
    ) -> Result<Self> {
        let (network_sender_in, network_receiver_in) = channel(1024); // TODO: configurable

        let keypair = load_identity(&mut keychain).await?;
        let mut swarm = build_swarm(&config.libp2p, &keypair).await?;

        let Config {
            libp2p:
                Libp2pConfig {
                    listening_multiaddr,
                    ..
                },
            rpc_client,
            ..
        } = config;

        let rpc_task = tokio::spawn(async move {
            // TODO: handle error
            rpc::new(rpc_addr, network_sender_in).await.unwrap()
        });

        let rpc_client = RpcClient::new(rpc_client)
            .await
            .context("failed to create rpc client")?;

        Swarm::listen_on(&mut swarm, listening_multiaddr).unwrap();

        Ok(Node {
            swarm,
            net_receiver_in: network_receiver_in,
            bitswap_queries: Default::default(),
            kad_queries: Default::default(),
            dial_queries: Default::default(),
            network_events: Vec::new(),
            rpc_client,
            _keychain: keychain,
            kad_last_range: None,
            rpc_task,
        })
    }

    /// Starts the libp2p service networking stack. This Future resolves when shutdown occurs.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("Local Peer ID: {}", self.swarm.local_peer_id());

        let mut nice_interval = Instant::now();
        let mut bootstrap_interval = Instant::now();
        let mut expiry_interval = Instant::now();

        let mut rpc_msgs = 0;

        loop {
            trace!("tick");
            // TODO: avoid starvaition of the swarm
            if rpc_msgs < 100 {
                if let Ok(rpc_message) = self.net_receiver_in.try_recv() {
                    trace!("tick: rpc message");
                    rpc_msgs += 1;
                    match self.handle_rpc_message(rpc_message).await {
                        Ok(true) => {
                            // shutdown
                            return Ok(());
                        }
                        Ok(false) => {
                            continue;
                        }
                        Err(err) => {
                            warn!("rpc: {:?}", err);
                        }
                    }
                }
            }

            // reset continous rpc msg handling
            rpc_msgs = 0;

            // check timers
            if nice_interval.elapsed() >= NICE_INTERVAL {
                trace!("tick:timer: nice");
                nice_interval = Instant::now();
                // Print peer count on an interval.
                info!(
                    "Peers connected: {:?}",
                    self.swarm.connected_peers().count()
                );

                self.dht_nice_tick().await;
            }

            if bootstrap_interval.elapsed() >= BOOTSTRAP_INTERVAL {
                trace!("tick:bootstrap: nice");
                bootstrap_interval = Instant::now();
                if let Err(e) = self.swarm.behaviour_mut().kad_bootstrap() {
                    warn!("kad bootstrap failed: {:?}", e);
                }
            }
            if expiry_interval.elapsed() >= Duration::from_secs(1) {
                trace!("tick:expiry: expiry");
                expiry_interval = Instant::now();

                if let Err(err) = self.expiry() {
                    warn!("expiry error {:?}", err);
                }
            }

            if let Some(swarm_event) = self.swarm.next().await {
                trace!("tick: swarm event: {:?}", swarm_event);
                if let Err(err) = self.handle_swarm_event(swarm_event).await {
                    warn!("swarm: {:?}", err);
                }
            }
        }
    }

    fn expiry(&mut self) -> Result<()> {
        let mut err = Ok(());
        self.bitswap_queries
            .retain(|key, state| match (key, state) {
                (
                    BitswapQueryKey::FindProviders(cid),
                    BitswapQueryChannel::FindProviders { timeout, .. },
                ) => {
                    if timeout.elapsed() < Duration::from_secs(30) {
                        true
                    } else {
                        err = self.swarm.behaviour_mut().cancel_want_block(cid);
                        false
                    }
                }
                (BitswapQueryKey::Want(cid), BitswapQueryChannel::Want { timeout, .. }) => {
                    if timeout.elapsed() < Duration::from_secs(60) {
                        true
                    } else {
                        err = self.swarm.behaviour_mut().cancel_block(cid);
                        false
                    }
                }
                _ => {
                    err = Err(anyhow!("invalid bitswap query state"));
                    false
                }
            });

        err
    }

    /// Check the next node in the DHT.
    #[tracing::instrument(skip(self))]
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
    #[tracing::instrument(skip(self))]
    pub fn network_events(&mut self) -> Receiver<NetworkEvent> {
        let (s, r) = channel(512);
        self.network_events.push(s);
        r
    }

    #[tracing::instrument(skip(self))]
    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<
            <NodeBehaviour as NetworkBehaviour>::OutEvent,
            <<<NodeBehaviour as NetworkBehaviour>::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::Error>,
    ) -> Result<()> {
        libp2p_metrics().record(&event);
        match event {
            // outbound events
            SwarmEvent::Behaviour(event) => self.handle_node_event(event).await,
            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                ..
            } => {
                if let Some(channels) = self.dial_queries.get_mut(&peer_id) {
                    while let Some(channel) = channels.pop() {
                        channel.send(true).ok();
                    }
                }

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
            SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                debug!("failed to dial: {:?}, {:?}", peer_id, error);

                if let Some(peer_id) = peer_id {
                    if let Some(channels) = self.dial_queries.get_mut(&peer_id) {
                        while let Some(channel) = channels.pop() {
                            channel.send(false).ok();
                        }
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn emit_network_event(&mut self, ev: NetworkEvent) {
        for sender in &mut self.network_events {
            if let Err(e) = sender.send(ev.clone()).await {
                warn!("failed to send network event: {:?}", e);
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn handle_node_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Bitswap(e) => {
                match e {
                    BitswapEvent::InboundRequest { request } => match request {
                        InboundRequest::Want { cid, sender, .. } => {
                            info!("bitswap want {}", cid);
                            match self.rpc_client.try_store() {
                                Ok(rpc_store) => match rpc_store.get(cid).await {
                                    Ok(Some(data)) => {
                                        trace!("Found data for: {}", cid);
                                        if let Err(e) = self
                                            .swarm
                                            .behaviour_mut()
                                            .send_block(&sender, cid, data)
                                        {
                                            warn!(
                                                "failed to send block for {} to {}: {:?}",
                                                cid, sender, e
                                            );
                                        }
                                    }
                                    Ok(None) => {
                                        trace!("Don't have data for: {}", cid);
                                    }
                                    Err(e) => {
                                        warn!("Failed to get data for: {}: {:?}", cid, e);
                                    }
                                },
                                Err(e) => {
                                    warn!("Failed to get data for: {}: {:?}", cid, e);
                                }
                            }
                        }
                        InboundRequest::WantHave { cid, sender, .. } => {
                            trace!("bitswap want have {}", cid);
                            if let Some(rpc_store) = self.rpc_client.store.as_ref() {
                                match rpc_store.has(cid).await {
                                    Ok(true) => {
                                        trace!("Have data for: {}", cid);
                                        if let Err(e) =
                                            self.swarm.behaviour_mut().send_have_block(&sender, cid)
                                        {
                                            warn!(
                                                "failed to send block have for {} to {}: {:?}",
                                                cid, sender, e
                                            );
                                        }
                                    }
                                    Ok(false) => {
                                        trace!("Don't have data for: {}", cid);
                                    }
                                    Err(e) => {
                                        warn!("Failed to check for data for: {}: {:?}", cid, e);
                                    }
                                }
                            } else {
                                warn!(
                                    "Failed to check for data for: {}: missing store rpc conn",
                                    cid
                                );
                            }
                        }
                        InboundRequest::Cancel { .. } => {
                            // nothing to do atm
                        }
                    },
                    BitswapEvent::OutboundQueryCompleted { result } => match result {
                        BitswapQueryResult::Want(WantResult::Ok { sender, cid, data }) => {
                            info!("got block {} from {}", cid, sender);
                            let cid2 = cid;
                            let data2 = data.clone();
                            match tokio::task::spawn_blocking(move || {
                                iroh_util::verify_hash(&cid2, &data2)
                            })
                            .await?
                            {
                                Some(true) => {
                                    let b = Block::new(data, cid);
                                    if let Some(BitswapQueryChannel::Want { chan, .. }) =
                                        self.bitswap_queries.remove(&BitswapQueryKey::Want(cid))
                                    {
                                        if chan.send(Ok(b)).is_err() {
                                            debug!("Bitswap response channel send failed");
                                        }
                                        trace!("Saved Bitswap block with cid {:?}", cid);
                                    } else {
                                        debug!("Received Bitswap response, but response channel cannot be found");
                                    }
                                }
                                Some(false) => {
                                    warn!("Invalid data received, ignoring");
                                }
                                None => {
                                    warn!(
                                        "unable to verify hash, unknown hash function {} for {}, ignoring",
                                        cid.hash().code(),
                                        cid
                                    );
                                }
                            }
                        }
                        BitswapQueryResult::Want(WantResult::Err { cid, error }) => {
                            if let Some(BitswapQueryChannel::Want { chan, .. }) =
                                self.bitswap_queries.remove(&BitswapQueryKey::Want(cid))
                            {
                                if chan.send(Err(error)).is_err() {
                                    debug!("Bitswap response channel send failed");
                                }
                            }
                        }
                        BitswapQueryResult::FindProviders(FindProvidersResult::Ok {
                            cid,
                            provider,
                        }) => {
                            info!("Bitswap found provider for {}", cid);
                            let query = self
                                .bitswap_queries
                                .get_mut(&BitswapQueryKey::FindProviders(cid));
                            let mut to_remove = query.is_none();

                            if let Some(BitswapQueryChannel::FindProviders {
                                provider_count,
                                expected_provider_count,
                                chan,
                                ..
                            }) = query
                            {
                                // filter out bad providers
                                if !self.swarm.behaviour().is_bad_peer(&provider) {
                                    *provider_count += 1;
                                    to_remove |= chan
                                        .send(Ok([provider].into_iter().collect()))
                                        .await
                                        .is_err();
                                    to_remove |= *provider_count >= *expected_provider_count;
                                }
                            } else {
                                inc!(P2PMetrics::SkippedPeerBitswap);
                            }

                            if to_remove {
                                self.swarm.behaviour_mut().cancel_want_block(&cid).ok();
                                self.bitswap_queries
                                    .remove(&BitswapQueryKey::FindProviders(cid));
                            }
                        }
                        BitswapQueryResult::FindProviders(FindProvidersResult::Err {
                            cid,
                            error,
                        }) => {
                            let query = self
                                .bitswap_queries
                                .remove(&BitswapQueryKey::FindProviders(cid));

                            let mut to_remove = query.is_none();
                            if let Some(BitswapQueryChannel::FindProviders { chan, .. }) = query {
                                to_remove |= chan.send(Err(error.to_string())).await.is_err();
                            }
                            if to_remove {
                                self.swarm.behaviour_mut().cancel_want_block(&cid).ok();
                                self.bitswap_queries
                                    .remove(&BitswapQueryKey::FindProviders(cid));
                            }
                        }
                        BitswapQueryResult::Send(_) => {
                            // Nothing to do yet
                        }
                        BitswapQueryResult::SendHave(_) => {
                            // Nothing to do yet
                        }
                        BitswapQueryResult::Cancel(_) => {
                            // Nothing to do yet
                        }
                    },
                }
            }
            Event::Kademlia(e) => {
                libp2p_metrics().record(&e);
                if let KademliaEvent::OutboundQueryProgressed {
                    id, result, step, ..
                } = e
                {
                    match result {
                        QueryResult::GetProviders(Ok(GetProvidersOk {
                            key, providers, ..
                        })) => {
                            if step.last {
                                let _ = self.kad_queries.remove(&QueryKey::ProviderKey(key));
                            } else if let Some(KadQueryChannel::GetProviders {
                                channels,
                                provider_count,
                            }) = self
                                .kad_queries
                                .get_mut(&QueryKey::ProviderKey(key.clone()))
                            {
                                // filter out bad providers
                                let providers: HashSet<_> = providers
                                    .into_iter()
                                    .filter(|provider| {
                                        inc!(P2PMetrics::SkippedPeerKad);
                                        !self.swarm.behaviour().is_bad_peer(provider)
                                    })
                                    .collect();

                                if !providers.is_empty() {
                                    for chan in channels.iter_mut() {
                                        chan.send(Ok(providers.clone())).await.ok();
                                    }
                                }

                                *provider_count += providers.len();
                                if *provider_count >= PROVIDER_LIMIT {
                                    debug!(
                                        "finish provider query {}/{}",
                                        provider_count, PROVIDER_LIMIT
                                    );
                                    // Finish query if we have enough providers.
                                    self.swarm.behaviour_mut().finish_query(&id);
                                }
                            }
                        }

                        QueryResult::GetProviders(Err(err)) => {
                            let key = match err {
                                GetProvidersError::Timeout { key, .. } => key,
                            };
                            debug!("GetProviders timeout {:?}", key);
                            if let Some(KadQueryChannel::GetProviders { channels, .. }) =
                                self.kad_queries.remove(&QueryKey::ProviderKey(key))
                            {
                                for chan in channels.into_iter() {
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
                }
            }
            Event::Identify(e) => {
                libp2p_metrics().record(&*e);
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
                    let supported_bs_protocols = self
                        .swarm
                        .behaviour()
                        .bitswap
                        .as_ref()
                        .map(|bs| bs.supported_protocols().to_vec())
                        .unwrap_or_default();
                    let mut protocol_bs_name = None;
                    for protocol in protocols {
                        let p = protocol.as_bytes();

                        if p == kad::protocol::DEFAULT_PROTO_NAME {
                            for addr in &listen_addrs {
                                if let Some(kad) = self.swarm.behaviour_mut().kad.as_mut() {
                                    kad.add_address(&peer_id, addr.clone());
                                }
                            }
                        } else if protocol_bs_name.is_none() {
                            for sp in &supported_bs_protocols {
                                if p == sp.protocol_name() {
                                    protocol_bs_name = Some(*sp);
                                    break;
                                }
                            }
                            if protocol_bs_name.is_some() {
                                if let Some(bs) = self.swarm.behaviour_mut().bitswap.as_mut() {
                                    bs.add_peer(peer_id, protocol_bs_name);
                                }
                            }
                        } else if p == b"/libp2p/autonat/1.0.0" {
                            // TODO: expose protocol name on `libp2p::autonat`.
                            // TODO: should we remove them at some point?
                            for addr in &listen_addrs {
                                if let Some(autonat) = self.swarm.behaviour_mut().autonat.as_mut() {
                                    autonat.add_server(peer_id, Some(addr.clone()));
                                }
                            }
                        }
                    }
                }
            }
            Event::Ping(e) => {
                libp2p_metrics().record(&e);
            }
            Event::Relay(e) => {
                libp2p_metrics().record(&e);
            }
            Event::Dcutr(e) => {
                libp2p_metrics().record(&e);
            }
            Event::Gossipsub(e) => {
                libp2p_metrics().record(&e);
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

    #[tracing::instrument(skip(self))]
    async fn handle_rpc_message(&mut self, message: RpcMessage) -> Result<bool> {
        // Inbound messages
        match message {
            RpcMessage::BitswapRequest {
                cids,
                response_channels,
                providers,
            } => {
                for (cid, response_channel) in cids.into_iter().zip(response_channels.into_iter()) {
                    self.swarm
                        .behaviour_mut()
                        .want_block(cid, 1000, providers.clone()) // TODO: priority?
                        .map_err(|err| anyhow!("Failed to send a bitswap want_block: {:?}", err))?;

                    self.bitswap_queries.insert(
                        BitswapQueryKey::Want(cid),
                        BitswapQueryChannel::Want {
                            timeout: Instant::now(),
                            chan: response_channel,
                        },
                    );
                }
            }
            RpcMessage::BitswapInjectProviders {
                cid,
                response_channel,
                providers,
            } => {
                let res = self
                    .swarm
                    .behaviour_mut()
                    .want_block(cid, 1000, providers) // TODO: priority?
                    .map_err(|e| anyhow!("Failed to send a bitswap want_block: {:?}", e));

                if response_channel.send(res).is_err() {
                    warn!("failed to send inject provider for {}", cid);
                }
            }
            RpcMessage::ProviderRequest {
                key,
                response_channel,
            } => match key {
                ProviderRequestKey::Dht(key) => {
                    if let Some(kad) = self.swarm.behaviour_mut().kad.as_mut() {
                        if let Some(KadQueryChannel::GetProviders { channels, .. }) = self
                            .kad_queries
                            .get_mut(&QueryKey::ProviderKey(key.clone()))
                        {
                            debug!(
                                "RpcMessage::ProviderRequest: already fetching providers for {:?}",
                                key
                            );
                            channels.push(response_channel);
                        } else {
                            debug!(
                                "RpcMessage::ProviderRequest: getting providers for {:?}",
                                key
                            );
                            let _ = kad.get_providers(key.clone());
                            self.kad_queries.insert(
                                QueryKey::ProviderKey(key),
                                KadQueryChannel::GetProviders {
                                    provider_count: 0,
                                    channels: vec![response_channel],
                                },
                            );
                        }
                    } else {
                        response_channel
                            .send(Err("kademlia is not available".into()))
                            .await
                            .ok();
                    }
                }
                ProviderRequestKey::Bitswap(cid) => {
                    debug!(
                        "RpcMessage::ProviderRequest: getting providers for {:?}",
                        key
                    );

                    match self.swarm.behaviour_mut().find_providers(cid, 1000) {
                        Ok(()) => {
                            self.bitswap_queries.insert(
                                BitswapQueryKey::FindProviders(cid),
                                BitswapQueryChannel::FindProviders {
                                    timeout: Instant::now(),
                                    expected_provider_count: PROVIDER_LIMIT,
                                    provider_count: 0,
                                    chan: response_channel,
                                },
                            );
                        }
                        Err(e) => {
                            response_channel.send(Err(e.to_string())).await.ok();
                        }
                    }
                }
            },
            RpcMessage::NetListeningAddrs(response_channel) => {
                let mut listeners: Vec<_> = Swarm::listeners(&self.swarm).cloned().collect();
                let peer_id = *Swarm::local_peer_id(&self.swarm);
                listeners.extend(Swarm::external_addresses(&self.swarm).map(|r| r.addr.clone()));

                response_channel
                    .send((peer_id, listeners))
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
            RpcMessage::NetConnect(response_channel, peer_id, addresses) => {
                let channels = self.dial_queries.entry(peer_id).or_default();
                channels.push(response_channel);

                let dial_opts = DialOpts::peer_id(peer_id)
                    .addresses(addresses)
                    .condition(libp2p::swarm::dial_opts::PeerCondition::Always)
                    .build();
                if let Err(e) = Swarm::dial(&mut self.swarm, dial_opts) {
                    warn!("invalid dial options: {:?}", e);
                    while let Some(channel) = channels.pop() {
                        channel.send(false).ok();
                    }
                }
            }
            RpcMessage::NetDisconnect(response_channel, _peer_id) => {
                warn!("NetDisconnect API not yet implemented"); // TODO: implement NetDisconnect

                response_channel
                    .send(())
                    .map_err(|_| anyhow!("sender dropped"))?;
            }
            RpcMessage::Gossipsub(g) => {
                let gossipsub = match self.swarm.behaviour_mut().gossipsub.as_mut() {
                    Some(gossipsub) => gossipsub,
                    None => {
                        tracing::warn!("Unexpected gossipsub message");
                        return Ok(false);
                    }
                };
                match g {
                    rpc::GossipsubMessage::AddExplicitPeer(response_channel, peer_id) => {
                        gossipsub.add_explicit_peer(&peer_id);
                        response_channel
                            .send(())
                            .map_err(|_| anyhow!("sender dropped"))?;
                    }
                    rpc::GossipsubMessage::AllMeshPeers(response_channel) => {
                        let peers = gossipsub.all_mesh_peers().copied().collect();
                        response_channel
                            .send(peers)
                            .map_err(|_| anyhow!("sender dropped"))?;
                    }
                    rpc::GossipsubMessage::AllPeers(response_channel) => {
                        let all_peers = gossipsub
                            .all_peers()
                            .map(|(p, t)| (*p, t.into_iter().cloned().collect()))
                            .collect();
                        response_channel
                            .send(all_peers)
                            .map_err(|_| anyhow!("sender dropped"))?;
                    }
                    rpc::GossipsubMessage::MeshPeers(response_channel, topic_hash) => {
                        let peers = gossipsub.mesh_peers(&topic_hash).copied().collect();
                        response_channel
                            .send(peers)
                            .map_err(|_| anyhow!("sender dropped"))?;
                    }
                    rpc::GossipsubMessage::Publish(response_channel, topic_hash, bytes) => {
                        let res = gossipsub
                            .publish(IdentTopic::new(topic_hash.into_string()), bytes.to_vec());
                        response_channel
                            .send(res)
                            .map_err(|_| anyhow!("sender dropped"))?;
                    }
                    rpc::GossipsubMessage::RemoveExplicitPeer(response_channel, peer_id) => {
                        gossipsub.remove_explicit_peer(&peer_id);
                        response_channel
                            .send(())
                            .map_err(|_| anyhow!("sender dropped"))?;
                    }
                    rpc::GossipsubMessage::Subscribe(response_channel, topic_hash) => {
                        let res = gossipsub.subscribe(&IdentTopic::new(topic_hash.into_string()));
                        response_channel
                            .send(res)
                            .map_err(|_| anyhow!("sender dropped"))?;
                    }
                    rpc::GossipsubMessage::Topics(response_channel) => {
                        let topics = gossipsub.topics().cloned().collect();
                        response_channel
                            .send(topics)
                            .map_err(|_| anyhow!("sender dropped"))?;
                    }
                    rpc::GossipsubMessage::Unsubscribe(response_channel, topic_hash) => {
                        let res = gossipsub.unsubscribe(&IdentTopic::new(topic_hash.into_string()));
                        response_channel
                            .send(res)
                            .map_err(|_| anyhow!("sender dropped"))?;
                    }
                }
            }
            RpcMessage::Shutdown => {
                return Ok(true);
            }
        }

        Ok(false)
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
        error!("identity loaded: {}", PeerId::from(keypair.public()));
        return Ok(keypair);
    }

    Err(anyhow!("inconsistent keystate"))
}

#[cfg(test)]
mod tests {
    use crate::keys::MemoryStorage;

    use super::*;
    use anyhow::Result;
    use futures::TryStreamExt;
    use iroh_rpc_types::{
        p2p::{P2pClientAddr, P2pServerAddr},
        Addr,
    };
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    #[cfg(feature = "rpc-grpc")]
    #[tokio::test]
    async fn test_fetch_providers_grpc_dht() -> Result<()> {
        let server_addr = "grpc://0.0.0.0:4401".parse().unwrap();
        let client_addr = "grpc://0.0.0.0:4401".parse().unwrap();
        fetch_providers(
            "/ip4/0.0.0.0/tcp/5001".parse().unwrap(),
            server_addr,
            client_addr,
            true,
        )
        .await?;
        Ok(())
    }

    #[cfg(all(feature = "rpc-grpc", unix))]
    #[tokio::test]
    async fn test_fetch_providers_uds_dht() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("cool.iroh");

        let server_addr = P2pServerAddr::GrpcUds(file.clone());
        let client_addr = P2pClientAddr::GrpcUds(file);
        fetch_providers(
            "/ip4/0.0.0.0/tcp/5002".parse().unwrap(),
            server_addr,
            client_addr,
            true,
        )
        .await?;
        Ok(())
    }

    #[cfg(feature = "rpc-mem")]
    #[tokio::test]
    async fn test_fetch_providers_mem_dht() -> Result<()> {
        let (server_addr, client_addr) = Addr::new_mem();
        fetch_providers(
            "/ip4/0.0.0.0/tcp/5003".parse().unwrap(),
            server_addr,
            client_addr,
            true,
        )
        .await?;
        Ok(())
    }

    #[cfg(feature = "rpc-mem")]
    #[tokio::test]
    async fn test_fetch_providers_mem_bitswap() -> Result<()> {
        tracing_subscriber::registry()
            .with(fmt::layer().pretty())
            .with(EnvFilter::from_default_env())
            .init();

        let (server_addr, client_addr) = Addr::new_mem();
        fetch_providers(
            "/ip4/0.0.0.0/tcp/5004".parse().unwrap(),
            server_addr,
            client_addr,
            false,
        )
        .await?;
        Ok(())
    }

    async fn fetch_providers(
        addr: Multiaddr,
        rpc_server_addr: P2pServerAddr,
        rpc_client_addr: P2pClientAddr,
        dht: bool,
    ) -> Result<()> {
        let mut network_config = Config::default_with_rpc(rpc_client_addr.clone());
        network_config.libp2p.listening_multiaddr = addr;

        let kc = Keychain::<MemoryStorage>::new();
        let mut p2p = Node::new(network_config, rpc_server_addr, kc).await?;

        let cfg = iroh_rpc_client::Config {
            p2p_addr: Some(rpc_client_addr),
            ..Default::default()
        };
        let p2p_task = tokio::task::spawn(async move {
            p2p.run().await.unwrap();
        });

        {
            let client = RpcClient::new(cfg).await?;
            let c = "QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR"
                .parse()
                .unwrap();
            if dht {
                let providers: Vec<PeerId> = client
                    .p2p
                    .unwrap()
                    .fetch_providers_dht(&c)
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?
                    .into_iter()
                    .flat_map(|p| p.into_iter())
                    .collect();
                println!("{:?}", providers);
                assert!(!providers.is_empty());
                assert!(
                    providers.len() >= PROVIDER_LIMIT,
                    "{} < {}",
                    providers.len(),
                    PROVIDER_LIMIT
                );
            } else {
                // force to connect to providers, so we have a chance
                let providers: Vec<_> = client
                    .p2p
                    .clone()
                    .unwrap()
                    .fetch_providers_dht(&c)
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?
                    .into_iter()
                    .flat_map(|p| p.into_iter())
                    .collect();
                assert!(!providers.is_empty());
                println!("found providers dht: {:?}", providers);

                let providers: Vec<_> = client
                    .p2p
                    .unwrap()
                    .fetch_providers_bitswap(&c)
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?
                    .into_iter()
                    .flat_map(|p| p.into_iter())
                    .collect();
                assert!(!providers.is_empty());
                println!("found providers bitswap: {:?}", providers);
            }
        };

        p2p_task.abort();
        Ok(())
    }
}

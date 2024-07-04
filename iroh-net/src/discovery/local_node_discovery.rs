use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use derive_more::FromStr;
use futures_lite::{stream::Boxed as BoxStream, StreamExt};
use tracing::{debug, error, trace, warn};

use flume::Sender;
use iroh_base::key::PublicKey;
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::task::{JoinHandle, JoinSet};

use crate::{
    discovery::{Discovery, DiscoveryItem},
    AddrInfo, Endpoint, NodeId,
};

/// The n0 local swarm node discovery name
const N0_LOCAL_SWARM: &str = "iroh.local.swarm";

/// Provenance string
const PROVENANCE: &str = "local.swarm.discovery";

/// How long we will wait before we stop sending discovery items
const DISCOVERY_DURATION: Duration = Duration::from_secs(10);

/// Discovery using `swarm-discovery`, a variation on mdns
#[derive(Debug)]
pub struct LocalSwarmDiscovery {
    handle: JoinHandle<()>,
    sender: Sender<Message>,
}

impl Drop for LocalSwarmDiscovery {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Debug)]
enum Message {
    Discovery(String, Peer),
    SendAddrs(NodeId, Sender<Result<DiscoveryItem>>),
    ChangeLocalAddrs(AddrInfo),
    Timeout(NodeId, usize),
}

impl LocalSwarmDiscovery {
    /// Create a new [`LocalSwarmDiscovery`] Service.
    ///
    /// This starts a [`Discoverer`] that broadcasts your addresses and receives addresses from other nodes in your local network.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    pub fn new(node_id: NodeId) -> Result<Self> {
        debug!("Creating new LocalSwarmDiscovery service");
        let (send, recv) = flume::bounded(64);
        let task_sender = send.clone();
        let rt = tokio::runtime::Handle::current();
        let mut guard = Some(LocalSwarmDiscovery::spawn_discoverer(
            node_id,
            task_sender.clone(),
            BTreeSet::new(),
            &rt,
        )?);

        let handle = tokio::spawn(async move {
            let mut node_addrs: HashMap<PublicKey, Peer> = HashMap::default();
            let mut last_id = 0;
            let mut senders: HashMap<PublicKey, HashMap<usize, Sender<Result<DiscoveryItem>>>> =
                HashMap::default();
            let mut timeouts = JoinSet::new();
            loop {
                trace!(?node_addrs, "LocalSwarmDiscovery Service loop tick");
                let msg = match recv.recv_async().await {
                    Err(err) => {
                        error!("LocalSwarmDiscovery service error: {err:?}");
                        error!("closing LocalSwarmDiscovery");
                        timeouts.abort_all();
                        return;
                    }
                    Ok(msg) => msg,
                };
                match msg {
                    Message::Discovery(discovered_node_id, peer_info) => {
                        trace!(
                            ?discovered_node_id,
                            ?peer_info,
                            "LocalSwarmDiscovery Message::Discovery"
                        );
                        let discovered_node_id = match PublicKey::from_str(&discovered_node_id) {
                            Ok(node_id) => node_id,
                            Err(e) => {
                                warn!(
                                    discovered_node_id,
                                    "couldn't parse node_id from mdns discovery service: {e:?}"
                                );
                                continue;
                            }
                        };

                        if discovered_node_id == node_id {
                            continue;
                        }

                        if peer_info.is_expiry() {
                            trace!(
                                ?discovered_node_id,
                                "removing node from LocalSwarmDiscovery address book"
                            );
                            node_addrs.remove(&discovered_node_id);
                            continue;
                        }

                        if let Some(senders) = senders.get(&discovered_node_id) {
                            for sender in senders.values() {
                                let item: DiscoveryItem = (&peer_info).into();
                                trace!(?item, "sending DiscoveryItem");
                                sender.send_async(Ok(item)).await.ok();
                            }
                        }
                        trace!(
                            ?discovered_node_id,
                            ?peer_info,
                            "adding node to LocalSwarmDiscovery address book"
                        );
                        node_addrs.insert(discovered_node_id, peer_info);
                    }
                    Message::SendAddrs(node_id, sender) => {
                        let id = last_id + 1;
                        last_id = id;
                        trace!(?node_id, "LocalSwarmDiscovery Message::SendAddrs");
                        if let Some(peer_info) = node_addrs.get(&node_id) {
                            let item: DiscoveryItem = peer_info.into();
                            debug!(?item, "sending DiscoveryItem");
                            sender.send_async(Ok(item)).await.ok();
                        }
                        if let Some(senders_for_node_id) = senders.get_mut(&node_id) {
                            senders_for_node_id.insert(id, sender);
                        } else {
                            let mut senders_for_node_id = HashMap::new();
                            senders_for_node_id.insert(id, sender);
                            senders.insert(node_id, senders_for_node_id);
                        }
                        let timeout_sender = task_sender.clone();
                        timeouts.spawn(async move {
                            tokio::time::sleep(DISCOVERY_DURATION).await;
                            trace!(?node_id, "discovery timeout");
                            timeout_sender
                                .send_async(Message::Timeout(node_id, id))
                                .await
                                .ok();
                        });
                    }
                    Message::Timeout(node_id, id) => {
                        trace!(?node_id, "LocalSwarmDiscovery Message::Timeout");
                        if let Some(senders_for_node_id) = senders.get_mut(&node_id) {
                            senders_for_node_id.remove(&id);
                            if senders_for_node_id.is_empty() {
                                senders.remove(&node_id);
                            }
                        }
                    }
                    Message::ChangeLocalAddrs(addrs) => {
                        trace!(?addrs, "LocalSwarmDiscovery Message::ChangeLocalAddrs");
                        let callback_send = task_sender.clone();
                        let g = guard.take();
                        drop(g);
                        guard = match LocalSwarmDiscovery::spawn_discoverer(
                            node_id,
                            callback_send.clone(),
                            addrs.direct_addresses,
                            &rt,
                        ) {
                            Ok(guard) => Some(guard),
                            Err(e) => {
                                error!("LocalSwarmDiscovery error creating discovery service: {e}");
                                return;
                            }
                        };
                    }
                }
            }
        });
        Ok(Self {
            handle,
            sender: send,
        })
    }

    fn spawn_discoverer(
        node_id: PublicKey,
        sender: Sender<Message>,
        socketaddrs: BTreeSet<SocketAddr>,
        rt: &tokio::runtime::Handle,
    ) -> Result<DropGuard> {
        let callback = move |node_id: &str, peer: &Peer| {
            trace!(
                node_id,
                ?peer,
                "Received peer information from LocalSwarmDiscovery"
            );

            sender
                .send(Message::Discovery(node_id.to_string(), peer.clone()))
                .ok();
        };

        let mut addrs: HashMap<u16, Vec<IpAddr>> = HashMap::default();
        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        for socketaddr in socketaddrs {
            addrs
                .entry(socketaddr.port())
                .and_modify(|a| {
                    if socketaddr.is_ipv6() {
                        has_ipv6 = true;
                    };
                    if socketaddr.is_ipv4() {
                        has_ipv4 = true;
                    };
                    a.push(socketaddr.ip())
                })
                .or_insert(vec![socketaddr.ip()]);
        }

        let ip_class = match (has_ipv4, has_ipv6) {
            (true, true) => IpClass::V4AndV6,
            (true, false) => IpClass::V4Only,
            (false, true) => IpClass::V6Only,
            // this case indicates no ip addresses were supplied, in which case, default to ipv4
            (false, false) => IpClass::V4Only,
        };
        let mut discoverer =
            Discoverer::new_interactive(N0_LOCAL_SWARM.to_string(), node_id.to_string())
                .with_callback(callback)
                .with_ip_class(ip_class);
        for addr in addrs {
            discoverer = discoverer.with_addrs(addr.0, addr.1);
        }
        discoverer.spawn(rt)
    }
}

impl From<&Peer> for DiscoveryItem {
    fn from(peer_info: &Peer) -> Self {
        let direct_addresses: BTreeSet<SocketAddr> = peer_info
            .addrs()
            .iter()
            .map(|(ip, port)| SocketAddr::new(*ip, *port))
            .collect();
        DiscoveryItem {
            provenance: PROVENANCE,
            last_updated: None,
            addr_info: AddrInfo {
                relay_url: None,
                direct_addresses,
            },
        }
    }
}

impl Discovery for LocalSwarmDiscovery {
    fn resolve(&self, _ep: Endpoint, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem>>> {
        let (send, recv) = flume::bounded(20);
        self.sender.send(Message::SendAddrs(node_id, send)).ok();
        Some(recv.into_stream().boxed())
    }

    fn publish(&self, info: &AddrInfo) {
        self.sender
            .send(Message::ChangeLocalAddrs(info.clone()))
            .ok();
    }
}

use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use derive_more::FromStr;
use futures_lite::{stream::Boxed as BoxStream, StreamExt};

use flume::Sender;
use iroh_base::key::PublicKey;
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::task::{JoinHandle, JoinSet};

use crate::{
    discovery::{Discovery, DiscoveryItem},
    AddrInfo, Endpoint, NodeId,
};

/// The n0 local node discovery name
// TODO(ramfox): bikeshed
const N0_MDNS_SWARM: &str = "iroh.local.node.discovery";

/// Provenance string
// TODO(ramfox): bikeshed
const PROVENANCE: &str = "local.node.discovery";

/// How long we will wait before we stop sending discovery items
const DISCOVERY_DURATION: Duration = Duration::from_secs(10);

/// Discovery using `swarm-discovery`, a variation on mdns
#[derive(Debug)]
pub struct LocalNodeDiscovery {
    handle: JoinHandle<()>,
    sender: Sender<Message>,
}

impl Drop for LocalNodeDiscovery {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Debug)]
enum Message {
    Discovery((String, Peer)),
    SendAddrs((NodeId, Sender<Result<DiscoveryItem>>)),
    ChangeLocalAddrs(AddrInfo),
    Timeout(NodeId),
}

impl LocalNodeDiscovery {
    /// Create a new LocalNodeDiscovery Service.
    ///
    /// This starts a `Discoverer` that broadcasts your addresses and receives addresses from other nodes in your local network.
    pub fn new(node_id: NodeId) -> Self {
        tracing::debug!("Creating new LocalNodeDiscovery service");
        let (send, recv) = flume::bounded(64);
        let task_sender = send.clone();
        let rt = tokio::runtime::Handle::current();
        let handle = tokio::spawn(async move {
            let mut guard = match LocalNodeDiscovery::spawn_discoverer(
                node_id,
                task_sender.clone(),
                BTreeSet::new(),
                &rt,
            ) {
                Ok(guard) => Some(guard),
                Err(e) => {
                    tracing::error!("LocalNodeDiscovery error creating discovery service: {e}");
                    return;
                }
            };
            let mut node_addrs: HashMap<PublicKey, Peer> = HashMap::default();
            let mut senders: HashMap<PublicKey, Sender<Result<DiscoveryItem>>> = HashMap::default();
            let mut timeouts = JoinSet::new();
            loop {
                tracing::trace!(?node_addrs, "LocalNodeDiscovery Service loop tick");
                let msg = match recv.recv_async().await {
                    Err(err) => {
                        tracing::error!("LocalNodeDiscovery service error: {err:?}");
                        tracing::error!("closing LocalNodeDiscovery");
                        timeouts.abort_all();
                        return;
                    }
                    Ok(msg) => msg,
                };
                match msg {
                    Message::Discovery((discovered_node_id, peer_info)) => {
                        tracing::trace!(
                            ?discovered_node_id,
                            ?peer_info,
                            "LocalNodeDiscovery Message::Discovery"
                        );
                        let discovered_node_id = match PublicKey::from_str(&discovered_node_id) {
                            Ok(node_id) => node_id,
                            Err(e) => {
                                tracing::warn!(
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
                            tracing::trace!(
                                ?discovered_node_id,
                                "removing node from LocalNodeDiscovery address book"
                            );
                            node_addrs.remove(&discovered_node_id);
                            continue;
                        }

                        if let Some(sender) = senders.get(&discovered_node_id) {
                            let item: DiscoveryItem = (&peer_info).into();
                            tracing::trace!(?item, "sending DiscoveryItem");
                            sender.send_async(Ok(item)).await.ok();
                        }
                        tracing::trace!(
                            ?discovered_node_id,
                            ?peer_info,
                            "adding node to LocalNodeDiscovery address book"
                        );
                        node_addrs.insert(discovered_node_id, peer_info);
                    }
                    Message::SendAddrs((node_id, sender)) => {
                        tracing::trace!(?node_id, "LocalNodeDiscovery Message::SendAddrs");
                        if let Some(peer_info) = node_addrs.get(&node_id) {
                            let item: DiscoveryItem = peer_info.into();
                            tracing::debug!(?item, "sending DiscoveryItem");
                            sender.send_async(Ok(item)).await.ok();
                        }
                        senders.insert(node_id, sender);
                        let timeout_sender = task_sender.clone();
                        timeouts.spawn(async move {
                            tokio::time::sleep(DISCOVERY_DURATION).await;
                            tracing::trace!(?node_id, "discovery timeout");
                            timeout_sender
                                .send_async(Message::Timeout(node_id))
                                .await
                                .ok();
                        });
                    }
                    Message::Timeout(node_id) => {
                        tracing::trace!(?node_id, "LocalNodeDiscovery Message::Timeout");
                        senders.remove(&node_id);
                    }
                    Message::ChangeLocalAddrs(addrs) => {
                        tracing::trace!(?addrs, "LocalNodeDiscovery Message::ChangeLocalAddrs");
                        let callback_send = task_sender.clone();
                        let g = guard.take();
                        drop(g);
                        guard = match LocalNodeDiscovery::spawn_discoverer(
                            node_id,
                            callback_send.clone(),
                            addrs.direct_addresses,
                            &rt,
                        ) {
                            Ok(guard) => Some(guard),
                            Err(e) => {
                                tracing::error!(
                                    "LocalNodeDiscovery error creating discovery service: {e}"
                                );
                                return;
                            }
                        };
                    }
                }
            }
        });
        Self {
            handle,
            sender: send.clone(),
        }
    }

    fn spawn_discoverer(
        node_id: PublicKey,
        sender: Sender<Message>,
        socketaddrs: BTreeSet<SocketAddr>,
        rt: &tokio::runtime::Handle,
    ) -> Result<DropGuard> {
        let callback = move |node_id: &str, peer: &Peer| {
            tracing::trace!(
                node_id,
                ?peer,
                "Received peer information from LocalNodeDiscovery"
            );
            sender
                .send(Message::Discovery((node_id.to_string(), peer.clone())))
                .ok();
        };

        let mut addrs: HashMap<u16, Vec<IpAddr>> = HashMap::default();
        let socketaddrs: BTreeSet<SocketAddr> = socketaddrs
            .into_iter()
            .filter(|socketaddr| socketaddr.is_ipv4())
            .collect();
        for socketaddr in socketaddrs {
            addrs
                .entry(socketaddr.port())
                .and_modify(|a| a.push(socketaddr.ip()))
                .or_insert(vec![socketaddr.ip()]);
        }

        let mut discoverer =
            Discoverer::new_interactive(N0_MDNS_SWARM.to_string(), node_id.to_string())
                .with_callback(callback)
                .with_ip_class(IpClass::V4Only);
        if !addrs.is_empty() {
            for addr in addrs {
                discoverer = discoverer.with_addrs(addr.0, addr.1);
            }
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

impl Discovery for LocalNodeDiscovery {
    fn resolve(&self, _ep: Endpoint, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem>>> {
        let (send, recv) = flume::bounded(20);
        self.sender.send(Message::SendAddrs((node_id, send))).ok();
        Some(recv.into_stream().boxed())
    }

    fn publish(&self, info: &AddrInfo) {
        self.sender
            .send(Message::ChangeLocalAddrs(info.clone()))
            .ok();
    }
}

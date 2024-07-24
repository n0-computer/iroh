//! A discovery service that uses an mdns-like service to discover local nodes.
//!
//! This allows you to use an mdns-like swarm discovery service to find address information about nodes that are on your local network, no relay or outside internet needed.
//! See the [`swarm-discovery`](https://crates.io/crates/swarm-discovery) crate for more details.

use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use derive_more::FromStr;
use futures_lite::{stream::Boxed as BoxStream, StreamExt};
use tracing::{debug, error, trace, warn};

use async_channel::Sender;
use iroh_base::key::PublicKey;
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::task::JoinSet;

use crate::{
    discovery::{Discovery, DiscoveryItem},
    util::AbortingJoinHandle,
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
    #[allow(dead_code)]
    handle: AbortingJoinHandle<()>,
    sender: Sender<Message>,
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
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    pub fn new(node_id: NodeId) -> Result<Self> {
        debug!("Creating new LocalSwarmDiscovery service");
        let (send, recv) = async_channel::bounded(64);
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
                let msg = match recv.recv().await {
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
                                sender.send(Ok(item)).await.ok();
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
                            sender.send(Ok(item)).await.ok();
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
                                .send(Message::Timeout(node_id, id))
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
            handle: handle.into(),
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
                .send_blocking(Message::Discovery(node_id.to_string(), peer.clone()))
                .ok();
        };
        let mut addrs: HashMap<u16, Vec<IpAddr>> = HashMap::default();
        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        for socketaddr in socketaddrs {
            if !has_ipv6 && socketaddr.is_ipv6() {
                has_ipv6 = true;
            };
            if !has_ipv4 && socketaddr.is_ipv4() {
                has_ipv4 = true;
            };
            addrs
                .entry(socketaddr.port())
                .and_modify(|a| a.push(socketaddr.ip()))
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
        let (send, recv) = async_channel::bounded(20);
        let discovery_sender = self.sender.clone();
        tokio::spawn(async move {
            discovery_sender
                .send(Message::SendAddrs(node_id, send))
                .await
                .ok();
        });
        Some(recv.boxed())
    }

    fn publish(&self, info: &AddrInfo) {
        let discovery_sender = self.sender.clone();
        let info = info.clone();
        tokio::spawn(async move {
            discovery_sender
                .send(Message::ChangeLocalAddrs(info))
                .await
                .ok();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testresult::TestResult;

    #[tokio::test]
    #[ignore = "flaky"]
    async fn test_local_swarm_discovery() -> TestResult {
        let (node_id_a, discovery_a) = make_discoverer()?;
        let (_, discovery_b) = make_discoverer()?;

        // make addr info for discoverer a
        let addr_info = AddrInfo {
            relay_url: None,
            direct_addresses: BTreeSet::from(["0.0.0.0:11111".parse()?]),
        };

        // pass in endpoint, this is never used
        let ep = crate::endpoint::Builder::default().bind(0).await?;
        // resolve twice to ensure we can create separate streams for the same node_id
        let mut s1 = discovery_b.resolve(ep.clone(), node_id_a).unwrap();
        let mut s2 = discovery_b.resolve(ep, node_id_a).unwrap();
        // publish discovery_a's address
        discovery_a.publish(&addr_info);
        let s1_res = tokio::time::timeout(Duration::from_secs(5), s1.next())
            .await?
            .unwrap()?;
        let s2_res = tokio::time::timeout(Duration::from_secs(5), s2.next())
            .await?
            .unwrap()?;
        assert_eq!(s1_res.addr_info, addr_info);
        assert_eq!(s2_res.addr_info, addr_info);
        Ok(())
    }

    fn make_discoverer() -> Result<(PublicKey, LocalSwarmDiscovery)> {
        let node_id = crate::key::SecretKey::generate().public();
        Ok((node_id, LocalSwarmDiscovery::new(node_id)?))
    }
}

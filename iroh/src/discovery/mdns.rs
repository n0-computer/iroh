//! A discovery service that uses an mdns-like service to discover local nodes.
//!
//! This allows you to use an mdns-like swarm discovery service to find address information about nodes that are on your local network, no relay or outside internet needed.
//! See the [`swarm-discovery`](https://crates.io/crates/swarm-discovery) crate for more details.
//!
//! When [`MdnsDiscovery`] is enabled, it's possible to get a list of the locally discovered nodes by filtering a list of `RemoteInfo`s.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use iroh::{
//!     SecretKey,
//!     discovery::mdns::{DiscoveryEvent, MdnsDiscovery},
//!     endpoint::{Endpoint, Source},
//! };
//! use n0_future::StreamExt;
//!
//! #[tokio::main]
//! async fn main() {
//!     let recent = Duration::from_secs(600); // 10 minutes in seconds
//!     let endpoint = Endpoint::builder().bind().await.unwrap();
//!
//!     // Register the discovery services with the endpoint
//!     let mdns = MdnsDiscovery::builder().build(endpoint.node_id()).unwrap();
//!     endpoint.discovery().add(mdns.clone());
//!
//!     // Subscribe to the discovery events
//!     let mut events = mdns.subscribe().await;
//!     while let Some(event) = events.next().await {
//!         match event {
//!             DiscoveryEvent::Discovered { node_info, .. } => {
//!                 println!("MDNS discovered: {:?}", node_info);
//!             }
//!             DiscoveryEvent::Expired { node_id } => {
//!                 println!("MDNS expired: {node_id}");
//!             }
//!         }
//!     }
//! }
//! ```
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use iroh_base::{NodeId, PublicKey};
use n0_future::{
    Stream,
    boxed::BoxStream,
    task::{self, AbortOnDropHandle, JoinSet},
    time::{self, Duration},
};
use n0_watcher::{Watchable, Watcher as _};
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{Instrument, debug, error, info_span, trace, warn};

use super::{DiscoveryContext, DiscoveryError, IntoDiscovery, IntoDiscoveryError};
use crate::discovery::{Discovery, DiscoveryItem, NodeData, NodeInfo};

/// The n0 local service name
const N0_SERVICE_NAME: &str = "irohv1";

/// Name of this discovery service.
///
/// Used as the `provenance` field in [`DiscoveryItem`]s.
///
/// Used in the [`crate::endpoint::Source::Discovery`] enum variant as the `name`.
pub const NAME: &str = "mdns";

/// The key of the attribute under which the `UserData` is stored in
/// the TXT record supported by swarm-discovery.
const USER_DATA_ATTRIBUTE: &str = "user-data";

/// How long we will wait before we stop sending discovery items
const DISCOVERY_DURATION: Duration = Duration::from_secs(10);

/// Discovery using `swarm-discovery`, a variation on mdns
#[derive(Debug, Clone)]
pub struct MdnsDiscovery {
    #[allow(dead_code)]
    handle: Arc<AbortOnDropHandle<()>>,
    sender: mpsc::Sender<Message>,
    advertise: bool,
    /// When `local_addrs` changes, we re-publish our info.
    local_addrs: Watchable<Option<NodeData>>,
}

#[derive(Debug)]
enum Message {
    Discovery(String, Peer),
    Resolve(NodeId, mpsc::Sender<Result<DiscoveryItem, DiscoveryError>>),
    Timeout(NodeId, usize),
    Subscribe(mpsc::Sender<DiscoveryEvent>),
}

/// Manages the list of subscribers that are subscribed to this discovery service.
#[derive(Debug)]
struct Subscribers(Vec<mpsc::Sender<DiscoveryEvent>>);

impl Subscribers {
    fn new() -> Self {
        Self(vec![])
    }

    /// Add the subscriber to the list of subscribers
    fn push(&mut self, subscriber: mpsc::Sender<DiscoveryEvent>) {
        self.0.push(subscriber);
    }

    /// Sends the `node_id` and `item` to each subscriber.
    ///
    /// Cleans up any subscribers that have been dropped.
    fn send(&mut self, item: DiscoveryEvent) {
        let mut clean_up = vec![];
        for (i, subscriber) in self.0.iter().enumerate() {
            // assume subscriber was dropped
            if let Err(err) = subscriber.try_send(item.clone()) {
                match err {
                    TrySendError::Full(_) => {
                        warn!(
                            ?item,
                            idx = i,
                            "local swarm discovery subscriber is blocked, dropping item"
                        )
                    }
                    TrySendError::Closed(_) => clean_up.push(i),
                }
            }
        }
        for i in clean_up.into_iter().rev() {
            self.0.swap_remove(i);
        }
    }
}

/// Builder for [`MdnsDiscovery`].
#[derive(Debug)]
pub struct MdnsDiscoveryBuilder {
    advertise: bool,
    service_name: String,
}

impl MdnsDiscoveryBuilder {
    /// Creates a new [`MdnsDiscoveryBuilder`] with default settings.
    fn new() -> Self {
        Self {
            advertise: true,
            service_name: N0_SERVICE_NAME.to_string(),
        }
    }

    /// Sets whether this node should advertise its presence.
    ///
    /// Default is true.
    pub fn advertise(mut self, advertise: bool) -> Self {
        self.advertise = advertise;
        self
    }

    /// Sets a custom service name.
    ///
    /// The default is `irohv1`, which will show up on a record in the
    /// following form, for example:
    /// `7rutqynuzu65fcdgoerbt4uoh3p62wuto2mp56x3uvhitqzssxga._irohv1._udp.local`
    ///
    /// Any custom service name will take the form, for example:
    /// `7rutqynuzu65fcdgoerbt4uoh3p62wuto2mp56x3uvhitqzssxga._{service_name}.upd.local`
    pub fn service_name(mut self, service_name: impl Into<String>) -> Self {
        self.service_name = service_name.into();
        self
    }

    /// Builds an [`MdnsDiscovery`] instance with the configured settings.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    pub fn build(self, node_id: NodeId) -> Result<MdnsDiscovery, IntoDiscoveryError> {
        MdnsDiscovery::new(node_id, self.advertise, self.service_name)
    }
}

impl Default for MdnsDiscoveryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoDiscovery for MdnsDiscoveryBuilder {
    fn into_discovery(
        self,
        context: &DiscoveryContext,
    ) -> Result<impl Discovery, IntoDiscoveryError> {
        self.build(context.node_id())
    }
}

/// An event emitted from the [`MdnsDiscovery`] service.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DiscoveryEvent {
    /// A peer was discovered or it's information was updated.
    Discovered {
        /// The node info for the node, as discovered.
        node_info: NodeInfo,
        /// Optional timestamp when this node address info was last updated.
        last_updated: Option<u64>,
    },
    /// A peer was expired due to being inactive, unreachable, or otherwise
    /// unavailable.
    Expired {
        /// The id of the node that expired.
        node_id: NodeId,
    },
}

impl MdnsDiscovery {
    /// Returns a [`MdnsDiscoveryBuilder`] that implements [`IntoDiscovery`].
    pub fn builder() -> MdnsDiscoveryBuilder {
        MdnsDiscoveryBuilder::default()
    }

    /// Create a new [`MdnsDiscovery`] Service.
    ///
    /// This starts a [`Discoverer`] that broadcasts your addresses (if advertise is set to true)
    /// and receives addresses from other nodes in your local network.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    fn new(
        node_id: NodeId,
        advertise: bool,
        service_name: String,
    ) -> Result<Self, IntoDiscoveryError> {
        debug!("Creating new MdnsDiscovery service");
        let (send, mut recv) = mpsc::channel(64);
        let task_sender = send.clone();
        let rt = tokio::runtime::Handle::current();
        let discovery = MdnsDiscovery::spawn_discoverer(
            node_id,
            advertise,
            task_sender.clone(),
            BTreeSet::new(),
            service_name,
            &rt,
        )?;

        let local_addrs: Watchable<Option<NodeData>> = Watchable::default();
        let mut addrs_change = local_addrs.watch();
        let discovery_fut = async move {
            let mut node_addrs: HashMap<PublicKey, Peer> = HashMap::default();
            let mut subscribers = Subscribers::new();
            let mut last_id = 0;
            let mut senders: HashMap<
                PublicKey,
                HashMap<usize, mpsc::Sender<Result<DiscoveryItem, DiscoveryError>>>,
            > = HashMap::default();
            let mut timeouts = JoinSet::new();
            loop {
                trace!(?node_addrs, "MdnsDiscovery Service loop tick");
                let msg = tokio::select! {
                    msg = recv.recv() => {
                        msg
                    }
                    Ok(Some(data)) = addrs_change.updated() => {
                        tracing::trace!(?data, "MdnsDiscovery address changed");
                        discovery.remove_all();
                        let addrs =
                            MdnsDiscovery::socketaddrs_to_addrs(data.direct_addresses());
                        for addr in addrs {
                            discovery.add(addr.0, addr.1)
                        }
                        if let Some(user_data) = data.user_data() {
                            if let Err(err) = discovery.set_txt_attribute(USER_DATA_ATTRIBUTE.to_string(), Some(user_data.to_string())) {
                                warn!("Failed to set the user-defined data in local swarm discovery: {err:?}");
                            }
                        }
                        continue;
                    }
                };
                let msg = match msg {
                    None => {
                        error!("MdnsDiscovery channel closed");
                        error!("closing MdnsDiscovery");
                        timeouts.abort_all();
                        discovery.remove_all();
                        return;
                    }
                    Some(msg) => msg,
                };
                match msg {
                    Message::Discovery(discovered_node_id, peer_info) => {
                        trace!(
                            ?discovered_node_id,
                            ?peer_info,
                            "MdnsDiscovery Message::Discovery"
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
                                "removing node from MdnsDiscovery address book"
                            );
                            node_addrs.remove(&discovered_node_id);
                            subscribers.send(DiscoveryEvent::Expired {
                                node_id: discovered_node_id,
                            });
                            continue;
                        }

                        let entry = node_addrs.entry(discovered_node_id);
                        if let std::collections::hash_map::Entry::Occupied(ref entry) = entry {
                            if entry.get() == &peer_info {
                                // this is a republish we already know about
                                continue;
                            }
                        }

                        debug!(
                            ?discovered_node_id,
                            ?peer_info,
                            "adding node to MdnsDiscovery address book"
                        );

                        let mut resolved = false;
                        let item = peer_to_discovery_item(&peer_info, &discovered_node_id);
                        if let Some(senders) = senders.get(&discovered_node_id) {
                            trace!(?item, senders = senders.len(), "sending DiscoveryItem");
                            resolved = true;
                            for sender in senders.values() {
                                sender.send(Ok(item.clone())).await.ok();
                            }
                        }
                        entry.or_insert(peer_info);

                        // only send nodes to the `subscriber` if they weren't explicitly resolved
                        // in other words, nodes sent to the `subscribers` should only be the ones that
                        // have been "passively" discovered
                        if !resolved {
                            subscribers.send(DiscoveryEvent::Discovered {
                                node_info: item.node_info,
                                last_updated: item.last_updated,
                            });
                        }
                    }
                    Message::Resolve(node_id, sender) => {
                        let id = last_id + 1;
                        last_id = id;
                        trace!(?node_id, "MdnsDiscovery Message::SendAddrs");
                        if let Some(peer_info) = node_addrs.get(&node_id) {
                            let item = peer_to_discovery_item(peer_info, &node_id);
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
                            time::sleep(DISCOVERY_DURATION).await;
                            trace!(?node_id, "discovery timeout");
                            timeout_sender
                                .send(Message::Timeout(node_id, id))
                                .await
                                .ok();
                        });
                    }
                    Message::Timeout(node_id, id) => {
                        trace!(?node_id, "MdnsDiscovery Message::Timeout");
                        if let Some(senders_for_node_id) = senders.get_mut(&node_id) {
                            senders_for_node_id.remove(&id);
                            if senders_for_node_id.is_empty() {
                                senders.remove(&node_id);
                            }
                        }
                    }
                    Message::Subscribe(subscriber) => {
                        trace!("MdnsDiscovery Message::Subscribe");
                        subscribers.push(subscriber);
                    }
                }
            }
        };
        let handle = task::spawn(discovery_fut.instrument(info_span!("swarm-discovery.actor")));
        Ok(Self {
            handle: Arc::new(AbortOnDropHandle::new(handle)),
            sender: send,
            advertise,
            local_addrs,
        })
    }

    /// Subscribe to discovered nodes
    pub async fn subscribe(&self) -> impl Stream<Item = DiscoveryEvent> + Unpin + use<> {
        let (sender, recv) = mpsc::channel(20);
        let discovery_sender = self.sender.clone();
        discovery_sender.send(Message::Subscribe(sender)).await.ok();
        tokio_stream::wrappers::ReceiverStream::new(recv)
    }

    fn spawn_discoverer(
        node_id: PublicKey,
        advertise: bool,
        sender: mpsc::Sender<Message>,
        socketaddrs: BTreeSet<SocketAddr>,
        service_name: String,
        rt: &tokio::runtime::Handle,
    ) -> Result<DropGuard, IntoDiscoveryError> {
        let spawn_rt = rt.clone();
        let callback = move |node_id: &str, peer: &Peer| {
            trace!(
                node_id,
                ?peer,
                "Received peer information from MdnsDiscovery"
            );

            let sender = sender.clone();
            let node_id = node_id.to_string();
            let peer = peer.clone();
            spawn_rt.spawn(async move {
                sender.send(Message::Discovery(node_id, peer)).await.ok();
            });
        };
        let node_id_str = data_encoding::BASE32_NOPAD
            .encode(node_id.as_bytes())
            .to_ascii_lowercase();
        let mut discoverer = Discoverer::new_interactive(service_name, node_id_str)
            .with_callback(callback)
            .with_ip_class(IpClass::Auto);
        if advertise {
            let addrs = MdnsDiscovery::socketaddrs_to_addrs(&socketaddrs);
            for addr in addrs {
                discoverer = discoverer.with_addrs(addr.0, addr.1);
            }
        }
        discoverer
            .spawn(rt)
            .map_err(|e| IntoDiscoveryError::from_err("mdns", e))
    }

    fn socketaddrs_to_addrs(socketaddrs: &BTreeSet<SocketAddr>) -> HashMap<u16, Vec<IpAddr>> {
        let mut addrs: HashMap<u16, Vec<IpAddr>> = HashMap::default();
        for socketaddr in socketaddrs {
            addrs
                .entry(socketaddr.port())
                .and_modify(|a| a.push(socketaddr.ip()))
                .or_insert(vec![socketaddr.ip()]);
        }
        addrs
    }
}

fn peer_to_discovery_item(peer: &Peer, node_id: &NodeId) -> DiscoveryItem {
    let direct_addresses: BTreeSet<SocketAddr> = peer
        .addrs()
        .iter()
        .map(|(ip, port)| SocketAddr::new(*ip, *port))
        .collect();
    // Get the user-defined data from the resolved peer info. We expect an attribute with a value
    // that parses as `UserData`. Otherwise, omit.
    let user_data = if let Some(Some(user_data)) = peer.txt_attribute(USER_DATA_ATTRIBUTE) {
        match user_data.parse() {
            Err(err) => {
                debug!("failed to parse user data from TXT attribute: {err}");
                None
            }
            Ok(data) => Some(data),
        }
    } else {
        None
    };
    let node_info = NodeInfo::new(*node_id)
        .with_direct_addresses(direct_addresses)
        .with_user_data(user_data);
    DiscoveryItem::new(node_info, NAME, None)
}

impl Discovery for MdnsDiscovery {
    fn resolve(&self, node_id: NodeId) -> Option<BoxStream<Result<DiscoveryItem, DiscoveryError>>> {
        use futures_util::FutureExt;

        let (send, recv) = mpsc::channel(20);
        let discovery_sender = self.sender.clone();
        let stream = async move {
            discovery_sender
                .send(Message::Resolve(node_id, send))
                .await
                .ok();
            tokio_stream::wrappers::ReceiverStream::new(recv)
        };
        Some(Box::pin(stream.flatten_stream()))
    }

    fn publish(&self, data: &NodeData) {
        if self.advertise {
            self.local_addrs.set(Some(data.clone())).ok();
        }
    }
}

#[cfg(test)]
mod tests {

    /// This module's name signals nextest to run test in a single thread (no other concurrent
    /// tests)
    mod run_in_isolation {
        use iroh_base::SecretKey;
        use n0_future::StreamExt;
        use n0_snafu::{Error, Result, ResultExt};
        use snafu::whatever;
        use tracing_test::traced_test;

        use super::super::*;
        use crate::discovery::UserData;

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_resolve() -> Result {
            // Create discoverer A with advertise=false (only listens)
            let (_, discovery_a) = make_discoverer(false)?;
            // Create discoverer B with advertise=true (will broadcast)
            let (node_id_b, discovery_b) = make_discoverer(true)?;

            // make addr info for discoverer b
            let user_data: UserData = "foobar".parse()?;
            let node_data = NodeData::new(None, BTreeSet::from(["0.0.0.0:11111".parse().unwrap()]))
                .with_user_data(Some(user_data.clone()));

            // resolve twice to ensure we can create separate streams for the same node_id
            let mut s1 = discovery_a.subscribe().await.filter(|event| match event {
                DiscoveryEvent::Discovered { node_info, .. } => node_info.node_id == node_id_b,
                _ => false,
            });
            let mut s2 = discovery_a.subscribe().await.filter(|event| match event {
                DiscoveryEvent::Discovered { node_info, .. } => node_info.node_id == node_id_b,
                _ => false,
            });

            tracing::debug!(?node_id_b, "Discovering node id b");
            // publish discovery_b's address
            discovery_b.publish(&node_data);
            let DiscoveryEvent::Discovered {
                node_info: s1_node_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s1.next())
                .await
                .context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            let DiscoveryEvent::Discovered {
                node_info: s2_node_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s2.next())
                .await
                .context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            assert_eq!(s1_node_info.data, node_data);
            assert_eq!(s2_node_info.data, node_data);

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_expire() -> Result {
            let (_, discovery_a) = make_discoverer(false)?;
            let (node_id_b, discovery_b) = make_discoverer(true)?;

            // publish discovery_b's address
            let node_data = NodeData::new(None, BTreeSet::from(["0.0.0.0:11111".parse().unwrap()]))
                .with_user_data(Some("".parse()?));
            discovery_b.publish(&node_data);

            let mut s1 = discovery_a.subscribe().await;
            tracing::debug!(?node_id_b, "Discovering node id b");

            // Wait for the specific node to be discovered
            loop {
                let event = tokio::time::timeout(Duration::from_secs(5), s1.next())
                    .await
                    .context("timeout")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Discovered { node_info, .. }
                        if node_info.node_id == node_id_b =>
                    {
                        break;
                    }
                    _ => continue, // Ignore other discovery events
                }
            }

            // Shutdown node B
            drop(discovery_b);
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Wait for the expiration event for the specific node
            loop {
                let event = tokio::time::timeout(Duration::from_secs(10), s1.next())
                    .await
                    .context("timeout waiting for expiration event")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Expired {
                        node_id: expired_node_id,
                    } if expired_node_id == node_id_b => {
                        break;
                    }
                    _ => continue, // Ignore other events
                }
            }

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_subscribe() -> Result {
            let num_nodes = 5;
            let mut node_ids = BTreeSet::new();
            let mut discoverers = vec![];

            let (_, discovery) = make_discoverer(false)?;
            let node_data = NodeData::new(None, BTreeSet::from(["0.0.0.0:11111".parse().unwrap()]));

            for i in 0..num_nodes {
                let (node_id, discovery) = make_discoverer(true)?;
                let user_data: UserData = format!("node{i}").parse()?;
                let node_data = node_data.clone().with_user_data(Some(user_data.clone()));
                node_ids.insert((node_id, Some(user_data)));
                discovery.publish(&node_data);
                discoverers.push(discovery);
            }

            let mut events = discovery.subscribe().await;

            let test = async move {
                let mut got_ids = BTreeSet::new();
                while got_ids.len() != num_nodes {
                    if let Some(DiscoveryEvent::Discovered { node_info, .. }) = events.next().await
                    {
                        let data = node_info.data.user_data().cloned();
                        if node_ids.contains(&(node_info.node_id, data.clone())) {
                            got_ids.insert((node_info.node_id, data));
                        }
                    } else {
                        whatever!(
                            "no more events, only got {} ids, expected {num_nodes}\n",
                            got_ids.len()
                        );
                    }
                }
                assert_eq!(got_ids, node_ids);
                Ok::<_, Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), test)
                .await
                .context("timeout")?
        }

        #[tokio::test]
        #[traced_test]
        async fn non_advertising_node_not_discovered() -> Result {
            let (_, discovery_a) = make_discoverer(false)?;
            let (node_id_b, discovery_b) = make_discoverer(false)?;

            let (node_id_c, discovery_c) = make_discoverer(true)?;
            let node_data_c =
                NodeData::new(None, BTreeSet::from(["0.0.0.0:22222".parse().unwrap()]));
            discovery_c.publish(&node_data_c);

            let node_data_b =
                NodeData::new(None, BTreeSet::from(["0.0.0.0:11111".parse().unwrap()]));
            discovery_b.publish(&node_data_b);

            let mut stream_c = discovery_a.resolve(node_id_c).unwrap();
            let result_c = tokio::time::timeout(Duration::from_secs(2), stream_c.next()).await;
            assert!(result_c.is_ok(), "Advertising node should be discoverable");

            let mut stream_b = discovery_a.resolve(node_id_b).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Expected timeout since node b isn't advertising"
            );

            Ok(())
        }

        fn make_discoverer(advertise: bool) -> Result<(PublicKey, MdnsDiscovery)> {
            let node_id = SecretKey::generate(rand::thread_rng()).public();
            Ok((
                node_id,
                MdnsDiscovery::builder()
                    .advertise(advertise)
                    .build(node_id)?,
            ))
        }

        #[tokio::test]
        #[traced_test]
        async fn test_service_names() -> Result {
            // Create a discovery service using the default
            // service name
            let id_a = SecretKey::generate(rand::rng()).public();
            let discovery_a = MdnsDiscovery::builder().build(id_a)?;

            // Create a discovery service using a custom
            // service name
            let id_b = SecretKey::generate(rand::rng()).public();
            let discovery_b = MdnsDiscovery::builder()
                .service_name("different.name")
                .build(id_b)?;

            // Create a discovery service using the same
            // custom service name
            let id_c = SecretKey::generate(rand::rng()).public();
            let discovery_c = MdnsDiscovery::builder()
                .service_name("different.name")
                .build(id_c)?;

            let node_data_a =
                NodeData::new(None, BTreeSet::from(["0.0.0.0:11111".parse().unwrap()]));
            discovery_a.publish(&node_data_a);

            let node_data_b =
                NodeData::new(None, BTreeSet::from(["0.0.0.0:22222".parse().unwrap()]));
            discovery_b.publish(&node_data_b);

            let node_data_c =
                NodeData::new(None, BTreeSet::from(["0.0.0.0:33333".parse().unwrap()]));
            discovery_c.publish(&node_data_c);

            let mut stream_a = discovery_a.resolve(id_b).unwrap();
            let result_a = tokio::time::timeout(Duration::from_secs(2), stream_a.next()).await;
            assert!(
                result_a.is_err(),
                "Node on a different service should NOT be discoverable"
            );

            let mut stream_b = discovery_b.resolve(id_c).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_ok(),
                "Node on the same service should be discoverable"
            );

            let mut stream_b = discovery_b.resolve(id_a).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Node on a different service should NOT be discoverable"
            );

            Ok(())
        }
    }
}

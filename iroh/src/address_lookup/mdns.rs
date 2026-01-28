//! An address lookup service that uses an mdns-like service to discover and lookup the addresses of local endpoints.
//!
//! This allows you to use an mdns-like swarm discovery service to find address information about endpoints that are on your local network, no relay or outside internet needed.
//! See the [`swarm-discovery`](https://crates.io/crates/swarm-discovery) crate for more details.
//!
//! When [`MdnsAddressLookup`] is enabled, it's possible to get a list of the locally discovered endpoints by filtering a list of `RemoteInfo`s.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use iroh::{
//!     RelayMode, SecretKey,
//!     address_lookup::{DiscoveryEvent, MdnsAddressLookup},
//!     endpoint::{Endpoint, Source},
//! };
//! use n0_future::StreamExt;
//!
//! #[tokio::main]
//! async fn main() {
//!     let recent = Duration::from_secs(600); // 10 minutes in seconds
//!     let endpoint = Endpoint::empty_builder(RelayMode::Disabled)
//!         .bind()
//!         .await
//!         .unwrap();
//!
//!     // Register the Address Lookupwith the endpoint
//!     let mdns = MdnsAddressLookup::builder().build(endpoint.id()).unwrap();
//!     endpoint.address_lookup().add(mdns.clone());
//!
//!     // Subscribe to the mdns discovery events
//!     let mut events = mdns.subscribe().await;
//!     while let Some(event) = events.next().await {
//!         match event {
//!             DiscoveryEvent::Discovered { endpoint_info, .. } => {
//!                 println!("MDNS discovered: {:?}", endpoint_info);
//!             }
//!             DiscoveryEvent::Expired { endpoint_id } => {
//!                 println!("MDNS expired: {endpoint_id}");
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

use iroh_base::{EndpointId, PublicKey};
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

use super::IntoAddressLookup;
use crate::{
    Endpoint,
    address_lookup::{
        AddressLookup, EndpointData, EndpointInfo, Error as AddressLookupError,
        IntoAddressLookupError, Item as AddressLookupItem,
    },
};

/// The n0 local service name
const N0_SERVICE_NAME: &str = "irohv1";

/// Name of this address lookup service.
///
/// Used as the `provenance` field in [`AddressLookupItem`]s.
///
/// Used in the [`crate::endpoint::Source::AddressLookup`] enum variant as the `name`.
pub const NAME: &str = "mdns";

/// The key of the attribute under which the `UserData` is stored in
/// the TXT record supported by swarm-discovery.
const USER_DATA_ATTRIBUTE: &str = "user-data";

/// How long we will wait before we stop attempting to resolve an endpoint ID to an address
const LOOKUP_DURATION: Duration = Duration::from_secs(10);

/// Address Lookup using `swarm-discovery`, a variation on mdns
#[derive(Debug, Clone)]
pub struct MdnsAddressLookup {
    #[allow(dead_code)]
    handle: Arc<AbortOnDropHandle<()>>,
    sender: mpsc::Sender<Message>,
    advertise: bool,
    /// When `local_addrs` changes, we re-publish our info.
    local_addrs: Watchable<Option<EndpointData>>,
}

#[derive(Debug)]
enum Message {
    Discovered(String, Peer),
    Resolve(
        EndpointId,
        mpsc::Sender<Result<AddressLookupItem, AddressLookupError>>,
    ),
    Timeout(EndpointId, usize),
    Subscribe(mpsc::Sender<DiscoveryEvent>),
}

/// Manages the list of subscribers that are subscribed to this Address Lookup.
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

    /// Sends the `endpoint_id` and `item` to each subscriber.
    ///
    /// Cleans up any subscribers that have been dropped.
    fn send(&mut self, item: DiscoveryEvent) {
        let mut clean_up = vec![];
        for (i, subscriber) in self.0.iter().enumerate() {
            // assume subscriber was dropped
            if let Err(err) = subscriber.try_send(item.clone()) {
                match err {
                    TrySendError::Full(_) => {
                        warn!(?item, idx = i, "mdns subscriber is blocked, dropping item")
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

/// Builder for [`MdnsAddressLookup`].
#[derive(Debug)]
pub struct MdnsAddressLookupBuilder {
    advertise: bool,
    service_name: String,
}

impl MdnsAddressLookupBuilder {
    /// Creates a new [`MdnsAddressLookupBuilder`] with default settings.
    fn new() -> Self {
        Self {
            advertise: true,
            service_name: N0_SERVICE_NAME.to_string(),
        }
    }

    /// Sets whether this endpoint should advertise its presence.
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

    /// Builds an [`MdnsAddressLookup`] instance with the configured settings.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    pub fn build(
        self,
        endpoint_id: EndpointId,
    ) -> Result<MdnsAddressLookup, IntoAddressLookupError> {
        MdnsAddressLookup::new(endpoint_id, self.advertise, self.service_name)
    }
}

impl Default for MdnsAddressLookupBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoAddressLookup for MdnsAddressLookupBuilder {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, IntoAddressLookupError> {
        self.build(endpoint.id())
    }
}

/// An event emitted from the [`MdnsAddressLookup`] service.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DiscoveryEvent {
    /// A peer was discovered or it's information was updated.
    Discovered {
        /// The endpoint info for the endpoint, as discovered.
        endpoint_info: EndpointInfo,
        /// Optional timestamp when this endpoint address info was last updated.
        last_updated: Option<u64>,
    },
    /// A peer was expired due to being inactive, unreachable, or otherwise
    /// unavailable.
    Expired {
        /// The id of the endpoint that expired.
        endpoint_id: EndpointId,
    },
}

impl MdnsAddressLookup {
    /// Returns a [`MdnsAddressLookupBuilder`] that implements [`Into`].
    pub fn builder() -> MdnsAddressLookupBuilder {
        MdnsAddressLookupBuilder::default()
    }

    /// Create a new [`MdnsAddressLookup`] Service.
    ///
    /// This starts a [`Discoverer`] that broadcasts your addresses (if advertise is set to true)
    /// and receives addresses from other endpoints in your local network.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    fn new(
        endpoint_id: EndpointId,
        advertise: bool,
        service_name: String,
    ) -> Result<Self, IntoAddressLookupError> {
        debug!("Creating new Mdns service");
        let (send, mut recv) = mpsc::channel(64);
        let task_sender = send.clone();
        let rt = tokio::runtime::Handle::current();
        let address_lookup = MdnsAddressLookup::spawn_discoverer(
            endpoint_id,
            advertise,
            task_sender.clone(),
            BTreeSet::new(),
            service_name,
            &rt,
        )?;

        let local_addrs: Watchable<Option<EndpointData>> = Watchable::default();
        let mut addrs_change = local_addrs.watch();
        let address_lookup_fut = async move {
            let mut endpoint_addrs: HashMap<PublicKey, Peer> = HashMap::default();
            let mut subscribers = Subscribers::new();
            let mut last_id = 0;
            let mut senders: HashMap<
                PublicKey,
                HashMap<usize, mpsc::Sender<Result<AddressLookupItem, AddressLookupError>>>,
            > = HashMap::default();
            let mut timeouts = JoinSet::new();
            loop {
                trace!(?endpoint_addrs, "Mdns Service loop tick");
                let msg = tokio::select! {
                    msg = recv.recv() => {
                        msg
                    }
                    Ok(Some(data)) = addrs_change.updated() => {
                        tracing::trace!(?data, "Mdns address changed");
                        address_lookup.remove_all();
                        let addrs =
                            MdnsAddressLookup::socketaddrs_to_addrs(data.ip_addrs());
                        for addr in addrs {
                            address_lookup.add(addr.0, addr.1)
                        }
                        if let Some(user_data) = data.user_data()
                            && let Err(err) = address_lookup.set_txt_attribute(USER_DATA_ATTRIBUTE.to_string(), Some(user_data.to_string())) {
                                warn!("Failed to set the user-defined data in mdns: {err:?}");
                            }
                        continue;
                    }
                };
                let msg = match msg {
                    None => {
                        error!("Mdns channel closed");
                        error!("closing Mdns");
                        timeouts.abort_all();
                        address_lookup.remove_all();
                        return;
                    }
                    Some(msg) => msg,
                };
                match msg {
                    Message::Discovered(discovered_endpoint_id, peer_info) => {
                        trace!(
                            ?discovered_endpoint_id,
                            ?peer_info,
                            "Mdns Message::Discovered"
                        );
                        let discovered_endpoint_id =
                            match PublicKey::from_str(&discovered_endpoint_id) {
                                Ok(endpoint_id) => endpoint_id,
                                Err(e) => {
                                    warn!(
                                        discovered_endpoint_id,
                                        "couldn't parse endpoint_id from mdns Address Lookup: {e:?}"
                                    );
                                    continue;
                                }
                            };

                        if discovered_endpoint_id == endpoint_id {
                            continue;
                        }

                        if peer_info.is_expiry() {
                            trace!(
                                ?discovered_endpoint_id,
                                "removing endpoint from Mdns address book"
                            );
                            endpoint_addrs.remove(&discovered_endpoint_id);
                            subscribers.send(DiscoveryEvent::Expired {
                                endpoint_id: discovered_endpoint_id,
                            });
                            continue;
                        }

                        let entry = endpoint_addrs.entry(discovered_endpoint_id);
                        if let std::collections::hash_map::Entry::Occupied(ref entry) = entry
                            && entry.get() == &peer_info
                        {
                            // this is a republish we already know about
                            continue;
                        }

                        debug!(
                            ?discovered_endpoint_id,
                            ?peer_info,
                            "adding endpoint to Mdns address book"
                        );

                        let mut resolved = false;
                        let item = peer_to_discovery_item(&peer_info, &discovered_endpoint_id);
                        if let Some(senders) = senders.get(&discovered_endpoint_id) {
                            trace!(?item, senders = senders.len(), "sending AddressLookupItem");
                            resolved = true;
                            for sender in senders.values() {
                                sender.send(Ok(item.clone())).await.ok();
                            }
                        }
                        entry.or_insert(peer_info);

                        // only send endpoints to the `subscriber` if they weren't explicitly resolved
                        // in other words, endpoints sent to the `subscribers` should only be the ones that
                        // have been "passively" discovered
                        if !resolved {
                            subscribers.send(DiscoveryEvent::Discovered {
                                endpoint_info: item.endpoint_info,
                                last_updated: item.last_updated,
                            });
                        }
                    }
                    Message::Resolve(endpoint_id, sender) => {
                        let id = last_id + 1;
                        last_id = id;
                        trace!(?endpoint_id, "Mdns Message::SendAddrs");
                        if let Some(peer_info) = endpoint_addrs.get(&endpoint_id) {
                            let item = peer_to_discovery_item(peer_info, &endpoint_id);
                            debug!(?item, "sending AddressLookupItem");
                            sender.send(Ok(item)).await.ok();
                        }
                        if let Some(senders_for_endpoint_id) = senders.get_mut(&endpoint_id) {
                            senders_for_endpoint_id.insert(id, sender);
                        } else {
                            let mut senders_for_endpoint_id = HashMap::new();
                            senders_for_endpoint_id.insert(id, sender);
                            senders.insert(endpoint_id, senders_for_endpoint_id);
                        }
                        let timeout_sender = task_sender.clone();
                        timeouts.spawn(async move {
                            time::sleep(LOOKUP_DURATION).await;
                            trace!(?endpoint_id, "resolution timeout");
                            timeout_sender
                                .send(Message::Timeout(endpoint_id, id))
                                .await
                                .ok();
                        });
                    }
                    Message::Timeout(endpoint_id, id) => {
                        trace!(?endpoint_id, "Mdns Message::Timeout");
                        if let Some(senders_for_endpoint_id) = senders.get_mut(&endpoint_id) {
                            senders_for_endpoint_id.remove(&id);
                            if senders_for_endpoint_id.is_empty() {
                                senders.remove(&endpoint_id);
                            }
                        }
                    }
                    Message::Subscribe(subscriber) => {
                        trace!("Mdns Message::Subscribe");
                        subscribers.push(subscriber);
                    }
                }
            }
        };
        let handle =
            task::spawn(address_lookup_fut.instrument(info_span!("swarm-discovery.actor")));
        Ok(Self {
            handle: Arc::new(AbortOnDropHandle::new(handle)),
            sender: send,
            advertise,
            local_addrs,
        })
    }

    /// Subscribe to discovered endpoints
    pub async fn subscribe(&self) -> impl Stream<Item = DiscoveryEvent> + Unpin + use<> {
        let (sender, recv) = mpsc::channel(20);
        let address_lookup_sender = self.sender.clone();
        address_lookup_sender
            .send(Message::Subscribe(sender))
            .await
            .ok();
        tokio_stream::wrappers::ReceiverStream::new(recv)
    }

    fn spawn_discoverer(
        endpoint_id: PublicKey,
        advertise: bool,
        sender: mpsc::Sender<Message>,
        socketaddrs: BTreeSet<SocketAddr>,
        service_name: String,
        rt: &tokio::runtime::Handle,
    ) -> Result<DropGuard, IntoAddressLookupError> {
        let spawn_rt = rt.clone();
        let callback = move |endpoint_id: &str, peer: &Peer| {
            trace!(endpoint_id, ?peer, "Received peer information from Mdns");

            let sender = sender.clone();
            let endpoint_id = endpoint_id.to_string();
            let peer = peer.clone();
            spawn_rt.spawn(async move {
                sender
                    .send(Message::Discovered(endpoint_id, peer))
                    .await
                    .ok();
            });
        };
        let endpoint_id_str = data_encoding::BASE32_NOPAD
            .encode(endpoint_id.as_bytes())
            .to_ascii_lowercase();
        let mut discoverer = Discoverer::new_interactive(service_name, endpoint_id_str)
            .with_callback(callback)
            .with_ip_class(IpClass::Auto);
        if advertise {
            let addrs = MdnsAddressLookup::socketaddrs_to_addrs(socketaddrs.iter());
            for addr in addrs {
                discoverer = discoverer.with_addrs(addr.0, addr.1);
            }
        }
        discoverer
            .spawn(rt)
            .map_err(|e| IntoAddressLookupError::from_err("mdns", e))
    }

    fn socketaddrs_to_addrs<'a>(
        socketaddrs: impl Iterator<Item = &'a SocketAddr>,
    ) -> HashMap<u16, Vec<IpAddr>> {
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

fn peer_to_discovery_item(peer: &Peer, endpoint_id: &EndpointId) -> AddressLookupItem {
    let ip_addrs: BTreeSet<SocketAddr> = peer
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
    let endpoint_info = EndpointInfo::new(*endpoint_id)
        .with_ip_addrs(ip_addrs)
        .with_user_data(user_data);
    AddressLookupItem::new(endpoint_info, NAME, None)
}

impl AddressLookup for MdnsAddressLookup {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        use futures_util::FutureExt;

        let (send, recv) = mpsc::channel(20);
        let address_lookup_sender = self.sender.clone();
        let stream = async move {
            address_lookup_sender
                .send(Message::Resolve(endpoint_id, send))
                .await
                .ok();
            tokio_stream::wrappers::ReceiverStream::new(recv)
        };
        Some(Box::pin(stream.flatten_stream()))
    }

    fn publish(&self, data: &EndpointData) {
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
        use iroh_base::{SecretKey, TransportAddr};
        use n0_error::{AnyError as Error, Result, StdResultExt, bail_any};
        use n0_future::StreamExt;
        use n0_tracing_test::traced_test;
        use rand::{CryptoRng, SeedableRng};

        use super::super::*;
        use crate::address_lookup::UserData;

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_resolve() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create Address LookupA with advertise=false (only listens)
            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            // Create Address LookupB with advertise=true (will broadcast)
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, true)?;

            // make addr info for discoverer b
            let user_data: UserData = "foobar".parse()?;
            let endpoint_data =
                EndpointData::new([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())])
                    .with_user_data(Some(user_data.clone()));

            // resolve twice to ensure we can create separate streams for the same endpoint_id
            let mut s1 = address_lookup_a
                .subscribe()
                .await
                .filter(|event| match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        endpoint_info.endpoint_id == endpoint_id_b
                    }
                    _ => false,
                });
            let mut s2 = address_lookup_a
                .subscribe()
                .await
                .filter(|event| match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        endpoint_info.endpoint_id == endpoint_id_b
                    }
                    _ => false,
                });

            tracing::debug!(?endpoint_id_b, "Discovering endpoint id b");
            // publish address_lookup_b's address
            address_lookup_b.publish(&endpoint_data);
            let DiscoveryEvent::Discovered {
                endpoint_info: s1_endpoint_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s1.next())
                .await
                .std_context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            let DiscoveryEvent::Discovered {
                endpoint_info: s2_endpoint_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s2.next())
                .await
                .std_context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            assert_eq!(s1_endpoint_info.data, endpoint_data);
            assert_eq!(s2_endpoint_info.data, endpoint_data);

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_expire() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, true)?;

            // publish address_lookup_b's address
            let endpoint_data =
                EndpointData::new([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())])
                    .with_user_data(Some("".parse()?));
            address_lookup_b.publish(&endpoint_data);

            let mut s1 = address_lookup_a.subscribe().await;
            tracing::debug!(?endpoint_id_b, "Discovering endpoint id b");

            // Wait for the specific endpoint to be discovered
            loop {
                let event = tokio::time::timeout(Duration::from_secs(5), s1.next())
                    .await
                    .std_context("timeout")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. }
                        if endpoint_info.endpoint_id == endpoint_id_b =>
                    {
                        break;
                    }
                    _ => continue, // Ignore other discovery events
                }
            }

            // Shutdown endpoint B
            drop(address_lookup_b);
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Wait for the expiration event for the specific endpoint
            loop {
                let event = tokio::time::timeout(Duration::from_secs(10), s1.next())
                    .await
                    .std_context("timeout waiting for expiration event")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Expired {
                        endpoint_id: expired_endpoint_id,
                    } if expired_endpoint_id == endpoint_id_b => {
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
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            let num_endpoints = 5;
            let mut endpoint_ids = BTreeSet::new();
            let mut address_lookup_list = vec![];

            let (_, address_lookup) = make_address_lookup(&mut rng, false)?;
            let endpoint_data =
                EndpointData::new([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);

            for i in 0..num_endpoints {
                let (endpoint_id, address_lookup) = make_address_lookup(&mut rng, true)?;
                let user_data: UserData = format!("endpoint{i}").parse()?;
                let endpoint_data = endpoint_data
                    .clone()
                    .with_user_data(Some(user_data.clone()));
                endpoint_ids.insert((endpoint_id, Some(user_data)));
                address_lookup.publish(&endpoint_data);
                address_lookup_list.push(address_lookup);
            }

            let mut events = address_lookup.subscribe().await;

            let test = async move {
                let mut got_ids = BTreeSet::new();
                while got_ids.len() != num_endpoints {
                    if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) =
                        events.next().await
                    {
                        let data = endpoint_info.data.user_data().cloned();
                        if endpoint_ids.contains(&(endpoint_info.endpoint_id, data.clone())) {
                            got_ids.insert((endpoint_info.endpoint_id, data));
                        }
                    } else {
                        bail_any!(
                            "no more events, only got {} ids, expected {num_endpoints}\n",
                            got_ids.len()
                        );
                    }
                }
                assert_eq!(got_ids, endpoint_ids);
                Ok::<_, Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), test)
                .await
                .std_context("timeout")?
        }

        #[tokio::test]
        #[traced_test]
        async fn non_advertising_endpoint_not_discovered() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, false)?;

            let (endpoint_id_c, address_lookup_c) = make_address_lookup(&mut rng, true)?;
            let endpoint_data_c =
                EndpointData::new([TransportAddr::Ip("0.0.0.0:22222".parse().unwrap())]);
            address_lookup_c.publish(&endpoint_data_c);

            let endpoint_data_b =
                EndpointData::new([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);
            address_lookup_b.publish(&endpoint_data_b);

            let mut stream_c = address_lookup_a.resolve(endpoint_id_c).unwrap();
            let result_c = tokio::time::timeout(Duration::from_secs(2), stream_c.next()).await;
            assert!(
                result_c.is_ok(),
                "Advertising endpoint should be discoverable"
            );

            let mut stream_b = address_lookup_a.resolve(endpoint_id_b).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Expected timeout since endpoint b isn't advertising"
            );

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn test_service_names() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create an Address Lookupusing the default
            // service name
            let id_a = SecretKey::generate(&mut rng).public();
            let address_lookup_a = MdnsAddressLookup::builder().build(id_a)?;

            // Create a Address Lookupusing a custom
            // service name
            let id_b = SecretKey::generate(&mut rng).public();
            let address_lookup_b = MdnsAddressLookup::builder()
                .service_name("different.name")
                .build(id_b)?;

            // Create an Address Lookupusing the same
            // custom service name
            let id_c = SecretKey::generate(&mut rng).public();
            let address_lookup_c = MdnsAddressLookup::builder()
                .service_name("different.name")
                .build(id_c)?;

            let endpoint_data_a =
                EndpointData::new([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);
            address_lookup_a.publish(&endpoint_data_a);

            let endpoint_data_b =
                EndpointData::new([TransportAddr::Ip("0.0.0.0:22222".parse().unwrap())]);
            address_lookup_b.publish(&endpoint_data_b);

            let endpoint_data_c =
                EndpointData::new([TransportAddr::Ip("0.0.0.0:33333".parse().unwrap())]);
            address_lookup_c.publish(&endpoint_data_c);

            let mut stream_a = address_lookup_a.resolve(id_b).unwrap();
            let result_a = tokio::time::timeout(Duration::from_secs(2), stream_a.next()).await;
            assert!(
                result_a.is_err(),
                "Endpoint on a different service should NOT be discoverable"
            );

            let mut stream_b = address_lookup_b.resolve(id_c).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_ok(),
                "Endpoint on the same service should be discoverable"
            );

            let mut stream_b = address_lookup_b.resolve(id_a).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Endpoint on a different service should NOT be discoverable"
            );

            Ok(())
        }

        fn make_address_lookup<R: CryptoRng + ?Sized>(
            rng: &mut R,
            advertise: bool,
        ) -> Result<(PublicKey, MdnsAddressLookup)> {
            let endpoint_id = SecretKey::generate(rng).public();
            Ok((
                endpoint_id,
                MdnsAddressLookup::builder()
                    .advertise(advertise)
                    .build(endpoint_id)?,
            ))
        }
    }
}

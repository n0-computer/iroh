use std::{
    collections::{BTreeSet, HashMap, hash_map::Entry},
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::Duration,
};

use iroh_base::{EndpointAddr, EndpointId, PublicKey, RelayUrl};
use n0_future::time::Instant;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, trace, warn};

use self::endpoint_state::{EndpointState, Options, PingHandled};
use super::{ActorMessage, EndpointIdMappedAddr, metrics::Metrics, transports};
use crate::disco::{CallMeMaybe, Pong, SendAddr, TransactionId};
#[cfg(any(test, feature = "test-utils"))]
use crate::endpoint::PathSelection;

mod endpoint_state;
mod path_state;
mod path_validity;
mod udp_paths;

pub use endpoint_state::{ConnectionType, ControlMsg, DirectAddrInfo};
pub(super) use endpoint_state::{DiscoPingPurpose, PingAction, PingRole, RemoteInfo, SendPing};

/// Number of endpoints that are inactive for which we keep info about. This limit is enforced
/// periodically via [`EndpointMap::prune_inactive`].
const MAX_INACTIVE_ENDPOINTS: usize = 30;

/// Map of the [`EndpointState`] information for all the known endpoints.
///
/// The endpoints can be looked up by:
///
/// - The endpoint's ID in this map, only useful if you know the ID from an insert or lookup.
///   This is static and never changes.
///
/// - The [`EndpointIdMappedAddr`] which internally identifies the endpoint to the QUIC stack.  This
///   is static and never changes.
///
/// - The endpoints's public key, aka `PublicKey` or "endpoint_key".  This is static and never changes,
///   however an endpoint could be added when this is not yet known.
///
/// - A public socket address on which they are reachable on the internet, known as ip-port.
///   These come and go as the endpoint moves around on the internet
///
/// An index of endpointInfos by endpoint key, EndpointIdMappedAddr, and discovered ip:port endpoints.
#[derive(Debug, Default)]
pub(super) struct EndpointMap {
    inner: Mutex<EndpointMapInner>,
}

#[derive(Default, Debug)]
pub(super) struct EndpointMapInner {
    by_endpoint_key: HashMap<EndpointId, usize>,
    by_ip_port: HashMap<IpPort, usize>,
    by_quic_mapped_addr: HashMap<EndpointIdMappedAddr, usize>,
    by_id: HashMap<usize, EndpointState>,
    next_id: usize,
    #[cfg(any(test, feature = "test-utils"))]
    path_selection: PathSelection,
}

/// Identifier to look up a [`EndpointState`] in the [`EndpointMap`].
///
/// You can look up entries in [`EndpointMap`] with various keys, depending on the context you
/// have for the endpoint.  These are all the keys the [`EndpointMap`] can use.
#[derive(Debug, Clone)]
enum EndpointStateKey {
    Idx(usize),
    EndpointId(EndpointId),
    EndpointIdMappedAddr(EndpointIdMappedAddr),
    IpPort(IpPort),
}

/// The origin or *source* through which an address associated with a remote endpoint
/// was discovered.
///
/// An aggregate of the [`Source`]s of all the addresses of an endpoint describe the
/// [`Source`]s of the endpoint itself.
///
/// A [`Source`] helps track how and where an address was learned. Multiple
/// sources can be associated with a single address, if we have discovered this
/// address through multiple means.
///
/// Each time a [`EndpointAddr`] is added to the endpoint map a [`Source`] must be supplied to indicate
/// how the address was obtained.
///
/// A [`Source`] can describe a variety of places that an address or endpoint was
/// discovered, such as a configured discovery service, the network itself
/// (if another endpoint has reached out to us), or as a user supplied [`EndpointAddr`].

#[derive(Serialize, Deserialize, strum::Display, Debug, Clone, Eq, PartialEq, Hash)]
#[strum(serialize_all = "kebab-case")]
pub enum Source {
    /// Address was loaded from the fs.
    Saved,
    /// An endpoint communicated with us first via UDP.
    Udp,
    /// An endpoint communicated with us first via relay.
    Relay,
    /// Application layer added the address directly.
    App,
    /// The address was discovered by a discovery service.
    #[strum(serialize = "{name}")]
    Discovery {
        /// The name of the discovery service that discovered the address.
        name: String,
    },
    /// Application layer with a specific name added the endpoint directly.
    #[strum(serialize = "{name}")]
    NamedApp {
        /// The name of the application that added the endpoint
        name: String,
    },
}

impl EndpointMap {
    /// Create a new [`EndpointMap`] from a list of [`EndpointAddr`]s.
    pub(super) fn load_from_vec(
        endpoints: Vec<EndpointAddr>,
        #[cfg(any(test, feature = "test-utils"))] path_selection: PathSelection,
        have_ipv6: bool,
        metrics: &Metrics,
    ) -> Self {
        Self::from_inner(EndpointMapInner::load_from_vec(
            endpoints,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection,
            have_ipv6,
            metrics,
        ))
    }

    fn from_inner(inner: EndpointMapInner) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Add the contact information for an endpoint.
    pub(super) fn add_endpoint_addr(
        &self,
        endpoint_addr: EndpointAddr,
        source: Source,
        have_v6: bool,
        metrics: &Metrics,
    ) {
        self.inner.lock().expect("poisoned").add_endpoint_addr(
            endpoint_addr,
            source,
            have_v6,
            metrics,
        )
    }

    /// Number of endpoints currently listed.
    pub(super) fn endpoint_count(&self) -> usize {
        self.inner.lock().expect("poisoned").endpoint_count()
    }

    #[cfg(not(wasm_browser))]
    pub(super) fn receive_udp(
        &self,
        udp_addr: SocketAddr,
    ) -> Option<(PublicKey, EndpointIdMappedAddr)> {
        self.inner.lock().expect("poisoned").receive_udp(udp_addr)
    }

    pub(super) fn receive_relay(
        &self,
        relay_url: &RelayUrl,
        src: EndpointId,
    ) -> EndpointIdMappedAddr {
        self.inner
            .lock()
            .expect("poisoned")
            .receive_relay(relay_url, src)
    }

    pub(super) fn notify_ping_sent(
        &self,
        id: usize,
        dst: SendAddr,
        tx_id: TransactionId,
        purpose: DiscoPingPurpose,
        msg_sender: tokio::sync::mpsc::Sender<ActorMessage>,
    ) {
        if let Some(ep) = self
            .inner
            .lock()
            .expect("poisoned")
            .get_mut(EndpointStateKey::Idx(id))
        {
            ep.ping_sent(dst, tx_id, purpose, msg_sender);
        }
    }

    pub(super) fn notify_ping_timeout(&self, id: usize, tx_id: TransactionId, metrics: &Metrics) {
        if let Some(ep) = self
            .inner
            .lock()
            .expect("poisoned")
            .get_mut(EndpointStateKey::Idx(id))
        {
            ep.ping_timeout(tx_id, Instant::now(), metrics);
        }
    }

    pub(super) fn get_quic_mapped_addr_for_endpoint_key(
        &self,
        endpoint_key: EndpointId,
    ) -> Option<EndpointIdMappedAddr> {
        self.inner
            .lock()
            .expect("poisoned")
            .get(EndpointStateKey::EndpointId(endpoint_key))
            .map(|ep| *ep.quic_mapped_addr())
    }

    /// Insert a received ping into the endpoint map, and return whether a ping with this tx_id was already
    /// received.
    pub(super) fn handle_ping(
        &self,
        sender: PublicKey,
        src: SendAddr,
        tx_id: TransactionId,
    ) -> PingHandled {
        self.inner
            .lock()
            .expect("poisoned")
            .handle_ping(sender, src, tx_id)
    }

    pub(super) fn handle_pong(
        &self,
        sender: PublicKey,
        src: &transports::Addr,
        pong: Pong,
        metrics: &Metrics,
    ) {
        self.inner
            .lock()
            .expect("poisoned")
            .handle_pong(sender, src, pong, metrics)
    }

    #[must_use = "actions must be handled"]
    pub(super) fn handle_call_me_maybe(
        &self,
        sender: PublicKey,
        cm: CallMeMaybe,
        metrics: &Metrics,
    ) -> Vec<PingAction> {
        self.inner
            .lock()
            .expect("poisoned")
            .handle_call_me_maybe(sender, cm, metrics)
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn get_send_addrs(
        &self,
        addr: EndpointIdMappedAddr,
        have_ipv6: bool,
        metrics: &Metrics,
    ) -> Option<(
        PublicKey,
        Option<SocketAddr>,
        Option<RelayUrl>,
        Vec<PingAction>,
    )> {
        let mut inner = self.inner.lock().expect("poisoned");
        let ep = inner.get_mut(EndpointStateKey::EndpointIdMappedAddr(addr))?;
        let public_key = *ep.public_key();
        trace!(dest = %addr, endpoint_id = %public_key.fmt_short(), "dst mapped to EndpointId");
        let (udp_addr, relay_url, ping_actions) = ep.get_send_addrs(have_ipv6, metrics);
        Some((public_key, udp_addr, relay_url, ping_actions))
    }

    pub(super) fn reset_endpoint_states(&self, metrics: &Metrics) {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("poisoned");
        for (_, ep) in inner.endpoint_states_mut() {
            ep.note_connectivity_change(now, metrics);
        }
    }

    pub(super) fn endpoints_stayin_alive(&self, have_ipv6: bool) -> Vec<PingAction> {
        let mut inner = self.inner.lock().expect("poisoned");
        inner
            .endpoint_states_mut()
            .flat_map(|(_idx, endpoint_state)| endpoint_state.stayin_alive(have_ipv6))
            .collect()
    }

    /// Returns the [`RemoteInfo`]s for each endpoint in the endpoint map.
    #[cfg(test)]
    pub(super) fn list_remote_infos(&self, now: Instant) -> Vec<RemoteInfo> {
        // NOTE: calls to this method will often call `into_iter` (or similar methods). Note that
        // we can't avoid `collect` here since it would hold a lock for an indefinite time. Even if
        // we were to find this acceptable, dealing with the lifetimes of the mutex's guard and the
        // internal iterator will be a hassle, if possible at all.
        self.inner
            .lock()
            .expect("poisoned")
            .remote_infos_iter(now)
            .collect()
    }

    /// Returns a [`n0_watcher::Direct`] for given endpoint's [`ConnectionType`].
    ///
    /// # Errors
    ///
    /// Will return `None` if there is not an entry in the [`EndpointMap`] for
    /// the `endpoint_id`
    pub(super) fn conn_type(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<n0_watcher::Direct<ConnectionType>> {
        self.inner.lock().expect("poisoned").conn_type(endpoint_id)
    }

    pub(super) fn latency(&self, endpoint_id: EndpointId) -> Option<Duration> {
        self.inner.lock().expect("poisoned").latency(endpoint_id)
    }

    /// Get the [`RemoteInfo`]s for the endpoint identified by [`EndpointId`].
    pub(super) fn remote_info(&self, endpoint_id: EndpointId) -> Option<RemoteInfo> {
        self.inner
            .lock()
            .expect("poisoned")
            .remote_info(endpoint_id)
    }

    /// Prunes endpoints without recent activity so that at most [`MAX_INACTIVE_ENDPOINTS`] are kept.
    pub(super) fn prune_inactive(&self) {
        self.inner.lock().expect("poisoned").prune_inactive();
    }

    pub(crate) fn on_direct_addr_discovered(&self, discovered: BTreeSet<SocketAddr>) {
        self.inner
            .lock()
            .expect("poisoned")
            .on_direct_addr_discovered(discovered, Instant::now());
    }
}

impl EndpointMapInner {
    /// Create a new [`EndpointMap`] from a list of [`EndpointAddr`]s.
    fn load_from_vec(
        endpoints: Vec<EndpointAddr>,
        #[cfg(any(test, feature = "test-utils"))] path_selection: PathSelection,
        have_ipv6: bool,
        metrics: &Metrics,
    ) -> Self {
        let mut me = Self {
            #[cfg(any(test, feature = "test-utils"))]
            path_selection,
            ..Default::default()
        };
        for endpoint_addr in endpoints {
            me.add_endpoint_addr(endpoint_addr, Source::Saved, have_ipv6, metrics);
        }
        me
    }

    /// Add the contact information for an endpoint.
    #[instrument(skip_all, fields(endpoint = %endpoint_addr.id.fmt_short()))]
    fn add_endpoint_addr(
        &mut self,
        endpoint_addr: EndpointAddr,
        source: Source,
        have_ipv6: bool,
        metrics: &Metrics,
    ) {
        let source0 = source.clone();
        let endpoint_id = endpoint_addr.id;
        let relay_url = endpoint_addr.relay_urls().next().cloned();
        #[cfg(any(test, feature = "test-utils"))]
        let path_selection = self.path_selection;
        let endpoint_state =
            self.get_or_insert_with(EndpointStateKey::EndpointId(endpoint_id), || Options {
                endpoint_id,
                relay_url,
                active: false,
                source,
                #[cfg(any(test, feature = "test-utils"))]
                path_selection,
            });
        endpoint_state.update_from_endpoint_addr(
            endpoint_addr.relay_url.as_ref(),
            &endpoint_addr.ip_addresses,
            source0,
            have_ipv6,
            metrics,
        );
        let id = endpoint_state.id();
        for addr in endpoint_addr.ip_addresses() {
            self.set_endpoint_state_for_ip_port(*addr, id);
        }
    }

    /// Prunes direct addresses from endpoints that claim to share an address we know points to us.
    pub(super) fn on_direct_addr_discovered(
        &mut self,
        discovered: BTreeSet<SocketAddr>,
        now: Instant,
    ) {
        for addr in discovered {
            self.remove_by_ipp(addr.into(), now, "matches our local addr")
        }
    }

    /// Removes a direct address from an endpoint.
    fn remove_by_ipp(&mut self, ipp: IpPort, now: Instant, why: &'static str) {
        if let Some(id) = self.by_ip_port.remove(&ipp) {
            if let Entry::Occupied(mut entry) = self.by_id.entry(id) {
                let endpoint = entry.get_mut();
                endpoint.remove_direct_addr(&ipp, now, why);
                if endpoint.direct_addresses().count() == 0 {
                    let endpoint_id = endpoint.public_key();
                    let mapped_addr = endpoint.quic_mapped_addr();
                    self.by_endpoint_key.remove(endpoint_id);
                    self.by_quic_mapped_addr.remove(mapped_addr);
                    debug!(endpoint_id=%endpoint_id.fmt_short(), why, "removing endpoint");
                    entry.remove();
                }
            }
        }
    }

    fn get_id(&self, id: EndpointStateKey) -> Option<usize> {
        match id {
            EndpointStateKey::Idx(id) => Some(id),
            EndpointStateKey::EndpointId(endpoint_key) => {
                self.by_endpoint_key.get(&endpoint_key).copied()
            }
            EndpointStateKey::EndpointIdMappedAddr(addr) => {
                self.by_quic_mapped_addr.get(&addr).copied()
            }
            EndpointStateKey::IpPort(ipp) => self.by_ip_port.get(&ipp).copied(),
        }
    }

    fn get_mut(&mut self, id: EndpointStateKey) -> Option<&mut EndpointState> {
        self.get_id(id).and_then(|id| self.by_id.get_mut(&id))
    }

    fn get(&self, id: EndpointStateKey) -> Option<&EndpointState> {
        self.get_id(id).and_then(|id| self.by_id.get(&id))
    }

    fn get_or_insert_with(
        &mut self,
        id: EndpointStateKey,
        f: impl FnOnce() -> Options,
    ) -> &mut EndpointState {
        let id = self.get_id(id);
        match id {
            None => self.insert_endpoint(f()),
            Some(id) => self.by_id.get_mut(&id).expect("is not empty"),
        }
    }

    /// Number of endpoints currently listed.
    fn endpoint_count(&self) -> usize {
        self.by_id.len()
    }

    /// Marks the endpoint we believe to be at `ipp` as recently used.
    #[cfg(not(wasm_browser))]
    fn receive_udp(&mut self, udp_addr: SocketAddr) -> Option<(EndpointId, EndpointIdMappedAddr)> {
        let ip_port: IpPort = udp_addr.into();
        let Some(endpoint_state) = self.get_mut(EndpointStateKey::IpPort(ip_port)) else {
            trace!(src=%udp_addr, "receive_udp: no endpoint_state found for addr, ignore");
            return None;
        };
        endpoint_state.receive_udp(ip_port, Instant::now());
        Some((
            *endpoint_state.public_key(),
            *endpoint_state.quic_mapped_addr(),
        ))
    }

    #[instrument(skip_all, fields(src = %src.fmt_short()))]
    fn receive_relay(&mut self, relay_url: &RelayUrl, src: EndpointId) -> EndpointIdMappedAddr {
        #[cfg(any(test, feature = "test-utils"))]
        let path_selection = self.path_selection;
        let endpoint_state = self.get_or_insert_with(EndpointStateKey::EndpointId(src), || {
            trace!("packets from unknown endpoint, insert into endpoint map");
            Options {
                endpoint_id: src,
                relay_url: Some(relay_url.clone()),
                active: true,
                source: Source::Relay,
                #[cfg(any(test, feature = "test-utils"))]
                path_selection,
            }
        });
        endpoint_state.receive_relay(relay_url, src, Instant::now());
        *endpoint_state.quic_mapped_addr()
    }

    #[cfg(test)]
    fn endpoint_states(&self) -> impl Iterator<Item = (&usize, &EndpointState)> {
        self.by_id.iter()
    }

    fn endpoint_states_mut(&mut self) -> impl Iterator<Item = (&usize, &mut EndpointState)> {
        self.by_id.iter_mut()
    }

    /// Get the [`RemoteInfo`]s for all endpoints.
    #[cfg(test)]
    fn remote_infos_iter(&self, now: Instant) -> impl Iterator<Item = RemoteInfo> + '_ {
        self.endpoint_states().map(move |(_, ep)| ep.info(now))
    }

    /// Get the [`RemoteInfo`]s for each endpoint.
    fn remote_info(&self, endpoint_id: EndpointId) -> Option<RemoteInfo> {
        self.get(EndpointStateKey::EndpointId(endpoint_id))
            .map(|ep| ep.info(Instant::now()))
    }

    /// Returns a stream of [`ConnectionType`].
    ///
    /// Sends the current [`ConnectionType`] whenever any changes to the
    /// connection type for `public_key` has occurred.
    ///
    /// # Errors
    ///
    /// Will return `None` if there is not an entry in the [`EndpointMap`] for
    /// the `public_key`
    fn conn_type(&self, endpoint_id: EndpointId) -> Option<n0_watcher::Direct<ConnectionType>> {
        self.get(EndpointStateKey::EndpointId(endpoint_id))
            .map(|ep| ep.conn_type())
    }

    fn latency(&self, endpoint_id: EndpointId) -> Option<Duration> {
        self.get(EndpointStateKey::EndpointId(endpoint_id))
            .and_then(|ep| ep.latency())
    }

    fn handle_pong(
        &mut self,
        sender: EndpointId,
        src: &transports::Addr,
        pong: Pong,
        metrics: &Metrics,
    ) {
        if let Some(ns) = self.get_mut(EndpointStateKey::EndpointId(sender)).as_mut() {
            let insert = ns.handle_pong(&pong, src.clone().into(), metrics);
            if let Some((src, key)) = insert {
                self.set_endpoint_key_for_ip_port(src, &key);
            }
            trace!(?insert, "received pong")
        } else {
            warn!("received pong: endpoint unknown, ignore")
        }
    }

    #[must_use = "actions must be handled"]
    fn handle_call_me_maybe(
        &mut self,
        sender: EndpointId,
        cm: CallMeMaybe,
        metrics: &Metrics,
    ) -> Vec<PingAction> {
        let ns_id = EndpointStateKey::EndpointId(sender);
        if let Some(id) = self.get_id(ns_id.clone()) {
            for number in &cm.my_numbers {
                // ensure the new addrs are known
                self.set_endpoint_state_for_ip_port(*number, id);
            }
        }
        match self.get_mut(ns_id) {
            None => {
                debug!("received call-me-maybe: ignore, endpoint is unknown");
                metrics.recv_disco_call_me_maybe_bad_disco.inc();
                vec![]
            }
            Some(ns) => {
                debug!(endpoints = ?cm.my_numbers, "received call-me-maybe");

                ns.handle_call_me_maybe(cm, metrics)
            }
        }
    }

    fn handle_ping(
        &mut self,
        sender: EndpointId,
        src: SendAddr,
        tx_id: TransactionId,
    ) -> PingHandled {
        #[cfg(any(test, feature = "test-utils"))]
        let path_selection = self.path_selection;
        let endpoint_state = self.get_or_insert_with(EndpointStateKey::EndpointId(sender), || {
            debug!("received ping: endpoint unknown, add to endpoint map");
            let source = if src.is_relay() {
                Source::Relay
            } else {
                Source::Udp
            };
            Options {
                endpoint_id: sender,
                relay_url: src.relay_url(),
                active: true,
                source,
                #[cfg(any(test, feature = "test-utils"))]
                path_selection,
            }
        });

        let handled = endpoint_state.handle_ping(src.clone(), tx_id);
        if let SendAddr::Udp(ref addr) = src {
            if matches!(handled.role, PingRole::NewPath) {
                self.set_endpoint_key_for_ip_port(*addr, &sender);
            }
        }
        handled
    }

    /// Inserts a new endpoint into the [`EndpointMap`].
    fn insert_endpoint(&mut self, options: Options) -> &mut EndpointState {
        info!(
            endpoint = %options.endpoint_id.fmt_short(),
            relay_url = ?options.relay_url,
            source = %options.source,
            "inserting new endpoint in EndpointMap",
        );
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let endpoint_state = EndpointState::new(id, options);

        // update indices
        self.by_quic_mapped_addr
            .insert(*endpoint_state.quic_mapped_addr(), id);
        self.by_endpoint_key
            .insert(*endpoint_state.public_key(), id);

        self.by_id.insert(id, endpoint_state);
        self.by_id.get_mut(&id).expect("just inserted")
    }

    /// Makes future endpoint lookups by ipp return the same endpoint as a lookup by nk.
    ///
    /// This should only be called with a fully verified mapping of ipp to
    /// nk, because calling this function defines the endpoint we hand to
    /// WireGuard for packets received from ipp.
    fn set_endpoint_key_for_ip_port(&mut self, ipp: impl Into<IpPort>, nk: &PublicKey) {
        let ipp = ipp.into();
        if let Some(id) = self.by_ip_port.get(&ipp) {
            if !self.by_endpoint_key.contains_key(nk) {
                self.by_endpoint_key.insert(*nk, *id);
            }
            self.by_ip_port.remove(&ipp);
        }
        if let Some(id) = self.by_endpoint_key.get(nk) {
            trace!("insert ip -> id: {:?} -> {}", ipp, id);
            self.by_ip_port.insert(ipp, *id);
        }
    }

    fn set_endpoint_state_for_ip_port(&mut self, ipp: impl Into<IpPort>, id: usize) {
        let ipp = ipp.into();
        trace!(?ipp, ?id, "set endpoint for ip:port");
        self.by_ip_port.insert(ipp, id);
    }

    /// Prunes endpoints without recent activity so that at most [`MAX_INACTIVE_ENDPOINTS`] are kept.
    fn prune_inactive(&mut self) {
        let now = Instant::now();
        let mut prune_candidates: Vec<_> = self
            .by_id
            .values()
            .filter(|endpoint| !endpoint.is_active(&now))
            .map(|endpoint| (*endpoint.public_key(), endpoint.last_used()))
            .collect();

        let prune_count = prune_candidates
            .len()
            .saturating_sub(MAX_INACTIVE_ENDPOINTS);
        if prune_count == 0 {
            // within limits
            return;
        }

        prune_candidates.sort_unstable_by_key(|(_pk, last_used)| *last_used);
        prune_candidates.truncate(prune_count);
        for (public_key, last_used) in prune_candidates.into_iter() {
            let endpoint = public_key.fmt_short();
            match last_used.map(|instant| instant.elapsed()) {
                Some(last_used) => trace!(%endpoint, ?last_used, "pruning inactive"),
                None => trace!(%endpoint, last_used=%"never", "pruning inactive"),
            }

            let Some(id) = self.by_endpoint_key.remove(&public_key) else {
                debug_assert!(false, "missing by_endpoint_key entry for pk in by_id");
                continue;
            };

            let Some(ep) = self.by_id.remove(&id) else {
                debug_assert!(false, "missing by_id entry for id in by_endpoint_key");
                continue;
            };

            for ip_port in ep.direct_addresses() {
                self.by_ip_port.remove(&ip_port);
            }

            self.by_quic_mapped_addr.remove(ep.quic_mapped_addr());
        }
    }
}

/// An (Ip, Port) pair.
///
/// NOTE: storing an [`IpPort`] is safer than storing a [`SocketAddr`] because for IPv6 socket
/// addresses include fields that can't be assumed consistent even within a single connection.
#[derive(Debug, derive_more::Display, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[display("{}", SocketAddr::from(*self))]
pub struct IpPort {
    ip: IpAddr,
    port: u16,
}

impl From<SocketAddr> for IpPort {
    fn from(socket_addr: SocketAddr) -> Self {
        Self {
            ip: socket_addr.ip(),
            port: socket_addr.port(),
        }
    }
}

impl From<IpPort> for SocketAddr {
    fn from(ip_port: IpPort) -> Self {
        let IpPort { ip, port } = ip_port;
        (ip, port).into()
    }
}

impl IpPort {
    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use iroh_base::SecretKey;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    use super::{endpoint_state::MAX_INACTIVE_DIRECT_ADDRESSES, *};

    impl EndpointMap {
        #[track_caller]
        fn add_test_addr(&self, endpoint_addr: EndpointAddr) {
            self.add_endpoint_addr(
                endpoint_addr,
                Source::NamedApp {
                    name: "test".into(),
                },
                true,
                &Default::default(),
            )
        }
    }

    /// Test persisting and loading of known endpoints.
    #[tokio::test]
    #[traced_test]
    async fn restore_from_vec() {
        let endpoint_map = EndpointMap::default();

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let endpoint_a = SecretKey::generate(&mut rng).public();
        let endpoint_b = SecretKey::generate(&mut rng).public();
        let endpoint_c = SecretKey::generate(&mut rng).public();
        let endpoint_d = SecretKey::generate(&mut rng).public();

        let relay_x: RelayUrl = "https://my-relay-1.com".parse().unwrap();
        let relay_y: RelayUrl = "https://my-relay-2.com".parse().unwrap();

        let direct_addresses_a = [addr(4000), addr(4001)];
        let direct_addresses_c = [addr(5000)];

        let endpoint_addr_a = EndpointAddr::new(endpoint_a)
            .with_relay_url(relay_x)
            .with_direct_addresses(direct_addresses_a);
        let endpoint_addr_b = EndpointAddr::new(endpoint_b).with_relay_url(relay_y);
        let endpoint_addr_c =
            EndpointAddr::new(endpoint_c).with_direct_addresses(direct_addresses_c);
        let endpoint_addr_d = EndpointAddr::new(endpoint_d);

        endpoint_map.add_test_addr(endpoint_addr_a);
        endpoint_map.add_test_addr(endpoint_addr_b);
        endpoint_map.add_test_addr(endpoint_addr_c);
        endpoint_map.add_test_addr(endpoint_addr_d);

        let mut addrs: Vec<EndpointAddr> = endpoint_map
            .list_remote_infos(Instant::now())
            .into_iter()
            .filter_map(|info| {
                let addr: EndpointAddr = info.into();
                if addr.is_empty() {
                    return None;
                }
                Some(addr)
            })
            .collect();
        let loaded_endpoint_map = EndpointMap::load_from_vec(
            addrs.clone(),
            PathSelection::default(),
            true,
            &Default::default(),
        );

        let mut loaded: Vec<EndpointAddr> = loaded_endpoint_map
            .list_remote_infos(Instant::now())
            .into_iter()
            .filter_map(|info| {
                let addr: EndpointAddr = info.into();
                if addr.is_empty() {
                    return None;
                }
                Some(addr)
            })
            .collect();

        loaded.sort_unstable();
        addrs.sort_unstable();

        // compare the endpoint maps via their known endpoints
        assert_eq!(addrs, loaded);
    }

    fn addr(port: u16) -> SocketAddr {
        (std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), port).into()
    }

    #[test]
    #[traced_test]
    fn test_prune_direct_addresses() {
        let endpoint_map = EndpointMap::default();
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let public_key = SecretKey::generate(&mut rng).public();
        let id = endpoint_map
            .inner
            .lock()
            .unwrap()
            .insert_endpoint(Options {
                endpoint_id: public_key,
                relay_url: None,
                active: false,
                source: Source::NamedApp {
                    name: "test".into(),
                },
                path_selection: PathSelection::default(),
            })
            .id();

        const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        // add [`MAX_INACTIVE_DIRECT_ADDRESSES`] active direct addresses and double
        // [`MAX_INACTIVE_DIRECT_ADDRESSES`] that are inactive

        info!("Adding active addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SocketAddr::new(LOCALHOST, 5000 + i as u16);
            let endpoint_addr = EndpointAddr::new(public_key).with_direct_addresses([addr]);
            // add address
            endpoint_map.add_test_addr(endpoint_addr);
            // make it active
            endpoint_map.inner.lock().unwrap().receive_udp(addr);
        }

        info!("Adding offline/inactive addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES * 2 {
            let addr = SocketAddr::new(LOCALHOST, 6000 + i as u16);
            let endpoint_addr = EndpointAddr::new(public_key).with_direct_addresses([addr]);
            endpoint_map.add_test_addr(endpoint_addr);
        }

        let mut endpoint_map_inner = endpoint_map.inner.lock().unwrap();
        let endpoint = endpoint_map_inner.by_id.get_mut(&id).unwrap();

        info!("Adding alive addresses");
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SendAddr::Udp(SocketAddr::new(LOCALHOST, 7000 + i as u16));
            let txid = TransactionId::from([i as u8; 12]);
            // Note that this already invokes .prune_direct_addresses() because these are
            // new UDP paths.
            endpoint.handle_ping(addr, txid);
        }

        info!("Pruning addresses");
        endpoint.prune_direct_addresses(Instant::now());

        // Half the offline addresses should have been pruned.  All the active and alive
        // addresses should have been kept.
        assert_eq!(
            endpoint.direct_addresses().count(),
            MAX_INACTIVE_DIRECT_ADDRESSES * 3
        );

        // We should have both offline and alive addresses which are not active.
        assert_eq!(
            endpoint
                .direct_address_states()
                .filter(|(_addr, state)| !state.is_active())
                .count(),
            MAX_INACTIVE_DIRECT_ADDRESSES * 2
        )
    }

    #[test]
    fn test_prune_inactive() {
        let endpoint_map = EndpointMap::default();
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

        // add one active endpoint and more than MAX_INACTIVE_ENDPOINTS inactive endpoints
        let active_endpoint = SecretKey::generate(&mut rng).public();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 167);
        endpoint_map
            .add_test_addr(EndpointAddr::new(active_endpoint).with_direct_addresses([addr]));
        endpoint_map
            .inner
            .lock()
            .unwrap()
            .receive_udp(addr)
            .expect("registered");

        for _ in 0..MAX_INACTIVE_ENDPOINTS + 1 {
            let endpoint = SecretKey::generate(&mut rng).public();
            endpoint_map.add_test_addr(EndpointAddr::new(endpoint));
        }

        assert_eq!(endpoint_map.endpoint_count(), MAX_INACTIVE_ENDPOINTS + 2);
        endpoint_map.prune_inactive();
        assert_eq!(endpoint_map.endpoint_count(), MAX_INACTIVE_ENDPOINTS + 1);
        endpoint_map
            .inner
            .lock()
            .unwrap()
            .get(EndpointStateKey::EndpointId(active_endpoint))
            .expect("should not be pruned");
    }
}

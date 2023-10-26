use std::{
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Instant,
};

use anyhow::{ensure, Context};
use iroh_metrics::inc;
use parking_lot::Mutex;
use stun_rs::TransactionId;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, instrument, trace, warn};

use self::endpoint::{Endpoint, Options};
use super::{
    metrics::Metrics as MagicsockMetrics, ActorMessage, DiscoMessageSource, QuicMappedAddr,
    SendAddr,
};
use crate::{
    disco::{CallMeMaybe, Pong},
    key::PublicKey,
    stun, PeerAddr,
};

mod best_addr;
mod endpoint;

pub use endpoint::{ConnectionType, DirectAddrInfo, EndpointInfo};
pub(super) use endpoint::{DiscoPingPurpose, PingAction, PingRole, SendPing};

/// Number of peers that are inactive for which we keep info about. This limit is enforced
/// periodically via [`PeerMap::prune_inactive`].
const MAX_INACTIVE_PEERS: usize = 30;

/// Map of the [`Endpoint`] information for all the known peers.
///
/// The peers can be looked up by:
///
/// - The peer's ID in this map, only useful if you know the ID from an insert or lookup.
///   This is static and never changes.
///
/// - The [`QuicMappedAddr`] which internally identifies the peer to the QUIC stack.  This
///   is static and never changes.
///
/// - The peers's public key, aka `PublicKey` or "node_key".  This is static and never changes,
///   however a peer could be added when this is not yet known.
///
/// - A public socket address on which they are reachable on the internet, known as ip-port.
///   These come and go as the peer moves around on the internet
///
/// An index of peerInfos by node key, QuicMappedAddr, and discovered ip:port endpoints.
#[derive(Default, Debug)]
pub(super) struct PeerMap {
    inner: Mutex<PeerMapInner>,
}

#[derive(Default, Debug)]
pub(super) struct PeerMapInner {
    by_node_key: HashMap<PublicKey, usize>,
    by_ip_port: HashMap<IpPort, usize>,
    by_quic_mapped_addr: HashMap<QuicMappedAddr, usize>,
    by_id: HashMap<usize, Endpoint>,
    next_id: usize,
}

enum EndpointId<'a> {
    Id(&'a usize),
    NodeKey(&'a PublicKey),
    QuicMappedAddr(&'a QuicMappedAddr),
    IpPort(&'a IpPort),
}

impl PeerMap {
    /// Create a new [`PeerMap`] from data stored in `path`.
    pub fn load_from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Ok(Self::from_inner(PeerMapInner::load_from_file(path)?))
    }

    fn from_inner(inner: PeerMapInner) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Get the known peer addresses stored in the map. Peers with empty addressing information are
    /// filtered out.
    #[cfg(test)]
    pub fn known_peer_addresses(&self) -> Vec<PeerAddr> {
        self.inner.lock().known_peer_addresses().collect()
    }

    /// Add the contact information for a peer.
    pub fn add_peer_addr(&self, peer_addr: PeerAddr) {
        self.inner.lock().add_peer_addr(peer_addr)
    }

    /// Number of nodes currently listed.
    pub fn node_count(&self) -> usize {
        self.inner.lock().node_count()
    }

    pub fn receive_udp(&self, udp_addr: SocketAddr) -> Option<(PublicKey, QuicMappedAddr)> {
        self.inner.lock().receive_udp(udp_addr)
    }

    pub fn receive_derp(&self, region_id: u16, src: PublicKey) -> QuicMappedAddr {
        self.inner.lock().receive_derp(region_id, &src)
    }

    pub fn notify_ping_sent(
        &self,
        id: usize,
        dst: SendAddr,
        tx_id: stun::TransactionId,
        purpose: DiscoPingPurpose,
        msg_sender: tokio::sync::mpsc::Sender<ActorMessage>,
    ) {
        if let Some(ep) = self.inner.lock().get_mut(EndpointId::Id(&id)) {
            ep.ping_sent(dst, tx_id, purpose, msg_sender);
        }
    }

    pub fn notify_ping_timeout(&self, id: usize, tx_id: stun::TransactionId) {
        if let Some(ep) = self.inner.lock().get_mut(EndpointId::Id(&id)) {
            ep.ping_timeout(tx_id);
        }
    }

    pub fn get_quic_mapped_addr_for_node_key(
        &self,
        node_key: &PublicKey,
    ) -> Option<QuicMappedAddr> {
        self.inner
            .lock()
            .get(EndpointId::NodeKey(node_key))
            .map(|ep| *ep.quic_mapped_addr())
    }

    /// Insert a received ping into the peer map, and return whether a ping with this tx_id was already
    /// received.
    pub fn handle_ping(&self, sender: PublicKey, src: SendAddr, tx_id: TransactionId) -> PingRole {
        self.inner.lock().handle_ping(sender, src, tx_id)
    }

    pub fn handle_pong(&self, sender: PublicKey, src: &DiscoMessageSource, pong: Pong) {
        self.inner.lock().handle_pong(sender, src, pong)
    }

    #[must_use = "actions must be handled"]
    pub fn handle_call_me_maybe(&self, sender: PublicKey, cm: CallMeMaybe) -> Vec<PingAction> {
        self.inner.lock().handle_call_me_maybe(sender, cm)
    }

    #[allow(clippy::type_complexity)]
    pub fn get_send_addrs_for_quic_mapped_addr(
        &self,
        addr: &QuicMappedAddr,
    ) -> Option<(PublicKey, Option<SocketAddr>, Option<u16>, Vec<PingAction>)> {
        let mut inner = self.inner.lock();
        let ep = inner.get_mut(EndpointId::QuicMappedAddr(addr))?;
        let public_key = *ep.public_key();
        let (udp_addr, derp_region, msgs) = ep.get_send_addrs();
        Some((public_key, udp_addr, derp_region, msgs))
    }

    pub fn notify_shutdown(&self) {
        let mut inner = self.inner.lock();
        for (_, ep) in inner.endpoints_mut() {
            ep.stop_and_reset();
        }
    }

    pub fn reset_endpoint_states(&self) {
        let mut inner = self.inner.lock();
        for (_, ep) in inner.endpoints_mut() {
            ep.note_connectivity_change();
        }
    }

    pub fn endpoints_stayin_alive(&self) -> Vec<PingAction> {
        let mut msgs = Vec::new();
        let mut inner = self.inner.lock();
        for (_, ep) in inner.endpoints_mut() {
            msgs.extend(ep.stayin_alive());
        }
        msgs
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    pub fn endpoint_infos(&self, now: Instant) -> Vec<EndpointInfo> {
        self.inner.lock().endpoint_infos(now)
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    pub fn endpoint_info(&self, public_key: &PublicKey) -> Option<EndpointInfo> {
        self.inner.lock().endpoint_info(public_key)
    }

    /// Saves the known peer info to the given path, returning the number of peers persisted.
    pub async fn save_to_file(&self, path: &Path) -> anyhow::Result<usize> {
        ensure!(!path.is_dir(), "{} must be a file", path.display());

        // So, not sure what to do here.
        let mut known_peers = self
            .inner
            .lock()
            .known_peer_addresses()
            .collect::<Vec<_>>()
            .into_iter()
            .peekable();
        if known_peers.peek().is_none() {
            // prevent file handling if unnecesary
            return Ok(0);
        }

        let mut ext = path.extension().map(|s| s.to_owned()).unwrap_or_default();
        ext.push(".tmp");
        let tmp_path = path.with_extension(ext);

        if tokio::fs::try_exists(&tmp_path).await.unwrap_or(false) {
            tokio::fs::remove_file(&tmp_path)
                .await
                .context("failed deleting existing tmp file")?;
        }
        if let Some(parent) = tmp_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut tmp = tokio::fs::File::create(&tmp_path)
            .await
            .context("failed creating tmp file")?;

        let mut count = 0;
        for peer_addr in known_peers {
            let ser = postcard::to_stdvec(&peer_addr).context("failed to serialize peer data")?;
            tmp.write_all(&ser)
                .await
                .context("failed to persist peer data")?;
            count += 1;
        }
        tmp.flush().await.context("failed to flush peer data")?;
        drop(tmp);

        // move the file
        tokio::fs::rename(tmp_path, path)
            .await
            .context("failed renaming peer data file")?;
        Ok(count)
    }

    /// Prunes peers without recent activity so that at most [`MAX_INACTIVE_PEERS`] are kept.
    pub fn prune_inactive(&self) {
        self.inner.lock().prune_inactive();
    }
}

impl PeerMapInner {
    /// Get the known peer addresses stored in the map. Peers with empty addressing information are
    /// filtered out.
    fn known_peer_addresses(&self) -> impl Iterator<Item = PeerAddr> + '_ {
        self.by_id.values().filter_map(|endpoint| {
            let peer_addr = endpoint.peer_addr();
            (!peer_addr.info.is_empty()).then_some(peer_addr)
        })
    }

    /// Create a new [`PeerMap`] from data stored in `path`.
    fn load_from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        ensure!(path.is_file(), "{} is not a file", path.display());
        let mut me = PeerMapInner::default();
        let contents = std::fs::read(path)?;
        let mut slice: &[u8] = &contents;
        while !slice.is_empty() {
            let (peer_addr, next_contents) =
                postcard::take_from_bytes(slice).context("failed to load peer data")?;
            me.add_peer_addr(peer_addr);
            slice = next_contents;
        }
        Ok(me)
    }

    /// Add the contact information for a peer.
    #[instrument(skip_all, fields(peer = %peer_addr.peer_id.fmt_short()))]
    fn add_peer_addr(&mut self, peer_addr: PeerAddr) {
        let PeerAddr { peer_id, info } = peer_addr;

        let endpoint = self.get_or_insert_with(EndpointId::NodeKey(&peer_id), || Options {
            public_key: peer_id,
            derp_region: info.derp_region,
            active: false,
        });

        endpoint.update_from_node_addr(&info);
        let id = endpoint.id();
        for endpoint in &info.direct_addresses {
            self.set_endpoint_for_ip_port(*endpoint, id);
        }
    }

    fn get_id(&self, id: EndpointId) -> Option<usize> {
        match id {
            EndpointId::Id(id) => Some(*id),
            EndpointId::NodeKey(node_key) => self.by_node_key.get(node_key).copied(),
            EndpointId::QuicMappedAddr(addr) => self.by_quic_mapped_addr.get(addr).copied(),
            EndpointId::IpPort(ipp) => self.by_ip_port.get(ipp).copied(),
        }
    }

    fn get_mut(&mut self, id: EndpointId) -> Option<&mut Endpoint> {
        self.get_id(id).and_then(|id| self.by_id.get_mut(&id))
    }

    fn get(&self, id: EndpointId) -> Option<&Endpoint> {
        self.get_id(id).and_then(|id| self.by_id.get(&id))
    }

    fn get_or_insert_with(&mut self, id: EndpointId, f: impl FnOnce() -> Options) -> &mut Endpoint {
        let id = self.get_id(id);
        match id {
            None => self.insert_endpoint(f()),
            Some(id) => self.by_id.get_mut(&id).expect("is not empty"),
        }
    }

    /// Number of nodes currently listed.
    fn node_count(&self) -> usize {
        self.by_id.len()
    }

    /// Marks the peer we believe to be at `ipp` as recently used, returning the [`Endpoint`] if found.
    fn receive_udp(&mut self, udp_addr: SocketAddr) -> Option<(PublicKey, QuicMappedAddr)> {
        let ip_port: IpPort = udp_addr.into();
        let Some(endpoint) = self.get_mut(EndpointId::IpPort(&ip_port)) else {
            info!(src=%udp_addr, "receive_udp: no peer_map state found for addr, ignore");
            return None;
        };
        endpoint.receive_udp(ip_port, Instant::now());
        Some((*endpoint.public_key(), *endpoint.quic_mapped_addr()))
    }

    fn receive_derp(&mut self, region_id: u16, src: &PublicKey) -> QuicMappedAddr {
        let endpoint = self.get_or_insert_with(EndpointId::NodeKey(src), || {
            info!(peer=%src.fmt_short(), "receive_derp: packets from unknown peer, insert into peer map");
            Options {
                public_key: *src,
                derp_region: Some(region_id),
                active: true,
            }
        });
        endpoint.receive_derp(region_id, src, Instant::now());
        *endpoint.quic_mapped_addr()
    }

    fn endpoints(&self) -> impl Iterator<Item = (&usize, &Endpoint)> {
        self.by_id.iter()
    }

    fn endpoints_mut(&mut self) -> impl Iterator<Item = (&usize, &mut Endpoint)> {
        self.by_id.iter_mut()
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    fn endpoint_infos(&self, now: Instant) -> Vec<EndpointInfo> {
        self.endpoints().map(|(_, ep)| ep.info(now)).collect()
    }

    /// Get the [`EndpointInfo`]s for each endpoint
    fn endpoint_info(&self, public_key: &PublicKey) -> Option<EndpointInfo> {
        self.get(EndpointId::NodeKey(public_key))
            .map(|ep| ep.info(Instant::now()))
    }

    fn handle_pong(&mut self, sender: PublicKey, src: &DiscoMessageSource, pong: Pong) {
        if let Some(ep) = self.get_mut(EndpointId::NodeKey(&sender)).as_mut() {
            let insert = ep.handle_pong(&pong, src.into());
            if let Some((src, key)) = insert {
                self.set_node_key_for_ip_port(src, &key);
            }
            debug!(?insert, "received pong")
        } else {
            warn!("received pong: peer unknown, ignore")
        }
    }

    #[must_use = "actions must be handled"]
    fn handle_call_me_maybe(&mut self, sender: PublicKey, cm: CallMeMaybe) -> Vec<PingAction> {
        match self.get_mut(EndpointId::NodeKey(&sender)) {
            None => {
                inc!(MagicsockMetrics, recv_disco_call_me_maybe_bad_disco);
                debug!("received call-me-maybe: ignore, peer is unknown");
                vec![]
            }
            Some(ep) => {
                debug!(endpoints = ?cm.my_number, clear_pongs = %cm.clear_pongs, "received call-me-maybe");
                ep.handle_call_me_maybe(cm)
            }
        }
    }

    fn handle_ping(&mut self, sender: PublicKey, src: SendAddr, tx_id: TransactionId) -> PingRole {
        let endpoint = self.get_or_insert_with(EndpointId::NodeKey(&sender), || {
            debug!("received ping: peer unknown, add to peer map");
            Options {
                public_key: sender,
                derp_region: src.derp_region(),
                active: true,
            }
        });

        let role = endpoint.handle_ping(src, tx_id);
        if let SendAddr::Udp(addr) = src {
            if matches!(role, PingRole::NewEndpoint) {
                self.set_node_key_for_ip_port(addr, &sender);
            }
        }
        role
    }

    /// Inserts a new endpoint into the [`PeerMap`].
    fn insert_endpoint(&mut self, options: Options) -> &mut Endpoint {
        info!(peer = %options.public_key.fmt_short(), derp_region = ?options.derp_region, "inserting new peer endpoint in PeerMap");
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let ep = Endpoint::new(id, options);

        // update indices
        self.by_quic_mapped_addr.insert(*ep.quic_mapped_addr(), id);
        self.by_node_key.insert(*ep.public_key(), id);

        self.by_id.insert(id, ep);
        self.by_id.get_mut(&id).expect("just inserted")
    }

    /// Makes future peer lookups by ipp return the same endpoint as a lookup by nk.
    ///
    /// This should only be called with a fully verified mapping of ipp to
    /// nk, because calling this function defines the endpoint we hand to
    /// WireGuard for packets received from ipp.
    fn set_node_key_for_ip_port(&mut self, ipp: impl Into<IpPort>, nk: &PublicKey) {
        let ipp = ipp.into();
        if let Some(id) = self.by_ip_port.get(&ipp) {
            if !self.by_node_key.contains_key(nk) {
                self.by_node_key.insert(*nk, *id);
            }
            self.by_ip_port.remove(&ipp);
        }
        if let Some(id) = self.by_node_key.get(nk) {
            trace!("insert ip -> id: {:?} -> {}", ipp, id);
            self.by_ip_port.insert(ipp, *id);
        }
    }

    fn set_endpoint_for_ip_port(&mut self, ipp: impl Into<IpPort>, id: usize) {
        let ipp = ipp.into();
        trace!(?ipp, ?id, "set endpoint for ip:port");
        self.by_ip_port.insert(ipp, id);
    }

    /// Prunes peers without recent activity so that at most [`MAX_INACTIVE_PEERS`] are kept.
    fn prune_inactive(&mut self) {
        let now = Instant::now();
        let mut prune_candidates: Vec<_> = self
            .by_id
            .values()
            .filter(|peer| !peer.is_active(&now))
            .map(|peer| (*peer.public_key(), peer.last_used()))
            .collect();

        let prune_count = prune_candidates.len().saturating_sub(MAX_INACTIVE_PEERS);
        if prune_count == 0 {
            // within limits
            return;
        }

        prune_candidates.sort_unstable_by_key(|(_pk, last_used)| *last_used);
        prune_candidates.truncate(prune_count);
        for (public_key, last_used) in prune_candidates.into_iter() {
            let peer = public_key.fmt_short();
            match last_used.map(|instant| instant.elapsed()) {
                Some(last_used) => trace!(%peer, ?last_used, "pruning inactive"),
                None => trace!(%peer, last_used=%"never", "pruning inactive"),
            }

            let Some(id) = self.by_node_key.remove(&public_key) else {
                debug_assert!(false, "missing by_node_key entry for pk in by_id");
                continue;
            };

            let Some(ep) = self.by_id.remove(&id) else {
                debug_assert!(false, "missing by_id entry for id in by_node_key");
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
#[derive(Debug, derive_more::Display, Clone, Copy, Hash, PartialEq, Eq)]
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
    use super::endpoint::MAX_INACTIVE_DIRECT_ADDRESSES;
    use super::*;
    use crate::{key::SecretKey, magic_endpoint::AddrInfo};
    use std::net::Ipv4Addr;

    /// Test persisting and loading of known peers.
    #[tokio::test]
    async fn load_save_peer_data() {
        let _guard = iroh_test::logging::setup();

        let peer_map = PeerMap::default();

        let peer_a = SecretKey::generate().public();
        let peer_b = SecretKey::generate().public();
        let peer_c = SecretKey::generate().public();
        let peer_d = SecretKey::generate().public();

        let region_x = 1;
        let region_y = 2;

        fn addr(port: u16) -> SocketAddr {
            (std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), port).into()
        }

        let direct_addresses_a = [addr(4000), addr(4001)];
        let direct_addresses_c = [addr(5000)];

        let peer_addr_a = PeerAddr::new(peer_a)
            .with_derp_region(region_x)
            .with_direct_addresses(direct_addresses_a);
        let peer_addr_b = PeerAddr::new(peer_b).with_derp_region(region_y);
        let peer_addr_c = PeerAddr::new(peer_c).with_direct_addresses(direct_addresses_c);
        let peer_addr_d = PeerAddr::new(peer_d);

        peer_map.add_peer_addr(peer_addr_a);
        peer_map.add_peer_addr(peer_addr_b);
        peer_map.add_peer_addr(peer_addr_c);
        peer_map.add_peer_addr(peer_addr_d);

        let root = testdir::testdir!();
        let path = root.join("peers.postcard");
        peer_map.save_to_file(&path).await.unwrap();

        let loaded_peer_map = PeerMap::load_from_file(&path).unwrap();
        let loaded: HashMap<PublicKey, AddrInfo> = loaded_peer_map
            .known_peer_addresses()
            .into_iter()
            .map(|PeerAddr { peer_id, info }| (peer_id, info))
            .collect();

        let og: HashMap<PublicKey, AddrInfo> = peer_map
            .known_peer_addresses()
            .into_iter()
            .map(|PeerAddr { peer_id, info }| (peer_id, info))
            .collect();
        // compare the peer maps via their known peers
        assert_eq!(og, loaded);
    }

    #[test]
    fn test_prune_direct_addresses() {
        let _guard = iroh_test::logging::setup();

        let peer_map = PeerMap::default();
        let public_key = SecretKey::generate().public();
        let id = peer_map
            .inner
            .lock()
            .insert_endpoint(Options {
                public_key,
                derp_region: None,
                active: false,
            })
            .id();

        const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        // add [`MAX_INACTIVE_DIRECT_ADDRESSES`] active direct addresses and double
        // [`MAX_INACTIVE_DIRECT_ADDRESSES`] that are inactive

        // active adddresses
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SocketAddr::new(LOCALHOST, 5000 + i as u16);
            let peer_addr = PeerAddr::new(public_key).with_direct_addresses([addr]);
            // add address
            peer_map.add_peer_addr(peer_addr);
            // make it active
            peer_map.inner.lock().receive_udp(addr);
        }

        // offline adddresses
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SocketAddr::new(LOCALHOST, 6000 + i as u16);
            let peer_addr = PeerAddr::new(public_key).with_direct_addresses([addr]);
            peer_map.add_peer_addr(peer_addr);
        }

        let mut peer_map_inner = peer_map.inner.lock();
        let endpoint = peer_map_inner.by_id.get_mut(&id).unwrap();

        // online but inactive addresses discovered via ping
        for i in 0..MAX_INACTIVE_DIRECT_ADDRESSES {
            let addr = SendAddr::Udp(SocketAddr::new(LOCALHOST, 7000 + i as u16));
            let txid = stun::TransactionId::from([i as u8; 12]);
            endpoint.handle_ping(addr, txid);
        }

        endpoint.prune_direct_addresses();

        assert_eq!(
            endpoint.direct_addresses().count(),
            MAX_INACTIVE_DIRECT_ADDRESSES * 2
        );

        assert_eq!(
            endpoint
                .direct_address_states()
                .filter(|(_addr, state)| !state.is_active())
                .count(),
            MAX_INACTIVE_DIRECT_ADDRESSES
        )
    }

    #[test]
    fn test_prune_inactive() {
        let peer_map = PeerMap::default();
        // add one active peer and more than MAX_INACTIVE_PEERS inactive peers
        let active_peer = SecretKey::generate().public();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 167);
        peer_map.add_peer_addr(PeerAddr::new(active_peer).with_direct_addresses([addr]));
        peer_map.inner.lock().receive_udp(addr).expect("registered");

        for _ in 0..MAX_INACTIVE_PEERS + 1 {
            let peer = SecretKey::generate().public();
            peer_map.add_peer_addr(PeerAddr::new(peer));
        }

        assert_eq!(peer_map.node_count(), MAX_INACTIVE_PEERS + 2);
        peer_map.prune_inactive();
        assert_eq!(peer_map.node_count(), MAX_INACTIVE_PEERS + 1);
        peer_map
            .inner
            .lock()
            .get(EndpointId::NodeKey(&active_peer))
            .expect("should not be pruned");
    }
}

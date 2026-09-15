//! Typed transport routing. Synthetic addresses are local QUIC handles only;
//! every relay route retains the complete peer ID and relay URL.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::sync::mpsc;

use super::{Error, PeerId};
use crate::{
    RelayUrl,
    metrics::EndpointMetrics,
    socket::transports::{IpTransport, TransportConfig},
};

const MAX_ROUTES: usize = 4096;
const RESERVED_ROUTES: usize = 64;
const ROUTE_GRACE: std::time::Duration = std::time::Duration::from_secs(30);
const QUEUE: usize = 256;
/// Unique local prefix for synthetic relay handles: fd15:70a:51ff::/64, port 1.
const SYNTHETIC_PREFIX: [u16; 4] = [0xfd15, 0x70a, 0x51ff, 0];
const SYNTHETIC_PORT: u16 = 1;

/// Whether an address is a synthetic relay handle. Such addresses must never
/// reach a real socket, even after their route has been pruned.
fn is_synthetic(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V6(ip) => {
            ip.segments()[..4] == SYNTHETIC_PREFIX && address.port() == SYNTHETIC_PORT
        }
        IpAddr::V4(_) => false,
    }
}

#[derive(Clone, Debug)]
pub(super) struct RelayDatagram {
    pub peer: PeerId,
    pub contents: Bytes,
}

#[derive(Debug)]
struct Received {
    relay: RelayUrl,
    datagram: RelayDatagram,
}

#[derive(Default, Debug)]
struct Routes {
    next: u64,
    addresses: HashMap<(PeerId, RelayUrl), SocketAddr>,
    peers: HashMap<SocketAddr, (PeerId, RelayUrl)>,
    expires: HashMap<SocketAddr, tokio::time::Instant>,
    pinned: HashMap<PeerId, usize>,
    next_prune: Option<tokio::time::Instant>,
    relays: HashMap<RelayUrl, mpsc::Sender<RelayDatagram>>,
}

/// A cloneable routing handle used by endpoint and relay actors.
#[derive(Clone, Debug)]
pub(super) struct Routing {
    routes: Arc<RwLock<Routes>>,
    incoming: mpsc::Sender<Received>,
    local: Arc<RwLock<Vec<SocketAddr>>>,
}

/// Keeps a peer's relay routes alive through dialing and connection lifetime.
#[derive(Debug)]
pub(super) struct RouteLease(Routing, PeerId);

impl Drop for RouteLease {
    fn drop(&mut self) {
        let mut routes = self.0.routes.write().expect("poisoned routing table");
        let count = routes.pinned.get_mut(&self.1).expect("route lease exists");
        *count -= 1;
        if *count == 0 {
            routes.pinned.remove(&self.1);
            let deadline = tokio::time::Instant::now() + ROUTE_GRACE;
            let Routes { peers, expires, .. } = &mut *routes;
            for (address, (peer, _)) in peers.iter() {
                if *peer == self.1 {
                    expires.insert(*address, deadline);
                }
            }
        }
    }
}

impl Routing {
    pub(super) fn pin_route(&self, address: SocketAddr) -> Option<RouteLease> {
        let mut routes = self.routes.write().expect("poisoned routing table");
        let peer = routes.peers.get(&address)?.0;
        *routes.pinned.entry(peer).or_default() += 1;
        Some(RouteLease(self.clone(), peer))
    }

    pub(super) fn pin(&self, peer: PeerId) -> RouteLease {
        *self
            .routes
            .write()
            .expect("poisoned routing table")
            .pinned
            .entry(peer)
            .or_default() += 1;
        RouteLease(self.clone(), peer)
    }

    pub(super) fn relay_address(&self, peer: PeerId, relay: RelayUrl) -> Result<SocketAddr, Error> {
        self.address(peer, relay, false)
    }

    pub(super) fn dial_address(&self, peer: PeerId, relay: RelayUrl) -> Result<SocketAddr, Error> {
        self.address(peer, relay, true)
    }

    fn address(
        &self,
        peer: PeerId,
        relay: RelayUrl,
        local_dial: bool,
    ) -> Result<SocketAddr, Error> {
        // Established routes are the common case for every inbound relay
        // packet; only a miss takes the exclusive lock.
        if let Some(address) = self
            .routes
            .read()
            .expect("poisoned routing table")
            .addresses
            .get(&(peer, relay.clone()))
        {
            return Ok(*address);
        }
        let mut routes = self.routes.write().expect("poisoned routing table");
        if let Some(address) = routes.addresses.get(&(peer, relay.clone())) {
            return Ok(*address);
        }
        let now = tokio::time::Instant::now();
        // Only prune at admission pressure. Unverified traffic never extends a lease.
        if routes.addresses.len() >= MAX_ROUTES - RESERVED_ROUTES
            && routes.next_prune.is_none_or(|deadline| now >= deadline)
        {
            routes.next_prune = Some(now + std::time::Duration::from_secs(1));
            let Routes {
                addresses,
                peers,
                expires,
                pinned,
                ..
            } = &mut *routes;
            addresses.retain(|(peer, _), address| {
                if pinned.contains_key(peer) || expires[address] > now {
                    true
                } else {
                    peers.remove(address);
                    expires.remove(address);
                    false
                }
            });
        }
        let limit = if local_dial {
            MAX_ROUTES
        } else {
            MAX_ROUTES - RESERVED_ROUTES
        };
        if routes.addresses.len() >= limit {
            return Err(Error::Protocol("routing table full"));
        }
        routes.next = routes
            .next
            .checked_add(1)
            .ok_or(Error::Protocol("route counter exhausted"))?;
        let n = routes.next;
        let address = SocketAddr::new(
            Ipv6Addr::new(
                SYNTHETIC_PREFIX[0],
                SYNTHETIC_PREFIX[1],
                SYNTHETIC_PREFIX[2],
                SYNTHETIC_PREFIX[3],
                (n >> 48) as u16,
                (n >> 32) as u16,
                (n >> 16) as u16,
                n as u16,
            )
            .into(),
            SYNTHETIC_PORT,
        );
        routes.addresses.insert((peer, relay.clone()), address);
        routes.peers.insert(address, (peer, relay));
        routes.expires.insert(address, now + ROUTE_GRACE);
        Ok(address)
    }

    pub(super) fn relay_for(&self, address: SocketAddr) -> Option<(PeerId, RelayUrl)> {
        self.routes
            .read()
            .expect("poisoned routing table")
            .peers
            .get(&address)
            .cloned()
    }

    pub(super) fn local_addrs(&self) -> Vec<SocketAddr> {
        self.local.read().expect("poisoned addresses").clone()
    }

    pub(super) fn add_relay(&self, relay: RelayUrl) -> mpsc::Receiver<RelayDatagram> {
        let (tx, rx) = mpsc::channel(QUEUE);
        self.routes
            .write()
            .expect("poisoned routing table")
            .relays
            .insert(relay, tx);
        rx
    }

    /// Forget a relay and every route through it. Packets for those synthetic
    /// addresses are dropped afterwards, so QUIC abandons the paths.
    pub(super) fn remove_relay(&self, relay: &RelayUrl) {
        let mut routes = self.routes.write().expect("poisoned routing table");
        routes.relays.remove(relay);
        let Routes {
            addresses,
            peers,
            expires,
            ..
        } = &mut *routes;
        addresses.retain(|(_, route_relay), address| {
            if route_relay == relay {
                peers.remove(address);
                expires.remove(address);
                false
            } else {
                true
            }
        });
    }

    /// Whether a pinned peer, dialing or connected, currently routes via this relay.
    pub(super) fn relay_in_use(&self, relay: &RelayUrl) -> bool {
        let routes = self.routes.read().expect("poisoned routing table");
        routes
            .addresses
            .keys()
            .any(|(peer, route_relay)| route_relay == relay && routes.pinned.contains_key(peer))
    }

    pub(super) fn received(&self, relay: RelayUrl, datagram: RelayDatagram) -> Result<(), Error> {
        if datagram.contents.is_empty() || datagram.contents.len() > 65535 {
            return Err(Error::Protocol("invalid datagram size"));
        }
        match self.incoming.try_send(Received { relay, datagram }) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::Closed),
        }
    }
}

#[derive(Debug)]
pub(super) struct Transport {
    ip: Vec<IpTransport>,
    routing: Routing,
    received: mpsc::Receiver<Received>,
    next_ip: usize,
    prefer_ip: bool,
}

impl Transport {
    fn poll_ip(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        for _ in 0..self.ip.len() {
            let index = self.next_ip;
            self.next_ip = (self.next_ip + 1) % self.ip.len();
            match noq::AsyncUdpSocket::poll_recv(&mut self.ip[index], cx, bufs, metas) {
                Poll::Ready(Ok(count)) => {
                    for meta in &mut metas[..count] {
                        if let IpAddr::V4(ip) = meta.addr.ip() {
                            meta.addr.set_ip(ip.to_ipv6_mapped().into());
                        }
                    }
                    return Poll::Ready(Ok(count));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }

    pub(super) fn bind(configs: &[TransportConfig]) -> Result<(Self, Routing), Error> {
        use noq::AsyncUdpSocket;
        let metrics = EndpointMetrics::default();
        let mut ip = Vec::new();
        for config in configs {
            if let TransportConfig::Ip { config, .. } = config {
                match IpTransport::bind(*config, metrics.socket.clone()) {
                    Ok(socket) => ip.push(socket),
                    Err(error) if config.is_required() => return Err(error.into()),
                    Err(_) => {}
                }
            }
        }
        let local = ip
            .iter()
            .map(AsyncUdpSocket::local_addr)
            .collect::<Result<Vec<_>, _>>()?;
        let (incoming, received) = mpsc::channel(QUEUE);
        let routing = Routing {
            routes: Default::default(),
            incoming,
            local: Arc::new(RwLock::new(local)),
        };
        Ok((
            Self {
                ip,
                routing: routing.clone(),
                received,
                next_ip: 0,
                prefer_ip: false,
            },
            routing,
        ))
    }
}

impl noq::AsyncUdpSocket for Transport {
    fn create_sender(&self) -> Pin<Box<dyn noq::UdpSender>> {
        let ip = self
            .ip
            .iter()
            .map(|socket| {
                (
                    noq::AsyncUdpSocket::local_addr(socket).expect("bound socket"),
                    noq::AsyncUdpSocket::create_sender(socket),
                )
            })
            .collect();
        Box::pin(Sender {
            ip,
            routing: self.routing.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || metas.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Alternate successful deliveries. A saturated relay queue must not
        // prevent polling the native sockets (including NAT traversal probes).
        let polled_ip = self.prefer_ip;
        if polled_ip && let Poll::Ready(result) = self.poll_ip(cx, bufs, metas) {
            self.prefer_ip = false;
            return Poll::Ready(result);
        }
        if let Poll::Ready(Some(received)) = self.received.poll_recv(cx) {
            self.prefer_ip = true;
            let contents = &received.datagram.contents;
            if contents.len() <= bufs[0].len()
                && let Ok(address) = self
                    .routing
                    .relay_address(received.datagram.peer, received.relay)
            {
                bufs[0][..contents.len()].copy_from_slice(contents);
                metas[0] = noq_udp::RecvMeta::default();
                metas[0].addr = address;
                metas[0].len = contents.len();
                metas[0].stride = contents.len();
                return Poll::Ready(Ok(1));
            }
            // Oversized packets and route exhaustion must not prevent IP progress.
            cx.waker().wake_by_ref();
        }
        if !polled_ip {
            let result = self.poll_ip(cx, bufs, metas);
            if result.is_ready() {
                self.prefer_ip = false;
            }
            return result;
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let address = self
            .routing
            .local_addrs()
            .first()
            .copied()
            .unwrap_or_else(|| SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0));
        Ok(match address {
            SocketAddr::V4(address) => {
                SocketAddr::new(address.ip().to_ipv6_mapped().into(), address.port())
            }
            address => address,
        })
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.ip
            .iter()
            .map(noq::AsyncUdpSocket::max_receive_segments)
            .max()
            .unwrap_or(NonZeroUsize::MIN)
    }

    fn may_fragment(&self) -> bool {
        self.ip.iter().any(noq::AsyncUdpSocket::may_fragment)
    }
}

type IpSender = (SocketAddr, Pin<Box<dyn noq::UdpSender>>);

#[derive(Debug)]
struct Sender {
    ip: Vec<IpSender>,
    routing: Routing,
}

impl noq::UdpSender for Sender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &noq_udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if is_synthetic(transmit.destination) {
            // Native traffic never reaches this branch, so it never takes the lock.
            let routes = this.routing.routes.read().expect("poisoned routing table");
            let Some((peer, relay)) = routes.peers.get(&transmit.destination) else {
                // The route was pruned. A synthetic address must never be
                // written to a real socket; treat the packet as lost instead.
                return Poll::Ready(Ok(()));
            };
            let peer = *peer;
            let sender = routes.relays.get(relay).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "relay not connected")
            })?;
            let segment = transmit
                .segment_size
                .unwrap_or(transmit.contents.len())
                .max(1);
            for contents in transmit.contents.chunks(segment) {
                // Bounded UDP-style queue: congestion drops datagrams and QUIC retries.
                match sender.try_send(RelayDatagram {
                    peer,
                    contents: Bytes::copy_from_slice(contents),
                }) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "relay closed",
                        )));
                    }
                }
            }
            return Poll::Ready(Ok(()));
        }
        let mut transmit = transmit.clone();
        transmit
            .destination
            .set_ip(transmit.destination.ip().to_canonical());
        transmit.src_ip = transmit.src_ip.map(|ip| ip.to_canonical());
        for (local, sender) in &mut this.ip {
            if local.is_ipv4() == transmit.destination.is_ipv4()
                && transmit
                    .src_ip
                    .is_none_or(|ip| local.ip().is_unspecified() || local.ip() == ip)
            {
                return sender.as_mut().poll_send(&transmit, cx);
            }
        }
        // An authenticated NAT traversal peer can advertise an address family
        // we did not bind. Treat its probe as lost so QUIC abandons that path;
        // a socket-wide I/O error would close an otherwise healthy connection.
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::transports::IpConfig;

    fn datagram() -> RelayDatagram {
        RelayDatagram {
            peer: PeerId::V1([7; 48]),
            contents: Bytes::from_static(b"relay"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn route_exhaustion_recovers_and_preserves_connection_leases() {
        let (_transport, routing) = Transport::bind(&[]).unwrap();
        let relay: RelayUrl = "http://127.0.0.1:1234".parse().unwrap();
        let active = PeerId::V1([255; 48]);
        let lease = routing.pin(active);
        let active_addr = routing.relay_address(active, relay.clone()).unwrap();
        let mut first = None;
        for n in 0..MAX_ROUTES - RESERVED_ROUTES - 1 {
            let mut id = [0; 48];
            id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            let addr = routing
                .relay_address(PeerId::V1(id), relay.clone())
                .unwrap();
            first.get_or_insert(addr);
        }
        let newcomer = PeerId::V1([254; 48]);
        assert!(routing.relay_address(newcomer, relay.clone()).is_err());
        // Locally requested dials retain admission under unauthenticated pressure.
        let dial = routing.pin(newcomer);
        let dial_addr = routing.dial_address(newcomer, relay.clone()).unwrap();
        tokio::time::advance(ROUTE_GRACE).await;
        let other = PeerId::V1([253; 48]);
        let other_addr = routing.relay_address(other, relay.clone()).unwrap();
        assert!(routing.relay_for(first.unwrap()).is_none());
        assert_ne!(other_addr, first.unwrap());
        assert_eq!(
            routing.relay_for(active_addr),
            Some((active, relay.clone()))
        );
        assert_eq!(
            routing.relay_for(dial_addr),
            Some((newcomer, relay.clone()))
        );
        drop(dial);
        drop(lease);
        // Release grants a drain grace period, not permanent ownership.
        assert_eq!(
            routing.routes.read().unwrap().expires[&active_addr],
            tokio::time::Instant::now() + ROUTE_GRACE
        );
        assert!(routing.routes.read().unwrap().pinned.is_empty());
    }

    #[tokio::test]
    async fn inbound_congestion_does_not_block_the_relay_actor() {
        let (_transport, routing) = Transport::bind(&[]).unwrap();
        let relay: RelayUrl = "http://127.0.0.1:1234".parse().unwrap();
        // `received` is synchronous: a full queue must report success and drop.
        for _ in 0..QUEUE + 1 {
            routing.received(relay.clone(), datagram()).unwrap();
        }
    }

    fn transmit(destination: SocketAddr, contents: &[u8]) -> noq_udp::Transmit<'_> {
        noq_udp::Transmit {
            destination,
            ecn: None,
            contents,
            segment_size: None,
            src_ip: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pruned_synthetic_routes_are_dropped_instead_of_sent_over_ip() {
        use noq::AsyncUdpSocket;
        let config = TransportConfig::Ip {
            config: IpConfig::V6 {
                ip_net: "::1/128".parse().unwrap(),
                port: 0,
                scope_id: 0,
                is_required: true,
                is_default: true,
            },
            is_user_defined: true,
        };
        let (transport, routing) = Transport::bind(&[config]).unwrap();
        let relay: RelayUrl = "http://127.0.0.1:1234".parse().unwrap();
        let mut sender = transport.create_sender();
        let stale = routing
            .relay_address(PeerId::V1([9; 48]), relay.clone())
            .unwrap();
        assert!(is_synthetic(stale));
        // Fill the table so that admission pressure prunes the unpinned route.
        for n in 0..MAX_ROUTES - RESERVED_ROUTES - 1 {
            let mut id = [0; 48];
            id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            routing
                .relay_address(PeerId::V1(id), relay.clone())
                .unwrap();
        }
        tokio::time::advance(ROUTE_GRACE).await;
        let _pinned = routing.pin(PeerId::V1([8; 48]));
        routing
            .dial_address(PeerId::V1([8; 48]), relay.clone())
            .unwrap();
        assert!(routing.relay_for(stale).is_none());
        // A watcher on the bound socket would observe a leaked packet as a
        // real datagram; the sender must instead report the packet as lost.
        let probe = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = sender
            .as_mut()
            .poll_send(&transmit(stale, b"retransmit"), &mut cx);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        let mut buffer = [0; 16];
        assert!(probe.try_recv(&mut buffer).is_err());
        // Live routes without a connected relay still surface an error.
        assert!(matches!(
            sender.as_mut().poll_send(
                &transmit(
                    routing.dial_address(PeerId::V1([8; 48]), relay).unwrap(),
                    b"x"
                ),
                &mut cx
            ),
            Poll::Ready(Err(_))
        ));
    }

    #[tokio::test]
    async fn removing_a_relay_forgets_its_routes_and_reports_pinned_use() {
        let (_transport, routing) = Transport::bind(&[]).unwrap();
        let relay: RelayUrl = "http://127.0.0.1:1234".parse().unwrap();
        let other: RelayUrl = "http://127.0.0.1:1235".parse().unwrap();
        let peer = PeerId::V1([1; 48]);
        let _outgoing = routing.add_relay(relay.clone());
        assert!(!routing.relay_in_use(&relay));
        let address = routing.relay_address(peer, relay.clone()).unwrap();
        assert!(!routing.relay_in_use(&relay));
        let lease = routing.pin(peer);
        assert!(routing.relay_in_use(&relay));
        assert!(!routing.relay_in_use(&other));
        let kept = routing.relay_address(peer, other.clone()).unwrap();
        routing.remove_relay(&relay);
        assert!(routing.relay_for(address).is_none());
        assert_eq!(routing.relay_for(kept), Some((peer, other)));
        assert!(!routing.relay_in_use(&relay));
        drop(lease);
    }

    async fn direct_progress(full_routes: bool) {
        use noq::AsyncUdpSocket;
        let config = TransportConfig::Ip {
            config: IpConfig::V4 {
                ip_net: "127.0.0.1/32".parse().unwrap(),
                port: 0,
                is_required: true,
                is_default: true,
            },
            is_user_defined: true,
        };
        let (mut transport, routing) = Transport::bind(&[config]).unwrap();
        let relay: RelayUrl = "http://127.0.0.1:1234".parse().unwrap();
        if full_routes {
            for n in 0..MAX_ROUTES - RESERVED_ROUTES {
                let mut id = [0; 48];
                id[..8].copy_from_slice(&(n as u64).to_be_bytes());
                routing
                    .relay_address(PeerId::V1(id), relay.clone())
                    .unwrap();
            }
        }
        for _ in 0..QUEUE {
            routing.received(relay.clone(), datagram()).unwrap();
        }
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"direct", routing.local_addrs()[0])
            .await
            .unwrap();
        // The transport alternates sources, so the direct packet must surface
        // within a small number of deliveries regardless of relay pressure.
        let mut delivered = false;
        for _ in 0..QUEUE {
            tokio::task::yield_now().await;
            let mut data = [0; 128];
            let mut metas = [noq_udp::RecvMeta::default()];
            std::future::poll_fn(|cx| {
                let _ = routing.incoming.try_send(Received {
                    relay: relay.clone(),
                    datagram: datagram(),
                });
                transport.poll_recv(cx, &mut [io::IoSliceMut::new(&mut data)], &mut metas)
            })
            .await
            .unwrap();
            if &data[..metas[0].len] == b"direct" {
                delivered = true;
                break;
            }
            // Keep the relay queue busy even while the UDP socket is ready.
            routing.received(relay.clone(), datagram()).unwrap();
        }
        assert!(
            delivered,
            "relay traffic must not starve direct UDP traffic"
        );
    }

    #[tokio::test]
    async fn direct_traffic_progresses_under_continuous_relay_input() {
        direct_progress(false).await;
    }

    #[tokio::test]
    async fn full_route_table_does_not_starve_direct_traffic() {
        direct_progress(true).await;
    }
}

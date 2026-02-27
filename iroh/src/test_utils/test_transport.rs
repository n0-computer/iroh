//! In-memory test transport for testing.
//!
//! This module provides [`TestNetwork`] and [`TestTransport`] for testing
//! using in-memory channels instead of real network transports.

use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
    task::Poll,
};

use bytes::Bytes;
use iroh_base::{CustomAddr, EndpointId, TransportAddr};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::info;

use crate::{
    address_lookup::{AddressLookup, EndpointData, EndpointInfo, Item},
    endpoint::{
        Builder,
        presets::Preset,
        transports::{Addr, CustomEndpoint, CustomSender, CustomTransport, Transmit},
    },
};

/// The transport ID used by [`TestNetwork`].
///
/// See `TRANSPORTS.md` for the registry of transport IDs.
pub const TEST_TRANSPORT_ID: u64 = 0x20;

/// An outgoing packet that can be sent across channels.
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    pub(crate) data: Bytes,
    pub(crate) from: CustomAddr,
}

/// A test transport for use with [`TestNetwork`].
///
/// Implements [`CustomTransport`] and [`CustomEndpoint`] for testing.
#[derive(Debug, Clone)]
pub struct TestTransport {
    id: EndpointId,
    id_watchable: n0_watcher::Watchable<Vec<CustomAddr>>,
    network: TestNetwork,
}

impl Preset for Arc<TestTransport> {
    /// Configures the builder with this transport and the network's address lookup.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let network = TestNetwork::new();
    /// let transport = network.create_transport(secret_key.public())?;
    /// let ep = Endpoint::builder()
    ///     .secret_key(secret_key)
    ///     .preset(transport)
    ///     .bind()
    ///     .await?;
    /// ```
    fn apply(self, builder: Builder) -> Builder {
        builder
            .add_custom_transport(self.clone())
            .address_lookup(self.network.address_lookup())
    }
}

/// A simulated network for testing custom transports.
///
/// This allows creating multiple [`TestTransport`] instances that can communicate
/// with each other through in-memory channels.
///
/// # Example
///
/// ```ignore
/// use iroh::test_utils::custom_transport::TestNetwork;
///
/// let network = TestNetwork::new();
/// let transport1 = network.create_transport(endpoint_id1)?;
/// let transport2 = network.create_transport(endpoint_id2)?;
/// // transport1 and transport2 can now communicate via the network
/// ```
#[derive(Debug, Clone, Default)]
pub struct TestNetwork {
    inner: Arc<Mutex<TestNetworkInner>>,
}

impl TestNetwork {
    /// Creates a new empty test network.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an address lookup service for this network.
    pub fn address_lookup(&self) -> impl AddressLookup {
        TestAddrLookup {
            network: self.clone(),
        }
    }

    /// Creates a new test transport for the given endpoint ID.
    ///
    /// Returns an error if the ID already exists in the network.
    pub fn create_transport(&self, id: EndpointId) -> io::Result<Arc<TestTransport>> {
        let id_custom = to_custom_addr(id);
        let mut guard = self.inner.lock().expect("poisoned");
        if guard.channels.contains_key(&id) {
            return Err(io::Error::other("endpoint ID already exists in network"));
        }
        guard.channels.insert(id, mpsc::channel(256));
        drop(guard);
        Ok(Arc::new(TestTransport {
            id_watchable: n0_watcher::Watchable::new(vec![id_custom]),
            network: self.clone(),
            id,
        }))
    }
}

#[derive(Debug)]
struct TestAddrLookup {
    network: TestNetwork,
}

#[derive(Debug, Default)]
struct TestNetworkInner {
    channels: BTreeMap<EndpointId, (mpsc::Sender<Packet>, mpsc::Receiver<Packet>)>,
}

impl AddressLookup for TestAddrLookup {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<n0_future::stream::Boxed<Result<Item, crate::address_lookup::Error>>> {
        if self
            .network
            .inner
            .lock()
            .expect("poisoned")
            .channels
            .contains_key(&endpoint_id)
        {
            Some(Box::pin(n0_future::stream::once(Ok(Item::new(
                EndpointInfo {
                    endpoint_id,
                    data: EndpointData::new([TransportAddr::Custom(CustomAddr::from_parts(
                        TEST_TRANSPORT_ID,
                        endpoint_id.as_bytes(),
                    ))]),
                },
                "test discovery",
                None,
            )))))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
struct TestSender {
    id: EndpointId,
    network: TestNetwork,
}

/// Converts an endpoint ID to a custom address for this test transport.
pub fn to_custom_addr(endpoint: EndpointId) -> CustomAddr {
    CustomAddr::from((TEST_TRANSPORT_ID, &endpoint.as_bytes()[..]))
}

fn try_parse_custom_addr(addr: &CustomAddr) -> io::Result<EndpointId> {
    if addr.id() != TEST_TRANSPORT_ID {
        return Err(io::Error::other("unexpected transport id"));
    }
    let key_bytes: &[u8; 32] = addr
        .data()
        .try_into()
        .map_err(|_| io::Error::other("wrong key length"))?;
    EndpointId::from_bytes(key_bytes).map_err(|_| io::Error::other("KeyParseError"))
}

impl TestSender {
    fn send_sync(&self, dst: &CustomAddr, packets: Vec<Packet>) -> io::Result<()> {
        let to_id = try_parse_custom_addr(dst)?;
        let guard = self.network.inner.lock().expect("poisoned");
        let (s, _) = guard
            .channels
            .get(&to_id)
            .ok_or_else(|| io::Error::other("Unknown endpoint"))?;
        for packet in packets {
            let len = packet.data.len();
            match s.try_send(packet) {
                Ok(_) => info!(
                    "send {} -> {}: sent {} bytes",
                    self.id.fmt_short(),
                    to_id.fmt_short(),
                    len
                ),
                Err(TrySendError::Full(_)) => info!(
                    "send {} -> {}: dropped {} bytes",
                    self.id.fmt_short(),
                    to_id.fmt_short(),
                    len
                ),
                Err(TrySendError::Closed(_)) => return Err(io::Error::other("channel closed")),
            }
        }
        Ok(())
    }

    fn split(&self, transmit: &Transmit) -> impl Iterator<Item = Packet> {
        let from = to_custom_addr(self.id);
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        transmit
            .contents
            .chunks(segment_size)
            .map(move |slice| Packet {
                from: from.clone(),
                data: Bytes::copy_from_slice(slice),
            })
    }
}

impl CustomSender for TestSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == TEST_TRANSPORT_ID
    }

    fn poll_send(
        &self,
        _cx: &mut std::task::Context,
        dst: &CustomAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let packets = self.split(transmit).collect();
        Poll::Ready(self.send_sync(dst, packets))
    }
}

impl CustomTransport for TestTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        Ok(Box::new(self.clone()))
    }
}

impl CustomEndpoint for TestTransport {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.id_watchable.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(TestSender {
            id: self.id,
            network: self.network.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        let n = bufs.len();
        debug_assert_eq!(n, metas.len());
        debug_assert_eq!(n, source_addrs.len());
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut guard = self.network.inner.lock().expect("poisoned");
        let Some((_, r)) = guard.channels.get_mut(&self.id) else {
            info!("me: {} not found in channels", self.id.fmt_short());
            return Poll::Ready(Ok(0));
        };
        let mut packets = Vec::new();
        match r.poll_recv_many(cx, &mut packets, n) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(0) => return Poll::Ready(Err(io::Error::other("channel closed"))),
            Poll::Ready(n) => n,
        };
        let mut count = 0;
        for (((packet, meta), buf), source_addr) in
            packets.into_iter().zip(metas).zip(bufs).zip(source_addrs)
        {
            if buf.len() < packet.data.len() {
                break;
            }
            let from = try_parse_custom_addr(&packet.from).expect("valid custom addr");
            info!(
                "recv {} -> {}: copying {} bytes",
                from.fmt_short(),
                self.id.fmt_short(),
                packet.data.len()
            );
            buf[..packet.data.len()].copy_from_slice(&packet.data);
            *source_addr = packet.from.into();
            meta.len = packet.data.len();
            meta.stride = packet.data.len();
            count += 1;
        }
        if count > 0 {
            info!("recv {}: filled {count} slots", self.id.fmt_short());
            Poll::Ready(Ok(count))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use iroh_relay::RelayMap;
    use n0_error::{Result, StdResultExt};
    use n0_watcher::Watcher;

    use super::*;
    use crate::{
        Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr,
        endpoint::{
            Builder, Connection,
            transports::{AddrKind, TransportBias},
        },
        protocol::{AcceptError, ProtocolHandler, Router},
        test_utils::run_relay_server,
    };

    const ECHO_ALPN: &[u8] = b"test/echo";

    #[derive(Debug, Clone)]
    struct Echo;

    impl ProtocolHandler for Echo {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let (mut send, mut recv) = connection.accept_bi().await?;
            tokio::io::copy(&mut recv, &mut send).await?;
            send.finish()?;
            connection.closed().await;
            Ok(())
        }
    }

    /// Configuration for endpoint builder.
    #[derive(Clone, Default)]
    struct EndpointConfig {
        custom_bias: Option<TransportBias>,
        keep_ip: bool,
        relay_map: Option<RelayMap>,
    }

    impl EndpointConfig {
        fn with_custom_bias(mut self, bias: TransportBias) -> Self {
            self.custom_bias = Some(bias);
            self
        }

        fn with_ip(mut self) -> Self {
            self.keep_ip = true;
            self
        }

        fn with_relay(mut self, relay_map: RelayMap) -> Self {
            self.relay_map = Some(relay_map);
            self
        }
    }

    /// Creates a basic endpoint builder with the given secret key and custom transport.
    fn endpoint_builder(
        secret_key: SecretKey,
        transport: Arc<TestTransport>,
        config: EndpointConfig,
    ) -> Builder {
        let relay_mode = match config.relay_map {
            Some(map) => RelayMode::Custom(map),
            None => RelayMode::Disabled,
        };
        let mut builder = Endpoint::builder()
            .secret_key(secret_key)
            .relay_mode(relay_mode)
            .ca_roots_config(crate::tls::CaRootsConfig::insecure_skip_verify())
            .add_custom_transport(transport);
        if let Some(bias) = config.custom_bias {
            builder = builder.transport_bias(AddrKind::Custom(TEST_TRANSPORT_ID), bias);
        }
        if !config.keep_ip {
            builder = builder.clear_ip_transports();
        }
        builder
    }

    /// Creates an address with both IP (from endpoint) and custom transport addresses.
    fn mixed_addr(ep: &Endpoint, endpoint_id: EndpointId) -> EndpointAddr {
        let ep_addr = ep.addr();
        let custom_addr = to_custom_addr(endpoint_id);
        EndpointAddr::from_parts(
            endpoint_id,
            ep_addr
                .addrs
                .iter()
                .cloned()
                .chain(std::iter::once(TransportAddr::Custom(custom_addr))),
        )
    }

    /// Creates an address with only the custom transport address.
    fn custom_only_addr(endpoint_id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(
            endpoint_id,
            std::iter::once(TransportAddr::Custom(to_custom_addr(endpoint_id))),
        )
    }

    /// Returns true if the selected path is the custom transport.
    fn is_custom_selected(conn: &crate::endpoint::Connection) -> bool {
        let paths = conn.paths().get();
        paths.iter().find(|p| p.is_selected()).is_some_and(
            |p| matches!(p.remote_addr(), TransportAddr::Custom(a) if a.id() == TEST_TRANSPORT_ID),
        )
    }

    /// Returns true if the selected path is an IP transport.
    fn is_ip_selected(conn: &crate::endpoint::Connection) -> bool {
        let paths = conn.paths().get();
        paths
            .iter()
            .find(|p| p.is_selected())
            .is_some_and(|p| matches!(p.remote_addr(), TransportAddr::Ip(_)))
    }

    /// Returns true if the selected path is a relay transport.
    fn is_relay_selected(conn: &crate::endpoint::Connection) -> bool {
        let paths = conn.paths().get();
        paths
            .iter()
            .find(|p| p.is_selected())
            .is_some_and(|p| matches!(p.remote_addr(), TransportAddr::Relay(_)))
    }

    /// Verifies echo works over the connection.
    async fn verify_echo(conn: &crate::endpoint::Connection, msg: &[u8]) -> Result<()> {
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        send.write_all(msg).await.anyerr()?;
        send.finish().anyerr()?;
        let response = recv.read_to_end(100).await.anyerr()?;
        assert_eq!(response, msg);
        Ok(())
    }

    /// Test custom transport only - no IP, no relay, dial by custom address.
    #[tokio::test]
    async fn test_custom_transport_only() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate(&mut rand::rng());
        let s2 = SecretKey::generate(&mut rand::rng());

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        let ep1 = endpoint_builder(s1, t1, EndpointConfig::default())
            .bind()
            .await?;
        let ep2 = endpoint_builder(s2.clone(), t2, EndpointConfig::default())
            .bind()
            .await?;
        let router = Router::builder(ep2).accept(ECHO_ALPN, Echo).spawn();

        let conn = ep1
            .connect(custom_only_addr(s2.public()), ECHO_ALPN)
            .await?;

        // Verify exactly one path exists and it's the custom transport
        let paths = conn.paths().get();
        assert_eq!(paths.len(), 1, "Expected exactly one path");
        assert!(
            is_custom_selected(&conn),
            "Custom transport should be selected"
        );

        verify_echo(&conn, b"custom only").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Test that custom transport is selected over IP when given an RTT advantage.
    #[tokio::test]
    async fn test_custom_transport_wins_over_ip() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate(&mut rand::rng());
        let s2 = SecretKey::generate(&mut rand::rng());

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Strong RTT advantage for custom transport
        let custom_bias = TransportBias::primary().with_rtt_advantage(Duration::from_millis(100));
        let config = EndpointConfig::default()
            .with_ip()
            .with_custom_bias(custom_bias);

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;
        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        let conn = ep1
            .connect(mixed_addr(&ep2, s2.public()), ECHO_ALPN)
            .await?;

        // Wait for paths to settle
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            is_custom_selected(&conn),
            "Custom transport should be selected with RTT advantage"
        );

        verify_echo(&conn, b"custom wins").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Test that IP is selected over custom transport when custom has an RTT disadvantage.
    #[tokio::test]
    async fn test_ip_wins_over_custom() -> Result<()> {
        let network = TestNetwork::new();
        let s1 = SecretKey::generate(&mut rand::rng());
        let s2 = SecretKey::generate(&mut rand::rng());

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Strong RTT disadvantage for custom transport
        let custom_bias =
            TransportBias::primary().with_rtt_disadvantage(Duration::from_millis(100));
        let config = EndpointConfig::default()
            .with_ip()
            .with_custom_bias(custom_bias);

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;
        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        let conn = ep1
            .connect(mixed_addr(&ep2, s2.public()), ECHO_ALPN)
            .await?;

        // Wait for paths to settle
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            is_ip_selected(&conn),
            "IP transport should be selected when custom has RTT disadvantage"
        );

        verify_echo(&conn, b"ip wins").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }

    /// Test that custom transport (primary) is selected over relay (backup).
    ///
    /// This test first connects using only the relay address, then reconnects with
    /// both relay and custom addresses to verify the custom transport (primary) wins
    /// over the relay (backup).
    #[tokio::test]
    async fn test_custom_transport_wins_over_relay() -> Result<()> {
        let (relay_map, _relay_url, _guard) = run_relay_server().await?;
        let network = TestNetwork::new();
        let s1 = SecretKey::generate(&mut rand::rng());
        let s2 = SecretKey::generate(&mut rand::rng());

        let t1 = network.create_transport(s1.public())?;
        let t2 = network.create_transport(s2.public())?;

        // Custom transport is primary by default, relay is backup
        let config = EndpointConfig::default().with_relay(relay_map.clone());

        let ep1 = endpoint_builder(s1, t1, config.clone()).bind().await?;
        let ep2 = endpoint_builder(s2.clone(), t2, config).bind().await?;

        // Wait for relay connection to be established
        ep1.online().await;
        ep2.online().await;

        let router = Router::builder(ep2.clone()).accept(ECHO_ALPN, Echo).spawn();

        // Get all addresses including relay and custom
        let ep2_addr = ep2.addr();
        let custom_addr = to_custom_addr(s2.public());

        // Debug: print ep2 address to see what's available
        eprintln!("ep2 address: {:?}", ep2_addr);

        // Create address with both relay and custom
        let all_addrs = EndpointAddr::from_parts(
            s2.public(),
            ep2_addr
                .addrs
                .iter()
                .cloned()
                .chain(std::iter::once(TransportAddr::Custom(custom_addr))),
        );
        eprintln!("Connecting with all addresses: {:?}", all_addrs);

        // First, connect with relay-only to verify relay works
        let relay_addrs: Vec<_> = ep2_addr
            .addrs
            .iter()
            .filter(|a| matches!(a, TransportAddr::Relay(_)))
            .cloned()
            .collect();
        eprintln!("Relay addresses in ep2_addr: {:?}", relay_addrs);

        // If there are no relay addresses, skip the relay-first test
        if relay_addrs.is_empty() {
            eprintln!(
                "WARNING: No relay addresses found in ep2_addr, skipping relay-first connection test"
            );
        } else {
            // Connect with relay-only address first to verify relay works
            let relay_only_addr = EndpointAddr::from_parts(s2.public(), relay_addrs.into_iter());
            eprintln!("Connecting with relay-only address: {:?}", relay_only_addr);

            let conn = ep1.connect(relay_only_addr, ECHO_ALPN).await?;

            // Wait for relay path to be established
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Debug: print paths after relay-only connect
            let paths = conn.paths().get();
            eprintln!("Paths after relay-only connect:");
            for path in paths.iter() {
                eprintln!(
                    "  {} selected={} rtt={:?}",
                    path.remote_addr(),
                    path.is_selected(),
                    path.rtt()
                );
            }

            // Verify relay is currently selected
            assert!(
                is_relay_selected(&conn),
                "Relay should be selected after connecting with relay-only address"
            );

            verify_echo(&conn, b"relay test").await?;
            conn.close(0u32.into(), b"done with relay test");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Now connect with all addresses (relay + custom)
        let conn = ep1.connect(all_addrs, ECHO_ALPN).await?;

        // Wait for paths to settle
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Debug: print all paths
        let paths = conn.paths().get();
        eprintln!("Paths after connecting with all addresses:");
        for path in paths.iter() {
            eprintln!(
                "  {} selected={} rtt={:?}",
                path.remote_addr(),
                path.is_selected(),
                path.rtt()
            );
        }

        // Custom (primary) should win over relay (backup)
        assert!(
            is_custom_selected(&conn),
            "Custom transport (primary) should be selected over relay (backup)"
        );

        verify_echo(&conn, b"custom wins over relay").await?;
        conn.close(0u32.into(), b"done");
        router.shutdown().await.anyerr()?;
        Ok(())
    }
}

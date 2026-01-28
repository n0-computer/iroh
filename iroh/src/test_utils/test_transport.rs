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
    endpoint::{Builder, presets::Preset, transports::{Addr, CustomEndpoint, CustomSender, CustomTransport, Transmit}},
};

/// The transport ID used by [`TestNetwork`].
pub const TEST_TRANSPORT_ID: u64 = 0;

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

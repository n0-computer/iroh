use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    task::Poll,
};

use bytes::Bytes;
use futures_util::{future::BoxFuture, io};
use iroh::{
    Endpoint, EndpointId, SecretKey, TransportAddr,
    discovery::{Discovery, DiscoveryItem, EndpointData, EndpointInfo},
    endpoint::transports::{Addr, DynUserSender, DynUserTransport, Transmit, UserTransportConfig},
};
use iroh_base::UserAddr;
use n0_error::Result;
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::info;

const TEST_TRANSPORT_ID: u64 = 0;

/// An outgoing packet that can be sent across channels.
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    pub(crate) data: Bytes,
    pub(crate) from: UserAddr,
}

#[derive(Debug, Clone)]
struct TestTransport {
    me: UserAddr,
    state: Arc<Mutex<TestTransportInner>>,
}

#[derive(Debug, Clone)]
struct TestDiscovery {
    state: Arc<Mutex<TestTransportInner>>,
}

#[derive(Debug, Default)]
struct TestTransportInner {
    channels: BTreeMap<UserAddr, (mpsc::Sender<Packet>, mpsc::Receiver<Packet>)>,
}

impl Discovery for TestDiscovery {
    fn publish(&self, _data: &iroh::discovery::EndpointData) {}

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<
        n0_future::stream::Boxed<
            std::result::Result<iroh::discovery::DiscoveryItem, iroh::discovery::DiscoveryError>,
        >,
    > {
        let user_addr = to_user_addr(endpoint_id);
        if self.state.lock().unwrap().channels.contains_key(&user_addr) {
            Some(Box::pin(n0_future::stream::once(Ok(DiscoveryItem::new(
                EndpointInfo {
                    endpoint_id,
                    data: EndpointData::new([TransportAddr::User(UserAddr {
                        id: TEST_TRANSPORT_ID,
                        data: endpoint_id.as_bytes().to_vec().into(),
                    })]),
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
    me: UserAddr,
    inner: Arc<Mutex<TestTransportInner>>,
}

impl TestTransport {
    fn add_node(&self, a: EndpointId) {
        let addr = to_user_addr(a);
        let mut guard = self.state.lock().unwrap();
        let _ = guard
            .channels
            .entry(addr)
            .or_insert_with(|| mpsc::channel(256));
    }
}

fn to_user_addr(endpoint: EndpointId) -> UserAddr {
    UserAddr {
        id: TEST_TRANSPORT_ID,
        data: endpoint.as_bytes().to_vec().into(),
    }
}

fn try_parse_user_addr(addr: &UserAddr) -> io::Result<EndpointId> {
    if addr.id != TEST_TRANSPORT_ID {
        return Err(io::Error::other("unexpected transport id"));
    }
    let key_bytes: &[u8; 32] = addr
        .data
        .as_ref()
        .try_into()
        .map_err(|_| io::Error::other("wrong key length"))?;
    Ok(EndpointId::from_bytes(key_bytes).map_err(|_| io::Error::other("KeyParseError"))?)
}

impl TestSender {
    fn send_sync(&self, dst: iroh_base::UserAddr, packets: Vec<Packet>) -> io::Result<()> {
        let guard = self.inner.lock().unwrap();
        let (s, _) = guard
            .channels
            .get(&dst)
            .ok_or_else(|| io::Error::other("Unknown key"))?;
        let from_id = try_parse_user_addr(&self.me).unwrap();
        let to_id = try_parse_user_addr(&dst).unwrap();
        for packet in packets {
            let len = packet.data.len();
            match s.try_send(packet) {
                Ok(_) => info!(
                    "send {} -> {}: sent {} bytes",
                    from_id.fmt_short(),
                    to_id.fmt_short(),
                    len
                ),
                Err(TrySendError::Full(_)) => info!(
                    "send {} -> {}: dropped {} bytes",
                    from_id.fmt_short(),
                    to_id.fmt_short(),
                    len
                ),
                Err(TrySendError::Closed(_)) => return Err(io::Error::other("channel closed")),
            }
        }
        Ok(())
    }

    fn split(&self, transmit: &Transmit) -> impl Iterator<Item = Packet> {
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        transmit.contents.chunks(segment_size).map(|slice| Packet {
            from: self.me.clone(),
            data: Bytes::copy_from_slice(slice),
        })
    }
}

impl DynUserSender for TestSender {
    fn is_valid_send_addr(&self, addr: &iroh_base::UserAddr) -> bool {
        addr.id == TEST_TRANSPORT_ID
    }

    fn poll_send(
        &self,
        _cx: &mut std::task::Context,
        dst: iroh_base::UserAddr,
        transmit: &Transmit<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let packets = self.split(transmit).collect();
        Poll::Ready(self.send_sync(dst, packets))
    }

    fn send(&self, dst: UserAddr, transmit: &Transmit<'_>) -> BoxFuture<io::Result<()>> {
        let this = self.clone();
        let packets = self.split(transmit).collect();
        Box::pin(async move { this.send_sync(dst, packets) })
    }
}

impl UserTransportConfig for TestTransport {
    fn bind(&self) -> std::io::Result<Box<dyn DynUserTransport>> {
        Ok(Box::new(self.clone()))
    }
}

impl DynUserTransport for TestTransport {
    fn create_sender(&self) -> Arc<dyn iroh::endpoint::transports::DynUserSender> {
        Arc::new(TestSender {
            me: self.me.clone(),
            inner: self.state.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let n = bufs.len();
        debug_assert_eq!(n, metas.len());
        debug_assert_eq!(n, source_addrs.len());
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut guard = self.state.lock().unwrap();
        let Some((_, r)) = guard.channels.get_mut(&self.me) else {
            let me = try_parse_user_addr(&self.me).unwrap();
            info!("me: {me}");
            return Poll::Ready(Ok(0));
        };
        let mut packets = Vec::new();
        let n = match r.poll_recv_many(cx, &mut packets, n) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(0) => return Poll::Ready(Err(io::Error::other("channel closed"))),
            Poll::Ready(n) => n,
        };
        let mut n = 0;
        let me = try_parse_user_addr(&self.me).unwrap();
        for (((packet, meta), buf), source_addr) in
            packets.into_iter().zip(metas).zip(bufs).zip(source_addrs)
        {
            if buf.len() < packet.data.len() {
                break;
            }
            let from = try_parse_user_addr(&packet.from).unwrap();
            info!(
                "recv {} -> {}: copying {} bytes",
                from.fmt_short(),
                me.fmt_short(),
                packet.data.len()
            );
            buf[..packet.data.len()].copy_from_slice(&packet.data);
            *source_addr = packet.from.into();
            meta.len = packet.data.len();
            meta.stride = packet.data.len();
            n += 1;
        }
        if n > 0 {
            info!("recv {}: filled {n} slots", me.fmt_short());
            Poll::Ready(Ok(n))
        } else {
            Poll::Pending
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let map = Arc::new(Mutex::new(Default::default()));
    let s1 = SecretKey::generate(&mut rand::rng());
    let s2 = SecretKey::generate(&mut rand::rng());
    let tt1 = TestTransport {
        state: map.clone(),
        me: to_user_addr(s1.public()),
    };
    let tt2 = TestTransport {
        state: map.clone(),
        me: to_user_addr(s2.public()),
    };
    let d = TestDiscovery { state: map.clone() };
    tt1.add_node(s1.public());
    tt1.add_node(s2.public());
    let ep1 = Endpoint::builder()
        .secret_key(s1.clone())
        .clear_discovery()
        .discovery(d.clone())
        .add_user_transport(tt1.clone())
        .clear_ip_transports()
        .bind()
        .await?;
    let ep2 = Endpoint::builder()
        .secret_key(s2.clone())
        .clear_discovery()
        .discovery(d.clone())
        .add_user_transport(tt2.clone())
        .clear_ip_transports()
        .bind()
        .await?;
    let conn = ep1.connect(s2.public(), b"TEST").await?;
    Ok(())
}

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

const TEST_TRANSPORT_ID: u64 = 0;

#[derive(Debug)]
struct SenderAndReceiver {
    sender: tokio::sync::mpsc::Sender<Bytes>,
    receiver: tokio::sync::mpsc::Receiver<Bytes>,
}

#[derive(Debug, Clone)]
struct TestTransport {
    nodes: Arc<Mutex<BTreeMap<EndpointId, SenderAndReceiver>>>,
}

impl Discovery for TestTransport {
    fn publish(&self, _data: &iroh::discovery::EndpointData) {}

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<
        n0_future::stream::Boxed<
            std::result::Result<iroh::discovery::DiscoveryItem, iroh::discovery::DiscoveryError>,
        >,
    > {
        println!("Got resolve! {}", endpoint_id.fmt_short());
        if self.nodes.lock().unwrap().contains_key(&endpoint_id) {
            println!("returning user addr");
            Some(Box::pin(n0_future::stream::once(Ok(DiscoveryItem::new(
                EndpointInfo {
                    endpoint_id,
                    data: EndpointData::new([TransportAddr::User(UserAddr {
                        id: TEST_TRANSPORT_ID,
                        data: Box::new([]),
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
    inner: Arc<Mutex<BTreeMap<EndpointId, SenderAndReceiver>>>,
}

impl TestTransport {
    fn add_connection(&self, a: EndpointId, b: EndpointId) {
        let (tx1, rx1) = tokio::sync::mpsc::channel(128);
        let (tx2, rx2) = tokio::sync::mpsc::channel(128);
        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(
            a,
            SenderAndReceiver {
                sender: tx1,
                receiver: rx2,
            },
        );
        nodes.insert(
            b,
            SenderAndReceiver {
                sender: tx2,
                receiver: rx1,
            },
        );
    }
}

impl DynUserSender for TestSender {
    fn is_valid_send_addr(&self, addr: &iroh_base::UserAddr) -> bool {
        addr.id == TEST_TRANSPORT_ID
    }

    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        dst: iroh_base::UserAddr,
        transmit: &Transmit<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        return Poll::Ready(Err(io::Error::other("DOH")));
    }

    fn send(&self, dst: UserAddr, transmit: &Transmit<'_>) -> BoxFuture<io::Result<()>> {
        Box::pin(async move { Err(io::Error::other("DOH")) })
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
            inner: self.nodes.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let map = Arc::new(Mutex::new(BTreeMap::new()));
    let s1 = SecretKey::generate(&mut rand::rng());
    let s2 = SecretKey::generate(&mut rand::rng());
    let tt = TestTransport { nodes: map.clone() };
    let ep1 = Endpoint::builder()
        .secret_key(s1.clone())
        .clear_discovery()
        .discovery(tt.clone())
        .add_user_transport(tt.clone())
        .clear_ip_transports()
        .bind()
        .await?;
    let ep2 = Endpoint::builder()
        .secret_key(s2.clone())
        .clear_discovery()
        .discovery(tt.clone())
        .add_user_transport(tt.clone())
        .clear_ip_transports()
        .bind()
        .await?;
    tt.add_connection(s1.public(), s2.public());
    let conn = ep1.connect(s2.public(), b"TEST").await?;
    Ok(())
}

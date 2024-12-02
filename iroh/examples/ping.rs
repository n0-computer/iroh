use std::{str::FromStr, sync::Arc};

use futures_lite::future;
use iroh_net::{endpoint, Endpoint, NodeId};
use iroh_router::{Protocol, ProtocolHandler};

#[derive(Debug)]
pub struct Ping(Arc<PingInner>);

const ALPN: &[u8] = b"ping";

impl From<Arc<PingInner>> for Ping {
    fn from(inner: Arc<PingInner>) -> Self {
        Self(inner)
    }
}

impl Ping {
    fn new(endpoint: Endpoint) -> Self {
        Self(Arc::new(PingInner { endpoint }))
    }

    async fn ping(&self, target: NodeId) -> anyhow::Result<()> {
        let conn = self.0.endpoint.connect(target, ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let request = b"Ping".to_vec();
        send.write_all(&request).await?;
        send.finish()?;
        let response = recv.read_to_end(1024).await?;
        println!("got response: {:?}", String::from_utf8_lossy(&response));
        Ok(())
    }
}

impl ProtocolHandler for PingInner {
    fn accept(self: Arc<Self>, conn: iroh_net::endpoint::Connecting) -> future::Boxed<anyhow::Result<()>> {
        Box::pin(async move {
            let conn = conn.await?;
            let (mut send, mut recv) = conn.accept_bi().await?;
            let request = recv.read_to_end(1024).await?;
            println!("got request: {:?}", String::from_utf8_lossy(&request));
            let response = b"Pong".to_vec();
            send.write_all(&response).await?;
            send.finish()?;
            conn.closed().await;
            Ok(())
        })
    }
}

// todo: figure out a way to derive this?
impl Protocol for Ping {
    fn protocol_handler(&self) -> Arc<dyn iroh_router::ProtocolHandler> {
        self.0.clone()
    }

    fn from_protocol_handler(handler: Arc<dyn iroh_router::ProtocolHandler>) -> Option<Self> {
        Self::downcast_via::<PingInner>(handler)
    }
}

#[derive(Debug)]
struct PingInner {
    endpoint: Endpoint,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    if let Some(target) = std::env::args().nth(1) {
        let nodeid = iroh::net::NodeId::from_str(&target)?;
        let endpoint = iroh::net::Endpoint::builder().discovery_n0().bind().await?;
        let ping = Ping::new(endpoint);
        ping.ping(nodeid).await?;
    } else {
        println!("Staring ping server");
        let endpoint = iroh::net::Endpoint::builder().discovery_n0().bind().await?;
        let builder = iroh::router::Router::builder(endpoint.clone());
        let ping = Ping::new(endpoint);
        let builder = builder.accept(ALPN, &ping);
        let router = builder.spawn().await?;
        let t = router.get_protocol::<Ping>(&ALPN).unwrap();
        println!("Listening for pings on {}", router.endpoint().node_id());
        tokio::signal::ctrl_c().await?;
        router.shutdown().await?;
    }
    Ok(())
}
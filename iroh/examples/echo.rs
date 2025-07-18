//! Very basic example to showcase how to use iroh's APIs.
//!
//! This example implements a simple protocol that echos any data sent to it in the first stream.
//!
//! ## Usage
//!
//!     cargo run --example echo --features=examples

use std::time::{Duration, Instant};

use anyhow::Result;
use iroh::{
    endpoint::Connection,
    protocol::{ProtocolHandler, Router},
    Endpoint, NodeAddr,
};
use n0_future::{boxed::BoxFuture, StreamExt};

/// Each protocol is identified by its ALPN string.
///
/// The ALPN, or application-layer protocol negotiation, is exchanged in the connection handshake,
/// and the connection is aborted unless both nodes pass the same bytestring.
const ALPN: &[u8] = b"iroh-example/echo/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let router = start_accept_side().await?;
    let node_addr = router.endpoint().node_addr().await?;

    connect_side(node_addr).await?;

    // This makes sure the endpoint in the router is closed properly and connections close gracefully
    router.shutdown().await?;

    Ok(())
}

async fn connect_side(addr: NodeAddr) -> Result<()> {
    let endpoint = Endpoint::builder().discovery_n0().bind().await?;

    let node_id = addr.node_id;

    // Open a connection to the accepting node
    let conn = endpoint.connect(addr, ALPN).await?;

    tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let start = Instant::now();
            let mut conn_type = endpoint.conn_type(node_id).unwrap().stream();
            while let Some(typ) = conn_type.next().await {
                println!("Connection type changed: {typ:?} ({:?})", start.elapsed());
            }
        }
    });

    // Open a bidirectional QUIC stream
    let (mut send, mut recv) = conn.open_bi().await?;

    let payload = b"Hello, world!";
    let iters = 10_000;

    n0_future::future::try_zip(
        async {
            for _ in 0..iters {
                // Send some data to be echoed
                send.write_all(payload).await?;
                // wait a bit
                tokio::time::sleep(Duration::from_millis(2)).await;
            }

            // Signal the end of data for this particular stream
            send.finish()?;

            anyhow::Ok(())
        },
        async {
            let _response = recv.read_to_end(iters * payload.len()).await?;

            anyhow::Ok(())
        },
    )
    .await?;

    // Explicitly close the whole connection.
    conn.close(0u32.into(), b"bye!");

    // The above call only queues a close message to be sent (see how it's not async!).
    // We need to actually call this to make sure this message is sent out.
    endpoint.close().await;
    // If we don't call this, but continue using the endpoint, we then the queued
    // close call will eventually be picked up and sent.
    // But always try to wait for endpoint.close().await to go through before dropping
    // the endpoint to ensure any queued messages are sent through and connections are
    // closed gracefully.
    Ok(())
}

async fn start_accept_side() -> Result<Router> {
    let endpoint = Endpoint::builder().discovery_n0().bind().await?;

    // Build our protocol handler and add our protocol, identified by its ALPN, and spawn the node.
    let router = Router::builder(endpoint).accept(ALPN, Echo).spawn();

    Ok(router)
}

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    /// The `accept` method is called for each incoming connection for our ALPN.
    ///
    /// The returned future runs on a newly spawned tokio task, so it can run as long as
    /// the connection lasts.
    fn accept(&self, connection: Connection) -> BoxFuture<Result<()>> {
        // We have to return a boxed future from the handler.
        Box::pin(async move {
            // We can get the remote's node id from the connection.
            let node_id = connection.remote_node_id()?;
            println!("accepted connection from {node_id}");

            // Our protocol is a simple request-response protocol, so we expect the
            // connecting peer to open a single bi-directional stream.
            let (mut send, mut recv) = connection.accept_bi().await?;

            // Echo any bytes received back directly.
            // This will keep copying until the sender signals the end of data on the stream.
            let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
            println!("Copied over {bytes_sent} byte(s)");

            // By calling `finish` on the send stream we signal that we will not send anything
            // further, which makes the receive stream on the other end terminate.
            send.finish()?;

            // Wait until the remote closes the connection, which it does once it
            // received the response.
            connection.closed().await;

            Ok(())
        })
    }
}

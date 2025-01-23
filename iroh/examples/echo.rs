//! Very basic example to showcase how to use iroh's APIs.
//!
//! This example implements a simple protocol that echos any data sent to it in the first stream.
//!
//! ## Usage
//!
//!     cargo run --example echo --features=examples

use anyhow::Result;
use futures_lite::future::Boxed as BoxedFuture;
use iroh::{
    endpoint::Connecting,
    protocol::{ProtocolHandler, Router},
    Endpoint, NodeAddr,
};

/// Each protocol is identified by its ALPN string.
///
/// The ALPN, or application-layer protocol negotiation, is exchanged in the connection handshake,
/// and the connection is aborted unless both nodes pass the same bytestring.
const ALPN: &[u8] = b"iroh-example/echo/0";

#[tokio::main]
async fn main() -> Result<()> {
    let router = accept_side().await?;
    let node_addr = router.endpoint().node_addr().await?;

    connect_side(node_addr).await?;

    router.shutdown().await?;

    Ok(())
}

async fn connect_side(addr: NodeAddr) -> Result<()> {
    let endpoint = Endpoint::builder().discovery_n0().bind().await?;

    // Open a connection to the accepting node
    let conn = endpoint.connect(addr, ALPN).await?;

    // Open a bidirectional QUIC stream
    let (mut send, mut recv) = conn.open_bi().await?;

    // Send some data to be echoed
    send.write_all(b"Hello, world!").await?;

    // Signal the end of transfer.
    send.finish()?;

    // Receive the echo
    let response = recv.read_to_end(1000).await?;
    assert_eq!(&response, b"Hello, world!");

    Ok(())
}

async fn accept_side() -> Result<Router> {
    let endpoint = Endpoint::builder().discovery_n0().bind().await?;

    // Build our protocol handler and add our protocol, identified by its ALPN, and spawn the node.
    let router = Router::builder(endpoint).accept(ALPN, Echo).spawn().await?;

    Ok(router)
}

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    /// The `accept` method is called for each incoming connection for our ALPN.
    ///
    /// The returned future runs on a newly spawned tokio task, so it can run as long as
    /// the connection lasts.
    fn accept(&self, connecting: Connecting) -> BoxedFuture<Result<()>> {
        // We have to return a boxed future from the handler.
        Box::pin(async move {
            // Wait for the connection to be fully established.
            let connection = connecting.await?;
            // We can get the remote's node id from the connection.
            let node_id = connection.remote_node_id()?;
            println!("accepted connection from {node_id}");

            // Our protocol is a simple request-response protocol, so we expect the
            // connecting peer to open a single bi-directional stream.
            let (mut send, mut recv) = connection.accept_bi().await?;

            // Echo any bytes received back directly.
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

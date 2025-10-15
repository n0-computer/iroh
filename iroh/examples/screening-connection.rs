//! Very basic example to showcase how to write a protocol that rejects new
//! connections based on internal state. Useful when you want an endpoint to
//! stop accepting new connections for some reason only known to the endpoint. Maybe
//! it's doing a migration, starting up, in a "maintenance mode", or serving
//! too many connections.
//!
//! ## Usage
//!
//!     cargo run --example screening-connection --features=examples
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connecting, Connection},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_snafu::{Result, ResultExt};

/// Each protocol is identified by its ALPN string.
///
/// The ALPN, or application-layer protocol negotiation, is exchanged in the connection handshake,
/// and the connection is aborted unless both endpoints pass the same bytestring.
const ALPN: &[u8] = b"iroh-example/screening-connection/0";

#[tokio::main]
async fn main() -> Result<()> {
    let router = start_accept_side().await?;
    // Wait for the endpoint to be reachable
    router.endpoint().online().await;
    let endpoint_addr = router.endpoint().addr();

    // call connect three times. connection index 1 will be an odd number, and rejected.
    connect_side(&endpoint_addr).await?;
    if let Err(err) = connect_side(&endpoint_addr).await {
        println!("Error connecting: {}", err);
    }
    connect_side(&endpoint_addr).await?;

    // This makes sure the endpoint in the router is closed properly and connections close gracefully
    router.shutdown().await.e()?;

    Ok(())
}

async fn connect_side(addr: &EndpointAddr) -> Result<()> {
    let endpoint = Endpoint::builder().discovery_n0().bind().await?;

    // Open a connection to the accepting endpoint
    let conn = endpoint.connect(addr.clone(), ALPN).await?;

    // Open a bidirectional QUIC stream
    let (mut send, mut recv) = conn.open_bi().await.e()?;

    // Send some data to be echoed
    send.write_all(b"Hello, world!").await.e()?;

    // Signal the end of data for this particular stream
    send.finish().e()?;

    // Receive the echo, but limit reading up to maximum 1000 bytes
    let response = recv.read_to_end(1000).await.e()?;
    assert_eq!(&response, b"Hello, world!");

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

    let echo = ScreenedEcho {
        conn_attempt_count: Arc::new(AtomicU64::new(0)),
    };

    // Build our protocol handler and add our protocol, identified by its ALPN, and spawn the endpoint.
    let router = Router::builder(endpoint).accept(ALPN, echo).spawn();

    Ok(router)
}

/// This is the same as the echo example, but keeps an internal count of the
/// number of connections that have been attempted. This is to demonstrate how
/// to plumb state into the protocol handler
#[derive(Debug, Clone)]
struct ScreenedEcho {
    conn_attempt_count: Arc<AtomicU64>,
}

impl ProtocolHandler for ScreenedEcho {
    /// `on_connecting` allows us to intercept a connection as it's being formed,
    /// which is the right place to cut off a connection as early as possible.
    /// This is an optional method on the ProtocolHandler trait.
    async fn on_connecting(&self, connecting: Connecting) -> Result<Connection, AcceptError> {
        self.conn_attempt_count.fetch_add(1, Ordering::Relaxed);
        let count = self.conn_attempt_count.load(Ordering::Relaxed);

        // reject every other connection
        if count % 2 == 0 {
            println!("rejecting connection");
            return Err(AcceptError::NotAllowed {});
        }

        // To allow normal connection construction, await the connecting future & return
        let conn = connecting.await?;
        Ok(conn)
    }

    /// The `accept` method is called for each incoming connection for our ALPN.
    /// This is the primary place to kick off work in response to a new connection.
    ///
    /// The returned future runs on a newly spawned tokio task, so it can run as long as
    /// the connection lasts.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // We can get the remote's endpoint id from the connection.
        let endpoint_id = connection.remote_endpoint_id()?;
        println!("accepted connection from {endpoint_id}");

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
    }
}

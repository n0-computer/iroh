//! Very basic example showing how to implement a basic echo protocol,
//! without using the `Router` API. (For the router version, check out the echo.rs example.)
//!
//! The echo protocol echos any data sent to it in the first stream.
//!
//! ## Running the Example
//!
//!     cargo run --example echo-no-router --features=examples

use iroh::{Endpoint, NodeAddr};
use n0_snafu::{Error, Result, ResultExt};
use n0_watcher::Watcher as _;

/// Each protocol is identified by its ALPN string.
///
/// The ALPN, or application-layer protocol negotiation, is exchanged in the connection handshake,
/// and the connection is aborted unless both nodes pass the same bytestring.
const ALPN: &[u8] = b"iroh-example/echo/0";

#[tokio::main]
async fn main() -> Result<()> {
    let endpoint = start_accept_side().await?;
    let node_addr = endpoint.node_addr().initialized().await?;

    connect_side(node_addr).await?;

    // This makes sure the endpoint is closed properly and connections close gracefully
    // and will indirectly close the tasks spawned by `start_accept_side`.
    endpoint.close().await;

    Ok(())
}

async fn connect_side(addr: NodeAddr) -> Result<()> {
    let endpoint = Endpoint::builder().discovery_n0().bind().await?;

    // Open a connection to the accepting node
    let conn = endpoint.connect(addr, ALPN).await?;

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
    // If we don't call this, but continue using the endpoint, then the queued
    // close call will eventually be picked up and sent.
    // But always try to wait for endpoint.close().await to go through before dropping
    // the endpoint to ensure any queued messages are sent through and connections are
    // closed gracefully.

    Ok(())
}

async fn start_accept_side() -> Result<Endpoint> {
    let endpoint = Endpoint::builder()
        .discovery_n0()
        // The accept side needs to opt-in to the protocols it accepts,
        // as any connection attempts that can't be found with a matching ALPN
        // will be rejected.
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    // spawn a task so that `start_accept_side` returns immediately and we can continue in main().
    tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            // This task won't leak, because we call `endpoint.close()` in `main()`,
            // which causes `endpoint.accept().await` to return `None`.
            // In a more serious environment, we recommend avoiding `tokio::spawn` and use either a `TaskTracker` or
            // `JoinSet` instead to make sure you're not accidentally leaking tasks.
            while let Some(incoming) = endpoint.accept().await {
                // spawn a task for each incoming connection, so we can serve multiple connections asynchronously
                tokio::spawn(async move {
                    let connection = incoming.await.e()?;

                    // We can get the remote's node id from the connection.
                    let node_id = connection.remote_node_id()?;
                    println!("accepted connection from {node_id}");

                    // Our protocol is a simple request-response protocol, so we expect the
                    // connecting peer to open a single bi-directional stream.
                    let (mut send, mut recv) = connection.accept_bi().await.e()?;

                    // Echo any bytes received back directly.
                    // This will keep copying until the sender signals the end of data on the stream.
                    let bytes_sent = tokio::io::copy(&mut recv, &mut send).await.e()?;
                    println!("Copied over {bytes_sent} byte(s)");

                    // By calling `finish` on the send stream we signal that we will not send anything
                    // further, which makes the receive stream on the other end terminate.
                    send.finish().e()?;

                    // Wait until the remote closes the connection, which it does once it
                    // received the response.
                    connection.closed().await;

                    Ok::<_, Error>(())
                });
            }

            Ok::<_, Error>(())
        }
    });

    Ok(endpoint)
}

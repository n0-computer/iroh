//! Example showing how to keep application data off the relay with stream affinity.
//!
//! Alice connects to Bob and wants to send some data over a direct IP path only, never
//! over the relay.
//!
//! The right way to make sure nothing goes out on the wrong path is to not write to the
//! stream until the path you want is available. Don't open the stream, block it with
//! [`StreamAffinity::Block`] and write ahead of time in the hope of unblocking it later:
//! blocked data still uses up the connection's send window, and blocking is meant as a
//! last resort. Here `Block` is only used mid-transfer, when no direct path is left.
//!
//! So Alice:
//! 1. Waits until the connection has a direct path.
//! 2. Opens a uni stream and pins it to that path with [`StreamAffinity::Sticky`] before
//!    writing anything.
//! 3. Sends the data over the stream while watching for any changes to the available paths.
//!    When the pinned path closes another direct path is pinned. Or as a last resort the
//!    stream is blocked. When a direct path opens while the stream is blocked, it pins the
//!    stream to it.
//!
//! ## Usage
//!
//!     cargo run --example stream_affinity_direct
//!
//! [`Connection::paths`]: iroh::endpoint::Connection::paths
use std::time::Duration;

use bytes::Bytes;
use iroh::{
    Endpoint,
    endpoint::{Connection, ConnectionError, PathList, presets},
};
use n0_error::{Result, StdResultExt, anyerr, ensure_any};
use n0_future::StreamExt;
use noq::StreamAffinity;

const ALPN: &[u8] = b"iroh-example/stream-affinity-direct/0";

/// Bytes of dummy data Alice sends.
const DATA_SIZE: usize = 1024 * 1024;
/// Size of each chunk Alice hands to the actor.
const CHUNK_SIZE: usize = 64 * 1024;

/// How long to wait for the endpoints to come online.
const ONLINE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for a verified direct path and the relay path.
const PATHS_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let alice = Endpoint::builder(presets::N0).bind().await?;
    let bob = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    tokio::try_join!(
        async {
            tokio::time::timeout(ONLINE_TIMEOUT, alice.online())
                .await
                .map_err(|_| anyerr!("alice did not come online within {ONLINE_TIMEOUT:?}"))
        },
        async {
            tokio::time::timeout(ONLINE_TIMEOUT, bob.online())
                .await
                .map_err(|_| anyerr!("bob did not come online within {ONLINE_TIMEOUT:?}"))
        },
    )?;

    let bob_addr = bob.addr();
    let (alice_conn, bob_conn) = tokio::join!(alice.connect(bob_addr, ALPN), async {
        bob.accept()
            .await
            .ok_or_else(|| anyerr!("bob's endpoint closed"))?
            .await
            .anyerr()
    });
    let (alice_conn, bob_conn) = (alice_conn?, bob_conn?);

    let alice_task = tokio::spawn(run_alice(alice_conn));
    let bob_task = tokio::spawn(run_bob(bob_conn));
    let (alice_res, bob_res) = tokio::try_join!(alice_task, bob_task).anyerr()?;
    alice_res?;
    bob_res?;

    alice.close().await;
    bob.close().await;
    Ok(())
}

async fn run_bob(conn: Connection) -> Result<()> {
    let mut recv = conn.accept_uni().await.anyerr()?;
    let received = recv.read_to_end(DATA_SIZE).await.anyerr()?;
    ensure_any!(received.len() == DATA_SIZE, "data stream truncated");
    conn.close(0u32.into(), b"all data read");
    n0_error::Ok(())
}

async fn run_alice(conn: Connection) -> Result<()> {
    // We need to watch the paths since we only want to transmit on a direct path.
    let mut paths_watcher = conn.paths_stream();

    // Wait for a direct path to appear. If we open the stream immediately and than set it's
    // affinity to blocked before we have a direct path we will already be consuming
    // connection-wide send window capacity for a stream that can not send anyway. So we
    // prefer to delay opening the stream.
    let direct_path = tokio::time::timeout(PATHS_TIMEOUT, async {
        loop {
            let Some(paths) = paths_watcher.next().await else {
                break Err(anyerr!("path watcher stopped"));
            };
            print_open_paths(&paths);
            if let Some(direct) = paths.iter().find(|p| p.is_ip()) {
                break Ok(direct.id());
            }
        }
    })
    .await
    .map_err(|_| anyerr!("direct path not open within {PATHS_TIMEOUT:?}"))??;

    // Create a SendStream and pin it to the a direct path.
    println!("pinning the stream to direct path {direct_path}");
    let mut send_stream = conn.open_uni().await.anyerr()?;
    send_stream
        .set_affinity(StreamAffinity::Sticky(direct_path))
        .anyerr()?;

    // Time to send the data, but watch for path changes in case we need to stop sending the
    // data.

    // Fill the first chunk of pending data.
    let mut chunks = [Bytes::from(vec![0xda; CHUNK_SIZE])];
    let mut remaining_data = DATA_SIZE - CHUNK_SIZE;
    loop {
        let mut bufs = chunks.as_mut_slice();
        tokio::select! {
            biased;
            paths = paths_watcher.next() => {
                // Paths have changed, check if our sticky path still exists, otherwise try
                // to find a new direct path.
                let paths = paths.ok_or(anyerr!("path watcher lost"))?;
                print_open_paths(&paths);
                if paths.iter().find(|p| p.id() == direct_path).is_none() {
                    if let Some(path) = paths.iter().find(|p| p.is_ip()) {
                        println!("pinning the stream to direct path {}", path.id());
                        send_stream
                            .set_affinity(StreamAffinity::Sticky(path.id()))
                            .anyerr()?;
                    } else {
                        println!("no direct path left, blocking the stream");
                        send_stream.set_affinity(StreamAffinity::Block).anyerr()?;
                    }
                }
            }
            // SendStream::write_many_chunks is cancel-safe: bufs will contain anything that
            // is not yet written.
            res = send_stream.write_many_chunks(&mut bufs) => {
                // Make sure a write error propagates out.
                res.anyerr()?;
            }
        }

        if bufs.is_empty() && remaining_data == 0 {
            // All data is written.
            break;
        }

        // If the chunk was entirely written we need to refill the chunk. Otherwise the
        // Bytes in the chunks has been shrunk to only contain the still pending data.
        if bufs.is_empty() {
            chunks[0] = Bytes::from(vec![0xda; CHUNK_SIZE]);
            remaining_data -= CHUNK_SIZE;
        }
    }

    send_stream.finish().anyerr()?;

    // Wait for blob to close the connection once all data was read.
    match conn.closed().await {
        ConnectionError::ApplicationClosed(_) => n0_error::Ok(()),
        err => Err(err).anyerr(),
    }
}

fn print_open_paths(paths: &PathList<'_>) {
    println!("open paths:");
    for path in paths.iter() {
        let transport = if path.is_relay() { "relay" } else { "ip" };
        let selected = if path.is_selected() {
            " (selected)"
        } else {
            ""
        };
        println!("  path {}: {transport}{selected}", path.id());
    }
}

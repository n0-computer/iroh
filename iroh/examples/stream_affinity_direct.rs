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
//! 2. Opens a uni stream and makes it sticky to that direct path with
//!    [`StreamAffinity::Sticky`] before writing anything.
//! 3. Sends the data over the stream while watching for any changes to the available paths.
//!    When the sticky path closes, she makes the stream sticky to another direct path. Or
//!    as a last resort the stream is blocked. When a direct path opens while the stream is
//!    blocked, she makes the stream stick to it.
//!
//! ## Usage
//!
//!     cargo run --example stream_affinity_direct
//!
//! [`Connection::paths`]: iroh::endpoint::Connection::paths

use bytes::Bytes;
use iroh::{
    Endpoint,
    endpoint::{Connection, ConnectionError, presets},
};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr, ensure_any};
use n0_future::{StreamExt, task::AbortOnDropHandle};
use noq::StreamAffinity;

const ALPN: &[u8] = b"iroh-example/stream-affinity-direct/0";

/// Bytes of dummy data Alice sends.
const DATA_SIZE: usize = 1024 * 1024;
/// Size of each chunk Alice hands to the actor.
const CHUNK_SIZE: usize = 64 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let alice = Endpoint::builder(presets::N0).bind().await?;
    let bob = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    // Wait for bob to come online, dial by his relay URL.
    bob.online().await;
    let mut bob_addr = bob.addr();
    bob_addr.addrs.retain(|addr| addr.is_relay());

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
    println!("bob: all data read");
    conn.close(0u32.into(), b"all data read");
    n0_error::Ok(())
}

async fn run_alice(conn: Connection) -> Result<()> {
    // Print all path changes.
    let _printer = AbortOnDropHandle::new(tokio::spawn(print_open_paths(conn.clone())));
    // We need to watch the paths since we only want to transmit on a direct path.
    let mut paths_watcher = conn.paths_stream();
    // Wait for a direct path to appear. If we open the stream immediately and than set it's
    // affinity to blocked before we have a direct path we will already be consuming
    // connection-wide send window capacity for a stream that can not send anyway. So we
    // prefer to delay opening the stream.
    let direct_path = paths_watcher.wait_any(|p| p.is_ip()).await.anyerr().id();

    // Create a SendStream and make it stick to a direct path.
    println!("stream sticks to direct path {direct_path}");
    let mut send_stream = conn.open_uni().await.anyerr()?;
    send_stream
        .set_affinity(StreamAffinity::Sticky(direct_path))
        .anyerr()?;

    // Spawn a task to watch the paths and update the affinity as needed. The task is aborted
    // once it is out of scope, so no need to manage it further. We do not know that bob
    // received all the data until it is signalled by closing the connection, that is the
    // protocol agreement. So we can not stop this task before we get this signal as before
    // that we might still need to retransmit data even though we already called
    // SendStream::finish.
    let _watcher: AbortOnDropHandle<Result<()>> = AbortOnDropHandle::new(tokio::spawn({
        let conn = conn.clone();
        let send_stream = send_stream.clone();
        async move {
            let mut direct_path = direct_path;
            let mut paths_watcher = conn.paths_stream();
            while let Some(paths) = paths_watcher.wait_closed(direct_path).await {
                direct_path = if let Some(path) = paths.iter().find(|p| p.is_ip()) {
                    // A new direct path is already available. Use it.
                    path.id()
                } else {
                    println!("no direct path left, blocking the stream");
                    // No direct path is available. Wait for one and block the stream until then.
                    send_stream.set_affinity(StreamAffinity::Block).anyerr()?;
                    paths_watcher.wait_any(|p| p.is_ip()).await.anyerr()?.id()
                };
                println!("stream sticks to direct path {direct_path}");
                send_stream
                    .set_affinity(StreamAffinity::Sticky(direct_path))
                    .anyerr()?;
            }
            Ok(())
        }
    }));

    // Send the data, this will stall when the paths watcher blocks the stream.
    for _ in 0..DATA_SIZE / CHUNK_SIZE {
        send_stream
            .write_chunk(Bytes::from(vec![0xda; CHUNK_SIZE]))
            .await
            .anyerr()?;
    }
    send_stream.finish().anyerr()?;

    // Wait for blob to close the connection once all data was read.
    match conn.closed().await {
        ConnectionError::ApplicationClosed(_) => n0_error::Ok(()),
        err => Err(err).anyerr(),
    }
}

async fn print_open_paths(conn: Connection) {
    let mut watcher = conn.paths_stream();
    while let Some(paths) = watcher.next().await {
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
}

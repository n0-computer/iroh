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
//! 1. Waits until the connection has a verified direct path. Paths only show up in
//!    [`Connection::paths`] once they are validated, so any IP path listed there is a
//!    verified direct path.
//! 2. Opens a uni stream and pins it to that path with [`StreamAffinity::Sticky`] before
//!    writing anything.
//! 3. Hands the stream to an actor task that writes the data and watches the connection's
//!    path events. When the pinned path closes, the actor pins the stream to another direct
//!    path, or blocks it if there is none. When a direct path opens while the stream is
//!    blocked, it pins the stream to it.
//!
//! Once Bob has received everything, the example sums noq's per-path STREAM frame counters
//! for the relay and the direct paths, including paths that closed along the way, and
//! checks that no STREAM frame went over the relay.
//!
//! ## Usage
//!
//!     cargo run --example stream_affinity_direct
//!
//! [`Connection::paths`]: iroh::endpoint::Connection::paths
use std::time::Duration;

use bytes::{Buf, Bytes};
use iroh::{
    Endpoint,
    endpoint::{PathEvent, presets},
};
use n0_error::{Result, StdResultExt, anyerr, ensure_any};
use n0_future::StreamExt;
use noq::StreamAffinity;
use tokio::sync::mpsc;

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

    // Subscribe before looking at the open paths, so no path change is missed.
    let mut events = alice_conn.path_events();

    // Don't open or write to the stream until there is a verified direct path to send on.
    let direct = tokio::time::timeout(PATHS_TIMEOUT, async {
        loop {
            let paths = alice_conn.paths();
            if let Some(direct) = paths.iter().find(|p| p.is_ip()) {
                return Ok(direct.id());
            }
            if events.next().await.is_none() {
                return Err(anyerr!("connection closed before the direct path was open"));
            }
        }
    })
    .await
    .map_err(|_| anyerr!("direct path not open within {PATHS_TIMEOUT:?}"))??;

    println!("open paths:");
    for path in alice_conn.paths().iter() {
        let transport = if path.is_relay() { "relay" } else { "ip" };
        let selected = if path.is_selected() {
            " (selected)"
        } else {
            ""
        };
        println!("  path {}: {transport}{selected}", path.id());
    }

    // Pin the stream before the first write, so all of its data uses the direct path.
    println!("pinning the stream to direct path {direct}");
    let mut send = alice_conn.open_uni().await.anyerr()?;
    send.set_affinity(StreamAffinity::Sticky(direct)).anyerr()?;

    // The actor owns the stream: it writes what Alice hands it and keeps the stream pinned
    // to a direct path as paths come and go. It returns the STREAM frames sent on paths
    // that closed during the transfer, since those leave `Connection::paths`.
    let (tx, mut rx) = mpsc::channel::<Bytes>(4);
    let conn = alice_conn.clone();
    let actor = tokio::spawn(async move {
        let mut pinned = Some(direct);
        let mut pending: Option<Bytes> = None;
        let mut finished = false;
        let (mut closed_relay_frames, mut closed_ip_frames) = (0, 0);

        loop {
            tokio::select! {
                event = events.next() => {
                    match event {
                        Some(PathEvent::Closed { remote_addr, last_stats, .. }) => {
                            if remote_addr.is_relay() {
                                closed_relay_frames += last_stats.frame_tx.stream;
                            } else if remote_addr.is_ip() {
                                closed_ip_frames += last_stats.frame_tx.stream;
                            }
                        }
                        Some(PathEvent::Opened { .. }) => {}
                        Some(PathEvent::Lagged { missed, .. }) => {
                            println!("warning: missed {missed} path events, totals may be incomplete");
                        }
                        Some(_) => continue,
                        None => return Err(anyerr!("connection closed during the transfer")),
                    }

                    // The open paths may have changed. Keep the current pin as long as its
                    // path is still open, otherwise move to another direct path or block.
                    let paths = conn.paths();
                    if pinned.is_some_and(|id| paths.iter().any(|p| p.id() == id)) {
                        continue;
                    }
                    pinned = paths.iter().find(|p| p.is_ip()).map(|p| p.id());
                    match pinned {
                        Some(id) => {
                            println!("pinning the stream to direct path {id}");
                            send.set_affinity(StreamAffinity::Sticky(id)).anyerr()?;
                        }
                        None => {
                            println!("no direct path left, blocking the stream");
                            send.set_affinity(StreamAffinity::Block).anyerr()?;
                        }
                    }
                }
                // Where we actually write to the stream:
                // Write the pending chunk, or once the stream is finished, wait until Bob has
                // received everything. Paths are still watched until then, since lost data is ////
                // retransmitted on whichever path the stream is pinned to.
                written = async {
                    match &pending {
                        Some(chunk) => send.write(chunk).await.map(Some).anyerr(),
                        None => match send.stopped().await.anyerr()? {
                            None => Ok(None),
                            Some(code) => Err(anyerr!("bob stopped the stream with code {code}")),
                        },
                    }
                }, if pending.is_some() || finished => match written? {
                    Some(n) => {
                        let chunk = pending.as_mut().expect("only writes while a chunk is pending");
                        chunk.advance(n);
                        if chunk.is_empty() {
                            pending = None;
                        }
                    }
                    None => return Ok((closed_relay_frames, closed_ip_frames)),
                },
                chunk = rx.recv(), if pending.is_none() && !finished => match chunk {
                    Some(chunk) => pending = Some(chunk),
                    None => {
                        send.finish().anyerr()?;
                        finished = true;
                    }
                },
            }
        }
    });

    let feed = async {
        for _ in 0..DATA_SIZE / CHUNK_SIZE {
            tx.send(Bytes::from(vec![0xda; CHUNK_SIZE]))
                .await
                .map_err(|_| anyerr!("the stream actor stopped early"))?;
        }
        // Closing the channel tells the actor to finish the stream.
        drop(tx);
        n0_error::Ok(())
    };
    let receive = async {
        let mut recv = bob_conn.accept_uni().await.anyerr()?;
        let received = recv.read_to_end(DATA_SIZE).await.anyerr()?;
        ensure_any!(received.len() == DATA_SIZE, "data stream truncated");
        n0_error::Ok(())
    };
    tokio::try_join!(feed, receive)?;
    let (mut relay_frames, mut ip_frames) = actor.await.anyerr()??;

    // Add the paths that are still open. This is the only stream on the connection, so
    // every STREAM frame is its data.
    for path in alice_conn.paths().iter() {
        if path.is_relay() {
            relay_frames += path.stats().frame_tx.stream;
        } else if path.is_ip() {
            ip_frames += path.stats().frame_tx.stream;
        }
    }

    println!("\n== alice -> bob, {DATA_SIZE} bytes of dummy data ==");
    // This is kind of a silly thing to report for a this example, since in reality, there is
    // basically no chance the relay connection is established before the direct one since this is
    // a local test.
    println!("STREAM frames over the relay: {relay_frames}");
    println!("STREAM frames over direct paths: {ip_frames}");
    ensure_any!(
        relay_frames == 0,
        "{relay_frames} STREAM frames went over the relay"
    );
    ensure_any!(ip_frames > 0, "no STREAM frames went over a direct path");
    println!("OK: all stream data went over a direct path");

    alice_conn.close(0u32.into(), b"done");
    alice.close().await;
    bob.close().await;
    Ok(())
}

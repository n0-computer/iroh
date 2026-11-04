//! TODO(ramfox): this example should likely be a test and the example
//! should really be about how to respond to path events.
//! If we change it to be a test, we should run a local relay server
//! rather than use the n0 preset

//! Example showing stream affinity in action.
//! A bulk data stream over the direct path and a control
//! stream over the relay, on the same connection at the same
//! time.
//!
//! Stream affinity allows you to specify on which path you
//! want your application data to travel.
//! This allows, for example, the ability to specifically send control
//! data one one stream over one particular path over the relay and
//! another stream to send larger files over a direct path.
//!
//! Alice opens two streams to Bob and sends data over them at the same time:
//! - a uni "data" stream, pinned to the direct IP path, carrying 10 MiB,
//! - a bi "control" stream, pinned to the relay path,
//!   carrying 10 messages of 2 KiB. Bob, also pinned to the
//!   relay, echoes each messages back.
//!
//! Compares, per direction and per transport, the expected
//! payload with noq's per-path counters: the STREAM frames
//! sent, the bytes the sender sent and the bytes the receiver
//! received.
//!
//! The byte counters include all QUIC overhead (headers,
//! encryption, ACKs, pings), so they are expected to be
//! somewhat above the payload data. The STREAM frame counts
//! show which transport carried stream data at all.
//!
//! ## Usage
//!
//!     cargo run --example stream_affinity
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::{
    Endpoint, TransportAddr,
    endpoint::{Connection, PathEvent, PathId, PathStats, SendStream, presets},
};
use n0_error::{Result, StdResultExt, anyerr, ensure_any};
use n0_future::StreamExt;
use noq::StreamAffinity;

const ALPN: &[u8] = b"iroh-example/stream-affinity/0";

/// Bytes Alice sends on the data stream.
const DATA_SIZE: usize = 10 * 1024 * 1024;
/// Number of messages Alice sends on the control stream.
const CONTROL_MESSAGES: usize = 10;
/// Size of each control message, and of each echo.
const CONTROL_MESSAGE_SIZE: usize = 2 * 1024;

/// How long to wait for both a relay and a direct IP path to be open.
const PATHS_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for an endpoint to come online.
const ONLINE_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // create alice and bob
    //
    // TODO(ramfox) when turning into a test, run a local relay, don't use presets
    let alice = Endpoint::builder(presets::N0).bind().await?;
    let bob = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    tokio::time::timeout(ONLINE_TIMEOUT, alice.online())
        .await
        .map_err(|_| anyerr!("alice did not come online within {ONLINE_TIMEOUT:?}"))?;
    tokio::time::timeout(ONLINE_TIMEOUT, bob.online())
        .await
        .map_err(|_| anyerr!("bob did not come online within {ONLINE_TIMEOUT:?}"))?;

    // connect alice and bob
    let bob_addr = bob.addr();
    let (alice_conn, bob_conn) = tokio::join!(alice.connect(bob_addr, ALPN), async {
        bob.accept()
            .await
            .ok_or_else(|| anyerr!("bob's endpoint closed"))?
            .await
            .anyerr()
    });
    let (alice_conn, bob_conn) = (alice_conn?, bob_conn?);

    // track the stats of paths after they have closed, since the stats don't live on the connection
    // once the path has been closed
    let alice_paths = PathTracker::spawn(alice_conn.clone());
    let bob_paths = PathTracker::spawn(bob_conn.clone());

    // TODO(ramfox): because I'm not responding to path events to
    // update the stream affinity, I'm just waiting for both paths to
    // exist before attempting to set an affinity
    tokio::try_join!(
        wait_for_paths_to_open(&alice_conn),
        wait_for_paths_to_open(&bob_conn)
    )?;

    // `Snapshot` concept is to take the stats before and after the transfer
    // to determine how much data when over the relay vs direct
    //
    // combines the stats of the open paths with the stats of the
    // closed paths collected above
    let alice_before = Snapshot::take(&alice_conn, &alice_paths);
    let bob_before = Snapshot::take(&bob_conn, &bob_paths);

    // transfer the data
    // - 10mb from alice to bob on a uni stream pinned to an IP addr
    // - 10 2k "messages" from alice to bob to alice on the "control"
    //   bidi stream going over the relay
    tokio::try_join!(run_alice(&alice_conn), run_bob(&bob_conn))?;

    // snapshot again to compare
    let alice_delta = Snapshot::take(&alice_conn, &alice_paths).since(&alice_before);
    let bob_delta = Snapshot::take(&bob_conn, &bob_paths).since(&bob_before);

    let control_payload = (CONTROL_MESSAGES * CONTROL_MESSAGE_SIZE) as u64;

    // display the results
    report(
        ("alice", &alice_delta),
        ("bob", &bob_delta),
        control_payload,
        DATA_SIZE as u64,
    );
    report(
        ("bob", &bob_delta),
        ("alice", &alice_delta),
        control_payload,
        0,
    );

    alice_conn.close(0u32.into(), b"done");
    alice.close().await;
    bob.close().await;
    Ok(())
}

/// Alice: runs the data and control streams concurrently.
async fn run_alice(conn: &Connection) -> Result<()> {
    let mut data = conn.open_uni().await.anyerr()?;
    set_affinity(conn, &mut data, TransportAddr::is_ip)?;
    let (mut control, mut control_recv) = conn.open_bi().await.anyerr()?;
    set_affinity(conn, &mut control, TransportAddr::is_relay)?;

    let send_data = async {
        data.write_all(&vec![0xda; DATA_SIZE]).await.anyerr()?;
        data.finish().anyerr()?;
        wait_for_finish(&data).await
    };
    let send_control = async {
        let mut echo = vec![0; CONTROL_MESSAGE_SIZE];
        for i in 0..CONTROL_MESSAGES {
            let message = vec![i as u8; CONTROL_MESSAGE_SIZE];
            control.write_all(&message).await.anyerr()?;
            control_recv.read_exact(&mut echo).await.anyerr()?;
            ensure_any!(echo == message, "control echo {i} does not match");
        }
        control.finish().anyerr()?;
        let rest = control_recv.read_to_end(0).await.anyerr()?;
        ensure_any!(
            rest.is_empty(),
            "unexpected data after the last control echo"
        );
        wait_for_finish(&control).await
    };
    tokio::try_join!(send_data, send_control)?;
    Ok(())
}

/// Bob: reads the data stream and echoes every control message.
async fn run_bob(conn: &Connection) -> Result<()> {
    let read_data = async {
        let mut data = conn.accept_uni().await.anyerr()?;
        let received = data.read_to_end(DATA_SIZE).await.anyerr()?;
        ensure_any!(received.len() == DATA_SIZE, "data stream truncated");
        Ok(())
    };
    let echo_control = async {
        let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
        set_affinity(conn, &mut send, TransportAddr::is_relay)?;
        let mut message = vec![0; CONTROL_MESSAGE_SIZE];
        for _ in 0..CONTROL_MESSAGES {
            recv.read_exact(&mut message).await.anyerr()?;
            send.write_all(&message).await.anyerr()?;
        }
        let rest = recv.read_to_end(0).await.anyerr()?;
        ensure_any!(
            rest.is_empty(),
            "unexpected data after the last control message"
        );
        send.finish().anyerr()?;
        wait_for_finish(&send).await
    };
    tokio::try_join!(read_data, echo_control)?;
    Ok(())
}

/// Selects a kind of transport, such as [`TransportAddr::is_relay`] or [`TransportAddr::is_ip`].
type TransportFilter = fn(&TransportAddr) -> bool;

/// Waits until `conn` has at least one relay and one IP path open.
async fn wait_for_paths_to_open(conn: &Connection) -> Result<()> {
    let mut paths = conn.paths_stream();
    let wait = async {
        while let Some(paths) = paths.next().await {
            if paths.iter().any(|p| p.is_relay()) && paths.iter().any(|p| p.is_ip()) {
                return Ok(());
            }
        }
        Err(anyerr!(
            "connection closed before relay and ip paths were open"
        ))
    };
    tokio::time::timeout(PATHS_TIMEOUT, wait)
        .await
        .map_err(|_| anyerr!("timed out waiting for relay and ip paths"))?
}

/// Pins `send` to the first open path on `conn` whose remote address matches `transport`.
fn set_affinity(
    conn: &Connection,
    send: &mut SendStream,
    transport: TransportFilter,
) -> Result<()> {
    let paths = conn.paths();
    let path = paths
        .iter()
        .find(|p| transport(p.remote_addr()))
        .ok_or_else(|| anyerr!("no open path on the requested transport"))?;
    send.set_affinity(StreamAffinity::Sticky(path.id()))
        .anyerr()
}

/// Waits until the peer acknowledged all data on the finished `send` stream.
async fn wait_for_finish(send: &SendStream) -> Result<()> {
    match send.stopped().await.anyerr()? {
        None => Ok(()),
        Some(code) => Err(anyerr!("peer stopped the stream with code {code}")),
    }
}

/// Keeps the final stats of closed paths.
///
/// Closed paths disappear from [`Connection::paths`], so without this their traffic would be
/// missing from the totals.
#[derive(Debug, Clone, Default)]
struct PathTracker {
    closed: Arc<Mutex<BTreeMap<PathId, PathCounters>>>,
}

impl PathTracker {
    fn spawn(conn: Connection) -> Self {
        let tracker = Self::default();
        let closed = tracker.closed.clone();
        tokio::spawn(async move {
            let mut events = conn.path_events();
            while let Some(event) = events.next().await {
                match event {
                    PathEvent::Closed {
                        id,
                        remote_addr,
                        last_stats,
                        ..
                    } => {
                        let counters = PathCounters::new(remote_addr, &last_stats);
                        closed.lock().expect("poisoned").insert(id, counters);
                    }
                    PathEvent::Lagged { missed, .. } => println!(
                        "warning: missed {missed} path events, totals may be missing closed paths"
                    ),
                    _ => {}
                }
            }
        });
        tracker
    }
}

/// Counters for one path, as reported by noq.
#[derive(Debug, Clone, Default)]
struct PathCounters {
    remote_addr: Option<TransportAddr>,
    stream_frames_tx: u64,
    udp_bytes_tx: u64,
    udp_bytes_rx: u64,
}

impl PathCounters {
    fn new(remote_addr: TransportAddr, stats: &PathStats) -> Self {
        Self {
            remote_addr: Some(remote_addr),
            stream_frames_tx: stats.frame_tx.stream,
            udp_bytes_tx: stats.udp_tx.bytes,
            udp_bytes_rx: stats.udp_rx.bytes,
        }
    }

    fn since(&self, before: &Self) -> Self {
        Self {
            remote_addr: self.remote_addr.clone(),
            stream_frames_tx: self.stream_frames_tx - before.stream_frames_tx,
            udp_bytes_tx: self.udp_bytes_tx - before.udp_bytes_tx,
            udp_bytes_rx: self.udp_bytes_rx - before.udp_bytes_rx,
        }
    }

    fn add(&mut self, other: &Self) {
        self.stream_frames_tx += other.stream_frames_tx;
        self.udp_bytes_tx += other.udp_bytes_tx;
        self.udp_bytes_rx += other.udp_bytes_rx;
    }
}

/// Counters of every path of a connection at a point in time, or the difference between two
/// such points.
#[derive(Debug, Clone, Default)]
struct Snapshot {
    paths: BTreeMap<PathId, PathCounters>,
}

impl Snapshot {
    fn take(conn: &Connection, tracker: &PathTracker) -> Self {
        let mut paths = tracker.closed.lock().expect("poisoned").clone();
        for path in conn.paths().iter() {
            let counters = PathCounters::new(path.remote_addr().clone(), &path.stats());
            paths.insert(path.id(), counters);
        }
        Self { paths }
    }

    fn since(&self, before: &Self) -> Self {
        let paths = self
            .paths
            .iter()
            .map(|(id, after)| {
                let before = before.paths.get(id).cloned().unwrap_or_default();
                (*id, after.since(&before))
            })
            .collect();
        Self { paths }
    }

    /// noq counters summed over all paths whose remote address matches `transport`.
    fn paths_on(&self, transport: TransportFilter) -> PathCounters {
        let mut sum = PathCounters::default();
        let matching = self
            .paths
            .values()
            .filter(|c| c.remote_addr.as_ref().is_some_and(transport));
        for counters in matching {
            sum.add(counters);
        }
        sum
    }
}

/// Prints the expected payload next to what noq counted, for traffic from `sender` to
/// `receiver`.
///
/// Bytes sent are counted on the sender's paths, bytes received on the receiver's paths.
fn report(
    (sender_name, sender): (&str, &Snapshot),
    (receiver_name, receiver): (&str, &Snapshot),
    relay_payload: u64,
    ip_payload: u64,
) {
    println!("\n== {sender_name} -> {receiver_name} ==");
    println!(
        "{:<6} {:>17} {:>14} {:>12} {:>12}",
        "",
        "expected payload",
        "STREAM frames",
        format!("{sender_name} sent"),
        format!("{receiver_name} recv"),
    );
    let rows: [(&str, TransportFilter, u64); 2] = [
        ("relay", TransportAddr::is_relay, relay_payload),
        ("ip", TransportAddr::is_ip, ip_payload),
    ];
    for (label, transport, payload) in rows {
        let sent = sender.paths_on(transport);
        let received = receiver.paths_on(transport);
        println!(
            "{:<6} {:>17} {:>14} {:>12} {:>12}",
            label,
            Bytes(payload).to_string(),
            sent.stream_frames_tx,
            Bytes(sent.udp_bytes_tx).to_string(),
            Bytes(received.udp_bytes_rx).to_string(),
        );
    }
}

/// Formats a byte count with a binary unit.
struct Bytes(u64);

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
        let mut value = self.0 as f64;
        let mut unit = 0;
        while value >= 1024.0 && unit < UNITS.len() - 1 {
            value /= 1024.0;
            unit += 1;
        }
        if unit == 0 {
            write!(f, "{} B", self.0)
        } else {
            write!(f, "{value:.1} {}", UNITS[unit])
        }
    }
}

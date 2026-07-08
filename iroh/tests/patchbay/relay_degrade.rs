//! Relay transport under network degradation.
//!
//! These tests exercise iroh's relay transport (the peer-to-peer noq/QUIC
//! connection tunneled over a relay) under a realistic ~1400-byte link MTU,
//! parameterized over the WebTransport framing selected on the data-path relay:
//!
//! - `wt-uni` (`use_datagrams = false`): a relay message is a WebTransport uni
//!   stream chunk of up to 64 KiB, so any iroh QUIC packet fits and the relay
//!   never forces packet loss.
//! - `wt-datagram` (`use_datagrams = true`): each relay message is a QUIC
//!   DATAGRAM on the client<->relay WebTransport connection, capped near
//!   `WT_MTU - 38`. On a ~1400-byte-MTU link that budget is below iroh's own
//!   packet ceiling (~1452), so over-large relayed packets are dropped in
//!   `h3_streams::send_one_message` rather than tearing the relay connection
//!   down (no reconnect storm).
//!
//! The **bulk** transfer tests (up/down/bidi) assert real throughput over
//! `wt-uni`. Their `wt-datagram` counterparts are `#[ignore]`d: at a realistic
//! MTU, bulk over datagrams starves the tunneled QUIC connection because iroh's
//! GSO batches become single over-budget datagrams that are dropped wholesale
//! (see the note by those tests). The **constant-rate small-datagram** workload
//! (`relay_degrade_datagrams_*`) is where datagrams are meant to be used, and it
//! is asserted in both framings.
//!
//! Topology (mirrors [`super::relay`] but adds symmetric NATs and a small MTU):
//!   relay-a  (client home relay, sets `udp_available` via QAD)
//!   relay-b  (data-path relay, WT framing controlled by the test)
//!   server behind a Corporate (symmetric) NAT
//!   client behind a Corporate (symmetric) NAT
//! Symmetric NATs on both sides make holepunching impossible, so the
//! connection stays relay-only for the whole test and the framing is actually
//! exercised. Every link is capped at a 1400-byte MTU.

use std::{
    collections::HashSet,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, H3Opts, RelayMode,
    endpoint::{Connection, presets},
    tls::CaTlsConfig,
};
use iroh_relay::RelayMap;
use n0_error::{Result, StdResultExt};
use n0_future::boxed::BoxFuture;
use n0_tracing_test::traced_test;
use patchbay::{IfaceConfig, IpSupport, LinkCondition, LinkDirection, LinkLimits, Nat};
use testdir::testdir;
use tokio::sync::{Barrier, oneshot};
use tracing::info;

use super::util::{self, is_relayed};

const ALPN: &[u8] = b"relay-degrade";

/// Link MTU used for the degraded path. At 1400, wt-datagram framing must drop
/// over-large relayed iroh packets while wt-uni framing does not.
const LINK_MTU: u32 = 1400;

/// One-way link latency applied to each endpoint's access link (30ms RTT).
const LATENCY_MS: u32 = 15;

/// Boxed run function invoked on each side with the established connection.
type ConnFn = Box<dyn FnOnce(Connection) -> BoxFuture<Result> + Send>;

fn conn_fn<F, Fut>(f: F) -> ConnFn
where
    F: FnOnce(Connection) -> Fut + Send + 'static,
    Fut: Future<Output = Result> + Send + 'static,
{
    Box::new(move |conn| Box::pin(f(conn)))
}

/// Builds the two-relay + dual-NAT lab, establishes a relay-only connection, and
/// runs `server_body`/`client_body` on the respective devices.
///
/// `use_datagrams` selects the WebTransport framing of the data-path relay
/// (relay-b). The connection is asserted to be relay-only before the bodies run.
async fn run_relay_degrade(
    use_datagrams: bool,
    server_body: ConnFn,
    client_body: ConnFn,
) -> Result {
    let mut builder = patchbay::Lab::builder().outdir(patchbay::OutDir::Exact(testdir!()));
    if let Some(name) = std::thread::current().name() {
        builder = builder.label(name);
    }
    let lab = builder.build().await?;
    let guard = lab.test_guard();

    let router = lab
        .add_router("net")
        .ip_support(IpSupport::DualStack)
        .mtu(LINK_MTU)
        .build()
        .await?;

    let dns = lab.dns_server()?;

    // Relay A: client's home relay (sets udp_available via QAD).
    let relay_a_dev = lab
        .add_device("relay-a")
        .uplink(router.id())
        .mtu(LINK_MTU)
        .build()
        .await?;
    dns.set_host("relay-a.test", relay_a_dev.ip().expect("v4").into())?;
    dns.set_host("relay-a.test", relay_a_dev.ip6().expect("v6").into())?;

    let (relay_a_tx, relay_a_rx) = oneshot::channel::<RelayMap>();
    let _relay_a_task = relay_a_dev.spawn(async move |_ctx| {
        let (map, _server) = util::relay::run_relay_server_named("relay-a.test")
            .await
            .unwrap();
        relay_a_tx.send(map).unwrap();
        std::future::pending::<()>().await;
    })?;
    let relay_a_map = relay_a_rx.await.std_context("relay-a")?;

    // Relay B: the measured data-path relay.
    let relay_b_dev = lab
        .add_device("relay-b")
        .uplink(router.id())
        .mtu(LINK_MTU)
        .build()
        .await?;
    dns.set_host("relay-b.test", relay_b_dev.ip().expect("v4").into())?;
    dns.set_host("relay-b.test", relay_b_dev.ip6().expect("v6").into())?;

    let (relay_b_tx, relay_b_rx) = oneshot::channel::<RelayMap>();
    let _relay_b_task = relay_b_dev.spawn(async move |_ctx| {
        let (map, _server) = util::relay::run_relay_server_named("relay-b.test")
            .await
            .unwrap();
        relay_b_tx.send(map).unwrap();
        std::future::pending::<()>().await;
    })?;
    let relay_b_map = relay_b_rx.await.std_context("relay-b")?;

    // Symmetric NATs on both sides: holepunching is impossible, so the
    // connection stays relay-only for the whole test.
    let nat_s = lab
        .add_router("nat-server")
        .nat(Nat::Corporate)
        .upstream(router.id())
        .mtu(LINK_MTU)
        .build()
        .await?;
    let nat_c = lab
        .add_router("nat-client")
        .nat(Nat::Corporate)
        .upstream(router.id())
        .mtu(LINK_MTU)
        .build()
        .await?;

    let latency = LinkCondition::Manual(LinkLimits {
        latency_ms: LATENCY_MS,
        jitter_ms: 2,
        loss_pct: 0.0,
        reorder_pct: 0.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    });

    let server_dev = lab
        .add_device("server")
        .iface(
            "eth0",
            IfaceConfig::routed(nat_s.id()).condition(latency, LinkDirection::Both),
        )
        .mtu(LINK_MTU)
        .build()
        .await?;
    let client_dev = lab
        .add_device("client")
        .iface(
            "eth0",
            IfaceConfig::routed(nat_c.id()).condition(latency, LinkDirection::Both),
        )
        .mtu(LINK_MTU)
        .build()
        .await?;

    let (addr_tx, addr_rx) = oneshot::channel();

    // Keep both connections alive until both bodies finish, so a sender never
    // tears down its connection before the receiver has drained the stream.
    let barrier_server = Arc::new(Barrier::new(2));
    let barrier_client = barrier_server.clone();

    let server_relay_b = relay_b_map.clone();
    let client_relay_b = relay_b_map;
    let server_task = server_dev.spawn(move |_dev| async move {
        let ep = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Custom(server_relay_b))
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .std_context("server bind")?;
        ep.online().await;

        let addr = ep.addr();
        let relay_addr =
            EndpointAddr::from_parts(addr.id, addr.addrs.into_iter().filter(|a| a.is_relay()));
        addr_tx.send(relay_addr).unwrap();

        let incoming = ep.accept().await.std_context("accept")?;
        let conn = incoming
            .accept()
            .std_context("handshake")?
            .await
            .std_context("await")?;
        assert!(is_relayed(&conn), "server: connection must start relayed");

        let res = server_body(conn.clone()).await;
        assert!(is_relayed(&conn), "server: connection must stay relayed");
        barrier_server.wait().await;
        res
    })?;

    let client_task = client_dev.spawn(move |_dev| async move {
        let server_addr = addr_rx.await.std_context("addr rx")?;

        // relay-a is the home relay (always WT-capable); relay-b carries the
        // data path with the framing selected by the test.
        let client_map = RelayMap::empty();
        let relays_a: Vec<_> = relay_a_map.relays();
        for cfg in relays_a {
            let mut c = iroh_relay::RelayConfig::clone(&cfg);
            c.h3 = Some(Default::default());
            client_map.insert(c.url.clone(), std::sync::Arc::new(c));
        }
        let relays_b: Vec<_> = client_relay_b.relays();
        for cfg in relays_b {
            let mut c = iroh_relay::RelayConfig::clone(&cfg);
            let mut opts = H3Opts::default();
            opts.use_datagrams = use_datagrams;
            c.h3 = Some(opts);
            client_map.insert(c.url.clone(), std::sync::Arc::new(c));
        }

        let ep = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Custom(client_map))
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .std_context("client bind")?;

        // Go online via relay-a so net_report sets udp_available before the
        // relay-b connection is created (which then selects WebTransport).
        ep.online().await;

        let conn = ep.connect(server_addr, ALPN).await.std_context("connect")?;
        assert!(is_relayed(&conn), "client: connection must start relayed");

        let res = client_body(conn.clone()).await;
        assert!(is_relayed(&conn), "client: connection must stay relayed");
        barrier_client.wait().await;
        res
    })?;

    let (server_res, client_res) = tokio::time::timeout(Duration::from_secs(110), async {
        tokio::join!(server_task, client_task)
    })
    .await
    .std_context("test timed out")?;
    server_res.std_context("server")??;
    client_res.std_context("client")??;

    guard.ok();
    Ok(())
}

// ---
// Bulk transfer workload
// ---

/// How long each bulk transfer pushes data.
const BULK_SECS: u64 = 5;

/// Lower bound on bytes moved by a 5s bulk transfer. The bulk tests run over
/// wt-uni framing, which carries full-size relay messages and is not
/// MTU-degraded. (wt-datagram bulk is a known non-use-case; see the ignored
/// datagram bulk tests below.)
const BULK_MIN_BYTES: u64 = 256 * 1024;

/// Fixed amount pushed each way in the bidirectional workload. Reliable QUIC
/// streams, so this must complete.
const BIDI_BYTES: u64 = 1024 * 1024;

/// Direction of a bulk transfer, from the client's point of view.
#[derive(Debug, Clone, Copy)]
enum Direction {
    /// Server sends, client receives.
    Download,
    /// Client sends, server receives.
    Upload,
    /// Both sides send and receive at once.
    Bidi,
}

/// Opens a uni stream and writes 64 KiB chunks until `dur` elapses, then
/// finishes the stream. Returns the number of bytes written.
async fn bulk_send(conn: &Connection, dur: Duration) -> Result<u64> {
    let mut send = conn.open_uni().await.anyerr()?;
    let chunk = vec![0u8; 64 * 1024];
    let deadline = Instant::now() + dur;
    let mut total = 0u64;
    while Instant::now() < deadline {
        send.write_all(&chunk).await.anyerr()?;
        total += chunk.len() as u64;
    }
    send.finish().anyerr()?;
    Ok(total)
}

/// Opens a uni stream, writes exactly `bytes` bytes, then finishes it.
///
/// Used for the bidirectional workload: saturating both directions at once
/// over the tiny wt-datagram budget can leave a full-size retransmit tail that
/// never fits the datagram, so instead a bounded amount is pushed each way.
/// Once the (small) data phase is done only small ACK packets remain, which
/// fit the budget and let the streams drain.
async fn bulk_send_bytes(conn: &Connection, bytes: u64) -> Result<u64> {
    let mut send = conn.open_uni().await.anyerr()?;
    let chunk = vec![0u8; 64 * 1024];
    let mut sent = 0u64;
    while sent < bytes {
        let n = (bytes - sent).min(chunk.len() as u64) as usize;
        send.write_all(&chunk[..n]).await.anyerr()?;
        sent += n as u64;
    }
    send.finish().anyerr()?;
    Ok(sent)
}

/// Accepts a uni stream and drains it to completion. Returns the number of
/// bytes received and the wall-clock time from first to last byte.
async fn bulk_recv(conn: &Connection) -> Result<(u64, Duration)> {
    let mut recv = conn.accept_uni().await.anyerr()?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    let mut last_log = Instant::now();
    let start = Instant::now();
    while let Some(n) = recv.read(&mut buf).await.anyerr()? {
        total += n as u64;
        if last_log.elapsed() >= Duration::from_secs(5) {
            last_log = Instant::now();
            tracing::debug!(
                "bulk_recv progress: {total} bytes after {:?}",
                start.elapsed()
            );
        }
    }
    Ok((total, start.elapsed()))
}

/// Runs a single-direction bulk transfer and asserts graceful completion.
async fn run_bulk(use_datagrams: bool, direction: Direction) -> Result {
    let label = if use_datagrams {
        "wt-datagram"
    } else {
        "wt-uni"
    };
    let dur = Duration::from_secs(BULK_SECS);
    let started = Instant::now();

    let server_body: ConnFn = match direction {
        Direction::Download => conn_fn(move |conn| async move {
            let sent = bulk_send(&conn, dur).await?;
            info!("bulk download: server sent {sent} bytes");
            Ok(())
        }),
        Direction::Upload => conn_fn(move |conn| async move {
            let (got, elapsed) = bulk_recv(&conn).await?;
            info!("bulk upload: server received {got} bytes in {elapsed:?}");
            assert!(got >= BULK_MIN_BYTES, "server received too little: {got}");
            Ok(())
        }),
        Direction::Bidi => conn_fn(move |conn| async move {
            let (send_res, recv_res) =
                tokio::join!(bulk_send_bytes(&conn, BIDI_BYTES), bulk_recv(&conn));
            let sent = send_res?;
            let (got, _) = recv_res?;
            info!("bulk bidi: server sent {sent}, received {got} bytes");
            assert!(got >= BULK_MIN_BYTES, "server received too little: {got}");
            Ok(())
        }),
    };

    let client_body: ConnFn = match direction {
        Direction::Download => conn_fn(move |conn| async move {
            let (got, elapsed) = bulk_recv(&conn).await?;
            let kbps = (got as f64 * 8.0 / 1000.0) / elapsed.as_secs_f64();
            info!("bulk download: client received {got} bytes in {elapsed:?} ({kbps:.0} kbit/s)");
            assert!(got >= BULK_MIN_BYTES, "client received too little: {got}");
            Ok(())
        }),
        Direction::Upload => conn_fn(move |conn| async move {
            let sent = bulk_send(&conn, dur).await?;
            info!("bulk upload: client sent {sent} bytes");
            Ok(())
        }),
        Direction::Bidi => conn_fn(move |conn| async move {
            let (send_res, recv_res) =
                tokio::join!(bulk_send_bytes(&conn, BIDI_BYTES), bulk_recv(&conn));
            let sent = send_res?;
            let (got, elapsed) = recv_res?;
            let kbps = (got as f64 * 8.0 / 1000.0) / elapsed.as_secs_f64();
            info!("bulk bidi: client sent {sent}, received {got} bytes ({kbps:.0} kbit/s)");
            assert!(got >= BULK_MIN_BYTES, "client received too little: {got}");
            Ok(())
        }),
    };

    run_relay_degrade(use_datagrams, server_body, client_body).await?;

    let total = started.elapsed();
    info!("{label} bulk {direction:?} completed in {total:?}");
    // Hard upper time bound: even under the worst wt-datagram degradation the
    // workload must finish well within this (guards against stalls/deadlocks).
    assert!(
        total < Duration::from_secs(90),
        "{label} bulk {direction:?} too slow: {total:?}"
    );
    Ok(())
}

// ---
// Small constant-rate datagram workload
// ---

/// Payload size of each small datagram. Small enough to fit a single
/// wt-datagram even at a 1400-byte link MTU. 30 fps * ~533 bytes ~= 128 kbit/s.
const DG_SIZE: usize = 533;
/// Number of datagrams sent (30 fps for ~5s).
const DG_COUNT: usize = 150;
/// Inter-datagram interval (30 fps).
const DG_INTERVAL: Duration = Duration::from_millis(33);
/// Minimum acceptable delivery ratio. Loose to avoid flaking; small datagrams
/// fit within budget in both framings, so most should arrive.
const DG_MIN_RATIO: f64 = 0.7;

/// Sends `DG_COUNT` sequence-tagged datagrams at ~30 fps, then signals
/// completion over a reliable bidi stream and waits for the ack.
async fn dg_client(conn: Connection) -> Result {
    let max = conn.max_datagram_size();
    assert!(
        max.map(|m| m >= DG_SIZE).unwrap_or(false),
        "datagrams unsupported or too small: {max:?}"
    );

    let mut sent = 0usize;
    for i in 0..DG_COUNT {
        let mut buf = vec![0u8; DG_SIZE];
        buf[..8].copy_from_slice(&(i as u64).to_le_bytes());
        // Over-budget datagrams may be dropped at the relay; that is graceful
        // degradation, not an error. A local buffer-full error is likewise fine.
        if conn.send_datagram(Bytes::from(buf)).is_ok() {
            sent += 1;
        }
        tokio::time::sleep(DG_INTERVAL).await;
    }
    info!("datagram client: submitted {sent}/{DG_COUNT} datagrams");

    // Signal completion and wait for the receiver's ack.
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"done").await.anyerr()?;
    send.finish().anyerr()?;
    let ack = recv.read_to_end(16).await.anyerr()?;
    assert_eq!(&ack, b"ack", "unexpected ack");
    Ok(())
}

/// Counts unique received datagrams until the sender signals completion over a
/// reliable stream, then asserts the delivery ratio.
async fn dg_server(conn: Connection) -> Result {
    let seen = Arc::new(AtomicUsize::new(0));
    let seen_set = Arc::new(tokio::sync::Mutex::new(HashSet::new()));

    let read_conn = conn.clone();
    let read_set = seen_set.clone();
    let read_seen = seen.clone();
    let reader = tokio::spawn(async move {
        while let Ok(data) = read_conn.read_datagram().await {
            if data.len() >= 8 {
                let mut seq = [0u8; 8];
                seq.copy_from_slice(&data[..8]);
                let seq = u64::from_le_bytes(seq);
                if read_set.lock().await.insert(seq) {
                    read_seen.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });

    // Wait for the completion signal, then ack.
    let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
    let marker = recv.read_to_end(16).await.anyerr()?;
    assert_eq!(&marker, b"done", "unexpected completion marker");
    // Allow a brief drain window for any in-flight datagrams.
    tokio::time::sleep(Duration::from_millis(200)).await;
    reader.abort();

    let received = seen.load(Ordering::Relaxed);
    let ratio = received as f64 / DG_COUNT as f64;
    info!("datagram server: received {received}/{DG_COUNT} unique ({ratio:.2} delivery ratio)");

    send.write_all(b"ack").await.anyerr()?;
    send.finish().anyerr()?;

    assert!(
        ratio >= DG_MIN_RATIO,
        "datagram delivery ratio too low: {ratio:.2} ({received}/{DG_COUNT})"
    );
    Ok(())
}

async fn run_datagrams(use_datagrams: bool) -> Result {
    run_relay_degrade(use_datagrams, conn_fn(dg_server), conn_fn(dg_client)).await
}

// ---
// Test entry points (parameterized over the WebTransport framing)
// ---

#[tokio::test]
#[traced_test]
async fn relay_degrade_bulk_download_wt_uni() -> Result {
    run_bulk(false, Direction::Download).await
}

// The wt-datagram bulk tests are ignored: at a realistic link MTU, bulk over
// datagrams starves the tunneled iroh QUIC connection. iroh coalesces sends into
// GSO batches, which the relay carries as one datagram; that batch far exceeds
// the datagram budget, so the whole batch is dropped (see
// `h3_streams::send_one_message`). With almost nothing getting through, the
// connection can idle out ("connection lost"). This is a known limitation --
// QUIC datagrams are for small messages, not bulk (see the module docs and
// `plans/h3-bench.md`); the constant-rate `relay_degrade_datagrams_*` tests
// cover the small-message case, which works. Un-ignore once relay-datagram
// sends split GSO batches into per-packet datagrams.
#[tokio::test]
#[traced_test]
#[ignore = "wt-datagram bulk starves the tunneled QUIC connection (GSO batches exceed the datagram budget)"]
async fn relay_degrade_bulk_download_wt_datagram() -> Result {
    run_bulk(true, Direction::Download).await
}

#[tokio::test]
#[traced_test]
async fn relay_degrade_bulk_upload_wt_uni() -> Result {
    run_bulk(false, Direction::Upload).await
}

#[tokio::test]
#[traced_test]
#[ignore = "wt-datagram bulk starves the tunneled QUIC connection (GSO batches exceed the datagram budget)"]
async fn relay_degrade_bulk_upload_wt_datagram() -> Result {
    run_bulk(true, Direction::Upload).await
}

#[tokio::test]
#[traced_test]
async fn relay_degrade_bulk_bidi_wt_uni() -> Result {
    run_bulk(false, Direction::Bidi).await
}

#[tokio::test]
#[traced_test]
#[ignore = "wt-datagram bulk starves the tunneled QUIC connection (GSO batches exceed the datagram budget)"]
async fn relay_degrade_bulk_bidi_wt_datagram() -> Result {
    run_bulk(true, Direction::Bidi).await
}

#[tokio::test]
#[traced_test]
async fn relay_degrade_datagrams_wt_uni() -> Result {
    run_datagrams(false).await
}

#[tokio::test]
#[traced_test]
async fn relay_degrade_datagrams_wt_datagram() -> Result {
    run_datagrams(true).await
}

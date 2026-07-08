//! Relay-transport throughput under network degradation.
//!
//! These tests exercise iroh's relay transport (a peer-to-peer noq/QUIC
//! connection tunneled over a single relay) at a standard 1500-byte link MTU,
//! parameterized over the WebTransport framing selected on the shared relay:
//!
//! - `ws`: WebSocket relay transport (`RelayConfig.h3 = None`).
//! - `wt-uni`: WebTransport, one uni stream per relay message (up to 64 KiB), so
//!   any iroh QUIC packet fits (`Some(H3Opts::default())`).
//! - `wt-datagram`: WebTransport, one QUIC DATAGRAM per relay message
//!   (`H3Opts { use_datagrams: true, .. }`). Each datagram carries one whole
//!   iroh QUIC packet, so the relay actor first splits GSO batches into one
//!   datagram per packet. The relay H3 connection pins its minimum MTU to 1280
//!   (IPv6 minimum) so the datagram budget always clears iroh's 1200-byte QUIC
//!   packet floor; only iroh's own oversized PLPMTUD probes are ever dropped.
//!
//! Topology (ONE relay, both peers behind hard NATs):
//!   relay   (shared data-path relay; WT framing controlled by the test)
//!   server  (behind a symmetric `Nat::Corporate` router)
//!   client  (behind a symmetric `Nat::Corporate` router)
//! Each peer sits behind its own symmetric (endpoint-dependent-mapping) NAT, for
//! which holepunching is impossible, so the connection stays relay-only for the
//! whole test (asserted via `is_relayed`) -- but IP transports are left ENABLED.
//! This is deliberately different from calling `clear_ip_transports()`: that
//! forces relay-only by disabling the direct paths entirely, which also disables
//! GSO (segment offload collapses to one packet per send), so the relay actor's
//! GSO-split path for wt-datagram framing is never exercised and the scenario is
//! unrealistic. Symmetric NATs keep the full IP/GSO machinery running while
//! still pinning the data path to the relay, matching a real corporate/CGNAT
//! peer that never manages to holepunch. Both endpoints share the same
//! `RelayMap` with the same framing applied, so both directions use the framing.
//!
//! Both peers' access links carry the same [`LinkCondition`] in
//! [`LinkDirection::Both`], so degradation is symmetric across peers and
//! directions. Three realistic last-mile levels (`wifi`/`4g`/`3g`, see
//! [`Degradation`]) form a matrix dimension alongside framing and direction.
//!
//! Throughput is measured over a FIXED transfer of N bytes (identical across
//! framings within a degradation level; see [`Degradation::n_bytes`]) on the
//! sender's own clock: `t0` is taken just before the first write and `t_done`
//! when the receiver confirms full receipt (the transfer-example pattern -- the
//! sender writes N on a bi stream and `finish()`es, the receiver drains to EOF
//! and `finish()`es its own send half, and the sender reads its recv half to
//! EOF). Connection setup is never included in the throughput timing.
//!
//! Connection setup time ("connect to connected") is measured separately on the
//! client's clock, from just before `Endpoint::connect` to the moment it returns
//! the established connection, and reported in the second metric column.
//!
//! Machine-readable results are printed with `println!` (not tracing, which
//! `traced_test` hides on passing tests). CSV schema (leading `RUNDOWN` tag):
//!
//!   RUNDOWN,<framing>,<degradation>,<direction>,<throughput_kbps>,<setup_ms>
//!   RUNDOWN,<framing>,<degradation>,datagrams,<delivery_pct>,<setup_ms>
//!   RUNDOWN,<framing>,<degradation>,<direction>,FAILED,<reason>
//!
//! Columns: framing (ws|wt-uni|wt-datagram), degradation (wifi|4g|3g), direction
//! (download|upload|bidi|datagrams), then two metric columns whose meaning
//! depends on the row (throughput in kbit/s for bulk, delivery percentage for
//! datagrams, FAILED on error) plus connection setup time in ms (reason on
//! error).

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
use patchbay::{IfaceConfig, IpSupport, LinkCondition, LinkDirection, Nat};
use testdir::testdir;
use tokio::sync::{Barrier, oneshot};
use tracing::info;

use super::util::{self, is_relayed};

const ALPN: &[u8] = b"relay-degrade";

/// Link MTU used for the degraded path: standard 1500-byte Ethernet, the most
/// common real last-mile MTU. This leaves enough headroom that a full-size iroh
/// QUIC packet still fits inside one WebTransport datagram (payload budget
/// ~= WT_MTU - 40) once the relay actor has split GSO batches, so wt-datagram
/// framing carries bulk traffic without dropping every packet.
const LINK_MTU: u32 = 1500;

/// Per-transfer upper bound: a single bulk transfer must finish within this or
/// it is treated as a failed cell (guards against stalls hanging the suite).
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

/// Overall per-cell timeout for the whole lab (setup + connect + transfer).
const CELL_TIMEOUT: Duration = Duration::from_secs(200);

/// Write chunk size on the sending side.
const SEND_CHUNK: usize = 256 * 1024;
/// Read buffer size on the receiving side.
const RECV_BUF: usize = 64 * 1024;

/// Relay transport framing under test on the shared relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// WebSocket (WebTransport disabled).
    Ws,
    /// WebTransport, one unidirectional stream per relay message.
    WtUni,
    /// WebTransport, one QUIC datagram per relay message.
    WtDatagram,
}

impl Framing {
    fn label(self) -> &'static str {
        match self {
            Framing::Ws => "ws",
            Framing::WtUni => "wt-uni",
            Framing::WtDatagram => "wt-datagram",
        }
    }

    /// The `RelayConfig.h3` value that selects this framing.
    fn h3(self) -> Option<H3Opts> {
        match self {
            Framing::Ws => None,
            Framing::WtUni => Some(H3Opts::default()),
            Framing::WtDatagram => {
                // H3Opts is #[non_exhaustive]; build via default + field set.
                let mut opts = H3Opts::default();
                opts.use_datagrams = true;
                Some(opts)
            }
        }
    }
}

/// Network degradation level applied to both peers' access links, both
/// directions. Uses patchbay's realistic last-mile presets (modelled on real
/// `tc netem` profiles), all at [`LINK_MTU`]. Latency is one-way, so the
/// end-to-end RTT over the relay traverses two impaired links each way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Degradation {
    /// Good 5 GHz WiFi: 5 ms / 2 ms jitter / 0.1% loss.
    Wifi,
    /// 4G/LTE, good signal: 25 ms / 8 ms jitter / 0.5% loss.
    Mobile4g,
    /// 3G or degraded 4G: 100 ms / 30 ms jitter / 2% loss, 2 Mbit rate cap.
    Mobile3g,
}

impl Degradation {
    fn label(self) -> &'static str {
        match self {
            Degradation::Wifi => "wifi",
            Degradation::Mobile4g => "4g",
            Degradation::Mobile3g => "3g",
        }
    }

    fn condition(self) -> LinkCondition {
        match self {
            Degradation::Wifi => LinkCondition::Wifi,
            Degradation::Mobile4g => LinkCondition::Mobile4G,
            Degradation::Mobile3g => LinkCondition::Mobile3G,
        }
    }

    /// Bytes moved per bulk transfer at this level.
    ///
    /// N is FIXED per level and IDENTICAL across all three framings and all
    /// three directions, so framing comparison within a level is apples-to-apples
    /// (throughput is a rate). N is sized so each transfer runs for several
    /// seconds -- long enough that the link's loss rate is well-averaged rather
    /// than dominated by a lucky/unlucky burst -- while staying under
    /// [`TRANSFER_TIMEOUT`]; it is larger where the link is faster.
    fn n_bytes(self) -> u64 {
        match self {
            Degradation::Wifi => 64 * 1024 * 1024,
            Degradation::Mobile4g => 8 * 1024 * 1024,
            Degradation::Mobile3g => 2 * 1024 * 1024,
        }
    }
}

/// Direction of a bulk transfer, from the client's point of view.
#[derive(Debug, Clone, Copy)]
enum Direction {
    /// Server sends, client receives.
    Download,
    /// Client sends, server receives.
    Upload,
    /// Both sides send and receive at once; the client->server stream is the
    /// measured/reported one.
    Bidi,
}

impl Direction {
    fn label(self) -> &'static str {
        match self {
            Direction::Download => "download",
            Direction::Upload => "upload",
            Direction::Bidi => "bidi",
        }
    }
}

/// Boxed run function invoked on each side with the established connection.
///
/// Returns the metric this side measured, if any: the bulk sender returns
/// `Some(throughput_kbps)`, the datagram server returns `Some(delivery_pct)`,
/// and every non-measuring side returns `None`. Exactly one of the two sides
/// produces a value per cell.
type ConnFn = Box<dyn FnOnce(Connection) -> BoxFuture<Result<Option<f64>>> + Send>;

fn conn_fn<F, Fut>(f: F) -> ConnFn
where
    F: FnOnce(Connection) -> Fut + Send + 'static,
    Fut: Future<Output = Result<Option<f64>>> + Send + 'static,
{
    Box::new(move |conn| Box::pin(f(conn)))
}

/// Returns a copy of `map` with every relay's `h3` config set for `framing`, so
/// both endpoints share the same framing.
fn apply_framing(map: &RelayMap, framing: Framing) -> RelayMap {
    let out = RelayMap::empty();
    let relays: Vec<_> = map.relays();
    for cfg in relays {
        let mut c = iroh_relay::RelayConfig::clone(&cfg);
        c.h3 = framing.h3();
        out.insert(c.url.clone(), Arc::new(c));
    }
    out
}

/// Emits one machine-readable CSV cell line. See the module docs for the schema.
/// `metric` is throughput in kbit/s (bulk) or delivery percentage (datagrams);
/// `setup_ms` is the connection setup time measured on the client.
fn emit_cell(framing: &str, degradation: &str, direction: &str, metric: f64, setup_ms: f64) {
    println!("RUNDOWN,{framing},{degradation},{direction},{metric:.0},{setup_ms:.1}");
}

// ---
// Bulk transfer measurement
// ---

/// Sends exactly `n` bytes on a fresh bi stream and returns the throughput in
/// kbit/s.
///
/// `t0` is taken just before the first write; the clock stops when the receiver
/// confirms full receipt by finishing its own send half (read here as EOF).
async fn send_measured(conn: &Connection, n: u64) -> Result<f64> {
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    let chunk = vec![0u8; SEND_CHUNK];
    let t0 = Instant::now();
    let mut left = n;
    while left > 0 {
        let k = left.min(SEND_CHUNK as u64) as usize;
        send.write_all(&chunk[..k]).await.anyerr()?;
        left -= k as u64;
    }
    send.finish().anyerr()?;

    // Confirmation: receiver finishes its send half after fully draining ours,
    // so reading it to EOF marks full receipt.
    recv.read_to_end(16).await.anyerr()?;
    let elapsed = t0.elapsed();

    let secs = elapsed.as_secs_f64();
    let throughput_kbps = if secs > 0.0 {
        (n as f64 * 8.0 / 1000.0) / secs
    } else {
        0.0
    };
    Ok(throughput_kbps)
}

/// Accepts a bi stream and drains exactly `n` bytes, then confirms full receipt
/// by finishing its own send half. Returns the number of bytes read.
async fn recv_measured(conn: &Connection, n: u64) -> Result<u64> {
    let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
    let mut buf = vec![0u8; RECV_BUF];
    let mut got = 0u64;
    while let Some(k) = recv.read(&mut buf).await.anyerr()? {
        got += k as u64;
    }

    // Confirm receipt by finishing our send half; the sender reads it as EOF.
    send.finish().anyerr()?;

    assert_eq!(got, n, "receiver: short transfer ({got} != {n})");
    Ok(got)
}

/// [`send_measured`] bounded by [`TRANSFER_TIMEOUT`].
async fn send_timed(conn: &Connection, n: u64) -> Result<f64> {
    tokio::time::timeout(TRANSFER_TIMEOUT, send_measured(conn, n))
        .await
        .std_context("send transfer timed out")?
}

/// [`recv_measured`] bounded by [`TRANSFER_TIMEOUT`].
async fn recv_timed(conn: &Connection, n: u64) -> Result<u64> {
    tokio::time::timeout(TRANSFER_TIMEOUT, recv_measured(conn, n))
        .await
        .std_context("recv transfer timed out")?
}

/// Runs a single bulk transfer for `(framing, degradation, direction)` and emits
/// one CSV cell: throughput from the measuring side, setup time from the client.
async fn run_bulk(framing: Framing, degradation: Degradation, direction: Direction) -> Result {
    let fl = framing.label();
    let dl = degradation.label();
    let dir = direction.label();
    let n = degradation.n_bytes();

    let (server_body, client_body): (ConnFn, ConnFn) = match direction {
        // Server sends -> server measures throughput, client receives.
        Direction::Download => (
            conn_fn(move |conn| async move { Ok(Some(send_timed(&conn, n).await?)) }),
            conn_fn(move |conn| async move {
                recv_timed(&conn, n).await?;
                Ok(None)
            }),
        ),
        // Client sends -> client measures throughput, server receives.
        Direction::Upload => (
            conn_fn(move |conn| async move {
                recv_timed(&conn, n).await?;
                Ok(None)
            }),
            conn_fn(move |conn| async move { Ok(Some(send_timed(&conn, n).await?)) }),
        ),
        // Both directions concurrently; the client->server stream is measured.
        Direction::Bidi => (
            conn_fn(move |conn| async move {
                let (send_res, recv_res) = tokio::join!(send_timed(&conn, n), recv_timed(&conn, n));
                send_res?;
                recv_res?;
                Ok(None)
            }),
            conn_fn(move |conn| async move {
                let (send_res, recv_res) = tokio::join!(send_timed(&conn, n), recv_timed(&conn, n));
                let kbps = send_res?;
                recv_res?;
                Ok(Some(kbps))
            }),
        ),
    };

    let (setup_ms, metric) = run_relay_degrade(framing, degradation, server_body, client_body).await?;
    emit_cell(fl, dl, dir, metric.unwrap_or(0.0), setup_ms);
    Ok(())
}

// ---
// Small constant-rate datagram workload
// ---

/// Payload of each small datagram; small enough to fit a single wt-datagram at a
/// 1400-byte link MTU. 30 fps * ~533 bytes ~= 128 kbit/s.
const DG_SIZE: usize = 533;
/// Number of datagrams sent (30 fps for ~5s).
const DG_COUNT: usize = 150;
/// Inter-datagram interval (30 fps).
const DG_INTERVAL: Duration = Duration::from_millis(33);
/// Minimum acceptable delivery ratio for the smoke tests. Loose to avoid
/// flaking; the rundown records the ratio regardless.
const DG_MIN_RATIO: f64 = 0.7;

/// Sends `DG_COUNT` sequence-tagged datagrams at ~30 fps, then signals
/// completion over a reliable bidi stream and waits for the ack.
async fn dg_client(conn: Connection) -> Result<Option<f64>> {
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

    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"done").await.anyerr()?;
    send.finish().anyerr()?;
    let ack = recv.read_to_end(16).await.anyerr()?;
    assert_eq!(&ack, b"ack", "unexpected ack");
    Ok(None)
}

/// Counts unique received datagrams until the sender signals completion over a
/// reliable stream, then returns the delivery percentage (and asserts a loose
/// floor).
async fn dg_server(conn: Connection) -> Result<Option<f64>> {
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

    let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
    let marker = recv.read_to_end(16).await.anyerr()?;
    assert_eq!(&marker, b"done", "unexpected completion marker");
    // Allow a brief drain window for any in-flight datagrams.
    tokio::time::sleep(Duration::from_millis(200)).await;
    reader.abort();

    let received = seen.load(Ordering::Relaxed);
    let ratio = received as f64 / DG_COUNT as f64;

    send.write_all(b"ack").await.anyerr()?;
    send.finish().anyerr()?;

    assert!(
        ratio >= DG_MIN_RATIO,
        "datagram delivery ratio too low: {ratio:.2} ({received}/{DG_COUNT})"
    );
    Ok(Some(ratio * 100.0))
}

async fn run_datagrams(framing: Framing, degradation: Degradation) -> Result {
    let fl = framing.label();
    let dl = degradation.label();
    let server = conn_fn(dg_server);
    let (setup_ms, metric) =
        run_relay_degrade(framing, degradation, server, conn_fn(dg_client)).await?;
    // datagrams row: the metric column is delivery percentage.
    emit_cell(fl, dl, "datagrams", metric.unwrap_or(0.0), setup_ms);
    Ok(())
}

// ---
// Lab harness
// ---

/// Builds the single-relay lab, establishes a relay-only connection under
/// `degradation`, and runs `server_body`/`client_body` on the respective
/// devices. `framing` selects the relay transport framing on the shared relay.
///
/// Returns `(setup_ms, metric)`: the connection setup time measured on the
/// client, and whichever metric the measuring side produced (see [`ConnFn`]).
async fn run_relay_degrade(
    framing: Framing,
    degradation: Degradation,
    server_body: ConnFn,
    client_body: ConnFn,
) -> Result<(f64, Option<f64>)> {
    let mut builder = patchbay::Lab::builder().outdir(patchbay::OutDir::Exact(testdir!()));
    if let Some(name) = std::thread::current().name() {
        builder = builder.label(name);
    }
    let lab = builder.build().await?;
    let guard = lab.test_guard();

    // Public backbone router carrying the shared relay.
    let net = lab
        .add_router("net")
        .ip_support(IpSupport::DualStack)
        .mtu(LINK_MTU)
        .build()
        .await?;

    let dns = lab.dns_server()?;

    // Single shared relay carrying the data path, on the public backbone.
    let relay_dev = lab
        .add_device("relay")
        .uplink(net.id())
        .mtu(LINK_MTU)
        .build()
        .await?;
    dns.set_host("relay.test", relay_dev.ip().expect("v4").into())?;
    dns.set_host("relay.test", relay_dev.ip6().expect("v6").into())?;

    let (relay_tx, relay_rx) = oneshot::channel::<RelayMap>();
    let _relay_task = relay_dev.spawn(async move |_ctx| {
        let (map, _server) = util::relay::run_relay_server_named("relay.test")
            .await
            .unwrap();
        relay_tx.send(map).unwrap();
        std::future::pending::<()>().await;
    })?;
    let relay_map = relay_rx.await.std_context("relay")?;

    // Same framing on both endpoints' shared map.
    let shared_map = apply_framing(&relay_map, framing);

    // Each peer sits behind its own symmetric NAT (Nat::Corporate). Holepunching
    // between two symmetric NATs is impossible, so the connection stays
    // relay-only, but IP transports remain enabled (unlike clear_ip_transports),
    // keeping GSO on so the relay actor's GSO-split path is exercised.
    let nat_server = lab
        .add_router("nat-server")
        .nat(Nat::Corporate)
        .mtu(LINK_MTU)
        .build()
        .await?;
    let nat_client = lab
        .add_router("nat-client")
        .nat(Nat::Corporate)
        .mtu(LINK_MTU)
        .build()
        .await?;

    // Impair both peers' access links, both directions, same condition.
    let condition = degradation.condition();
    let server_dev = lab
        .add_device("server")
        .iface(
            "eth0",
            IfaceConfig::routed(nat_server.id()).condition(condition, LinkDirection::Both),
        )
        .mtu(LINK_MTU)
        .build()
        .await?;
    let client_dev = lab
        .add_device("client")
        .iface(
            "eth0",
            IfaceConfig::routed(nat_client.id()).condition(condition, LinkDirection::Both),
        )
        .mtu(LINK_MTU)
        .build()
        .await?;

    let (addr_tx, addr_rx) = oneshot::channel();
    // Client reports its connect-to-connected setup time back to the harness.
    let (setup_tx, setup_rx) = oneshot::channel::<Duration>();

    // Keep both connections alive until both bodies finish, so a sender never
    // tears down its connection before the receiver has drained the stream.
    let barrier_server = Arc::new(Barrier::new(2));
    let barrier_client = barrier_server.clone();

    let server_map = shared_map.clone();
    let server_task = server_dev.spawn(move |_dev| async move {
        let ep = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Custom(server_map))
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .std_context("server bind")?;
        // Server must be reachable over the relay before it can accept.
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

        let ep = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Custom(shared_map))
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .std_context("client bind")?;

        // The client does not await online(); it connects on demand. Time the
        // connect-to-connected setup and report it back to the harness.
        let t_connect = Instant::now();
        let conn = ep.connect(server_addr, ALPN).await.std_context("connect")?;
        let setup = t_connect.elapsed();
        setup_tx.send(setup).ok();
        assert!(is_relayed(&conn), "client: connection must start relayed");

        let res = client_body(conn.clone()).await;
        assert!(is_relayed(&conn), "client: connection must stay relayed");
        barrier_client.wait().await;
        res
    })?;

    let (server_res, client_res) = tokio::time::timeout(CELL_TIMEOUT, async {
        tokio::join!(server_task, client_task)
    })
    .await
    .std_context("cell timed out")?;
    let server_metric = server_res.std_context("server")??;
    let client_metric = client_res.std_context("client")??;

    let setup_ms = setup_rx
        .await
        .std_context("client setup time")?
        .as_secs_f64()
        * 1000.0;
    let metric = server_metric.or(client_metric);

    guard.ok();
    Ok((setup_ms, metric))
}

const FRAMINGS: &[Framing] = &[Framing::Ws, Framing::WtUni, Framing::WtDatagram];
const DEGRADATIONS: &[Degradation] =
    &[Degradation::Wifi, Degradation::Mobile4g, Degradation::Mobile3g];
const DIRECTIONS: &[Direction] = &[Direction::Download, Direction::Upload, Direction::Bidi];

// ---
// Test entry points
// ---

/// Full rundown: bulk throughput for framing x degradation x direction, plus the
/// constant-rate datagram delivery for framing x degradation. Every cell emits a
/// `RUNDOWN,...` CSV line (see module docs); per-cell failures are caught and
/// logged as a `RUNDOWN,...,FAILED,<reason>` line so one run captures the whole
/// matrix.
///
/// `#[ignore]`d (dozens of relay setups); run in release, serially:
///   cargo test --release -p iroh --test patchbay relay_degrade_rundown \
///     -- --ignored --test-threads=1 --nocapture 2>&1 | grep RUNDOWN
#[tokio::test]
#[traced_test]
#[ignore = "full rundown matrix; long, run manually"]
async fn relay_degrade_rundown() -> Result {
    for &framing in FRAMINGS {
        for &degradation in DEGRADATIONS {
            for &direction in DIRECTIONS {
                if let Err(err) = run_bulk(framing, degradation, direction).await {
                    let reason = format!("{err:#}").replace([',', '\n'], " ");
                    println!(
                        "RUNDOWN,{},{},{},FAILED,{reason}",
                        framing.label(),
                        degradation.label(),
                        direction.label(),
                    );
                }
            }
            if let Err(err) = run_datagrams(framing, degradation).await {
                let reason = format!("{err:#}").replace([',', '\n'], " ");
                println!(
                    "RUNDOWN,{},{},datagrams,FAILED,{reason}",
                    framing.label(),
                    degradation.label(),
                );
            }
        }
    }
    Ok(())
}

// Smoke tests run in CI: one framing x one degradation, bulk (bidi) + datagram.
// Run with `--test-threads=1` (patchbay needs serial execution).
#[tokio::test]
#[traced_test]
async fn relay_degrade_smoke_ws() -> Result {
    run_bulk(Framing::Ws, Degradation::Wifi, Direction::Bidi).await?;
    run_datagrams(Framing::Ws, Degradation::Wifi).await
}

#[tokio::test]
#[traced_test]
async fn relay_degrade_smoke_wt_uni() -> Result {
    run_bulk(Framing::WtUni, Degradation::Wifi, Direction::Bidi).await?;
    run_datagrams(Framing::WtUni, Degradation::Wifi).await
}

#[tokio::test]
#[traced_test]
async fn relay_degrade_smoke_wt_datagram() -> Result {
    run_bulk(Framing::WtDatagram, Degradation::Wifi, Direction::Bidi).await?;
    run_datagrams(Framing::WtDatagram, Degradation::Wifi).await
}

//! Relay TTFB measurement tests.
//!
//! Two relays: relay-a is the client's home relay (for net_report to set
//! `udp_available`), relay-b is the server's relay (measured path). The client
//! discovers relay-b from the server's address and creates a fresh relay actor
//! that reads the current `udp_available` state and the `h3` flag.

use std::time::{Duration, Instant};

use iroh::{
    Endpoint, EndpointAddr, RelayMode,
    endpoint::{Connection, presets},
    tls::CaRootsConfig,
};
use iroh_relay::RelayMap;
use n0_error::{Result, StdResultExt};
use n0_tracing_test::traced_test;
use patchbay::{IpSupport, LinkCondition, LinkDirection, LinkLimits};
use testdir::testdir;
use tokio::sync::oneshot;

use super::util;

const ALPN: &[u8] = b"relay-ttfb";
const PING_DATA: &[u8] = b"relay-ttfb-ping";

async fn ttfb_accept(conn: &Connection) -> Result {
    let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
    let mut buf = vec![0u8; PING_DATA.len()];
    recv.read_exact(&mut buf).await.anyerr()?;
    send.write_all(&buf).await.anyerr()?;
    send.finish().anyerr()?;
    Ok(())
}

async fn ttfb_measure(conn: &Connection) -> Result<Duration> {
    let start = Instant::now();
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(PING_DATA).await.anyerr()?;
    let mut buf = vec![0u8; PING_DATA.len()];
    recv.read_exact(&mut buf).await.anyerr()?;
    let elapsed = start.elapsed();
    assert_eq!(&buf, PING_DATA);
    Ok(elapsed)
}

/// Run a TTFB measurement at 60ms RTT with the given `h3` setting on relay-b.
///
/// Topology:
///   relay-a (client home, no latency)
///   relay-b (server relay, no latency)
///   server and client (30ms one-way = 60ms RTT)
///
/// The client goes online via relay-a (sets `udp_available`), then connects
/// to the server which is on relay-b. A fresh relay actor is created for
/// relay-b with the `h3` flag controlling WS vs WT.
async fn run_relay_ttfb(h3: bool) -> Result {
    let label = if h3 { "WT" } else { "WS" };

    let mut opts = patchbay::LabOpts::default().outdir(patchbay::OutDir::Exact(testdir!()));
    if let Some(name) = std::thread::current().name() {
        opts = opts.label(name);
    }
    let lab = patchbay::Lab::with_opts(opts).await?;
    let guard = lab.test_guard();

    let router = lab
        .add_router("net")
        .ip_support(IpSupport::DualStack)
        .build()
        .await?;

    // Relay A: client's home relay.
    let relay_a_dev = lab
        .add_device("relay-a")
        .uplink(router.id())
        .build()
        .await?;
    lab.dns_entry("relay-a.test", relay_a_dev.ip().expect("v4").into())?;
    lab.dns_entry("relay-a.test", relay_a_dev.ip6().expect("v6").into())?;

    let (relay_a_tx, relay_a_rx) = oneshot::channel::<RelayMap>();
    let _relay_a_task = relay_a_dev.spawn(async move |_ctx| {
        let (map, _server) = util::relay::run_relay_server_named("relay-a.test")
            .await
            .unwrap();
        relay_a_tx.send(map).unwrap();
        std::future::pending::<()>().await;
    })?;
    let relay_a_map = relay_a_rx.await.std_context("relay-a")?;

    // Relay B: server's relay.
    let relay_b_dev = lab
        .add_device("relay-b")
        .uplink(router.id())
        .build()
        .await?;
    lab.dns_entry("relay-b.test", relay_b_dev.ip().expect("v4").into())?;
    lab.dns_entry("relay-b.test", relay_b_dev.ip6().expect("v6").into())?;

    let (relay_b_tx, relay_b_rx) = oneshot::channel::<RelayMap>();
    let _relay_b_task = relay_b_dev.spawn(async move |_ctx| {
        let (map, _server) = util::relay::run_relay_server_named("relay-b.test")
            .await
            .unwrap();
        relay_b_tx.send(map).unwrap();
        std::future::pending::<()>().await;
    })?;
    let relay_b_map = relay_b_rx.await.std_context("relay-b")?;

    // 30ms one-way (60ms RTT).
    let latency = LinkCondition::Manual(LinkLimits {
        latency_ms: 30,
        jitter_ms: 2,
        loss_pct: 0.0,
        reorder_pct: 0.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    });

    let server_dev = lab
        .add_device("server")
        .iface("eth0", router.id())
        .build()
        .await?;
    server_dev
        .set_link_condition("eth0", Some(latency), LinkDirection::Both)
        .await?;

    let client_dev = lab
        .add_device("client")
        .iface("eth0", router.id())
        .build()
        .await?;
    client_dev
        .set_link_condition("eth0", Some(latency), LinkDirection::Both)
        .await?;

    let (addr_tx, addr_rx) = oneshot::channel();

    // Server: uses relay-b.
    let server_relay_b = relay_b_map.clone();
    let client_relay_b = relay_b_map;
    let server_task = server_dev.spawn({
        move |_dev| async move {
            let ep = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Custom(server_relay_b))
                .ca_roots_config(CaRootsConfig::insecure_skip_verify())
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
            ttfb_accept(&conn).await?;

            // Keep connection alive while the client reads the echo.
            tokio::time::sleep(Duration::from_secs(5)).await;
            n0_error::Ok(())
        }
    })?;

    // Client: home relay is relay-a. Relay-b is in the map with the h3 flag.
    let client_task = client_dev.spawn({
        move |_dev| async move {
            let server_addr = addr_rx.await.std_context("addr rx")?;

            // Build a relay map with relay-a (home, h3=true) and relay-b
            // (server's relay, h3 flag from test parameter).
            let client_map = RelayMap::empty();
            let relays_a: Vec<_> = relay_a_map.relays();
            for cfg in relays_a {
                let mut c = iroh_relay::RelayConfig::clone(&cfg);
                c.h3 = true;
                client_map.insert(c.url.clone(), std::sync::Arc::new(c));
            }
            let relays_b: Vec<_> = client_relay_b.relays();
            for cfg in relays_b {
                let mut c = iroh_relay::RelayConfig::clone(&cfg);
                c.h3 = h3;
                client_map.insert(c.url.clone(), std::sync::Arc::new(c));
            }

            let ep = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Custom(client_map))
                .ca_roots_config(CaRootsConfig::insecure_skip_verify())
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await
                .std_context("client bind")?;

            // Go online via relay-a so net_report sets udp_available.
            ep.online().await;

            // Connect to server on relay-b. This creates a new relay actor
            // for relay-b that reads udp_available and h3 from the map.
            let t0 = Instant::now();
            let conn = ep.connect(server_addr, ALPN).await.std_context("connect")?;
            let connect_time = t0.elapsed();
            let echo_time = ttfb_measure(&conn).await?;
            let total = t0.elapsed();

            println!(
                "{label} relay TTFB at 60ms RTT: connect={connect_time:?} echo={echo_time:?} total={total:?}"
            );

            assert!(total < Duration::from_secs(3), "{label} too slow: {total:?}");

            n0_error::Ok(())
        }
    })?;

    let (server_res, client_res) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(server_task, client_task)
    })
    .await
    .std_context("test timed out")?;
    server_res.std_context("server")??;
    client_res.std_context("client")??;

    guard.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn relay_ttfb_60ms_ws() -> Result {
    run_relay_ttfb(false).await
}

#[tokio::test]
#[traced_test]
async fn relay_ttfb_60ms_wt() -> Result {
    run_relay_ttfb(true).await
}

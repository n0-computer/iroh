//! Patchbay network simulation tests.
//!
//! These tests use the [`patchbay`] crate to create virtual network topologies
//! in Linux user namespaces, testing iroh's NAT traversal, holepunching,
//! and connectivity under various network conditions.
//!
//! These tests require Linux with user namespace support. On non-Linux systems, you can use
//! the `patchbay` CLI to get a Linux container or VM with the required capabilities.
//! See patchbay docs for details.
//!
//! To run:
//!
//! ```sh
//! # On Linux (with user namespace support):
//! cargo nextest run -p iroh --test patchbay --profile patchbay
//! # or use the `cargo make` alias:
//! cargo make patchbay
//! # can also pass additional args:
//! cargo make patchbay holepunch_simple --no-capture
//!
//! # On macOS (runs in container via patchbay CLI):
//! patchbay test --release -p iroh --test patchbay
//! ```

// patchbay only runs on linux, and is skipped in cross-compile environments
// via a cfg directive
#![cfg(all(target_os = "linux", not(skip_patchbay)))]

use std::time::Duration;

use iroh::{TransportAddr, endpoint::Side};
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_tracing_test::traced_test;
use patchbay::{IpSupport, LinkCondition, LinkDirection, LinkLimits, Nat, RouterPreset, TestGuard};
use testdir::testdir;
use tracing::info;

use self::util::{Pair, PathWatcherExt, lab_with_relay, ping_accept, ping_open};

#[path = "patchbay/util.rs"]
mod util;

/// Init the user namespace before any threads are spawned.
///
/// This gives us all permissions we need for the patchbay tests.
#[ctor::ctor]
fn userns_ctor() {
    patchbay::init_userns().expect("failed to init userns");
}

// ---
// Holepunch tests
// ---

/// Two devices behind destination-independent NATs holepunch a direct connection.
///
/// Both devices connect through a relay first, then upgrade to a direct path.
/// The client asserts that the connection starts as relayed, then waits for
/// a direct (IP) path to be selected.
#[tokio::test]
#[traced_test]
async fn holepunch_simple() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let server = lab.add_device("server").uplink(nat1.id()).build().await?;
    let client = lab.add_device("client").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(server, async |_dev, _ep, conn| {
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            paths
                .wait_ip(timeout)
                .await
                .context("holepunch to direct")?;
            info!("connection became direct");
            conn.close(0u32.into(), b"bye!");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Switches the client's IPv4 uplink to a different NAT mid-connection.
///
/// The client starts behind `nat2`, holepunches a direct path, then replugs
/// its interface to `nat3`. The server waits until a direct path with a new
/// remote address is selected. We verify with a ping that the new path works.
///
/// Currently ignored because iroh does not yet recover reliably from an
/// uplink switch.
#[tokio::test]
#[traced_test]
async fn switch_uplink_v4() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let nat3 = lab.add_router("nat3").nat(Nat::Home).build().await?;
    let server = lab.add_device("server").uplink(nat1.id()).build().await?;
    let client = lab.add_device("client").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");

            // Wait until a first direct path is established.
            let first = paths.wait_ip(timeout).await?;
            info!(addr=?first.remote_addr(), "connection became direct, waiting for path change");

            // Now wait until the direct path changes, which happens after the other endpoint
            // changes its uplink. We check is_ip() explicitly to avoid triggering on a
            // transient relay fallback during the network switch.
            let second = paths
                .wait_selected(timeout, |p| {
                    p.is_ip() && p.remote_addr() != first.remote_addr()
                })
                .await
                .context("did not switch paths")?;
            info!(addr=?second.remote_addr(), "connection changed path, wait for ping");

            ping_accept(&conn, timeout).await?;
            info!("ping done");
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");

            // Wait for conn to become direct.
            paths
                .wait_ip(timeout)
                .await
                .context("holepunch to direct")?;

            // Wait a little more and then switch wifis.
            tokio::time::sleep(Duration::from_secs(1)).await;
            info!("switch IP uplink");
            dev.replug_iface("eth0", nat3.id()).await?;

            // We don't assert any path changes here, because the remote stays identical,
            // and PathInfo does not contain info on local addrs. Instead, the remote
            // only accepts our ping after the path changed.
            info!("send ping");
            ping_open(&conn, timeout)
                .await
                .context("failed at ping_open")?;
            info!("ping done");
            conn.close(0u32.into(), b"bye!");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Switches the client's uplink from an IPv4 NAT to an IPv6-only ISP network.
///
/// Similar to [`switch_uplink_v4`], but the client replugs from a Home NAT
/// to an IPv6-only ISP router. The server waits for the selected path to
/// switch from an IPv4 to an IPv6 remote address.
///
/// Currently ignored because this fails in roughly half of runs.
#[tokio::test]
#[traced_test]
async fn switch_uplink_v6() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let public = lab
        .add_router("public")
        .preset(RouterPreset::Public)
        .build()
        .await?;
    let home = lab
        .add_router("nat2")
        .preset(RouterPreset::Home)
        .ip_support(IpSupport::V4Only)
        .build()
        .await?;
    let mobile = lab
        .add_router("nat3")
        .preset(RouterPreset::IspV6)
        .build()
        .await?;
    let server = lab.add_device("server").uplink(public.id()).build().await?;
    let client = lab.add_device("client").uplink(home.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");

            // Wait until a first direct path is established.
            let first = paths
                .wait_selected(
                    timeout,
                    |p| matches!(p.remote_addr(), TransportAddr::Ip(addr) if addr.ip().is_ipv4()),
                )
                .await
                .context("did not become direct")?;
            info!(addr=?first.remote_addr(), "connection became direct, waiting for path change");

            ping_accept(&conn, timeout).await.context("ping_accept 1")?;

            // Now wait until the direct path changes, which happens after the other endpoint
            // changes its uplink. We check is_ip() explicitly to avoid triggering on a
            // transient relay fallback during the network switch.
            let second = paths
                .wait_selected(
                    timeout,
                    |p| matches!(p.remote_addr(), TransportAddr::Ip(addr) if addr.ip().is_ipv6()),
                )
                .await
                .context("did not switch paths to v6")?;
            info!(addr=?second.remote_addr(), "connection changed path, wait for ping");

            ping_accept(&conn, timeout).await.context("ping_accept 2")?;
            info!("ping done");
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");

            // Wait for conn to become direct.
            paths
                .wait_ip(timeout)
                .await
                .context("holepunch to direct")?;

            ping_open(&conn, timeout)
                .await
                .context("ping before switch")?;

            info!("switch IP uplink to v6");
            dev.replug_iface("eth0", mobile.id()).await?;

            // We don't assert any path changes here, because the remote stays identical,
            // and PathInfo does not contain info on local addrs. Instead, the remote
            // only accepts our ping after the path changed.
            ping_open(&conn, timeout)
                .await
                .context("ping after v6 switch")?;
            conn.close(0u32.into(), b"bye!");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Adds a faster LAN interface and verifies the path becomes selected.
///
/// The server sits on `nat1`. The client starts on `nat2` with a 4G-impaired
/// link and has a second interface `eth1` connected to `nat1` (a LAN path),
/// but `eth1` starts down. After holepunching over the impaired link, the test
/// brings `eth1` up and waits for the selected path to change to the new,
/// faster LAN address. A ping verifies the new path works.
#[tokio::test]
#[traced_test]
#[ignore = "sometimes is flaky (does not become direct after the link_up)"]
async fn change_ifaces() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;

    // Client has two uplinks (eth0=4G via nat2, eth1=LAN via nat1). eth1 starts down.
    let server = lab
        .add_device("server")
        .iface("eth0", nat1.id())
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .iface("eth0", nat2.id())
        .iface("eth1", nat1.id())
        .build()
        .await?;
    client
        .set_link_condition("eth0", Some(LinkCondition::Mobile4G), LinkDirection::Both)
        .await?;
    client.link_down("eth1").await?;

    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await.context("ping_accept")?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            let first = paths
                .wait_ip(timeout)
                .await
                .context("did not become direct")?;
            info!(addr=?first.remote_addr(), "connection became direct");

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Bring up the LAN interface to the other ep.
            info!("bring up eth1");
            dev.link_up("eth1").await?;

            // Wait for a new direct path to be established. We check is_ip() explicitly
            // to avoid triggering on a transient relay fallback during the switch.
            let next = paths
                .wait_selected(timeout, |p| {
                    p.is_ip() && p.remote_addr() != first.remote_addr()
                })
                .await
                .context("did not switch paths")?;
            info!(addr=?next.remote_addr(), "new direct path established");

            ping_open(&conn, timeout).await.context("ping_open")?;
            conn.close(0u32.into(), b"bye!");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Takes the client's link down for five seconds after holepunching, then brings it back.
///
/// After recovery, the test verifies that we can ping (via relay fallback or
/// a re-established direct path), and then waits for a direct path to be
/// selected again.
#[tokio::test]
#[traced_test]
async fn link_outage_recovery() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let server = lab.add_device("server").uplink(nat1.id()).build().await?;
    let client = lab.add_device("client").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await.context("ping_accept 1")?;
            ping_accept(&conn, timeout).await.context("ping_accept 2")?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            paths.wait_ip(timeout).await.context("initial holepunch")?;
            let downtime = Duration::from_secs(5);
            info!("holepunched, now killing link for {downtime:?}");
            // Take the link down.
            dev.link_down("eth0").await?;
            tokio::time::sleep(downtime).await;
            dev.link_up("eth0").await?;
            info!("link restored, waiting for recovery");

            // After link recovery, we should be able to ping, either via relay
            // fallback or re-established direct path.
            ping_open(&conn, Duration::from_secs(30))
                .await
                .context("ping_open after link_up")?;
            info!("connection recovered after link outage");

            // Eventually the direct path should come back.
            paths
                .wait_ip(Duration::from_secs(30))
                .await
                .context("did not re-establish direct path")?;
            ping_open(&conn, timeout)
                .await
                .context("ping_open after direct")?;
            conn.close(0u32.into(), b"bye!");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

// ---
// Degradation ladder: find where holepunching breaks under worsening conditions
// ---

/// Increasingly degraded link conditions applied to one side of the connection.
///
/// Each level adds more latency, loss, and reordering. The levels are tested
/// individually for both server-side and client-side impairment.
const DEGRADE_LEVELS: &[LinkLimits] = &[
    // 0: mild - good wifi
    LinkLimits {
        latency_ms: 10,
        jitter_ms: 5,
        loss_pct: 0.5,
        reorder_pct: 0.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 1: poor - bad wifi or 3G
    LinkLimits {
        latency_ms: 100,
        jitter_ms: 30,
        loss_pct: 3.0,
        reorder_pct: 3.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 2: bad - congested 3G
    LinkLimits {
        latency_ms: 200,
        jitter_ms: 60,
        loss_pct: 5.0,
        reorder_pct: 5.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 3: terrible - barely usable
    LinkLimits {
        latency_ms: 300,
        jitter_ms: 80,
        loss_pct: 8.0,
        reorder_pct: 8.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 4: extreme - GEO satellite with heavy loss
    LinkLimits {
        latency_ms: 500,
        jitter_ms: 100,
        loss_pct: 12.0,
        reorder_pct: 12.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 5: absurd - stress test
    LinkLimits {
        latency_ms: 800,
        jitter_ms: 200,
        loss_pct: 20.0,
        reorder_pct: 20.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
];

/// Runs a single degradation level.
///
/// Creates two devices behind Home NATs, applies the given [`LinkLimits`] to
/// `impaired_side`, then attempts to holepunch and ping. Returns the
/// [`TestGuard`] on success so the caller can mark it as passed.
async fn run_degrade_level(impaired_side: Side, level: usize) -> Result<TestGuard> {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let timeout = Duration::from_secs(30);

    let limits = DEGRADE_LEVELS[level];
    let link_condition = Some(LinkCondition::Manual(limits));

    let server = lab
        .add_device("server")
        .iface("eth0", nat1.id())
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .iface("eth0", nat2.id())
        .build()
        .await?;
    let impaired_device = match impaired_side {
        Side::Client => &client,
        Side::Server => &server,
    };
    impaired_device
        .set_link_condition("eth0", link_condition, LinkDirection::Both)
        .await?;

    let result = tokio::time::timeout(
        timeout * 2,
        Pair::new(relay_map)
            .server(server, async move |_dev, _ep, conn| {
                ping_accept(&conn, timeout).await.context("ping_accept")?;
                conn.closed().await;
                Ok(())
            })
            .client(client, async move |_dev, _ep, conn| {
                let mut paths = conn.paths();
                paths
                    .wait_ip(timeout)
                    .await
                    .context("holepunch to direct")?;
                info!("direct path established, sending ping");
                ping_open(&conn, timeout).await.context("ping_open")?;
                info!("ping complete");
                conn.close(0u32.into(), b"bye!");
                Ok(())
            })
            .run(),
    )
    .await
    .std_context("pair timed out")
    .flatten();

    match &result {
        Ok(()) => tracing::event!(
            target: "iroh::_events::test_ladder_pass",
            tracing::Level::INFO,
            level,
            latency_ms = limits.latency_ms,
            loss_pct = limits.loss_pct,
            reorder_pct = limits.reorder_pct,
            impaired_side = ?impaired_side,
            "PASSED",
        ),
        Err(err) => tracing::event!(
            target: "iroh::_events::test_ladder_fail",
            tracing::Level::WARN,
            level,
            latency_ms = limits.latency_ms,
            loss_pct = limits.loss_pct,
            reorder_pct = limits.reorder_pct,
            impaired_side = ?impaired_side,
            error = format!("{err:#}"),
            "FAILED",
        ),
    }

    result?;
    Ok(guard)
}

#[tokio::test]
#[traced_test]
async fn degrade_server_0_mild() -> Result {
    run_degrade_level(Side::Server, 0).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_server_1_poor() -> Result {
    run_degrade_level(Side::Server, 1).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_server_2_bad() -> Result {
    run_degrade_level(Side::Server, 2).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_server_3_terrible() -> Result {
    run_degrade_level(Side::Server, 3).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_server_4_extreme() -> Result {
    run_degrade_level(Side::Server, 4).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_server_5_absurd() -> Result {
    run_degrade_level(Side::Server, 5).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_client_0_mild() -> Result {
    run_degrade_level(Side::Client, 0).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_client_1_poor() -> Result {
    run_degrade_level(Side::Client, 1).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_client_2_bad() -> Result {
    run_degrade_level(Side::Client, 2).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_client_3_terrible() -> Result {
    run_degrade_level(Side::Client, 3).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_client_4_extreme() -> Result {
    run_degrade_level(Side::Client, 4).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_client_5_absurd() -> Result {
    run_degrade_level(Side::Client, 5).await?.ok();
    Ok(())
}

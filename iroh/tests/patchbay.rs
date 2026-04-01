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
use patchbay::{Firewall, LinkCondition, LinkDirection, LinkLimits, Nat, RouterPreset, TestGuard};
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

/// Simple holepunch: Two devices behind destination-independent NATs,
/// establish via relay, upgrade to direct.
#[tokio::test]
#[traced_test]
async fn holepunch_simple() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async |_dev, _ep, _conn| Ok(()))
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            paths.wait_ip(timeout).await?;
            info!("connection became direct");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Tests that changing the uplink of an interface works (i.e. switching wifis).
///
/// For this we observe a change in the selected path's remote addr on the *other* side.
/// Whether the side that changes interfaces opens a new path or does an RFC9000-style migration
/// is an implementation detail which we won't test for.
///
/// The test currently fails, but should pass.
#[tokio::test]
#[traced_test]
#[ignore = "known to still fail"]
async fn switch_uplink() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let nat3 = lab.add_router("nat3").nat(Nat::Home).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
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
            Ok(())
        })
        .client(dev2, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");

            // Wait for conn to become direct.
            paths.wait_ip(timeout).await.context("become direct")?;

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
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Tests that changing the uplink from IPv4 to IPv6 works.
///
/// Similar to `switch_uplink` but switches to an IPv6 only network.
///
/// The test currently fails, but should pass.
#[tokio::test]
#[traced_test]
#[ignore = "known to still fail"]
async fn switch_uplink_ipv6() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let public = lab
        .add_router("public")
        .preset(RouterPreset::Public)
        .build()
        .await?;
    let home = lab
        .add_router("nat2")
        .preset(RouterPreset::Home)
        .build()
        .await?;
    let mobile = lab
        .add_router("nat3")
        .preset(RouterPreset::IspV6)
        .build()
        .await?;
    let dev1 = lab.add_device("dev1").uplink(public.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(home.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
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

            ping_accept(&conn, timeout).await?;
            info!("ping done");
            Ok(())
        })
        .client(dev2, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");

            // Wait for conn to become direct.
            paths.wait_ip(timeout).await.context("become direct")?;

            // Wait a little more and then switch wifis.
            tokio::time::sleep(Duration::from_secs(1)).await;
            info!("switch IP uplink");
            dev.replug_iface("eth0", mobile.id()).await?;

            // We don't assert any path changes here, because the remote stays identical,
            // and PathInfo does not contain info on local addrs. Instead, the remote
            // only accepts our ping after the path changed.
            info!("send ping");
            ping_open(&conn, timeout)
                .await
                .context("failed at ping_open")?;
            info!("ping done");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Test that switching to a faster link works.
///
/// Two devices, connected initially over holepunched NAT. Then mid connection
/// device 2 plugs a cable into device 1's router, i.e. they now have a LAN
/// connection.
///
/// Verify we switch to the LAN connection.
#[tokio::test]
#[traced_test]
async fn change_ifaces() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;

    // dev2 has two uplinks (wifi=Mobile3G on eth0, LAN on eth1). eth1 starts down.
    let dev1 = lab
        .add_device("dev1")
        .iface("eth0", nat1.id())
        .build()
        .await?;
    let dev2 = lab
        .add_device("dev2")
        .iface("eth0", nat2.id())
        .iface("eth1", nat1.id())
        .build()
        .await?;
    dev2.set_link_condition("eth0", Some(LinkCondition::Mobile4G), LinkDirection::Both)
        .await?;
    dev2.link_down("eth1").await?;

    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout)
                .await
                .context("failed at ping_accept")?;
            Ok(())
        })
        .client(dev2, async move |dev, _ep, conn| {
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

            ping_open(&conn, timeout)
                .await
                .context("failed at ping_open")?;
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

// ---
// NAT type matrix: verify holepunching across different NAT combinations
// ---

/// One peer behind Home NAT, the other on a public network.
/// Holepunching should succeed: EIM mapping means the public peer can reach
/// the NATted peer's mapped port once it learns the address via relay.
#[tokio::test]
#[traced_test]
#[ignore = "stays relayed, holepunch times out (deadline elapsed)"]
async fn holepunch_home_nat_one_side() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat = lab.add_router("nat").nat(Nat::Home).build().await?;
    let public = lab.add_router("public").build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(public.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            paths.wait_ip(timeout).await.context("did not holepunch")?;
            ping_open(&conn, timeout).await?;
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Both peers behind CGNAT (EIM+EIF). The most permissive real-world NAT.
/// Holepunching should succeed easily since filtering is endpoint-independent.
#[tokio::test]
#[traced_test]
#[ignore = "stays relayed, holepunch times out (deadline elapsed)"]
async fn holepunch_cgnat_both() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Cgnat).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Cgnat).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            paths
                .wait_ip(timeout)
                .await
                .context("did not holepunch through CGNAT")?;
            ping_open(&conn, timeout).await?;
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Both peers behind FullCone NAT (EIM+EIF with hairpin). The most permissive
/// NAT type — any external host can send to the mapped port. Holepunching
/// always succeeds on the first try.
#[tokio::test]
#[traced_test]
async fn holepunch_full_cone_both() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::FullCone).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::FullCone).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            paths
                .wait_ip(timeout)
                .await
                .context("did not holepunch through full cone")?;
            ping_open(&conn, timeout).await?;
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Both peers behind Corporate (symmetric/EDM) NAT. Each destination gets a
/// different external port, making holepunching impossible. The connection
/// must stay on the relay.
#[tokio::test]
#[traced_test]
async fn symmetric_nat_stays_relayed() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Corporate).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Corporate).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "should start on relay");
            // Ping to verify the relay path works.
            ping_open(&conn, timeout).await?;
            // Give holepunching time to attempt and fail.
            tokio::time::sleep(Duration::from_secs(8)).await;
            assert!(
                paths.selected().is_relay(),
                "should still be relayed — symmetric NAT blocks holepunching"
            );
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// One peer behind Home NAT (EIM), the other behind Corporate/symmetric NAT
/// (EDM). Holepunching fails because the symmetric side allocates a different
/// port for each destination, so the Home peer's probes never reach the right
/// port. Connection stays relayed.
#[tokio::test]
#[traced_test]
async fn mixed_home_vs_symmetric_stays_relayed() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let home = lab.add_router("home").nat(Nat::Home).build().await?;
    let corp = lab.add_router("corp").nat(Nat::Corporate).build().await?;
    let dev1 = lab.add_device("dev1").uplink(home.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(corp.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "should start on relay");
            ping_open(&conn, timeout).await?;
            tokio::time::sleep(Duration::from_secs(8)).await;
            assert!(
                paths.selected().is_relay(),
                "should still be relayed — symmetric NAT on one side blocks holepunching"
            );
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Both peers behind CloudNat (EDM+APDF), the symmetric NAT used by cloud
/// providers (AWS NAT Gateway, GCP Cloud NAT). Same as Corporate: holepunching
/// is impossible, connection stays relayed.
#[tokio::test]
#[traced_test]
async fn cloud_nat_stays_relayed() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::CloudNat).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::CloudNat).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "should start on relay");
            ping_open(&conn, timeout).await?;
            tokio::time::sleep(Duration::from_secs(8)).await;
            assert!(
                paths.selected().is_relay(),
                "should still be relayed — cloud symmetric NAT blocks holepunching"
            );
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Double NAT: device behind a Home router, which itself sits behind an ISP
/// CGNAT router. This is a common real-world scenario (carrier-grade NAT +
/// consumer router). Both NATs use endpoint-independent mapping, so
/// holepunching should succeed.
#[tokio::test]
#[traced_test]
#[ignore = "stays relayed, holepunch times out (deadline elapsed)"]
async fn holepunch_double_nat() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    // ISP-level CGNAT routers
    let isp1 = lab.add_router("isp1").nat(Nat::Cgnat).build().await?;
    let isp2 = lab.add_router("isp2").nat(Nat::Cgnat).build().await?;
    // Home routers behind ISPs
    let home1 = lab
        .add_router("home1")
        .nat(Nat::Home)
        .upstream(isp1.id())
        .build()
        .await?;
    let home2 = lab
        .add_router("home2")
        .nat(Nat::Home)
        .upstream(isp2.id())
        .build()
        .await?;
    let dev1 = lab.add_device("dev1").uplink(home1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(home2.id()).build().await?;
    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            paths
                .wait_ip(timeout)
                .await
                .context("did not holepunch through double NAT")?;
            ping_open(&conn, timeout).await?;
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

// ---
// Firewall and adverse conditions
// ---

/// Corporate firewall blocks all UDP except DNS (port 53) and only allows TCP
/// on ports 80 and 443. Holepunching is impossible, but the relay connection
/// via HTTPS (TCP 443) must still work.
#[tokio::test]
#[traced_test]
async fn corporate_firewall_relay_only() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let fw = lab
        .add_router("fw")
        .firewall(Firewall::Corporate)
        .build()
        .await?;
    let public = lab.add_router("public").build().await?;
    let dev1 = lab.add_device("dev1").uplink(fw.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(public.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "should start on relay");
            ping_open(&conn, timeout).await?;
            tokio::time::sleep(Duration::from_secs(8)).await;
            assert!(
                paths.selected().is_relay(),
                "should still be relayed — corporate firewall blocks UDP"
            );
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Holepunch through Home NATs with a degraded mobile link (100ms latency,
/// 30ms jitter, 2% loss). Connection should still upgrade to direct despite
/// the poor link quality.
#[tokio::test]
#[traced_test]
async fn holepunch_mobile_3g() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let dev1 = lab
        .add_device("dev1")
        .iface("eth0", nat1.id())
        .build()
        .await?;
    let dev2 = lab
        .add_device("dev2")
        .iface("eth0", nat2.id())
        .build()
        .await?;
    dev1.set_link_condition("eth0", Some(LinkCondition::Mobile3G), LinkDirection::Both)
        .await?;
    dev2.set_link_condition("eth0", Some(LinkCondition::Mobile3G), LinkDirection::Both)
        .await?;
    let timeout = Duration::from_secs(20);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            paths
                .wait_ip(timeout)
                .await
                .context("did not holepunch over 3G link")?;
            ping_open(&conn, timeout).await?;
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Holepunch through Home NATs on a satellite link (high latency, moderate
/// jitter). Tests that iroh handles high-RTT environments without timing out
/// during NAT traversal.
#[tokio::test]
#[traced_test]
async fn holepunch_satellite() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let dev1 = lab
        .add_device("dev1")
        .iface("eth0", nat1.id())
        .build()
        .await?;
    let dev2 = lab
        .add_device("dev2")
        .iface("eth0", nat2.id())
        .build()
        .await?;
    dev1.set_link_condition("eth0", Some(LinkCondition::Satellite), LinkDirection::Both)
        .await?;
    dev2.set_link_condition("eth0", Some(LinkCondition::Satellite), LinkDirection::Both)
        .await?;
    let timeout = Duration::from_secs(20);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            paths
                .wait_ip(timeout)
                .await
                .context("did not holepunch over satellite link")?;
            ping_open(&conn, timeout).await?;
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Brief link outage: after holepunching succeeds, the link goes down for 2
/// seconds and comes back up. The connection should recover — either by
/// falling back to relay during the outage or by re-establishing the direct
/// path after recovery.
#[tokio::test]
#[traced_test]
async fn link_outage_recovery() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await.context("ping 1")?;
            ping_accept(&conn, timeout).await.context("ping 2")?;
            Ok(())
        })
        .client(dev2, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            paths.wait_ip(timeout).await.context("initial holepunch")?;
            info!("holepunched, now killing link for 2s");

            // Take the link down.
            dev.link_down("eth0").await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            dev.link_up("eth0").await?;
            info!("link restored, waiting for recovery");

            // After link recovery, we should be able to ping — via relay
            // fallback or re-established direct path.
            ping_open(&conn, Duration::from_secs(20))
                .await
                .context("ping after link recovery")?;
            info!("connection recovered after link outage");

            // Eventually the direct path should come back.
            paths
                .wait_ip(Duration::from_secs(20))
                .await
                .context("did not re-establish direct path")?;
            ping_open(&conn, timeout).await.context("ping on direct")?;
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Hotel WiFi: captive-portal firewall allows all outbound TCP but only UDP
/// port 53 (DNS). Similar to corporate firewall but less restrictive on TCP.
/// Relay via HTTPS should work, holepunching should not.
#[tokio::test]
#[traced_test]
async fn hotel_wifi_relay_only() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let hotel = lab
        .add_router("hotel")
        .preset(RouterPreset::Hotel)
        .build()
        .await?;
    let public = lab.add_router("public").build().await?;
    let dev1 = lab.add_device("dev1").uplink(hotel.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(public.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "should start on relay");
            ping_open(&conn, timeout).await?;
            tokio::time::sleep(Duration::from_secs(8)).await;
            assert!(
                paths.selected().is_relay(),
                "should still be relayed — hotel firewall blocks UDP"
            );
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Asymmetric link conditions: one peer on a fast LAN, the other on degraded
/// WiFi. Holepunching should still succeed, and the connection should use
/// the direct path despite the asymmetric quality.
#[tokio::test]
#[traced_test]
async fn holepunch_asymmetric_links() -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let dev1 = lab
        .add_device("dev1")
        .iface("eth0", nat1.id())
        .build()
        .await?;
    let dev2 = lab
        .add_device("dev2")
        .iface("eth0", nat2.id())
        .build()
        .await?;
    dev1.set_link_condition("eth0", Some(LinkCondition::Lan), LinkDirection::Both)
        .await?;
    dev2.set_link_condition("eth0", Some(LinkCondition::WifiBad), LinkDirection::Both)
        .await?;
    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .server(dev1, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await?;
            Ok(())
        })
        .client(dev2, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            paths
                .wait_ip(timeout)
                .await
                .context("did not holepunch with asymmetric links")?;
            ping_open(&conn, timeout).await?;
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

/// Increasingly degraded link on one side, clean link on the other.
/// Each level adds more latency, loss, and reordering. The test runs each level
/// twice: once with the impaired side accepting, once connecting.
const DEGRADE_LEVELS: &[LinkLimits] = &[
    // 0: mild — good wifi
    LinkLimits {
        latency_ms: 10,
        jitter_ms: 5,
        loss_pct: 0.5,
        reorder_pct: 0.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 1: poor — bad wifi or 3G
    LinkLimits {
        latency_ms: 100,
        jitter_ms: 30,
        loss_pct: 3.0,
        reorder_pct: 3.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 2: bad — congested 3G
    LinkLimits {
        latency_ms: 200,
        jitter_ms: 60,
        loss_pct: 5.0,
        reorder_pct: 5.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 3: terrible — barely usable
    LinkLimits {
        latency_ms: 300,
        jitter_ms: 80,
        loss_pct: 8.0,
        reorder_pct: 8.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 4: extreme — GEO satellite with heavy loss
    LinkLimits {
        latency_ms: 500,
        jitter_ms: 100,
        loss_pct: 12.0,
        reorder_pct: 12.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 6: absurd — stress test
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

/// Run a single degradation level: create devices with the given impairment,
/// try to holepunch and ping, return Ok if successful.
async fn run_degrade_level(impaired_side: Side, level: usize) -> Result<TestGuard> {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let timeout = Duration::from_secs(20);

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
                ping_accept(&conn, timeout).await?;
                Ok(())
            })
            .client(client, async move |_dev, _ep, conn| {
                let mut paths = conn.paths();
                paths.wait_ip(timeout).await?;
                ping_open(&conn, timeout).await?;
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
async fn degrade_server_3_terrible() -> Result {
    run_degrade_level(Side::Server, 3).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_server_4_extreme() -> Result {
    run_degrade_level(Side::Server, 4).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
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
async fn degrade_client_3_terrible() -> Result {
    run_degrade_level(Side::Client, 3).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_client_4_extreme() -> Result {
    run_degrade_level(Side::Client, 4).await?.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_client_5_absurd() -> Result {
    run_degrade_level(Side::Client, 5).await?.ok();
    Ok(())
}

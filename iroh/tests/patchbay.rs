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

use std::{net::Ipv4Addr, time::Duration};

use ipnet::Ipv4Net;
use iroh::endpoint::Side;
use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::{IfaceConfig, LinkCondition, LinkDirection, Nat};
use testdir::testdir;
use tracing::info;

use self::util::{Pair, PathWatcherExt, lab_with_relay, ping_accept, ping_open};

// Because we're in an integration test, we can't declare modules under patchbay/
// without setting an explicit path.
#[path = "patchbay/degrade.rs"]
mod degrade;
#[path = "patchbay/nat.rs"]
mod nat;
#[path = "patchbay/switch-uplink.rs"]
mod switch_uplink;
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
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

/// Adds a faster LAN interface on one side and verifies the path switches to it.
///
/// The active side has two uplinks: eth0 (4G-impaired) and eth1 (LAN to the
/// peer's NAT, starts down). After holepunching over 4G, eth1 comes up and
/// the selected path should switch to the faster LAN link.
async fn run_add_faster_link(active_side: Side) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat_a = lab.add_router("nat_a").nat(Nat::Home).build().await?;
    let nat_b = lab.add_router("nat_b").nat(Nat::Home).build().await?;

    let active = lab
        .add_device("active")
        .iface(
            "eth0",
            IfaceConfig::routed(nat_a.id()).condition(LinkCondition::Mobile4G, LinkDirection::Both),
        )
        .iface("eth1", IfaceConfig::routed(nat_b.id()).down())
        .build()
        .await?;
    let passive = lab
        .add_device("passive")
        .iface("eth0", nat_b.id())
        .build()
        .await?;

    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .left(active_side, active, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            let first = paths
                .wait_ip(timeout)
                .await
                .context("did not become direct")?;
            info!(addr=?first.remote_addr(), "connection became direct");
            ping_accept(&conn, timeout)
                .await
                .context("ping_accept before switch")?;

            info!("bring up faster link (eth1)");
            dev.iface("eth1").unwrap().link_up().await?;

            let next = paths
                .wait_selected(timeout, |p| {
                    p.is_ip() && p.remote_addr() != first.remote_addr()
                })
                .await
                .context("did not switch paths")?;
            info!(addr=?next.remote_addr(), "new direct path established");
            ping_accept(&conn, timeout)
                .await
                .context("ping_accept after switch")?;

            conn.closed().await;
            Ok(())
        })
        .right(passive, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            let first = paths
                .wait_ip(timeout)
                .await
                .context("did not become direct")?;
            info!(addr=?first.remote_addr(), "connection became direct");
            ping_open(&conn, timeout)
                .await
                .context("ping_open before switch")?;

            let next = paths
                .wait_selected(timeout, |p| {
                    p.is_ip() && p.remote_addr() != first.remote_addr()
                })
                .await
                .context("did not switch paths")?;
            info!(addr=?next.remote_addr(), "new direct path established");
            ping_open(&conn, timeout)
                .await
                .context("ping_open after switch")?;

            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn add_faster_link_client() -> Result {
    run_add_faster_link(Side::Client).await
}

#[tokio::test]
#[traced_test]
async fn add_faster_link_server() -> Result {
    run_add_faster_link(Side::Server).await
}

/// Takes one side's link down after holepunching, then brings it back.
///
/// After recovery, verifies connectivity (via relay fallback or re-established
/// direct path), then waits for a direct path to be selected again.
async fn run_link_outage_recovery(outage_side: Side, downtime: Duration) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let outage = lab.add_device("outage").uplink(nat1.id()).build().await?;
    let peer = lab.add_device("peer").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .left(outage_side, outage, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            paths.wait_ip(timeout).await.context("initial holepunch")?;
            info!("holepunched, now killing link for {downtime:?}");
            dev.iface("eth0").unwrap().link_down().await?;
            tokio::time::sleep(downtime).await;
            dev.iface("eth0").unwrap().link_up().await?;
            info!("link restored, waiting for recovery");

            ping_open(&conn, timeout)
                .await
                .context("ping_open after link_up")?;
            info!("connection recovered after link outage");

            paths
                .wait_ip(timeout)
                .await
                .context("did not re-establish direct path")?;
            ping_open(&conn, timeout)
                .await
                .context("ping_open after direct")?;
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .right(peer, async move |_dev, _ep, conn| {
            ping_accept(&conn, timeout).await.context("ping_accept 1")?;
            ping_accept(&conn, timeout).await.context("ping_accept 2")?;
            conn.closed().await;
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn link_outage_recovery_client() -> Result {
    run_link_outage_recovery(Side::Client, Duration::from_secs(5)).await
}

#[tokio::test]
#[traced_test]
async fn link_outage_recovery_server() -> Result {
    run_link_outage_recovery(Side::Server, Duration::from_secs(5)).await
}

/// Starts one side behind a symmetric NAT (no holepunch possible), then replugs
/// it to a Home NAT and verifies a direct path is established.
async fn run_hard_nat_to_holepunchable(replug_side: Side) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat_easy = lab.add_router("nat_easy").nat(Nat::Home).build().await?;
    let nat_hard = lab
        .add_router("nat_hard")
        .nat(Nat::Corporate)
        .build()
        .await?;
    let nat_peer = lab.add_router("nat_peer").nat(Nat::Home).build().await?;

    let replug = lab
        .add_device("replug")
        .uplink(nat_hard.id())
        .build()
        .await?;
    let stable = lab
        .add_device("stable")
        .uplink(nat_peer.id())
        .build()
        .await?;

    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .left(replug_side, replug, async move |dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");

            ping_accept(&conn, timeout)
                .await
                .context("ping 1 (relay)")?;

            tokio::time::sleep(Duration::from_secs(3)).await;
            assert!(
                paths.selected().is_relay(),
                "should still be relayed behind symmetric NAT"
            );

            info!("replug to holepunchable NAT");
            dev.iface("eth0").unwrap().replug(nat_easy.id()).await?;

            paths
                .wait_ip(timeout)
                .await
                .context("did not become direct after replug")?;
            info!("connection became direct");

            ping_accept(&conn, timeout)
                .await
                .context("ping 2 (direct)")?;
            conn.closed().await;
            Ok(())
        })
        .right(stable, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            ping_open(&conn, timeout).await.context("ping 1 (relay)")?;
            paths
                .wait_ip(timeout)
                .await
                .context("did not become direct after replug")?;
            info!("connection became direct");
            ping_open(&conn, timeout).await.context("ping 2 (direct)")?;
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn hard_nat_to_holepunchable_client() -> Result {
    run_hard_nat_to_holepunchable(Side::Client).await
}

#[tokio::test]
#[traced_test]
async fn hard_nat_to_holepunchable_server() -> Result {
    run_hard_nat_to_holepunchable(Side::Server).await
}

/// Holepunching succeeds despite many unreachable local addresses on one side.
async fn run_holepunch_many_addrs(many_addrs_side: Side, addr_count: u8) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;

    let mut builder = lab.add_device("many_addrs").uplink(nat1.id());
    for i in 0..addr_count {
        builder = builder.iface(
            &format!("virt{i}"),
            IfaceConfig::dummy().addr(Ipv4Net::new_assert(
                Ipv4Addr::new(172, 16, 0, i + 1),
                24,
            )),
        );
    }
    let many_addrs = builder.build().await?;
    let plain = lab.add_device("plain").uplink(nat2.id()).build().await?;

    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .left(many_addrs_side, many_addrs, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            paths
                .wait_ip(timeout)
                .await
                .context("holepunch to direct with many addrs")?;
            info!("connection became direct");
            ping_accept(&conn, timeout).await.context("ping_accept")?;
            conn.closed().await;
            Ok(())
        })
        .right(plain, async move |_dev, _ep, conn| {
            let mut paths = conn.paths();
            assert!(paths.selected().is_relay(), "connection started relayed");
            paths
                .wait_ip(timeout)
                .await
                .context("holepunch to direct with many addrs")?;
            info!("connection became direct");
            ping_open(&conn, timeout).await.context("ping_accept")?;
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn holepunch_many_addrs_client_8() -> Result {
    run_holepunch_many_addrs(Side::Client, 8).await
}

#[tokio::test]
#[traced_test]
async fn holepunch_many_addrs_server_8() -> Result {
    run_holepunch_many_addrs(Side::Server, 8).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn holepunch_many_addrs_client_16() -> Result {
    run_holepunch_many_addrs(Side::Client, 16).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn holepunch_many_addrs_server_16() -> Result {
    run_holepunch_many_addrs(Side::Server, 16).await
}

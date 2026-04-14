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

use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::{LinkCondition, LinkDirection, Nat};
use testdir::testdir;
use tracing::info;

use self::util::{Pair, PathWatcherExt, lab_with_relay, ping_accept, ping_open};

#[path = "patchbay/degrade.rs"]
mod degrade;
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
        .iface("eth0")
        .unwrap()
        .set_condition(LinkCondition::Mobile4G, LinkDirection::Both)
        .await?;
    client.iface("eth1").unwrap().link_down().await?;

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
            dev.iface("eth1").unwrap().link_up().await?;

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
            conn.close(0u32.into(), b"bye");
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
            dev.iface("eth0").unwrap().link_down().await?;
            tokio::time::sleep(downtime).await;
            dev.iface("eth0").unwrap().link_up().await?;
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
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

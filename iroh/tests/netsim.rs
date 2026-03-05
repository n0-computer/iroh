#![cfg(target_os = "linux")]

use std::time::Duration;

use iroh::TransportAddr;
use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::{LinkCondition, Nat, RouterPreset};
use testdir::testdir;
use tracing::info;

use self::util::{Pair, PathWatcherExt, lab_with_relay, ping_accept, ping_open};

#[path = "netsim/util.rs"]
mod util;

/// Init the user namespace before any threads are spawned.
///
/// This gives us all permissions we need for netsim.
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
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(dev1, dev2, relay_map)
        .run(
            async move |_dev, _ep, _conn| Ok(()),
            async move |_dev, _ep, conn| {
                let mut paths = conn.paths();
                assert!(paths.is_relay(), "connection started relayed");
                paths.wait_ip(timeout).await?;
                info!("connection became direct");
                Ok(())
            },
        )
        .await
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
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let nat3 = lab.add_router("nat3").nat(Nat::Home).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(10);
    Pair::new(dev1, dev2, relay_map)
        .run(
            async move |_dev, _ep, conn| {
                let mut paths = conn.paths();
                assert!(paths.is_relay(), "connection started relayed");

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
            },
            async move |dev, _ep, conn| {
                let mut paths = conn.paths();
                assert!(paths.is_relay(), "connection started relayed");

                // Wait for conn to become direct.
                paths
                    .wait_ip(timeout)
                    .await
                    .context("become direct")?;

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
            },
        )
        .await
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
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
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
    Pair::new(dev1, dev2, relay_map)
        .run(
            async move |_dev, _ep, conn| {
                let mut paths = conn.paths();
                assert!(paths.is_relay(), "connection started relayed");

                // Wait until a first direct path is established.
                let first = paths
                    .wait_selected(timeout, |p| {
                        matches!(p.remote_addr(), TransportAddr::Ip(addr) if addr.ip().is_ipv4())
                    })
                    .await
                    .context("did not become direct")?;
                info!(addr=?first.remote_addr(), "connection became direct, waiting for path change");

                // Now wait until the direct path changes, which happens after the other endpoint
                // changes its uplink. We check is_ip() explicitly to avoid triggering on a
                // transient relay fallback during the network switch.
                let second = paths
                    .wait_selected(timeout, |p| {
                        matches!(p.remote_addr(), TransportAddr::Ip(addr) if addr.ip().is_ipv6())
                    })
                    .await
                    .context("did not switch paths to v6")?;
                info!(addr=?second.remote_addr(), "connection changed path, wait for ping");

                ping_accept(&conn, timeout).await?;
                info!("ping done");
                Ok(())
            },
            async move |dev, _ep, conn| {
                let mut paths = conn.paths();
                assert!(paths.is_relay(), "connection started relayed");

                // Wait for conn to become direct.
                paths
                    .wait_ip(timeout)
                    .await
                    .context("become direct")?;

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
            },
        )
        .await
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
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;

    // dev2 has two uplinks (wifi=Mobile3G on eth0, LAN on eth1). eth1 starts down.
    let dev1 = lab
        .add_device("dev1")
        .iface("eth0", nat1.id(), None)
        .build()
        .await?;
    let dev2 = lab
        .add_device("dev2")
        .iface("eth0", nat2.id(), Some(LinkCondition::Mobile3G))
        .iface("eth1", nat1.id(), None)
        .build()
        .await?;
    dev2.link_down("eth1").await?;

    let timeout = Duration::from_secs(10);
    Pair::new(dev1, dev2, relay_map)
        .run(
            async move |_dev, _ep, conn| {
                ping_accept(&conn, timeout)
                    .await
                    .context("failed at ping_accept")?;
                Ok(())
            },
            async move |dev, _ep, conn| {
                let mut paths = conn.paths();
                assert!(paths.is_relay(), "connection started relayed");
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
            },
        )
        .await
}

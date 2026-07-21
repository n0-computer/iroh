//! Relay connectivity and reconnect tests.
//!
//! The relay from [`util::relay::run_relay_server`] binds `[::]` and is
//! reachable as `https://relay.test` through lab-wide DNS A and AAAA records.
//!
//! The connect tests place both peers on access networks that support only
//! one IP family, so all traffic to the relay uses that family. The
//! reconnect tests pin the connection to the relay by putting both peers
//! behind symmetric (`Nat::Corporate`) NATs, for which holepunching is
//! impossible while IP transports stay enabled, and then break either one
//! peer's access link or the relay server itself.

use std::time::Duration;

use iroh::endpoint::Side;
use n0_error::{Result, StackResultExt, StdResultExt, anyerr};
use n0_future::task::AbortOnDropHandle;
use n0_tracing_test::traced_test;
use patchbay::{Firewall, IpSupport, Lab, Nat, OutDir};
use testdir::testdir;
use tokio::sync::oneshot;
use tracing::info;

use super::util::{self, Pair, is_relayed, lab_with_relay, ping_accept, ping_open};

/// Connects two peers whose access networks support only one IP family.
///
/// The relay's own network is dual-stack. The connection starts relayed
/// (the [`Pair`] harness hands out relay-only addresses) and a ping in each
/// direction proves the relay carries data over the family under test.
async fn run_relay_connect(ip_support: IpSupport) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let access1 = lab
        .add_router("access1")
        .ip_support(ip_support)
        .build()
        .await?;
    let access2 = lab
        .add_router("access2")
        .ip_support(ip_support)
        .build()
        .await?;
    let server = lab
        .add_device("server")
        .uplink(access1.id())
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .uplink(access2.id())
        .build()
        .await?;
    for dev in [&server, &client] {
        assert_eq!(dev.ip().is_some(), ip_support.has_v4(), "IPv4 assignment");
        assert_eq!(dev.ip6().is_some(), ip_support.has_v6(), "IPv6 assignment");
    }
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_accept(&conn, timeout).await.context("ping_accept")?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_open(&conn, timeout).await.context("ping_open")?;
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
async fn relay_connect_ipv4() -> Result {
    run_relay_connect(IpSupport::V4Only).await
}

#[tokio::test]
#[traced_test]
async fn relay_connect_ipv6() -> Result {
    run_relay_connect(IpSupport::V6Only).await
}

/// Which peers sit behind a UDP-blocking access router.
#[derive(Debug, Clone, Copy)]
enum UdpBlocked {
    Both,
    ServerOnly,
    ClientOnly,
}

/// Connects two peers of which one or both cannot use UDP at all.
///
/// The blocked peers sit behind a home NAT with a [`Firewall::CaptivePortal`]
/// ruleset: outbound TCP is free, but all UDP except DNS is dropped, like
/// hotel or airport guest WiFi. That rules out QAD and holepunching, so the
/// endpoints must connect through the relay over TCP and stay there. The
/// unblocked peer is behind a plain home NAT; a direct path still needs UDP
/// on both ends, so the connection must remain relayed in every variant.
async fn run_relay_udp_blocked(blocked: UdpBlocked) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let server_blocked = matches!(blocked, UdpBlocked::Both | UdpBlocked::ServerOnly);
    let client_blocked = matches!(blocked, UdpBlocked::Both | UdpBlocked::ClientOnly);
    let mut net1 = lab.add_router("net1").nat(Nat::Home);
    if server_blocked {
        net1 = net1.firewall(Firewall::CaptivePortal);
    }
    let net1 = net1.build().await?;
    let mut net2 = lab.add_router("net2").nat(Nat::Home);
    if client_blocked {
        net2 = net2.firewall(Firewall::CaptivePortal);
    }
    let net2 = net2.build().await?;
    let server = lab.add_device("server").uplink(net1.id()).build().await?;
    let client = lab.add_device("client").uplink(net2.id()).build().await?;

    // Long enough for a holepunch to complete if one were possible.
    let hold = Duration::from_secs(3);
    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_accept(&conn, timeout).await.context("ping 1")?;
            tokio::time::sleep(hold).await;
            assert!(is_relayed(&conn), "still relayed with UDP blocked");
            ping_accept(&conn, timeout).await.context("ping 2")?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_open(&conn, timeout).await.context("ping 1")?;
            tokio::time::sleep(hold).await;
            assert!(is_relayed(&conn), "still relayed with UDP blocked");
            ping_open(&conn, timeout).await.context("ping 2")?;
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
async fn relay_udp_blocked_both() -> Result {
    run_relay_udp_blocked(UdpBlocked::Both).await
}

#[tokio::test]
#[traced_test]
async fn relay_udp_blocked_server() -> Result {
    run_relay_udp_blocked(UdpBlocked::ServerOnly).await
}

#[tokio::test]
#[traced_test]
async fn relay_udp_blocked_client() -> Result {
    run_relay_udp_blocked(UdpBlocked::ClientOnly).await
}

/// Takes one peer's link down and verifies the relay path recovers.
///
/// Both peers sit behind symmetric NATs, so the connection cannot escape to
/// a direct path and recovery must happen through a relay reconnect.
async fn run_relay_reconnect_link_outage(outage_side: Side, downtime: Duration) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Corporate).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Corporate).build().await?;
    let outage = lab.add_device("outage").uplink(nat1.id()).build().await?;
    let peer = lab.add_device("peer").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .left(outage_side, outage, async move |dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_open(&conn, timeout)
                .await
                .context("ping before outage")?;
            info!("killing link for {downtime:?}");
            dev.iface("eth0").unwrap().link_down().await?;
            tokio::time::sleep(downtime).await;
            dev.iface("eth0").unwrap().link_up().await?;
            info!("link restored, waiting for relay reconnect");
            ping_open(&conn, timeout)
                .await
                .context("ping after link restored")?;
            assert!(is_relayed(&conn), "still relayed behind symmetric NAT");
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .right(peer, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_accept(&conn, timeout)
                .await
                .context("ping before outage")?;
            ping_accept(&conn, timeout)
                .await
                .context("ping after link restored")?;
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
async fn relay_reconnect_link_outage_client() -> Result {
    run_relay_reconnect_link_outage(Side::Client, Duration::from_secs(5)).await
}

#[tokio::test]
#[traced_test]
async fn relay_reconnect_link_outage_server() -> Result {
    run_relay_reconnect_link_outage(Side::Server, Duration::from_secs(5)).await
}

/// Restarts the relay server underneath an established relay-pinned
/// connection and verifies data flows again once the clients reconnect.
///
/// The replacement relay binds the same ports and is reachable under the
/// same `https://relay.test` URL, like a relay deployment restarting in
/// place. Both peers' relay actors must notice the dead connection and
/// reconnect on their own.
#[tokio::test]
#[traced_test]
async fn relay_reconnect_relay_restart() -> Result {
    let mut builder = Lab::builder().outdir(OutDir::Exact(testdir!()));
    if let Some(name) = std::thread::current().name() {
        builder = builder.label(name);
    }
    let lab = builder.build().await?;
    let guard = lab.test_guard();

    let dc = lab
        .add_router("dc")
        .ip_support(IpSupport::DualStack)
        .build()
        .await?;
    let dev_relay = lab.add_device("relay").uplink(dc.id()).build().await?;
    let dns = lab.dns_server()?;
    dns.set_host("relay.test", dev_relay.ip().expect("relay has IPv4").into())?;
    dns.set_host(
        "relay.test",
        dev_relay.ip6().expect("relay has IPv6").into(),
    )?;

    let (map_tx, map_rx) = oneshot::channel();
    let (restart_tx, restart_rx) = oneshot::channel::<()>();
    let (restarted_tx, restarted_rx) = oneshot::channel::<()>();
    let relay_task = dev_relay.spawn(async move |_dev| {
        let (relay_map, server) = util::relay::run_relay_server().await.expect("relay spawn");
        map_tx.send(relay_map).expect("test task alive");
        restart_rx.await.expect("restart signal");
        server.shutdown().await.expect("relay shutdown");
        info!("relay stopped, starting a new relay on the same ports");
        let (_relay_map, _server) = util::relay::run_relay_server()
            .await
            .expect("relay respawn");
        restarted_tx.send(()).expect("test task alive");
        std::future::pending::<()>().await;
    })?;
    let _relay_guard = AbortOnDropHandle::new(relay_task);
    let relay_map = map_rx.await.std_context("relay task died before binding")?;

    let nat1 = lab.add_router("nat1").nat(Nat::Corporate).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Corporate).build().await?;
    let server = lab.add_device("server").uplink(nat1.id()).build().await?;
    let client = lab.add_device("client").uplink(nat2.id()).build().await?;

    let timeout = Duration::from_secs(20);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_accept(&conn, timeout)
                .await
                .context("ping before restart")?;
            ping_accept(&conn, timeout)
                .await
                .context("ping after restart")?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_open(&conn, timeout)
                .await
                .context("ping before restart")?;
            restart_tx
                .send(())
                .map_err(|_| anyerr!("relay task died"))?;
            restarted_rx.await.std_context("relay did not restart")?;
            info!("relay restarted, waiting for reconnect");
            ping_open(&conn, timeout)
                .await
                .context("ping after relay restart")?;
            assert!(is_relayed(&conn), "still relayed behind symmetric NAT");
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;
    guard.ok();
    Ok(())
}

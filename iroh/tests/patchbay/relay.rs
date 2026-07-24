//! Relay connectivity and reconnect tests.
//!
//! The relay from [`util::relay::run_relay_server`] binds `[::]` and is
//! reachable as `https://relay.test` through lab-wide DNS A and AAAA records.
//!
//! The connect tests place both peers on access networks that support only
//! one IP family, so all traffic to the relay uses that family. The
//! reconnect tests pin the connection to the relay by putting both peers
//! behind symmetric (`Nat::Corporate`) NATs, for which holepunching fails
//! even though IP transports stay enabled, and then break either one
//! peer's access link or the relay server itself.

use std::{net::SocketAddr, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayMode, RelayUrl, TransportAddr, Watcher,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    dns::DnsResolver,
    endpoint::{Side, presets},
    tls::CaTlsConfig,
};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr, ensure_any};
use n0_future::task::AbortOnDropHandle;
use n0_tracing_test::traced_test;
use patchbay::{
    FirewallConfigBuilder, IfaceConfig, IpSupport, Lab, LinkCondition, LinkDirection, LinkLimits,
    Nat, OutDir,
};
use testdir::testdir;
use tokio::sync::oneshot;
use tracing::info;
use url::Url;

use super::util::{self, Pair, is_relayed, lab_with_relay, ping_accept, ping_open};

/// Firewall rules that block all outbound UDP except DNS, leaving TCP open.
///
/// The lab DNS server is UDP-only, so port 53 must stay open. Everything else
/// over UDP (QAD, holepunch probes) is dropped, forcing traffic onto the relay
/// over TCP. Pass to [`RouterBuilder::firewall_custom`](patchbay::RouterBuilder).
fn block_udp_except_dns(f: &mut FirewallConfigBuilder) -> &mut FirewallConfigBuilder {
    f.block_inbound().allow_udp(&[53])
}

/// Connects two peers through the relay over a single IP family.
///
/// The relay's own network is dual-stack; both access routers support only
/// the family under test. Their firewall drops all UDP except DNS, so QAD
/// and holepunching are impossible and the relay is the only usable path:
/// the ping exchange proves the relay carries data over that family.
/// Direct-path coverage per family lives in the switch_uplink and nat
/// matrices.
async fn run_relay_connect(ip_support: IpSupport) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let access1 = lab
        .add_router("access1")
        .ip_support(ip_support)
        .firewall_custom(block_udp_except_dns)
        .build()
        .await?;
    let access2 = lab
        .add_router("access2")
        .ip_support(ip_support)
        .firewall_custom(block_udp_except_dns)
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
    // Sanity-check the harness: only the family under test is assigned.
    for dev in [&server, &client] {
        assert_eq!(dev.ip().is_some(), ip_support.has_v4(), "IPv4 assignment");
        assert_eq!(dev.ip6().is_some(), ip_support.has_v6(), "IPv6 assignment");
    }
    let timeout = Duration::from_secs(10);
    Pair::new(relay_map)
        .server(server, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_accept(&conn, timeout).await.context("ping_accept")?;
            assert!(is_relayed(&conn), "still relayed with UDP blocked");
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            ping_open(&conn, timeout).await.context("ping_open")?;
            assert!(is_relayed(&conn), "still relayed with UDP blocked");
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

/// Connects two peers of which one or both cannot use UDP beyond DNS.
///
/// The blocked peers sit behind a home NAT that drops unsolicited inbound and
/// all outbound UDP except DNS (the lab DNS server is UDP-only), the hotel or
/// airport guest WiFi shape. That rules out QAD and holepunching, so they must
/// reach each other through the relay over TCP. Any unblocked peer is behind a
/// plain home NAT; a direct path needs UDP on both ends, so the connection
/// stays relayed in every variant.
async fn run_relay_udp_blocked(blocked: UdpBlocked) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let server_blocked = matches!(blocked, UdpBlocked::Both | UdpBlocked::ServerOnly);
    let client_blocked = matches!(blocked, UdpBlocked::Both | UdpBlocked::ClientOnly);
    let mut net1 = lab.add_router("net1").nat(Nat::Home);
    if server_blocked {
        net1 = net1.firewall_custom(block_udp_except_dns);
    }
    let net1 = net1.build().await?;
    let mut net2 = lab.add_router("net2").nat(Nat::Home);
    if client_blocked {
        net2 = net2.firewall_custom(block_udp_except_dns);
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
/// a direct path; the affected peer's relay client notices the dead link and
/// reconnects once the link is back.
async fn run_relay_reconnect_link_outage(outage_side: Side, downtime: Duration) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Corporate).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Corporate).build().await?;
    let outage = lab.add_device("outage").uplink(nat1.id()).build().await?;
    let peer = lab.add_device("peer").uplink(nat2.id()).build().await?;
    let timeout = Duration::from_secs(15);
    // The reconnect backoff can sleep through the link returning: dials during
    // the outage fail fast and grow the backoff to several seconds plus jitter,
    // so the post-outage pings need generous headroom.
    let recovery_timeout = Duration::from_secs(30);
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
            ping_open(&conn, recovery_timeout)
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
            ping_accept(&conn, recovery_timeout)
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
    // Register DNS before the endpoint devices below; only later devices
    // resolve it.
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
        // The old server's sockets are released asynchronously after
        // shutdown() returns; retry briefly if a port is still taken.
        let mut attempts = 0;
        let (_relay_map, _server) = loop {
            match util::relay::run_relay_server().await {
                Ok(relay) => break relay,
                Err(err) if attempts < 20 => {
                    attempts += 1;
                    info!("relay respawn attempt {attempts} failed: {err:#}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(err) => panic!("relay respawn: {err:#}"),
            }
        };
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

/// The relay carrying the connection dies; the client re-resolves and recovers.
///
/// The peers have disjoint relay maps: the server holds relay-s1 (fast) and
/// relay-s2 (behind a 100 ms link, so the server homes on s1), the client only
/// relay-c1. The client dials the server's relay-only addr, so the connection
/// runs over s1, the server's home relay; relay-c1 plays no role in it. Both
/// peers block UDP beyond DNS, so the relay is the only possible path.
///
/// Address lookup runs through an iroh-dns-server in the lab: the server
/// publishes its endpoint info over pkarr HTTP, the client resolves the
/// `_iroh` TXT records over DNS.
///
/// s1 is torn down. The server fails over its home relay to s2 and republishes
/// its endpoint info. The client notices the lost relay connection, re-runs
/// address lookup for the server, learns s2, and opens a path over it; only
/// the client can do this. The final ping proves the connection carried across.
#[tokio::test]
#[traced_test]
async fn relay_teardown_failover() -> Result {
    const ALPN: &[u8] = b"relay-failover";
    // The default origin served by iroh-dns-server.
    const LOOKUP_ORIGIN: &str = "irohdns.example";

    let mut builder = Lab::builder().outdir(OutDir::Exact(testdir!()));
    if let Some(name) = std::thread::current().name() {
        builder = builder.label(name);
    }
    let lab = builder.build().await?;
    let guard = lab.test_guard();

    let net = lab
        .add_router("net")
        .ip_support(IpSupport::DualStack)
        .build()
        .await?;

    // The server's relays: s1 fast, s2 behind 100 ms each way. The client's
    // own relay c1 must never carry the connection.
    let dev_s1 = lab.add_device("relay-s1").uplink(net.id()).build().await?;
    let slow = LinkCondition::Manual(LinkLimits {
        latency_ms: 100,
        ..Default::default()
    });
    let dev_s2 = lab
        .add_device("relay-s2")
        .iface(
            "eth0",
            IfaceConfig::routed(net.id()).condition(slow, LinkDirection::Both),
        )
        .build()
        .await?;
    let dev_c1 = lab.add_device("relay-c1").uplink(net.id()).build().await?;

    // The address lookup service: an iroh-dns-server (pkarr relay over HTTP,
    // DNS server on port 53).
    let dev_dns = lab.add_device("dns").uplink(net.id()).build().await?;

    // Register DNS before the endpoint devices below; only later devices
    // resolve it. Only the IPv4 address for dns.test: on this branch the
    // dns-server's default binds are IPv4-only.
    let dns = lab.dns_server()?;
    for (host, dev) in [
        ("relay-s1.test", &dev_s1),
        ("relay-s2.test", &dev_s2),
        ("relay-c1.test", &dev_c1),
    ] {
        dns.set_host(host, dev.ip().expect("relay has IPv4").into())?;
        dns.set_host(host, dev.ip6().expect("relay has IPv6").into())?;
    }
    let dns_ip = dev_dns.ip().expect("dns has IPv4");
    dns.set_host("dns.test", dns_ip.into())?;

    let _dns_guard = util::spawn_dns_server(&dev_dns, testdir!().join("dns-server-data")).await?;
    let pkarr_url: Url = "http://dns.test:8080/pkarr".parse().expect("valid url");
    let lookup_nameserver = SocketAddr::new(dns_ip.into(), 53);

    // s1 runs until the test signals a teardown; s2 and c1 run throughout.
    let (s1_map_tx, s1_map_rx) = oneshot::channel();
    let (teardown_tx, teardown_rx) = oneshot::channel::<()>();
    let (down_tx, down_rx) = oneshot::channel::<()>();
    let s1_task = dev_s1.spawn(async move |_dev| {
        let (map, server) = util::relay::run_relay_server_named("relay-s1.test")
            .await
            .expect("relay-s1 spawn");
        s1_map_tx.send(map).expect("test task alive");
        teardown_rx.await.expect("teardown signal");
        server.shutdown().await.expect("relay-s1 shutdown");
        down_tx.send(()).expect("test task alive");
        std::future::pending::<()>().await;
    })?;
    let _s1_guard = AbortOnDropHandle::new(s1_task);
    let s1_map = s1_map_rx
        .await
        .std_context("relay-s1 died before binding")?;

    let (s2_map, _s2_guard) = spawn_static_relay(&dev_s2, "relay-s2.test").await?;
    let (client_map, _c1_guard) = spawn_static_relay(&dev_c1, "relay-c1.test").await?;

    let server_map = RelayMap::empty();
    for config in s1_map
        .relays::<Vec<_>>()
        .into_iter()
        .chain(s2_map.relays::<Vec<_>>())
    {
        server_map.insert(config.url.clone(), config);
    }
    let [s1_url, s2_url, c1_url] = ["relay-s1", "relay-s2", "relay-c1"].map(|host| {
        format!("https://{host}.test")
            .parse::<RelayUrl>()
            .expect("valid relay url")
    });

    // Both peers behind home NATs that block UDP beyond DNS, so the whole
    // connection runs over the relay.
    let nat1 = lab
        .add_router("nat1")
        .nat(Nat::Home)
        .firewall_custom(block_udp_except_dns)
        .build()
        .await?;
    let nat2 = lab
        .add_router("nat2")
        .nat(Nat::Home)
        .firewall_custom(block_udp_except_dns)
        .build()
        .await?;
    let dev_server = lab.add_device("server").uplink(nat1.id()).build().await?;
    let dev_client = lab.add_device("client").uplink(nat2.id()).build().await?;

    let timeout = Duration::from_secs(10);
    // Recovery spans the server's home failover (deferred full net report), the
    // republish, and the client's lookup retries; observed well under 15s with
    // noq's abandon-time retransmit fix, so this is still a comfortable margin.
    let recovery_timeout = Duration::from_secs(15);

    // Both run functions wait here before dropping their endpoint, so neither
    // side is left waiting out QUIC timeouts on a vanished peer (the same
    // pattern as `Pair::run`).
    let barrier_server = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let barrier_client = barrier_server.clone();

    let (addr_tx, addr_rx) = oneshot::channel();
    let server_task = dev_server.spawn({
        let s1_url = s1_url.clone();
        move |_dev| async move {
            let ep = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Custom(server_map))
                // Publishes the endpoint info (including the home relay) to the
                // lab dns-server, republished whenever it changes. TTL 1s so
                // the client's lookup retries are not served stale records
                // from its resolver cache.
                .address_lookup(PkarrPublisher::builder(pkarr_url).ttl(1))
                .ca_tls_config(CaTlsConfig::insecure_skip_verify())
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await
                .context("server bind")?;
            ep.online().await;
            let home = connected_home_relay(&ep, timeout)
                .await
                .context("no home relay")?;
            ensure_any!(
                home == s1_url,
                "server should home on the fast relay, got {home}"
            );

            let addr = ep.addr();
            let relay_addr =
                EndpointAddr::from_parts(addr.id, addr.addrs.into_iter().filter(|a| a.is_relay()));
            addr_tx.send(relay_addr).ok();

            let incoming = ep.accept().await.context("accept")?;
            let conn = incoming.accept().anyerr()?.await.context("handshake")?;
            assert!(is_relayed(&conn), "connection started relayed");
            ping_accept(&conn, timeout)
                .await
                .context("ping before teardown")?;
            ping_accept(&conn, recovery_timeout)
                .await
                .context("ping after relay-s1 teardown")?;
            barrier_server.wait().await;
            n0_error::Ok(())
        }
    })?;

    let client_task = dev_client.spawn(move |_dev| async move {
        let ep = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Custom(client_map))
            // Resolves `_iroh` TXT records at the lab dns-server. The relay
            // hostnames keep resolving through the system resolver.
            .address_lookup(
                DnsAddressLookup::builder(LOOKUP_ORIGIN.to_string())
                    .dns_resolver(DnsResolver::with_nameserver(lookup_nameserver)),
            )
            .ca_tls_config(CaTlsConfig::insecure_skip_verify())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .context("client bind")?;
        ep.online().await;

        let addr = addr_rx.await.std_context("server addr")?;
        let conn = ep.connect(addr, ALPN).await.context("connect")?;
        let selected = selected_remote_addr(&conn);
        ensure_any!(
            matches!(&selected, TransportAddr::Relay(url) if *url == s1_url),
            "connection should start over the server's home relay, got {selected:?}"
        );
        ping_open(&conn, timeout)
            .await
            .context("ping before teardown")?;

        info!("tearing down relay-s1 (the relay carrying the connection)");
        teardown_tx.send(()).map_err(|_| anyerr!("relay-s1 died"))?;
        down_rx.await.std_context("relay-s1 did not shut down")?;

        info!("relay-s1 down, expecting re-lookup and failover to relay-s2");
        ping_open(&conn, recovery_timeout)
            .await
            .context("ping after relay-s1 teardown")?;
        let selected = selected_remote_addr(&conn);
        ensure_any!(
            matches!(&selected, TransportAddr::Relay(url) if *url == s2_url),
            "connection should have moved to the server's new home relay, got {selected:?}"
        );
        ensure_any!(
            conn.paths()
                .iter()
                .all(|p| !matches!(p.remote_addr(), TransportAddr::Relay(url) if *url == c1_url)),
            "the client's own relay must not carry a path to the server"
        );
        conn.close(0u32.into(), b"bye");
        barrier_client.wait().await;
        n0_error::Ok(())
    })?;

    let (server_res, client_res) = tokio::time::timeout(Duration::from_secs(90), async {
        tokio::join!(server_task, client_task)
    })
    .await
    .std_context("test timed out")?;
    server_res.std_context("server task")??;
    client_res.std_context("client task")??;
    guard.ok();
    Ok(())
}

/// Spawns a relay on `dev` under `host` that runs for the whole test.
async fn spawn_static_relay(
    dev: &patchbay::Device,
    host: &'static str,
) -> Result<(RelayMap, AbortOnDropHandle<()>)> {
    let (map_tx, map_rx) = oneshot::channel();
    let task = dev.spawn(async move |_dev| {
        let (map, _server) = util::relay::run_relay_server_named(host)
            .await
            .expect("relay spawn");
        map_tx.send(map).expect("test task alive");
        std::future::pending::<()>().await;
    })?;
    let map = map_rx.await.std_context("relay died before binding")?;
    Ok((map, AbortOnDropHandle::new(task)))
}

/// Returns the remote address of the connection's selected path.
fn selected_remote_addr(conn: &iroh::endpoint::Connection) -> TransportAddr {
    conn.paths()
        .iter()
        .find(|p| p.is_selected())
        .expect("no selected path")
        .remote_addr()
        .clone()
}

/// Waits until the endpoint has a connected home relay and returns its URL.
async fn connected_home_relay(ep: &Endpoint, timeout: Duration) -> Result<RelayUrl> {
    tokio::time::timeout(timeout, async move {
        let mut watcher = ep.home_relay_status();
        let mut statuses = watcher.get();
        loop {
            if let Some(status) = statuses.iter().find(|s| s.is_connected()) {
                return Ok(status.url().clone());
            }
            statuses = watcher
                .updated()
                .await
                .map_err(|_| anyerr!("home relay watcher disconnected"))?;
        }
    })
    .await
    .std_context("timed out waiting for a connected home relay")?
}

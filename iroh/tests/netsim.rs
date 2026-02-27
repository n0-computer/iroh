#![cfg(target_os = "linux")]

use std::time::Duration;

use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayMode, Watcher,
    endpoint::{Connection, PathInfo, PathWatcher, QuicTransportConfig},
    tls::CaRootsConfig,
};
use n0_error::{Result, StackResultExt, StdResultExt, ensure_any};
use n0_future::task::AbortOnDropHandle;
use n0_tracing_test::traced_test;
use netsim_core::{Impair, Lab, NatMode};
use tokio::sync::oneshot;
use tracing::{Instrument, error_span, info};

use self::relay::run_relay_server;

/// Init the user namespace before any threads are spawned.
///
/// This gives us all permissions we need for netsim.
#[ctor::ctor]
fn userns_ctor() {
    // SAFETY: Running this in a constructor is safe.
    unsafe { netsim_core::init_userns_for_ctor() }
}

const TEST_ALPN: &[u8] = b"test";

/// Simple holepunch: Two devices behind destination-independent NATs,
/// establish via relay, upgrade to direct.
#[tokio::test]
#[traced_test]
async fn holepunch_simple() -> Result {
    let lab = Lab::default();
    let (relay_map, _relay_guard) = spawn_relay(&lab).await?;

    let nat_mode = NatMode::DestinationIndependent;
    let nat1 = lab.add_router("nat1").nat(nat_mode).build().await?;
    let nat2 = lab.add_router("nat2").nat(nat_mode).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;

    let timeout = Duration::from_secs(10);

    // spawn acceptor endpoint on dev1
    let (addr_tx, addr_rx) = oneshot::channel();
    let relay_map_2 = relay_map.clone();
    let task1 = dev1.spawn(|ctx| {
        async move {
            info!("local ip: {}", ctx.ip());
            let endpoint = endpoint_builder(relay_map_2).bind().await?;
            endpoint.online().await;
            addr_tx.send(addr_relay_only(endpoint.addr())).unwrap();
            let conn = endpoint.accept().await.unwrap().accept().anyerr()?.await?;
            conn.closed().await;
            endpoint.close().await;
            n0_error::Ok(())
        }
        .instrument(error_span!("ep1"))
    });

    // spawn connector endpoint on dev2
    let task2 = dev2.spawn(move |ctx| {
        async move {
            info!("local ip: {}", ctx.ip());
            let endpoint = endpoint_builder(relay_map).bind().await?;
            let addr1 = addr_rx.await.unwrap();
            let conn = endpoint.connect(addr1, TEST_ALPN).await?;
            let mut paths = conn.paths();
            match_selected_path(&mut paths, timeout, PathInfo::is_relay).await?;
            info!("connection started relayed");
            match_selected_path(&mut paths, timeout, PathInfo::is_ip).await?;
            info!("connection became direct");
            endpoint.close().await;
            n0_error::Ok(())
        }
        .instrument(error_span!("ep2"))
    });
    task2.await.anyerr()??;
    task1.await.anyerr()??;
    Ok(())
}

/// Tests that changing the uplink of an interface works (i.e. switching wifis).
///
/// For this we observe a change in the selected path's remote addr on the *other* side.
/// Whether the side that changes interfaces opens a new path or does an RFC9000-style migration
/// is an implementation detail which we won't test for.
#[tokio::test]
#[traced_test]
async fn switch_uplink() -> Result {
    let lab = Lab::default();
    let (relay_map, _relay_guard) = spawn_relay(&lab).await?;

    let nat_mode = NatMode::DestinationIndependent;
    let nat1 = lab.add_router("nat1").nat(nat_mode).build().await?;
    let nat2 = lab.add_router("nat2").nat(nat_mode).build().await?;
    let nat3 = lab.add_router("nat3").nat(nat_mode).build().await?;
    let dev1 = lab.add_device("dev1").uplink(nat1.id()).build().await?;
    let dev2 = lab.add_device("dev2").uplink(nat2.id()).build().await?;

    let timeout = Duration::from_secs(10);

    // spawn acceptor endpoint on dev1
    let (addr_tx, addr_rx) = oneshot::channel();
    let relay_map_2 = relay_map.clone();
    let task1 = dev1.spawn(move |ctx| {
        async move {
            info!("local ip: {}", ctx.ip());
            let endpoint = endpoint_builder(relay_map_2).bind().await?;
            endpoint.online().await;
            addr_tx.send(addr_relay_only(endpoint.addr())).unwrap();
            let conn = endpoint.accept().await.unwrap().accept().anyerr()?.await?;
            watch_selected_path(&conn);
            let mut paths = conn.paths();

            // Wait until a first direct path is established.
            let first = match_selected_path(&mut paths, timeout, PathInfo::is_ip).await?;
            info!(addr=?first.remote_addr(), "connection became direct, waiting for path change");

            // Now wait until the direct path changes, which happens after the other endpoint
            // changes its uplink.
            let second = match_selected_path(&mut paths, timeout, |p| {
                p.is_ip() && p.remote_addr() != first.remote_addr()
            })
            .await?;
            info!(addr=?second.remote_addr(), "connection changed path, wait for ping");

            // Ping for final confirmation, then wait for connection close.
            ping_accept(&conn, timeout).await?;
            info!("ping done, wait for close");
            conn.closed().await;
            info!("closed");
            endpoint.close().await;
            n0_error::Ok(())
        }
        .instrument(error_span!("ep1"))
    });

    // spawn connector endpoint on dev2
    let task2 = dev2.spawn(move |ctx| {
        async move {
            info!("local ip: {}", ctx.ip());
            let endpoint = endpoint_builder(relay_map).bind().await?;
            let addr1 = addr_rx.await.unwrap();
            let conn = endpoint.connect(addr1, TEST_ALPN).await?;
            watch_selected_path(&conn);
            let mut paths = conn.paths();

            // Wait for conn to become direct.
            let first_selected = match_selected_path(&mut paths, timeout, PathInfo::is_ip)
                .await
                .context("did not become direct")?;
            let first_addr = first_selected.remote_addr();
            info!(?first_addr, "connection became direct");

            // Wait a little more and then switch wifis.
            tokio::time::sleep(Duration::from_secs(1)).await;
            info!("switch IP uplink");
            ctx.switch_uplink("eth0", nat3.id()).await?;

            // We don't assert any path changes here, because the remote stays identical,
            // and PathInfo does not contain info on local addrs. Instead, the remote
            // only accepts our ping after the path changed.
            info!("send ping");
            ping_open(&conn, timeout)
                .await
                .context("failed at ping_open")?;
            info!("ping done, close");

            endpoint.close().await;
            n0_error::Ok(())
        }
        .instrument(error_span!("ep2"))
    });
    task2.await.anyerr()??;
    task1.await.anyerr()??;
    Ok(())
}
/// Test that switching to a faster link works.
///
/// Two devices, connected initiall over holepunched NAT. Then mid connection
/// device 2 plugs a cable into device 1's router, i.e. they now have a LAN
/// connection.
///
/// Verify we switch to the LAN connection.
#[tokio::test]
#[traced_test]
async fn change_ifaces() -> Result {
    let lab = Lab::default();
    let (relay_map, _relay_guard) = spawn_relay(&lab).await?;

    let nat_mode = NatMode::DestinationIndependent;
    let nat1 = lab.add_router("nat1").nat(nat_mode).build().await?;
    let nat2 = lab.add_router("nat2").nat(nat_mode).build().await?;

    // setup dev2 with two uplinks (i.e. wifi and mobile).
    // eth0 is enabled, eth1 is disabled
    let dev1 = lab
        .add_device("dev1")
        .iface("eth0", nat1.id(), None)
        .build()
        .await?;

    let dev2 = lab
        .add_device("dev2")
        .iface("eth0", nat2.id(), Some(Impair::Mobile))
        .iface("eth1", nat1.id(), None)
        .build()
        .await?;
    // The iface in dev1's LAN is down initially.
    dev2.link_down("eth1").await?;

    let timeout = Duration::from_secs(10);

    // spawn acceptor endpoint on dev1
    let (addr_tx, addr_rx) = oneshot::channel();
    let relay_map_2 = relay_map.clone();
    let task1 = dev1.spawn(move |ctx| {
        async move {
            info!("local ip: {}", ctx.ip());
            let endpoint = endpoint_builder(relay_map_2).bind().await?;
            endpoint.online().await;
            addr_tx.send(addr_relay_only(endpoint.addr())).unwrap();
            let conn = endpoint.accept().await.unwrap().accept().anyerr()?.await?;
            watch_selected_path(&conn);

            // On the accept side, we do nothing, just watch paths, accept a ping, and wait until the connection closes.
            ping_accept(&conn, timeout)
                .await
                .context("failed at ping_accept")?;
            conn.closed().await;
            endpoint.close().await;
            n0_error::Ok(())
        }
        .instrument(error_span!("ep1"))
    });

    // spawn connector endpoint on dev2
    let task2 = dev2.spawn(move |ctx| {
        async move {
            info!("local ip: {}", ctx.ip());
            let endpoint = endpoint_builder(relay_map).bind().await?;
            let addr1 = addr_rx.await.unwrap();
            let conn = endpoint.connect(addr1, TEST_ALPN).await?;
            watch_selected_path(&conn);

            let mut paths = conn.paths();
            let first = match_selected_path(&mut paths, timeout, PathInfo::is_ip)
                .await
                .context("did not become direct")?;
            info!(addr = ?first.remote_addr(), "connection became direct");

            tokio::time::sleep(Duration::from_secs(1)).await;

            // Bring up the LAN interface to the other ep.
            info!("bring up eth1");
            ctx.link_up("eth1").await?;

            // Wait for a new direct path to be established.
            let next = match_selected_path(&mut paths, timeout, |p| {
                p.is_ip() && p.remote_addr() != first.remote_addr()
            })
            .await
            .context("did not switch paths")?;
            info!(addr=?next.remote_addr(), "new direct path established");

            ping_open(&conn, timeout)
                .await
                .context("failed at ping_open")?;

            endpoint.close().await;
            n0_error::Ok(())
        }
        .instrument(error_span!("ep2"))
    });
    task2.await.anyerr()??;
    task1.await.anyerr()??;
    Ok(())
}

// ---
// utility functions
// ---

/// Prints info logs when the selected path changes.
fn watch_selected_path(conn: &Connection) {
    let mut watcher = conn.paths();
    tokio::spawn(
        async move {
            let mut prev = None;
            loop {
                let paths = watcher.get();
                let selected = paths.iter().find(|p| p.is_selected()).unwrap();
                if Some(selected) != prev.as_ref() {
                    info!(
                        "selected path: [{}] {:?} rtt {:?}",
                        selected.id(),
                        selected.remote_addr(),
                        selected.rtt().unwrap()
                    );
                    prev = Some(selected.clone());
                }
                if watcher.updated().await.is_err() {
                    break;
                }
            }
        }
        .instrument(tracing::Span::current()),
    );
}

async fn ping_open(conn: &Connection, timeout: Duration) -> Result {
    tokio::time::timeout(timeout, async {
        let data: [u8; 8] = rand::random();
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        send.write_all(&data).await.anyerr()?;
        send.finish().anyerr()?;
        let r = recv.read_to_end(8).await.anyerr()?;
        ensure_any!(r == data, "reply matches");
        Ok(())
    })
    .await
    .anyerr()?
}

async fn ping_accept(conn: &Connection, timeout: Duration) -> Result {
    tokio::time::timeout(timeout, async {
        let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
        let data = recv.read_to_end(8).await.anyerr()?;
        send.write_all(&data).await.anyerr()?;
        send.finish().anyerr()?;
        Ok(())
    })
    .await
    .anyerr()?
}

async fn match_selected_path(
    watcher: &mut PathWatcher,
    timeout: Duration,
    f: impl Fn(&PathInfo) -> bool,
) -> Result<PathInfo> {
    tokio::time::timeout(timeout, async {
        loop {
            let paths = watcher.get();
            if let Some(p) = paths.iter().find(|p| p.is_selected() && f(p)) {
                return n0_error::Ok(p.clone());
            }
            watcher.updated().await?;
        }
    })
    .await
    .anyerr()?
}

fn endpoint_builder(relay_map: RelayMap) -> iroh::endpoint::Builder {
    let name = tracing::Span::current()
        .metadata()
        .map(|m| m.name())
        .unwrap_or("ep");
    let mut builder = Endpoint::empty_builder(RelayMode::Custom(relay_map))
        .ca_roots_config(CaRootsConfig::insecure_skip_verify())
        .alpns(vec![TEST_ALPN.to_vec()]);
    #[cfg(feature = "qlog")]
    {
        let transport_config = QuicTransportConfig::builder().qlog_from_env(name).build();
        builder = builder.transport_config(transport_config);
    }
    builder
}

fn addr_relay_only(addr: EndpointAddr) -> EndpointAddr {
    EndpointAddr::from_parts(addr.id, addr.addrs.into_iter().filter(|a| a.is_relay()))
}

/// Spawn a relay with a public IP and return a relay map and drop guard.
async fn spawn_relay(lab: &Lab) -> Result<(RelayMap, AbortOnDropHandle<()>)> {
    let dc = lab.add_router("dc").build().await?;
    let dev_relay = lab.add_device("relay").uplink(dc.id()).build().await?;
    let (relay_map_tx, relay_map_rx) = oneshot::channel();
    let task_relay = dev_relay.spawn(async move |ctx| {
        let (relay_map, _relay_url, _server) = run_relay_server(ctx.ip().into()).await.unwrap();
        relay_map_tx.send(relay_map).unwrap();
        std::future::pending::<()>().await;
    });
    let relay_map = relay_map_rx.await.unwrap();
    Ok((relay_map, AbortOnDropHandle::new(task_relay)))
}

mod relay {
    use std::net::IpAddr;

    use iroh_base::RelayUrl;
    use iroh_relay::{
        RelayConfig, RelayMap, RelayQuicConfig,
        server::{
            AccessConfig, CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server,
            ServerConfig, SpawnError, TlsConfig,
        },
    };

    pub async fn run_relay_server(
        bind_ip: IpAddr,
    ) -> Result<(RelayMap, RelayUrl, Server), SpawnError> {
        let (certs, server_config) =
            iroh_relay::server::testing::self_signed_tls_certs_and_config();

        let tls = TlsConfig {
            cert: CertConfig::<(), ()>::Manual { certs },
            https_bind_addr: (bind_ip, 443).into(),
            quic_bind_addr: (bind_ip, 7842).into(),
            server_config,
        };
        let quic = Some(QuicConfig {
            server_config: tls.server_config.clone(),
            bind_addr: tls.quic_bind_addr,
        });
        let config = ServerConfig {
            relay: Some(RelayServerConfig {
                http_bind_addr: (bind_ip, 80).into(),
                tls: Some(tls),
                limits: Default::default(),
                key_cache_capacity: Some(1024),
                access: AccessConfig::Everyone,
            }),
            quic,
            ..Default::default()
        };
        let server = Server::spawn(config).await?;
        let url: RelayUrl = format!("https://{}", server.https_addr().expect("configured"))
            .parse()
            .expect("invalid relay url");

        let quic = server
            .quic_addr()
            .map(|addr| RelayQuicConfig { port: addr.port() });
        let n: RelayMap = RelayConfig {
            url: url.clone(),
            quic,
        }
        .into();
        Ok((n, url, server))
    }
}

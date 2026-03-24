use std::{future::Future, path::PathBuf, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayMode, Watcher,
    endpoint::{Connection, PathInfo, PathWatcher},
    tls::CaRootsConfig,
};
use n0_error::{Result, StdResultExt, ensure_any};
use n0_future::task::AbortOnDropHandle;
use patchbay::{Device, IpSupport, Lab, LabOpts, OutDir, TestGuard};
use tokio::sync::oneshot;
use tracing::{Instrument, debug, error_span};

use self::relay::run_relay_server;

const TEST_ALPN: &[u8] = b"test";

/// Create a lab with a dual-stack relay server. Returns the lab, relay map, a drop guard
/// that keeps the relay alive, and a [`TestGuard`] that records pass/fail.
///
/// The relay binds on `[::]` and is reachable via `https://relay.test` (resolved
/// through lab-wide DNS entries for both IPv4 and IPv6).
pub async fn lab_with_relay(
    path: PathBuf,
) -> Result<(Lab, RelayMap, AbortOnDropHandle<()>, TestGuard)> {
    let mut opts = LabOpts::default().outdir(OutDir::Exact(path));
    if let Some(name) = std::thread::current().name() {
        opts = opts.label(name);
    }
    let lab = Lab::with_opts(opts).await?;
    let guard = lab.test_guard();
    let (relay_map, relay_guard) = spawn_relay(&lab).await?;
    Ok((lab, relay_map, relay_guard, guard))
}

async fn spawn_relay(lab: &Lab) -> Result<(RelayMap, AbortOnDropHandle<()>)> {
    let dc = lab
        .add_router("dc")
        .ip_support(IpSupport::DualStack)
        .build()
        .await?;
    let dev_relay = lab.add_device("relay").uplink(dc.id()).build().await?;

    // Register both v4 and v6 addresses under "relay.test" lab-wide.
    // Devices created after this will resolve "relay.test" to both addresses.
    let relay_v4 = dev_relay.ip().expect("relay has IPv4");
    let relay_v6 = dev_relay.ip6().expect("relay has IPv6");
    lab.dns_entry("relay.test", relay_v4.into())?;
    lab.dns_entry("relay.test", relay_v6.into())?;

    let (relay_map_tx, relay_map_rx) = oneshot::channel();
    let task_relay = dev_relay.spawn(async move |_ctx| {
        let (relay_map, _server) = run_relay_server().await.unwrap();
        relay_map_tx.send(relay_map).unwrap();
        std::future::pending::<()>().await;
    })?;
    let relay_map = relay_map_rx.await.unwrap();
    Ok((relay_map, AbortOnDropHandle::new(task_relay)))
}

// ---
// Pair: run two connected endpoints
// ---

/// Two connected endpoints in the test lab, ready to run.
///
/// `peer1` runs in `dev1`'s namespace as the accepting side.
/// `peer2` runs in `dev2`'s namespace as the connecting side.
///
/// `peer1` awaits the connection to be closed afterwards, whereas `peer2` closes
/// the connection.
pub struct Pair {
    dev1: Device,
    dev2: Device,
    relay_map: RelayMap,
}

impl Pair {
    pub fn new(dev1: Device, dev2: Device, relay_map: RelayMap) -> Self {
        Self {
            dev1,
            dev2,
            relay_map,
        }
    }

    pub async fn run<F1, Fut1, F2, Fut2>(self, peer1: F1, peer2: F2) -> Result
    where
        F1: FnOnce(Device, Endpoint, Connection) -> Fut1 + Send + 'static,
        Fut1: Future<Output = Result> + Send,
        F2: FnOnce(Device, Endpoint, Connection) -> Fut2 + Send + 'static,
        Fut2: Future<Output = Result> + Send,
    {
        let (addr_tx, addr_rx) = oneshot::channel();
        let relay_map2 = self.relay_map.clone();
        let task1 = self.dev1.spawn(move |dev| {
            async move {
                let endpoint = endpoint_builder(&dev, relay_map2).bind().await?;
                endpoint.online().await;
                addr_tx.send(addr_relay_only(endpoint.addr())).unwrap();
                let conn = endpoint.accept().await.unwrap().accept().anyerr()?.await?;
                watch_selected_path(&conn);
                peer1(dev, endpoint.clone(), conn.clone()).await?;
                conn.closed().await;
                endpoint.close().await;
                n0_error::Ok(())
            }
            .instrument(error_span!("ep-acpt"))
        })?;
        let task2 = self.dev2.spawn(move |dev| {
            async move {
                let endpoint = endpoint_builder(&dev, self.relay_map).bind().await?;
                let addr = addr_rx.await.unwrap();
                let conn = endpoint.connect(addr, TEST_ALPN).await?;
                watch_selected_path(&conn);
                peer2(dev, endpoint.clone(), conn).await?;
                endpoint.close().await;
                n0_error::Ok(())
            }
            .instrument(error_span!("ep-cnct"))
        })?;

        let (res1, res2) = tokio::join!(task1, task2);

        let res1: Result<()> = res1
            .std_context("device1 panicked")
            .map(|res| res.context("device1 failed"))
            .flatten();
        let res2: Result<()> = res2
            .std_context("device2 panicked")
            .map(|res| res.context("device2 failed"))
            .flatten();

        if let Err(err) = res1.as_ref() {
            self.dev1.run_sync(|| {
                tracing::event!(
                    target: "test::_event::failed",
                    tracing::Level::ERROR,
                    error: format!("{err:#}"),
                );
                Ok(())
            });
        }
        if let Err(err) = res2.as_ref() {
            self.dev2.run_sync(|| {
                tracing::event!(
                    target: "test::_event::failed",
                    tracing::Level::ERROR,
                    error: format!("{err:#}"),
                );
                Ok(())
            });
        }
        res1?;
        res2?;
        Ok(())
    }
}

/// Extension methods on [`PathWatcher`] for common waiting patterns in tests.
#[allow(unused)]
pub trait PathWatcherExt {
    async fn wait_selected(
        &mut self,
        timeout: Duration,
        f: impl Fn(&PathInfo) -> bool,
    ) -> Result<PathInfo>;

    fn selected(&mut self) -> PathInfo;

    fn match_selected(&mut self, f: impl FnOnce(&PathInfo) -> bool) -> bool {
        f(&self.selected())
    }

    fn is_ip(&mut self) -> bool {
        self.match_selected(PathInfo::is_ip)
    }

    fn is_relay(&mut self) -> bool {
        self.match_selected(PathInfo::is_relay)
    }
    /// Wait until the selected path is a direct (IP) path.
    async fn wait_ip(&mut self, timeout: Duration) -> Result<PathInfo> {
        self.wait_selected(timeout, PathInfo::is_ip).await
    }

    /// Wait until the selected path is a relay path.
    async fn wait_relay(&mut self, timeout: Duration) -> Result<PathInfo> {
        self.wait_selected(timeout, PathInfo::is_relay).await
    }
}

impl PathWatcherExt for PathWatcher {
    fn selected(&mut self) -> PathInfo {
        let p = self.get();
        p.iter()
            .find(|p| p.is_selected())
            .cloned()
            .expect("no selected path")
    }

    async fn wait_selected(
        &mut self,
        timeout: Duration,
        f: impl Fn(&PathInfo) -> bool,
    ) -> Result<PathInfo> {
        tokio::time::timeout(timeout, async {
            loop {
                let selected = self.selected();
                if f(&selected) {
                    return n0_error::Ok(selected);
                }
                self.updated().await?;
            }
        })
        .await
        .anyerr()?
    }
}

pub async fn ping_open(conn: &Connection, timeout: Duration) -> Result {
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

pub async fn ping_accept(conn: &Connection, timeout: Duration) -> Result {
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

fn watch_selected_path(conn: &Connection) {
    let mut watcher = conn.paths();
    tokio::spawn(
        async move {
            let mut prev = None;
            loop {
                let paths = watcher.get();
                let selected = paths.iter().find(|p| p.is_selected()).unwrap();
                if Some(selected) != prev.as_ref() {
                    debug!(
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

fn endpoint_builder(device: &Device, relay_map: RelayMap) -> iroh::endpoint::Builder {
    #[allow(unused_mut)]
    let mut builder = Endpoint::empty_builder(RelayMode::Custom(relay_map))
        .ca_roots_config(CaRootsConfig::insecure_skip_verify())
        .alpns(vec![TEST_ALPN.to_vec()]);

    #[cfg(not(feature = "qlog"))]
    let _ = device;

    #[cfg(feature = "qlog")]
    {
        if let Some(path) = device.filepath("qlog") {
            let prefix = path.file_name().unwrap().to_str().unwrap();
            let directory = path.parent().unwrap();
            let transport_config = iroh::endpoint::QuicTransportConfig::builder()
                .qlog_from_path(directory, prefix)
                .build();
            builder = builder.transport_config(transport_config);
        }
    }

    builder
}

fn addr_relay_only(addr: EndpointAddr) -> EndpointAddr {
    EndpointAddr::from_parts(addr.id, addr.addrs.into_iter().filter(|a| a.is_relay()))
}

mod relay {
    use std::net::{IpAddr, Ipv6Addr};

    use iroh_base::RelayUrl;
    use iroh_relay::{
        RelayConfig, RelayMap, RelayQuicConfig,
        server::{
            AccessConfig, CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server,
            ServerConfig, SpawnError, TlsConfig,
        },
    };

    /// Spawn a relay server bound on `[::]` that accepts both IPv4 and IPv6.
    /// Uses `https://relay.test` as the URL — callers must set up lab-wide DNS
    /// entries for `relay.test` pointing to the relay's v4 and v6 addresses.
    pub async fn run_relay_server() -> Result<(RelayMap, Server), SpawnError> {
        let bind_ip: IpAddr = Ipv6Addr::UNSPECIFIED.into();

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

        let url: RelayUrl = "https://relay.test".parse().expect("valid relay url");
        let quic = server
            .quic_addr()
            .map(|addr| RelayQuicConfig { port: addr.port() });
        let relay_map: RelayMap = RelayConfig { url, quic }.into();

        Ok((relay_map, server))
    }
}

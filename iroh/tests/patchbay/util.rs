use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};

use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayMode, Watcher,
    endpoint::{Connection, PathInfo, PathWatcher, presets},
    tls::CaRootsConfig,
};
use iroh_metrics::MetricsGroupSet;
use n0_error::{Result, StackResultExt, StdResultExt, anyerr, ensure_any};
use n0_future::{boxed::BoxFuture, task::AbortOnDropHandle};
use patchbay::{Device, IpSupport, Lab, LabOpts, OutDir, TestGuard};
use tokio::sync::{Barrier, oneshot};
use tracing::{Instrument, debug, error, error_span, event, info};

use self::relay::run_relay_server;

const TEST_ALPN: &[u8] = b"test";

/// Creates a lab with a relay server.
///
/// Returns the lab, relay map, a drop guard that keeps the relay alive,
/// and a [`TestGuard`] that records pass/fail.
///
/// The relay binds on `[::]` and is reachable via `https://relay.test`
/// (resolved through lab-wide DNS entries for both IPv4 and IPv6).
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

/// Creates a router `dc` and device `relay` and spawns a relay server on the device.
///
/// Also creates a lab-wide DNS entry `relay.test` that resolves to the relay server's
/// IPv4 and IPv6 addresses.
///
/// Returns a [`RelayMap`] with an entry for the relay, and a drop handle that will
/// stop the relay server once dropped.
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
    info!(%relay_v4, %relay_v6, "DNS entries for relay.test registered");

    let (relay_map_tx, relay_map_rx) = oneshot::channel();
    let task_relay = dev_relay.spawn(async move |_ctx| {
        let (relay_map, _server) = run_relay_server().await.unwrap();
        relay_map_tx.send(relay_map).unwrap();
        std::future::pending::<()>().await;
    })?;
    let relay_map = relay_map_rx.await.unwrap();
    Ok((relay_map, AbortOnDropHandle::new(task_relay)))
}

/// Type alias for boxed run functions used in [`Pair`].
type RunFn = Box<dyn 'static + Send + FnOnce(Device, Endpoint, Connection) -> BoxFuture<Result>>;

/// Builder for two connected endpoints in a lab.
///
/// Use this to quickly create two endpoints on two different devices and create a
/// connection between them that starts as relay-only.
pub struct Pair {
    relay_map: RelayMap,
    server: Option<(Device, RunFn)>,
    client: Option<(Device, RunFn)>,
}

impl Pair {
    /// Creates a new pair builder with a shared [`RelayMap`].
    pub fn new(relay_map: RelayMap) -> Self {
        Self {
            relay_map,
            server: None,
            client: None,
        }
    }

    /// Sets the server device and run function.
    pub fn server<F, Fut>(mut self, device: Device, run_fn: F) -> Self
    where
        F: FnOnce(Device, Endpoint, Connection) -> Fut + Send + 'static,
        Fut: Future<Output = Result> + Send + 'static,
    {
        let run_fn: RunFn =
            Box::new(move |device, endpoint, conn| Box::pin(run_fn(device, endpoint, conn)));
        self.server = Some((device, run_fn));
        self
    }

    /// Sets the client device and run function.
    pub fn client<F, Fut>(mut self, device: Device, run_fn: F) -> Self
    where
        F: FnOnce(Device, Endpoint, Connection) -> Fut + Send + 'static,
        Fut: Future<Output = Result> + Send + 'static,
    {
        let run_fn: RunFn =
            Box::new(move |device, endpoint, conn| Box::pin(run_fn(device, endpoint, conn)));
        self.client = Some((device, run_fn));
        self
    }

    /// Runs the pair to completion.
    ///
    /// This will bind an endpoint on each device, wait for the server endpoint to be online,
    /// then send a relay-only [`EndpointAddr`] to the client task.
    /// The client task will connect to the server, and the server will accept a connection.
    /// Once a connection is established on either side, its run function is invoked.
    /// Once both run functions completed, the endpoints are dropped without awaiting
    /// [`Endpoint::close`], so the corresponding ERROR logs are expected.
    ///
    /// After completion, this will:
    /// - log the result of the run functions
    /// - record the endpoint metrics as a `patchbay::_metrics` tracing event
    /// - emit a `test::_events::pass` or `test::_events::fail` event for each device
    ///
    /// Returns an error if any step or run function failed.
    pub async fn run(mut self) -> Result {
        let (server_device, server_run) = self
            .server
            .take()
            .context("Missing server initialization")?;
        let (client_device, client_run) = self
            .client
            .take()
            .context("Missing client initialization")?;

        let (addr_tx, addr_rx) = oneshot::channel();
        let relay_map2 = self.relay_map.clone();

        // Create an in-memory synchronization barrier to wait for both run functions to complete
        // before dropping endpoints. We use this to guarantee completion without awaiting
        // `Endpoint::close` on both sides. `Endpoint::close` often takes several seconds,
        // which increases test runtime for all tests significantly, and closing behavior
        // should be tested for separately from the tests that use `Pair`.
        let barrier_server = Arc::new(Barrier::new(2));
        let barrier_client = barrier_server.clone();

        let server_task = server_device.spawn(|dev| {
            async move {
                let endpoint = endpoint_builder(&dev, relay_map2)
                    .bind()
                    .await
                    .context("server endpoint bind")?;
                info!(
                    id=%endpoint.id().fmt_short(),
                    bound_sockets=?endpoint.bound_sockets(),
                    "server endpoint bound",
                );
                endpoint.online().await;
                info!("endpoint online");

                // Send address to client task. Make it a relay-only address,
                // like in the default address lookup services.
                addr_tx.send(addr_relay_only(endpoint.addr())).unwrap();
                let incoming = endpoint.accept().await.context("server accept incoming")?;
                let conn = incoming
                    .accept()
                    .anyerr()?
                    .await
                    .context("server accept handshake")?;

                info!(remote=%conn.remote_id().fmt_short(), "accepted, executing run function");
                watch_selected_path(&conn);
                let res = server_run(dev.clone(), endpoint.clone(), conn).await;
                match &res {
                    Ok(()) => info!("run function completed successfully"),
                    Err(err) => error!("run function failed: {err:#}"),
                }

                // Wait until the client run function completed before dropping the endpoint.
                barrier_server.wait().await;
                for group in endpoint.metrics().groups() {
                    dev.record_iroh_metrics(group);
                }
                res
            }
            .instrument(error_span!("ep-server"))
        })?;
        let client_task = client_device.spawn(move |dev| {
            async move {
                let endpoint = endpoint_builder(&dev, self.relay_map)
                    .bind()
                    .await
                    .context("client endpoint bind")?;
                info!(
                    id=%endpoint.id().fmt_short(),
                    bound_sockets=?endpoint.bound_sockets(),
                    "client endpoint bound",
                );

                let addr = addr_rx
                    .await
                    .std_context("server did not send its address")?;
                info!(?addr, "connecting to server");
                let conn = endpoint
                    .connect(addr, TEST_ALPN)
                    .await
                    .context("client connect")?;
                watch_selected_path(&conn);
                info!(
                    remote=%conn.remote_id().fmt_short(),
                    "connected, executing run function",
                );

                let res = client_run(dev.clone(), endpoint.clone(), conn).await;
                match &res {
                    Ok(()) => info!("run function completed successfully"),
                    Err(err) => error!("run function failed: {err:#}"),
                }

                // Wait until the server run function completed before dropping the endpoint.
                barrier_client.wait().await;
                for group in endpoint.metrics().groups() {
                    dev.record_iroh_metrics(group);
                }
                res
            }
            .instrument(error_span!("ep-client"))
        })?;

        let (server_res, client_res) = tokio::join!(server_task, client_task);

        // Map the results to include the device name, and emit a tracing event within the device context.
        let [server_res, client_res] = [(&server_device, server_res), (&client_device, client_res)]
            .map(|(dev, res)| {
                let res = match res {
                    Err(err) => Err(anyerr!(err, "device {} panicked", dev.name())),
                    Ok(Err(err)) => Err(anyerr!(err, "device {} failed", dev.name())),
                    Ok(Ok(())) => Ok(()),
                };
                let res_str = res.as_ref().map_err(|err| format!("{err:#}")).cloned();
                log_result_on_device(dev, res_str);
                res
            });
        server_res?;
        client_res?;
        Ok(())
    }
}

fn log_result_on_device<E: std::fmt::Display + Send + 'static>(dev: &Device, res: Result<(), E>) {
    let _ = dev.run_sync(move || {
        match res {
            Ok(_) => event!(
                target: "test::_events::pass",
                tracing::Level::INFO,
                msg = %"device passed"
            ),
            Err(error) => event!(
                target: "test::_events::fail",
                tracing::Level::ERROR,
                %error,
                msg = %"device failed"
            ),
        }
        Ok(())
    });
}

/// Extension methods on [`PathWatcher`] for common waiting patterns in tests.
#[allow(unused)]
pub trait PathWatcherExt {
    /// Waits until the selected path fulfills a condition.
    ///
    /// Calls `f` with the currently-selected path, and again after each path update,
    /// until `f` returns true or `timeout` elapses.
    ///
    /// Returns an error if the timeout elapses before `f` returned true.
    async fn wait_selected(
        &mut self,
        timeout: Duration,
        f: impl Fn(&PathInfo) -> bool,
    ) -> Result<PathInfo>;

    /// Returns the currently selected path.
    ///
    /// Panics if no path is marked as selected.
    fn selected(&mut self) -> PathInfo;

    /// Wait until the selected path is a direct (IP) path.
    async fn wait_ip(&mut self, timeout: Duration) -> Result<PathInfo> {
        self.wait_selected(timeout, PathInfo::is_ip)
            .await
            .context("wait_ip")
    }

    /// Wait until the selected path is a relay path.
    async fn wait_relay(&mut self, timeout: Duration) -> Result<PathInfo> {
        self.wait_selected(timeout, PathInfo::is_relay)
            .await
            .context("wait_relay")
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
        .with_std_context(|_| "wait_selected timed out after {timeout:?}")?
    }
}

/// Opens a bidi stream, sends 8 bytes of data, and waits to receive the same data back.
pub async fn ping_open(conn: &Connection, timeout: Duration) -> Result {
    tokio::time::timeout(timeout, async {
        let data: [u8; 8] = rand::random();
        debug!("open_bi");
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        debug!("write_all");
        send.write_all(&data).await.anyerr()?;
        send.finish().anyerr()?;
        debug!("read_to_end");
        let r = recv.read_to_end(8).await.anyerr()?;
        ensure_any!(r == data, "reply matches");
        debug!("done");
        Ok(())
    })
    .instrument(error_span!("ping_open"))
    .await
    .with_std_context(|_| "ping_open timed out after {timeout:?}")?
}

/// Accepts a bidi stream, reads 8 bytes of data, and sends the same data back.
pub async fn ping_accept(conn: &Connection, timeout: Duration) -> Result {
    tokio::time::timeout(timeout, async {
        debug!("accept_bi");
        let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
        debug!("read_to_end");
        let data = recv.read_to_end(8).await.anyerr()?;
        debug!("write_all");
        send.write_all(&data).await.anyerr()?;
        send.finish().anyerr()?;
        debug!("done");
        Ok(())
    })
    .instrument(error_span!("ping_accept"))
    .await
    .with_std_context(|_| "ping_accept timed out after {timeout:?}")?
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
    let mut builder = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map))
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
    ///
    /// The returned [`RelayMap`] uses `https://relay.test` as the relay URL.
    /// Callers are responsible for ensuring that a DNS entry for `relay.test`
    /// exists and points to the relay's IP addresses.
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

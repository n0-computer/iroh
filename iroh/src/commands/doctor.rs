//! Tool to get information about the current network environment of a node,
//! and to test connectivity to specific other nodes.
use std::{
    collections::HashMap,
    net::SocketAddr,
    num::NonZeroU16,
    time::{Duration, Instant},
};

use crate::config::{path_with_env, NodeConfig};

use anyhow::Context;
use clap::Subcommand;
use indicatif::{HumanBytes, MultiProgress, ProgressBar};
use iroh::util::{path::IrohPaths, progress::ProgressWriter};
use iroh_net::{
    config,
    defaults::{DEFAULT_DERP_STUN_PORT, TEST_REGION_ID},
    derp::{DerpMap, DerpMode, UseIpv4, UseIpv6},
    key::{PublicKey, SecretKey},
    netcheck, portmapper, MagicEndpoint, PeerAddr,
};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync};

use iroh_metrics::core::Core;
use iroh_net::metrics::MagicsockMetrics;

#[derive(Debug, Clone, derive_more::Display)]
pub enum SecretKeyOption {
    /// Generate random secret key
    Random,
    /// Use local secret key
    Local,
    /// Explicitly specify a secret key
    Hex(String),
}

impl std::str::FromStr for SecretKeyOption {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_lower = s.to_ascii_lowercase();
        Ok(if s_lower == "random" {
            SecretKeyOption::Random
        } else if s_lower == "local" {
            SecretKeyOption::Local
        } else {
            SecretKeyOption::Hex(s.to_string())
        })
    }
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Report on the current network environment, using either an explicitly provided stun host
    /// or the settings from the config file.
    Report {
        /// Explicitly provided stun host. If provided, this will disable derp and just do stun.
        #[clap(long)]
        stun_host: Option<String>,
        /// The port of the STUN server.
        #[clap(long, default_value_t = DEFAULT_DERP_STUN_PORT)]
        stun_port: u16,
    },
    /// Wait for incoming requests from iroh doctor connect
    Accept {
        /// Our own secret key, in hex. If not specified, the locally configured key will be used.
        #[clap(long, default_value_t = SecretKeyOption::Local)]
        secret_key: SecretKeyOption,

        /// Number of bytes to send to the remote for each test
        #[clap(long, default_value_t = 1024 * 1024 * 16)]
        size: u64,

        /// Number of iterations to run the test for. If not specified, the test will run forever.
        #[clap(long)]
        iterations: Option<u64>,

        /// Use a local derp relay
        #[clap(long)]
        local_derper: bool,
    },
    /// Connect to an iroh doctor accept node.
    Connect {
        /// hex peer id of the node to connect to
        dial: String,

        /// One or more remote endpoints to use when dialing
        #[clap(long)]
        remote_endpoint: Vec<SocketAddr>,

        /// Our own secret key, in hex. If not specified, a random key will be generated.
        #[clap(long, default_value_t = SecretKeyOption::Random)]
        secret_key: SecretKeyOption,

        /// Use a local derp relay
        ///
        /// Overrides the `derp_region` field.
        #[clap(long)]
        local_derper: bool,

        /// The DERP region the peer you are dialing can be found on.
        ///
        /// If `local_derper` is true, this field is ignored.
        ///
        /// When `None`, or if attempting to dial an unknown region, no hole punching can occur.
        ///
        /// Default is `None`.
        #[clap(long)]
        derp_region: Option<u16>,
    },
    /// Probe the port mapping protocols.
    PortMapProbe {
        /// Whether to enable UPnP.
        #[clap(long)]
        enable_upnp: bool,
        /// Whether to enable PCP.
        #[clap(long)]
        enable_pcp: bool,
        /// Whether to enable NAT-PMP.
        #[clap(long)]
        enable_nat_pmp: bool,
    },
    /// Attempt to get a port mapping to the given local port.
    PortMap {
        /// Protocol to use for port mapping. One of ["upnp", "nat_pmp", "pcp"].
        protocol: String,
        /// Local port to get a mapping.
        local_port: NonZeroU16,
        /// How long to wait for an external port to be ready in seconds.
        #[clap(long, default_value_t = 10)]
        timeout_secs: u64,
    },
    /// Get the latencies of the different DERP regions
    ///
    /// Tests the latencies of the default DERP regions and nodes. To test custom regions or nodes,
    /// adjust the [`Config`].
    DerpRegions,
}

#[derive(Debug, Serialize, Deserialize, MaxSize)]
enum TestStreamRequest {
    Echo { bytes: u64 },
    Drain { bytes: u64 },
    Send { bytes: u64, block_size: u32 },
}

struct TestConfig {
    size: u64,
    iterations: Option<u64>,
}

fn update_pb(
    task: &'static str,
    pb: ProgressBar,
    total_bytes: u64,
    mut updates: sync::mpsc::Receiver<u64>,
) -> tokio::task::JoinHandle<()> {
    pb.set_message(task);
    pb.set_position(0);
    pb.set_length(total_bytes);
    tokio::spawn(async move {
        while let Some(position) = updates.recv().await {
            pb.set_position(position);
        }
    })
}

/// handle a test stream request
async fn handle_test_request(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    gui: &Gui,
) -> anyhow::Result<()> {
    let mut buf = [0u8; TestStreamRequest::POSTCARD_MAX_SIZE];
    recv.read_exact(&mut buf).await?;
    let request: TestStreamRequest = postcard::from_bytes(&buf)?;
    match request {
        TestStreamRequest::Echo { bytes } => {
            // copy the stream back
            let (mut send, updates) = ProgressWriter::new(&mut send);
            let t0 = Instant::now();
            let progress = update_pb("echo", gui.pb.clone(), bytes, updates);
            tokio::io::copy(&mut recv, &mut send).await?;
            let elapsed = t0.elapsed();
            drop(send);
            progress.await?;
            gui.set_echo(bytes, elapsed);
        }
        TestStreamRequest::Drain { bytes } => {
            // drain the stream
            let (mut send, updates) = ProgressWriter::new(tokio::io::sink());
            let progress = update_pb("recv", gui.pb.clone(), bytes, updates);
            let t0 = Instant::now();
            tokio::io::copy(&mut recv, &mut send).await?;
            let elapsed = t0.elapsed();
            drop(send);
            progress.await?;
            gui.set_recv(bytes, elapsed);
        }
        TestStreamRequest::Send { bytes, block_size } => {
            // send the requested number of bytes, in blocks of the requested size
            let (mut send, updates) = ProgressWriter::new(&mut send);
            let progress = update_pb("send", gui.pb.clone(), bytes, updates);
            let t0 = Instant::now();
            send_blocks(&mut send, bytes, block_size).await?;
            drop(send);
            let elapsed = t0.elapsed();
            progress.await?;
            gui.set_send(bytes, elapsed);
        }
    }
    send.finish().await?;
    Ok(())
}

async fn send_blocks(
    mut send: impl tokio::io::AsyncWrite + Unpin,
    total_bytes: u64,
    block_size: u32,
) -> anyhow::Result<()> {
    // send the requested number of bytes, in blocks of the requested size
    let buf = vec![0u8; block_size as usize];
    let mut remaining = total_bytes;
    while remaining > 0 {
        let n = remaining.min(block_size as u64);
        send.write_all(&buf[..n as usize]).await?;
        remaining -= n;
    }
    Ok(())
}

async fn report(
    stun_host: Option<String>,
    stun_port: u16,
    config: &NodeConfig,
) -> anyhow::Result<()> {
    let port_mapper = portmapper::Client::default().await;
    let mut client = netcheck::Client::new(Some(port_mapper)).await?;

    let dm = match stun_host {
        Some(host_name) => {
            let url = host_name.parse()?;
            // creating a derp map from host name and stun port
            DerpMap::default_from_node(url, stun_port, UseIpv4::TryDns, UseIpv6::TryDns, 0)
        }
        None => config.derp_map()?.unwrap_or_else(DerpMap::empty),
    };
    println!("getting report using derp map {dm:#?}");

    let r = client.get_report(dm, None, None).await?;
    println!("{r:#?}");
    Ok(())
}

/// Contain all the gui state
struct Gui {
    #[allow(dead_code)]
    mp: MultiProgress,
    pb: ProgressBar,
    #[allow(dead_code)]
    counters: ProgressBar,
    send_pb: ProgressBar,
    recv_pb: ProgressBar,
    echo_pb: ProgressBar,
    counter_task: Option<tokio::task::JoinHandle<()>>,
}

impl Gui {
    fn new() -> Self {
        let mp = MultiProgress::new();
        mp.set_draw_target(indicatif::ProgressDrawTarget::stderr());
        let pb = indicatif::ProgressBar::hidden();
        let counters = mp.add(ProgressBar::hidden());
        let send_pb = mp.add(ProgressBar::hidden());
        let recv_pb = mp.add(ProgressBar::hidden());
        let echo_pb = mp.add(ProgressBar::hidden());
        let style = indicatif::ProgressStyle::default_bar()
            .template("{msg}")
            .unwrap();
        send_pb.set_style(style.clone());
        recv_pb.set_style(style.clone());
        echo_pb.set_style(style.clone());
        counters.set_style(style);
        let pb = mp.add(pb);
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_style(indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:80.cyan/blue}] {msg} {bytes}/{total_bytes} ({bytes_per_sec})").unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ "));
        let counters2 = counters.clone();
        let counter_task = tokio::spawn(async move {
            loop {
                Self::update_counters(&counters2);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        Self {
            mp,
            pb,
            counters,
            send_pb,
            recv_pb,
            echo_pb,
            counter_task: Some(counter_task),
        }
    }

    fn update_counters(target: &ProgressBar) {
        if let Some(core) = Core::get() {
            let metrics = core.get_collector::<MagicsockMetrics>().unwrap();
            tracing::error!("metrics enabled");
            let send_ipv4 = HumanBytes(metrics.send_ipv4.get());
            let send_ipv6 = HumanBytes(metrics.send_ipv6.get());
            let send_derp = HumanBytes(metrics.send_derp.get());
            let recv_data_derp = HumanBytes(metrics.recv_data_derp.get());
            let recv_data_ipv4 = HumanBytes(metrics.recv_data_ipv4.get());
            let recv_data_ipv6 = HumanBytes(metrics.recv_data_ipv6.get());
            let text = format!(
                r#"Counters

Derp:
  send: {send_derp}
  recv: {recv_data_derp}
Ipv4:
  send: {send_ipv4}
  recv: {recv_data_ipv4}
Ipv6:
  send: {send_ipv6}
  recv: {recv_data_ipv6}
"#,
            );
            target.set_message(text);
        }
    }

    fn set_send(&self, b: u64, d: Duration) {
        Self::set_bench_speed(&self.send_pb, "send", b, d);
    }

    fn set_recv(&self, b: u64, d: Duration) {
        Self::set_bench_speed(&self.recv_pb, "recv", b, d);
    }

    fn set_echo(&self, b: u64, d: Duration) {
        Self::set_bench_speed(&self.echo_pb, "echo", b, d);
    }

    fn set_bench_speed(pb: &ProgressBar, text: &str, b: u64, d: Duration) {
        pb.set_message(format!(
            "{}: {}/s",
            text,
            HumanBytes((b as f64 / d.as_secs_f64()) as u64)
        ));
    }
}

impl Drop for Gui {
    fn drop(&mut self) {
        if let Some(task) = self.counter_task.take() {
            task.abort();
        }
    }
}

async fn active_side(connection: quinn::Connection, config: &TestConfig) -> anyhow::Result<()> {
    let n = config.iterations.unwrap_or(u64::MAX);
    let gui = Gui::new();
    let Gui { pb, .. } = &gui;
    for _ in 0..n {
        let d = send_test(&connection, config, pb).await?;
        gui.set_send(config.size, d);
        let d = recv_test(&connection, config, pb).await?;
        gui.set_recv(config.size, d);
        let d = echo_test(&connection, config, pb).await?;
        gui.set_echo(config.size, d);
    }
    Ok(())
}

async fn send_test_request(
    send: &mut quinn::SendStream,
    request: &TestStreamRequest,
) -> anyhow::Result<()> {
    let mut buf = [0u8; TestStreamRequest::POSTCARD_MAX_SIZE];
    postcard::to_slice(&request, &mut buf)?;
    send.write_all(&buf).await?;
    Ok(())
}

async fn echo_test(
    connection: &quinn::Connection,
    config: &TestConfig,
    pb: &indicatif::ProgressBar,
) -> anyhow::Result<Duration> {
    let size = config.size;
    let (mut send, mut recv) = connection.open_bi().await?;
    send_test_request(&mut send, &TestStreamRequest::Echo { bytes: size }).await?;
    let (mut sink, updates) = ProgressWriter::new(tokio::io::sink());
    let copying = tokio::spawn(async move { tokio::io::copy(&mut recv, &mut sink).await });
    let progress = update_pb("echo", pb.clone(), size, updates);
    let t0 = Instant::now();
    send_blocks(&mut send, size, 1024 * 1024).await?;
    send.finish().await?;
    let received = copying.await??;
    anyhow::ensure!(received == size);
    let duration = t0.elapsed();
    progress.await?;
    Ok(duration)
}

async fn send_test(
    connection: &quinn::Connection,
    config: &TestConfig,
    pb: &indicatif::ProgressBar,
) -> anyhow::Result<Duration> {
    let size = config.size;
    let (mut send, mut recv) = connection.open_bi().await?;
    send_test_request(&mut send, &TestStreamRequest::Drain { bytes: size }).await?;
    let (mut send_with_progress, updates) = ProgressWriter::new(&mut send);
    let copying =
        tokio::spawn(async move { tokio::io::copy(&mut recv, &mut tokio::io::sink()).await });
    let progress = update_pb("send", pb.clone(), size, updates);
    let t0 = Instant::now();
    send_blocks(&mut send_with_progress, size, 1024 * 1024).await?;
    drop(send_with_progress);
    send.finish().await?;
    drop(send);
    let received = copying.await??;
    anyhow::ensure!(received == 0);
    let duration = t0.elapsed();
    progress.await?;
    Ok(duration)
}

async fn recv_test(
    connection: &quinn::Connection,
    config: &TestConfig,
    pb: &indicatif::ProgressBar,
) -> anyhow::Result<Duration> {
    let size = config.size;
    let (mut send, mut recv) = connection.open_bi().await?;
    let t0 = Instant::now();
    let (mut sink, updates) = ProgressWriter::new(tokio::io::sink());
    send_test_request(
        &mut send,
        &TestStreamRequest::Send {
            bytes: size,
            block_size: 1024 * 1024,
        },
    )
    .await?;
    let copying = tokio::spawn(async move { tokio::io::copy(&mut recv, &mut sink).await });
    let progress = update_pb("recv", pb.clone(), size, updates);
    send.finish().await?;
    let received = copying.await??;
    anyhow::ensure!(received == size);
    let duration = t0.elapsed();
    progress.await?;
    Ok(duration)
}

/// Passive side that just accepts connections and answers requests (echo, drain or send)
async fn passive_side(connection: quinn::Connection) -> anyhow::Result<()> {
    let gui = Gui::new();
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                if let Err(cause) = handle_test_request(send, recv, &gui).await {
                    eprintln!("Error handling test request {cause}");
                }
            }
            Err(cause) => {
                eprintln!("error accepting bidi stream {cause}");
                break Err(cause.into());
            }
        };
    }
}

fn configure_local_derp_map() -> DerpMap {
    let stun_port = DEFAULT_DERP_STUN_PORT;
    let url = "http://derp.invalid:3340".parse().unwrap();
    let derp_ipv4 = UseIpv4::Some("127.0.0.1".parse().unwrap());
    let derp_ipv6 = UseIpv6::TryDns;
    DerpMap::default_from_node(url, stun_port, derp_ipv4, derp_ipv6, TEST_REGION_ID)
}

const DR_DERP_ALPN: [u8; 11] = *b"n0/drderp/1";

async fn make_endpoint(
    secret_key: SecretKey,
    derp_map: Option<DerpMap>,
) -> anyhow::Result<MagicEndpoint> {
    tracing::info!(
        "public key: {}",
        hex::encode(secret_key.public().as_bytes())
    );
    tracing::info!("derp map {:#?}", derp_map);

    let (on_derp_s, mut on_derp_r) = sync::mpsc::channel(8);
    let on_net_info = |ni: config::NetInfo| {
        tracing::info!("got net info {:#?}", ni);
    };

    let on_endpoints = move |ep: &[config::Endpoint]| {
        tracing::info!("got endpoint {:#?}", ep);
    };

    let on_derp_active = move || {
        tracing::info!("got derp active");
        on_derp_s.try_send(()).ok();
    };

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

    let endpoint = MagicEndpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![DR_DERP_ALPN.to_vec()])
        .transport_config(transport_config)
        .on_net_info(Box::new(on_net_info))
        .on_endpoints(Box::new(on_endpoints))
        .on_derp_active(Box::new(on_derp_active));
    let endpoint = match derp_map {
        Some(derp_map) => endpoint.derp_mode(DerpMode::Custom(derp_map)),
        None => endpoint,
    };
    let endpoint = endpoint.bind(0).await?;

    tokio::time::timeout(Duration::from_secs(10), on_derp_r.recv())
        .await
        .context("wait for derp connection")?;

    Ok(endpoint)
}

async fn connect(
    dial: String,
    secret_key: SecretKey,
    direct_addresses: Vec<SocketAddr>,
    derp_region: Option<u16>,
    derp_map: Option<DerpMap>,
) -> anyhow::Result<()> {
    let endpoint = make_endpoint(secret_key, derp_map).await?;

    let bytes = hex::decode(dial)?;
    let peer_id = PublicKey::try_from(&bytes[..]).context("failed to parse PublicKey")?;

    tracing::info!("dialing {:?}", peer_id);
    let peer_addr = PeerAddr::from_parts(peer_id, derp_region, direct_addresses);
    let conn = endpoint.connect(peer_addr, &DR_DERP_ALPN).await;
    match conn {
        Ok(connection) => {
            if let Err(cause) = passive_side(connection).await {
                eprintln!("error handling connection: {cause}");
            }
        }
        Err(cause) => {
            eprintln!("unable to connect to {peer_id}: {cause}");
        }
    }

    Ok(())
}

/// format a socket addr so that it does not have to be escaped on the console
fn format_addr(addr: SocketAddr) -> String {
    if addr.is_ipv6() {
        format!("'{addr}'")
    } else {
        format!("{addr}")
    }
}

async fn accept(
    secret_key: SecretKey,
    config: TestConfig,
    derp_map: Option<DerpMap>,
) -> anyhow::Result<()> {
    let endpoint = make_endpoint(secret_key.clone(), derp_map).await?;

    let endpoints = endpoint.local_endpoints().await?;
    let remote_addrs = endpoints
        .iter()
        .map(|endpoint| format!("--remote-endpoint {}", format_addr(endpoint.addr)))
        .collect::<Vec<_>>()
        .join(" ");
    println!(
            "Run\n\niroh doctor connect {} {}\n\nin another terminal or on another machine to connect by key and addr.",
            hex::encode(secret_key.public().as_bytes()),
            remote_addrs,
        );
    println!("Omit the --remote-endpoint args to connect just by key.");
    while let Some(connecting) = endpoint.accept().await {
        match connecting.await {
            Ok(connection) => {
                println!("\nAccepted connection. Performing test.\n");
                let t0 = Instant::now();
                if let Err(cause) = active_side(connection, &config).await {
                    println!("error after {}: {cause}", t0.elapsed().as_secs_f64());
                }
            }
            Err(cause) => {
                eprintln!("error accepting connection {cause}");
            }
        }
    }

    Ok(())
}

async fn port_map(protocol: &str, local_port: NonZeroU16, timeout: Duration) -> anyhow::Result<()> {
    // create the config that enables exlusively the required protocol
    let mut enable_upnp = false;
    let mut enable_pcp = false;
    let mut enable_nat_pmp = false;
    match protocol.to_ascii_lowercase().as_ref() {
        "upnp" => enable_upnp = true,
        "nat_pmp" => enable_nat_pmp = true,
        "pcp" => enable_pcp = true,
        other => anyhow::bail!("Unknown port mapping protocol {other}"),
    }
    let config = portmapper::Config {
        enable_upnp,
        enable_pcp,
        enable_nat_pmp,
    };
    let port_mapper = portmapper::Client::new(config).await;
    let mut watcher = port_mapper.watch_external_address();
    port_mapper.update_local_port(local_port);

    // wait for the mapping to be ready, or timeout waiting for a change.
    match tokio::time::timeout(timeout, watcher.changed()).await {
        Ok(Ok(_)) => match *watcher.borrow() {
            Some(address) => {
                println!("Port mapping ready: {address}");
                // Ensure the port mapper remains alive until the end.
                drop(port_mapper);
                Ok(())
            }
            None => anyhow::bail!("No port mapping found"),
        },
        Ok(Err(_recv_err)) => anyhow::bail!("Service dropped. This is a bug"),
        Err(_) => anyhow::bail!("Timed out waiting for a port mapping"),
    }
}

async fn port_map_probe(config: portmapper::Config) -> anyhow::Result<()> {
    println!("probing port mapping protocols with {config:?}");
    let port_mapper = portmapper::Client::new(config).await;
    let probe_rx = port_mapper.probe();
    let probe = probe_rx.await?.map_err(|e| anyhow::anyhow!(e))?;
    println!("{probe}");
    Ok(())
}

async fn derp_regions(config: NodeConfig) -> anyhow::Result<()> {
    let key = SecretKey::generate();
    if config.derp_regions.is_empty() {
        println!("No DERP Regions specified in the config file.");
    }

    let mut clients = HashMap::new();
    for region in &config.derp_regions {
        let secret_key = key.clone();
        let reg = region.clone();
        let client = iroh_net::derp::http::ClientBuilder::new()
            .get_region(move || {
                let region = reg.clone();
                Box::pin(async move { Some(region) })
            })
            .build(secret_key)?;

        clients.insert(region.region_id, client);
    }

    let mut success = Vec::new();
    let mut fail = Vec::new();

    for i in 0..5 {
        println!("-- round {i}");
        let derp_regions = config.derp_regions.clone();
        for region in derp_regions.into_iter() {
            let mut region_details = RegionDetails {
                connect: None,
                latency: None,
                error: None,
                region_id: region.region_id,
                hosts: region.nodes.iter().map(|n| n.url.clone()).collect(),
            };

            let client = clients.get(&region.region_id).cloned().unwrap();

            let start = std::time::Instant::now();
            assert!(!client.is_connected().await);
            match tokio::time::timeout(Duration::from_secs(2), client.connect()).await {
                Err(e) => {
                    tracing::warn!("connect timeout");
                    region_details.error = Some(e.to_string());
                }
                Ok(Err(e)) => {
                    tracing::warn!("connect error");
                    region_details.error = Some(e.to_string());
                }
                Ok(_) => {
                    assert!(client.is_connected().await);
                    region_details.connect = Some(start.elapsed());

                    let c = client.clone();
                    let t = tokio::task::spawn(async move {
                        loop {
                            match c.recv_detail().await {
                                Ok(msg) => {
                                    tracing::debug!("derp: {:?}", msg);
                                }
                                Err(err) => {
                                    tracing::warn!("derp: {:?}", err);
                                }
                            }
                        }
                    });

                    match client.ping().await {
                        Ok(latency) => {
                            region_details.latency = Some(latency);
                        }
                        Err(e) => {
                            tracing::warn!("ping error: {:?}", e);
                            region_details.error = Some(e.to_string());
                        }
                    }
                    t.abort();
                }
            }
            // disconnect, to be able to measure reconnects
            client.close_for_reconnect().await;
            assert!(!client.is_connected().await);
            if region_details.error.is_none() {
                success.push(region_details);
            } else {
                fail.push(region_details);
            }
        }
    }

    // success.sort_by_key(|d| d.latency);
    if !success.is_empty() {
        println!("DERP Region Latencies:");
        println!();
    }
    for region in success {
        println!("{region}");
        println!();
    }
    if !fail.is_empty() {
        println!("Connection Failures:");
        println!();
    }
    for region in fail {
        println!("{region}");
        println!();
    }

    Ok(())
}

struct RegionDetails {
    connect: Option<Duration>,
    latency: Option<Duration>,
    region_id: u16,
    hosts: Vec<url::Url>,
    error: Option<String>,
}

impl std::fmt::Display for RegionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.error {
            None => {
                write!(
                    f,
                    "Region {}\nConnect: {:?}\nLatency: {:?}\nHosts:\n\t{:?}",
                    self.region_id,
                    self.connect.unwrap_or_default(),
                    self.latency.unwrap_or_default(),
                    self.hosts
                        .iter()
                        .map(|u| u.to_string())
                        .collect::<Vec<String>>()
                )
            }
            Some(ref err) => {
                write!(
                    f,
                    "Region {}\nConnection Error: {:?}\nHosts:\n\t{:?}",
                    self.region_id,
                    err,
                    self.hosts
                        .iter()
                        .map(|u| u.to_string())
                        .collect::<Vec<String>>()
                )
            }
        }
    }
}

fn create_secret_key(secret_key: SecretKeyOption) -> anyhow::Result<SecretKey> {
    Ok(match secret_key {
        SecretKeyOption::Random => SecretKey::generate(),
        SecretKeyOption::Hex(hex) => {
            let bytes = hex::decode(hex)?;
            SecretKey::try_from(&bytes[..])?
        }
        SecretKeyOption::Local => {
            let path = path_with_env(IrohPaths::SecretKey)?;
            if path.exists() {
                let bytes = std::fs::read(&path)?;
                SecretKey::try_from_openssh(bytes)?
            } else {
                println!(
                    "Local key not found in {}. Using random key.",
                    path.display()
                );
                SecretKey::generate()
            }
        }
    })
}

pub async fn run(command: Commands, config: &NodeConfig) -> anyhow::Result<()> {
    match command {
        Commands::Report {
            stun_host,
            stun_port,
        } => report(stun_host, stun_port, config).await,
        Commands::Connect {
            dial,
            secret_key,
            local_derper,
            derp_region,
            remote_endpoint,
        } => {
            let (derp_map, derp_region) = if local_derper {
                (Some(configure_local_derp_map()), Some(TEST_REGION_ID))
            } else {
                (config.derp_map()?, derp_region)
            };
            let secret_key = create_secret_key(secret_key)?;
            connect(dial, secret_key, remote_endpoint, derp_region, derp_map).await
        }
        Commands::Accept {
            secret_key,
            local_derper,
            size,
            iterations,
        } => {
            let derp_map = if local_derper {
                Some(configure_local_derp_map())
            } else {
                config.derp_map()?
            };
            let secret_key = create_secret_key(secret_key)?;
            let config = TestConfig { size, iterations };
            accept(secret_key, config, derp_map).await
        }
        Commands::PortMap {
            protocol,
            local_port,
            timeout_secs,
        } => port_map(&protocol, local_port, Duration::from_secs(timeout_secs)).await,
        Commands::PortMapProbe {
            enable_upnp,
            enable_pcp,
            enable_nat_pmp,
        } => {
            let config = portmapper::Config {
                enable_upnp,
                enable_pcp,
                enable_nat_pmp,
            };

            port_map_probe(config).await
        }
        Commands::DerpRegions => {
            let config = NodeConfig::from_env(None)?;
            derp_regions(config).await
        }
    }
}

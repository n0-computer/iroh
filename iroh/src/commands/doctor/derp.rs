//! Tool to get information about the current network environment of a node,
//! and to test connectivity to specific other nodes.
use std::{
    collections::HashMap,
    net::SocketAddr,
    num::NonZeroU16,
    pin::Pin,
    task::Poll,
    time::{Duration, Instant},
};

use crate::config::{iroh_config_path, Config, IrohPaths, CONFIG_FILE_NAME, ENV_PREFIX};

use anyhow::Context;
use bytes::{Bytes, BytesMut};
use clap::Subcommand;
use futures::FutureExt;
use indicatif::{HumanBytes, MultiProgress, ProgressBar};
use iroh::util::progress::ProgressWriter;
use iroh_net::derp::{http::Client, ReceivedMessage};
use iroh_net::{
    config,
    defaults::{DEFAULT_DERP_STUN_PORT, TEST_REGION_ID},
    derp::{DerpMap, UseIpv4, UseIpv6},
    key::{PublicKey, SecretKey},
    netcheck, portmapper, MagicEndpoint,
};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, Sink},
    sync,
};

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
    /// Get the latencies of the different DERP regions
    ///
    /// Tests the latencies of the default DERP regions and nodes. To test custom regions or nodes,
    /// adjust the [`Config`].
    Regions,
    /// Wait for incoming requests from iroh doctor derp connect
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

        /// The DERP region the peer you are dialing can be found on.
        ///
        /// If `local_derper` is true, this field is ignored.
        ///
        /// When `None`, or if attempting to dial an unknown region, no relaying can occur.
        ///
        /// Default is `None`.
        #[clap(long)]
        derp_region: Option<u16>,
    },
    /// Connect to an iroh doctor derp accept node.
    Connect {
        /// hex peer id of the node to connect to
        dial: String,

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
        /// When `None`, or if attempting to dial an unknown region, no relaying can occur.
        ///
        /// Default is `None`.
        #[clap(long)]
        derp_region: Option<u16>,
    },
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
async fn handle_test_request(mut client: Client, gui: &Gui) -> anyhow::Result<()> {
    let (request, source): (TestStreamRequest, PublicKey) = {
        let (msg, _) = client.recv_detail().await?;
        match msg {
            ReceivedMessage::ReceivedPacket { data, source } => {
                (postcard::from_bytes(&data)?, source)
            }
            m => {
                anyhow::bail!("unexpected message {m:?} received");
            }
        }
    };
    match request {
        TestStreamRequest::Echo { bytes } => {
            let (sink, updates) = ProgressWriter::new(tokio::io::sink());
            let t0 = Instant::now();
            let progress = update_pb("echo", gui.pb.clone(), bytes, updates);
            // copy the msgs back
            derp_echo(client, source, sink).await?;
            let elapsed = t0.elapsed();
            progress.await?;
            gui.set_echo(bytes, elapsed);
        }
        TestStreamRequest::Drain { bytes } => {
            // drain the stream
            let (sink, updates) = ProgressWriter::new(tokio::io::sink());
            let progress = update_pb("recv", gui.pb.clone(), bytes, updates);
            let t0 = Instant::now();
            recv_sink(client, sink).await?;
            let elapsed = t0.elapsed();
            progress.await?;
            gui.set_recv(bytes, elapsed);
        }
        TestStreamRequest::Send { bytes, .. } => {
            // send the requested number of bytes, in blocks of the requested size
            let (sink, updates) = ProgressWriter::new(tokio::io::sink());
            let progress = update_pb("send", gui.pb.clone(), bytes, updates);
            let t0 = Instant::now();
            send_blocks(&mut client, source, bytes, Some(sink)).await?;
            let elapsed = t0.elapsed();
            progress.await?;
            gui.set_send(bytes, elapsed);
        }
    }
    Ok(())
}

async fn send_blocks(
    client: &Client,
    peer: PublicKey,
    total_bytes: u64,
    mut progress: Option<ProgressWriter<Sink>>,
) -> anyhow::Result<()> {
    let block_size = iroh_net::derp::MAX_PACKET_SIZE;
    // send the requested number of bytes, in blocks of the requested size
    let buf = vec![0u8; block_size as usize];
    let mut remaining = total_bytes;
    while remaining > 0 {
        let n = remaining.min(block_size as u64);
        if let Some(mut p) = progress.take() {
            p.write_all(&buf[..n as usize]).await?;
            progress = Some(p);
        }
        client
            .send(peer, Bytes::from(buf[..n as usize].to_vec()))
            .await?;
        remaining -= n;
    }
    Ok(())
}

async fn report(stun_host: Option<String>, stun_port: u16, config: &Config) -> anyhow::Result<()> {
    let port_mapper = portmapper::Client::default().await;
    let mut client = netcheck::Client::new(Some(port_mapper)).await?;

    let dm = match stun_host {
        Some(host_name) => {
            let url = host_name.parse()?;
            // creating a derp map from host name and stun port
            DerpMap::default_from_node(url, stun_port, UseIpv4::TryDns, UseIpv6::TryDns, 0)
        }
        None => config.derp_map().expect("derp map not configured"),
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

async fn active_side(client: Client, peer: PublicKey, config: &TestConfig) -> anyhow::Result<()> {
    let n = config.iterations.unwrap_or(u64::MAX);
    let gui = Gui::new();
    let Gui { pb, .. } = &gui;
    for _ in 0..n {
        let d = send_test(client.clone(), peer.clone(), config, pb).await?;
        gui.set_send(config.size, d);
        let d = recv_test(client.clone(), peer.clone(), config, pb).await?;
        gui.set_recv(config.size, d);
        let d = echo_test(client.clone(), peer.clone(), config, pb).await?;
        gui.set_echo(config.size, d);
    }
    Ok(())
}

async fn send_test_request(
    client: &mut Client,
    peer: PublicKey,
    request: &TestStreamRequest,
) -> anyhow::Result<()> {
    let mut buf = BytesMut::with_capacity(TestStreamRequest::POSTCARD_MAX_SIZE);
    postcard::to_slice(&request, &mut buf)?;
    client.send(peer, buf.freeze()).await?;
    Ok(())
}

// struct RecvDerp {
//     client: Client,
// }

// impl AsyncRead for RecvDerp {
//     fn poll_read(
//         self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//         buf: &mut tokio::io::ReadBuf<'_>,
//     ) -> tokio::io::Poll<Result<()>> {
//         while let Ok(msg) = self.client.recv_detail() {

//     }
// }

// TODO: either make a DerpClient struct that is AsyncRead/AsyncWrite, or remove
// the `ProgressWriter` code
async fn recv_sink(client: Client, mut sink: ProgressWriter<Sink>) -> anyhow::Result<u64> {
    let mut size = 0;
    while let Ok(msg) = client.recv_detail().await {
        match msg.0 {
            ReceivedMessage::ReceivedPacket { data, .. } => {
                let len = data.len() as u64;
                sink.write_all(&data).await?;
                size += len;
            }
            m => {
                anyhow::bail!("received unexpected message {m:?}");
            }
        }
    }
    Ok(size)
}

// TODO: either make a DerpClient struct that is AsyncRead/AsyncWrite, or remove
// the `ProgressWriter` code
async fn derp_echo(
    client: Client,
    peer: PublicKey,
    mut sink: ProgressWriter<Sink>,
) -> anyhow::Result<u64> {
    let mut size = 0;
    while let Ok(msg) = client.recv_detail().await {
        match msg.0 {
            ReceivedMessage::ReceivedPacket { data, .. } => {
                // ew
                let echo_data = data.clone();
                client.send(peer, echo_data).await?;
                let len = data.len() as u64;
                sink.write_all(&data).await?;
                size += len;
            }
            m => {
                anyhow::bail!("received unexpected message {m:?}");
            }
        }
    }
    Ok(size)
}

async fn echo_test(
    mut client: Client,
    peer: PublicKey,
    config: &TestConfig,
    pb: &indicatif::ProgressBar,
) -> anyhow::Result<Duration> {
    let size = config.size;
    send_test_request(
        &mut client,
        peer.clone(),
        &TestStreamRequest::Echo { bytes: size },
    )
    .await?;
    let (sink, updates) = ProgressWriter::new(tokio::io::sink());
    let recv_client = client.clone();
    let copying = tokio::spawn(async move { recv_sink(recv_client, sink).await });
    let progress = update_pb("echo", pb.clone(), size, updates);
    let t0 = Instant::now();
    send_blocks(&mut client, peer, size, None).await?;
    let received = copying.await??;
    anyhow::ensure!(received == size);
    let duration = t0.elapsed();
    progress.await?;
    Ok(duration)
}

async fn send_test(
    mut client: Client,
    peer: PublicKey,
    config: &TestConfig,
    pb: &indicatif::ProgressBar,
) -> anyhow::Result<Duration> {
    let size = config.size;
    send_test_request(
        &mut client,
        peer.clone(),
        &TestStreamRequest::Drain { bytes: size },
    )
    .await?;
    let (sink, updates) = ProgressWriter::new(tokio::io::sink());
    let progress = update_pb("send", pb.clone(), size, updates);
    let t0 = Instant::now();
    send_blocks(&mut client, peer, size, Some(sink)).await?;
    let duration = t0.elapsed();
    progress.await?;
    Ok(duration)
}

// struct DerpWriter {
//     client: Client,
//     peer: PublicKey,
//     fut: Option<(
//         Pin<Box<dyn std::future::Future<Output = Result<(), iroh_net::derp::http::ClientError>>>>,
//         usize,
//     )>,
// }

// impl tokio::io::AsyncWrite for DerpWriter {
//     fn poll_write(
//         self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//         buf: &[u8],
//     ) -> Poll<Result<usize, std::io::Error>> {
//         // if we are in the middle of sending, keep polling the send
//         if let Some((fut, size)) = self.fut {
//             let poll = fut.poll_unpin(cx);
//             match poll {
//                 Poll::Ready(res) => {

//                 }
//                 Poll::Pending => Poll::Pending,
//             }
//         }
//         // if buf.len() > iroh_net::derp::MAX_PACKET_SIZE {
//         //     self.client.send(
//         //         self.peer.clone(),
//         //         &buf[..iroh_net::derp::MAX_PACKET_SIZE].into(),
//         //     )
//         // }
//     }

//     fn poll_flush(
//         self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Result<(), std::io::Error>> {
//         std::task::Poll::Ready(Ok(()))
//     }
//     fn poll_shutdown(
//         self: std::pin::Pin<&mut Self>,
//         cx: &mut std::task::Context<'_>,
//     ) -> std::task::Poll<Result<(), std::io::Error>> {
//         std::task::Poll::Ready(Ok(()))
//     }
// }

async fn recv_test(
    mut client: Client,
    peer: PublicKey,
    config: &TestConfig,
    pb: &indicatif::ProgressBar,
) -> anyhow::Result<Duration> {
    let size = config.size;
    let t0 = Instant::now();
    let (sink, updates) = ProgressWriter::new(tokio::io::sink());
    send_test_request(
        &mut client,
        peer.clone(),
        &TestStreamRequest::Send {
            bytes: size,
            block_size: 1024 * 1024,
        },
    )
    .await?;
    let copying = tokio::spawn(async move { recv_sink(client, sink).await });
    let progress = update_pb("recv", pb.clone(), size, updates);
    let received = copying.await??;
    anyhow::ensure!(received == size);
    let duration = t0.elapsed();
    progress.await?;
    Ok(duration)
}

/// Passive side that just accepts connections and answers requests (echo, drain or send)
async fn passive_side(client: Client) -> anyhow::Result<()> {
    let gui = Gui::new();
    loop {
        let client = client.clone();
        if let Err(cause) = handle_test_request(client, &gui).await {
            eprintln!("Error handling test request {cause}");
        }
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

async fn make_derp_client(
    secret_key: SecretKey,
    derp_map: DerpMap,
) -> anyhow::Result<MagicEndpoint> {
    todo!();
}

async fn connect(
    dial: String,
    secret_key: SecretKey,
    derp_region: u16,
    derp_map: DerpMap,
) -> anyhow::Result<()> {
    todo!();
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
    derp_map: DerpMap,
    region: u16,
) -> anyhow::Result<()> {
    todo!();
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

async fn derp_regions(config: Config) -> anyhow::Result<()> {
    let key = SecretKey::generate();
    let mut set = tokio::task::JoinSet::new();
    if config.derp_regions.is_empty() {
        println!("No DERP Regions specified in the config file.");
    }
    for region in config.derp_regions.into_iter() {
        let secret_key = key.clone();
        set.spawn(async move {
            let mut region_details = RegionDetails {
                latency: None,
                error: None,
                region_id: region.region_id,
                hosts: region.nodes.iter().map(|n| n.url.clone()).collect(),
            };
            let client = match iroh_net::derp::http::ClientBuilder::new()
                .get_region(move || {
                    let region = region.clone();
                    Box::pin(async move { Some(region) })
                })
                .build(secret_key)
            {
                Ok(c) => c,
                Err(e) => {
                    region_details.error = Some(e.to_string());
                    return region_details;
                }
            };
            let start = std::time::Instant::now();
            match tokio::time::timeout(Duration::from_secs(2), client.connect()).await {
                Err(e) => {
                    region_details.error = Some(e.to_string());
                }
                Ok(Err(e)) => {
                    region_details.error = Some(e.to_string());
                }
                Ok(_) => {
                    region_details.latency = Some(start.elapsed());
                }
            }
            region_details
        });
    }
    let mut success = Vec::new();
    let mut fail = Vec::new();
    while let Some(region_details) = set.join_next().await {
        let region_details = region_details?;
        if region_details.latency.is_some() {
            success.push(region_details);
        } else {
            fail.push(region_details);
        }
    }
    success.sort_by_key(|d| d.latency);
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
    latency: Option<Duration>,
    region_id: u16,
    hosts: Vec<url::Url>,
    error: Option<String>,
}

impl std::fmt::Display for RegionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.latency {
            Some(duration) => {
                write!(
                    f,
                    "Region {}\nLatency {:?}\nHosts:\n\t{:?}",
                    self.region_id,
                    duration,
                    self.hosts
                        .iter()
                        .map(|u| u.to_string())
                        .collect::<Vec<String>>()
                )
            }
            None => {
                write!(
                    f,
                    "Region {}\nError connecting to region: {}\nHosts:\n\t{:?}",
                    self.region_id,
                    self.error
                        .as_ref()
                        .map_or("Unknown Error".to_string(), |e| e.clone()),
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
            let path = IrohPaths::SecretKey.with_env()?;
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

pub async fn run(command: Commands, config: &Config) -> anyhow::Result<()> {
    match command {
        Commands::Connect {
            dial,
            secret_key,
            local_derper,
            derp_region,
        } => {
            let (derp_map, derp_region) = if local_derper {
                (configure_local_derp_map(), TEST_REGION_ID)
            } else {
                match (config.derp_map(), derp_region) {
                    (Some(derp_map), Some(region_id)) => (derp_map, region_id),
                    _ => {
                        anyhow::bail!("must provide `derp_map` configuration in the config file and a `--region-id`");
                    }
                }
            };
            let secret_key = create_secret_key(secret_key)?;
            connect(dial, secret_key, derp_region, derp_map).await
        }
        Commands::Accept {
            secret_key,
            local_derper,
            size,
            iterations,
            derp_region,
        } => {
            let (derp_map, derp_region) = if local_derper {
                (configure_local_derp_map(), TEST_REGION_ID)
            } else {
                match (config.derp_map(), derp_region) {
                    (Some(derp_map), Some(region_id)) => (derp_map, region_id),
                    _ => {
                        anyhow::bail!("must provide `derp_map` configuration in the config file and a `--region-id`");
                    }
                }
            };
            let secret_key = create_secret_key(secret_key)?;
            let config = TestConfig { size, iterations };
            accept(secret_key, config, derp_map, derp_region).await
        }
        Commands::Regions => {
            let default_config_path =
                iroh_config_path(CONFIG_FILE_NAME).context("invalid config path")?;

            let sources = [Some(default_config_path.as_path())];
            let config = Config::load(
                // potential config files
                &sources,
                // env var prefix for this config
                ENV_PREFIX,
                // map of present command line arguments
                // args.make_overrides_map(),
                HashMap::<String, String>::new(),
            )?;
            derp_regions(config).await
        }
    }
}

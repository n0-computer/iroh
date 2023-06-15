//! Tool to get information about the current network environment of a node,
//! and to test connectivity to specific other nodes.
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    config::Config,
    hp::{
        self,
        derp::{DerpMap, UseIpv4, UseIpv6},
        key::node::SecretKey,
        magicsock,
    },
    main_util::iroh_data_root,
    tls,
    tokio_util::ProgressWriter,
    Keypair,
};
use anyhow::Context;
use clap::Subcommand;
use indicatif::{HumanBytes, MultiProgress, ProgressBar};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync};

#[derive(Debug, Clone, derive_more::Display)]
pub enum PrivateKey {
    /// Generate random private key
    Random,
    /// Use local private key
    Local,
    /// Explicitly specify a private key
    Hex(String),
}

impl std::str::FromStr for PrivateKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_lower = s.to_ascii_lowercase();
        Ok(if s_lower == "random" {
            PrivateKey::Random
        } else if s_lower == "local" {
            PrivateKey::Local
        } else {
            PrivateKey::Hex(s.to_string())
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
        #[clap(long, default_value_t = 3478)]
        stun_port: u16,
    },
    Accept {
        /// Our own private key, in hex. If not specified, the locally configured key will be used.
        #[clap(long, default_value_t = PrivateKey::Local)]
        private_key: PrivateKey,

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
    Connect {
        /// hex peer id of the node to connect to
        dial: String,

        /// One or more remote endpoints to use when dialing
        #[clap(long)]
        remote_endpoint: Vec<SocketAddr>,

        /// Our own private key, in hex. If not specified, a random key will be generated.
        #[clap(long, default_value_t = PrivateKey::Random)]
        private_key: PrivateKey,

        /// Use a local derp relay
        #[clap(long)]
        local_derper: bool,
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

async fn report(stun_host: Option<String>, stun_port: u16, config: &Config) -> anyhow::Result<()> {
    let mut client = hp::netcheck::Client::new(None).await?;

    let dm = stun_host
        .map(|host_name|
        // creating a derp map from host name and stun port
        DerpMap::default_from_node(host_name, stun_port, 0, UseIpv4::None, UseIpv6::None))
        .unwrap_or_else(|| config.derp_map().expect("derp map not configured"));
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
        let metrics = &crate::metrics::core::CORE;
        if metrics.is_enabled() {
            let mm = metrics.magicsock_metrics();
            let send_ipv4 = HumanBytes(mm.send_ipv4.get());
            let send_ipv6 = HumanBytes(mm.send_ipv6.get());
            let send_derp = HumanBytes(mm.send_derp.get());
            let recv_data_derp = HumanBytes(mm.recv_data_derp.get());
            let recv_data_ipv4 = HumanBytes(mm.recv_data_ipv4.get());
            let recv_data_ipv6 = HumanBytes(mm.recv_data_ipv6.get());
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
    let stun_port = 3478;
    let host_name = "derp.invalid".into();
    let derp_port = 3340;
    let derp_ipv4 = UseIpv4::Some("127.0.0.1".parse().unwrap());
    let derp_ipv6 = UseIpv6::None;
    DerpMap::default_from_node(host_name, stun_port, derp_port, derp_ipv4, derp_ipv6)
}

const DR_DERP_ALPN: [u8; 11] = *b"n0/drderp/1";
const DEFAULT_DERP_REGION: u16 = 1;

async fn make_endpoint(
    private_key: SecretKey,
    derp_map: Option<DerpMap>,
) -> anyhow::Result<(magicsock::Conn, quinn::Endpoint)> {
    let (on_derp_s, mut on_derp_r) = sync::mpsc::channel(8);
    let on_net_info = |ni: hp::cfg::NetInfo| {
        tracing::info!("got net info {:#?}", ni);
    };

    let on_endpoints = move |ep: &[hp::cfg::Endpoint]| {
        tracing::info!("got endpoint {:#?}", ep);
    };

    let on_derp_active = move || {
        tracing::info!("got derp active");
        on_derp_s.try_send(()).ok();
    };

    tracing::info!(
        "public key: {}",
        hex::encode(private_key.public_key().as_bytes())
    );
    tracing::info!("derp map {:#?}", derp_map);
    let opts = magicsock::Options {
        port: 0,
        on_endpoints: Some(Box::new(on_endpoints)),
        on_derp_active: Some(Box::new(on_derp_active)),
        on_net_info: Some(Box::new(on_net_info)),
        private_key,
    };
    let key = opts.private_key.clone();
    let conn = magicsock::Conn::new(opts).await?;

    conn.set_derp_map(derp_map).await?;
    tokio::time::timeout(Duration::from_secs(10), on_derp_r.recv())
        .await
        .context("wait for derp connection")?;
    let tls_server_config =
        tls::make_server_config(&key.clone().into(), vec![DR_DERP_ALPN.to_vec()], false)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
    server_config.transport_config(Arc::new(transport_config));
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        conn.clone(),
        Arc::new(quinn::TokioRuntime),
    )?;

    let tls_client_config = tls::make_client_config(
        &key.clone().into(),
        None,
        vec![DR_DERP_ALPN.to_vec()],
        false,
    )?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
    client_config.transport_config(Arc::new(transport_config));
    endpoint.set_default_client_config(client_config);
    Ok((conn, endpoint))
}

async fn connect(
    dial: String,
    private_key: SecretKey,
    remote_endpoints: Vec<SocketAddr>,
    derp_map: Option<DerpMap>,
) -> anyhow::Result<()> {
    let (conn, endpoint) = make_endpoint(private_key.clone(), derp_map).await?;

    let bytes = hex::decode(dial)?;
    let bytes: [u8; 32] = bytes.try_into().ok().context("unexpected key length")?;
    let key: hp::key::node::PublicKey = hp::key::node::PublicKey::from(bytes);

    let endpoints = remote_endpoints;
    let addresses = endpoints.iter().map(|a| a.ip()).collect();
    conn.set_network_map(hp::netmap::NetworkMap {
        peers: vec![hp::cfg::Node {
            name: None,
            key: key.clone(),
            endpoints,
            addresses,
            derp: Some(SocketAddr::new(hp::cfg::DERP_MAGIC_IP, DEFAULT_DERP_REGION)),
            created: Instant::now(),
            hostinfo: crate::hp::hostinfo::Hostinfo::default(),
            keep_alive: false,
            expired: false,
            online: None,
            last_seen: None,
        }],
    })
    .await?;
    let addr = conn.get_mapping_addr(&key).await;
    let addr = addr.context("no mapping address")?;
    tracing::info!("dialing {:?} at {:?}", key, addr);
    let connecting = endpoint.connect(addr, "localhost")?;
    match connecting.await {
        Ok(connection) => {
            if let Err(cause) = passive_side(connection).await {
                eprintln!("error handling connection: {cause}");
            }
        }
        Err(cause) => {
            eprintln!("unable to connect to {addr}: {cause}");
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
    private_key: SecretKey,
    config: TestConfig,
    derp_map: Option<DerpMap>,
) -> anyhow::Result<()> {
    let (conn, endpoint) = make_endpoint(private_key.clone(), derp_map).await?;

    let endpoints = conn.local_endpoints().await?;
    let remote_addrs = endpoints
        .iter()
        .map(|endpoint| format!("--remote-endpoint {}", format_addr(endpoint.addr)))
        .collect::<Vec<_>>()
        .join(" ");
    println!(
            "Run\n\niroh doctor connect {} {}\n\nin another terminal or on another machine to connect by key and addr.",
            hex::encode(private_key.public_key().as_bytes()),
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

fn create_secret_key(private_key: PrivateKey) -> anyhow::Result<SecretKey> {
    Ok(match private_key {
        PrivateKey::Random => SecretKey::generate(),
        PrivateKey::Hex(hex) => {
            let bytes = hex::decode(hex)?;
            let bytes: [u8; 32] = bytes.try_into().ok().context("unexpected key length")?;
            SecretKey::from(bytes)
        }
        PrivateKey::Local => {
            let iroh_data_root = iroh_data_root()?;
            let path = iroh_data_root.join("keypair");
            if path.exists() {
                let bytes = std::fs::read(&path)?;
                let keypair = Keypair::try_from_openssh(bytes)?;
                SecretKey::from(keypair.secret().to_bytes())
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
        Commands::Report {
            stun_host,
            stun_port,
        } => report(stun_host, stun_port, config).await,
        Commands::Connect {
            dial,
            private_key,
            local_derper,
            remote_endpoint,
        } => {
            let derp_map = if local_derper {
                Some(configure_local_derp_map())
            } else {
                config.derp_map()
            };
            let private_key = create_secret_key(private_key)?;
            connect(dial, private_key, remote_endpoint, derp_map).await
        }
        Commands::Accept {
            private_key,
            local_derper,
            size,
            iterations,
        } => {
            let derp_map = if local_derper {
                Some(configure_local_derp_map())
            } else {
                config.derp_map()
            };
            let private_key = create_secret_key(private_key)?;
            let config = TestConfig { size, iterations };
            accept(private_key, config, derp_map).await
        }
    }
}

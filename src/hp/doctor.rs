use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    hp::{
        self,
        derp::{DerpMap, UseIpv4, UseIpv6},
        key::node::SecretKey,
        magicsock,
    },
    tls,
    tokio_util::ProgressWriter,
};
use anyhow::Context;
use clap::Subcommand;
use indicatif::{HumanBytes, MultiProgress, ProgressBar};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync};

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    Report {
        #[clap(long, default_value = "derp.iroh.computer")]
        host_name: String,
        #[clap(long, default_value_t = 3478)]
        stun_port: u16,
    },
    Accept {
        /// Our own private key, in hex. If not specified, a random key will be generated.
        #[clap(long)]
        private_key: Option<String>,

        #[clap(long, default_value_t = 1024 * 1024 * 16)]
        min_size: u64,

        #[clap(long, default_value_t = 1024 * 1024 * 16)]
        max_size: u64,

        #[clap(long, default_value_t = 16)]
        size_multiplier: u64,

        #[clap(long, default_value_t = -1)]
        iterations: i64,

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
        #[clap(long)]
        private_key: Option<String>,

        /// Use a local derp relay
        #[clap(long)]
        local_derper: bool,
    },
}

#[derive(Debug, Serialize, Deserialize, MaxSize)]
enum TestStreamRequest {
    Echo,
    Drain,
    Send { bytes: u64, block_size: u32 },
}

struct TestConfig {
    min_size: u64,
    max_size: u64,
    size_multiplier: u64,
    iterations: Option<u64>,
}

/// handle a test stream request
async fn handle_test_request(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> anyhow::Result<()> {
    let mut buf = [0u8; TestStreamRequest::POSTCARD_MAX_SIZE];
    recv.read_exact(&mut buf).await?;
    let request: TestStreamRequest = postcard::from_bytes(&buf)?;
    match request {
        TestStreamRequest::Echo => {
            // copy the stream back
            tokio::io::copy(&mut recv, &mut send).await?;
        }
        TestStreamRequest::Drain => {
            // drain the stream
            tokio::io::copy(&mut recv, &mut tokio::io::sink()).await?;
        }
        TestStreamRequest::Send { bytes, block_size } => {
            // send the requested number of bytes, in blocks of the requested size
            send_blocks(&mut send, bytes, block_size).await?;
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

async fn report(host_name: String, stun_port: u16) -> anyhow::Result<()> {
    let mut client = hp::netcheck::Client::new(None).await?;

    let derp_port = 0;
    let derp_ipv4 = UseIpv4::None;
    let derp_ipv6 = UseIpv6::None;
    let dm = DerpMap::default_from_node(host_name, stun_port, derp_port, derp_ipv4, derp_ipv6);
    println!("getting report using derp map {:#?}", dm);

    let r = client.get_report(&dm, None, None).await?;
    println!("{:#?}", r);
    Ok(())
}

async fn active_side(connection: quinn::Connection, config: &TestConfig) -> anyhow::Result<()> {
    let n = config.iterations.unwrap_or(u64::MAX);
    let mp = MultiProgress::new();
    mp.set_draw_target(indicatif::ProgressDrawTarget::stderr());
    let pb = indicatif::ProgressBar::hidden();
    let send_pb = mp.add(ProgressBar::hidden());
    let recv_pb = mp.add(ProgressBar::hidden());
    let echo_pb = mp.add(ProgressBar::hidden());
    let style = indicatif::ProgressStyle::default_bar()
        .template("{msg}")
        .unwrap();
    send_pb.set_style(style.clone());
    recv_pb.set_style(style.clone());
    echo_pb.set_style(style.clone());
    let pb = mp.add(pb);
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_style(indicatif::ProgressStyle::default_bar()
        .template("{spinner:.green} [{bar:80.cyan/blue}] {msg} {bytes}/{total_bytes} ({bytes_per_sec})").unwrap()
        .progress_chars("█▉▊▋▌▍▎▏ "));
    for _ in 0..n {
        let (b, d) = send_test(&connection, config, &pb).await?;
        send_pb.set_message(format!(
            "send: {}/s",
            HumanBytes((b as f64 / d.as_secs_f64()) as u64)
        ));
        let (b, d) = recv_test(&connection, config, &pb).await?;
        recv_pb.set_message(format!(
            "recv: {}/s",
            HumanBytes((b as f64 / d.as_secs_f64()) as u64)
        ));
        let (b, d) = echo_test(&connection, config, &pb).await?;
        echo_pb.set_message(format!(
            "echo: {}/s",
            HumanBytes((b as f64 / d.as_secs_f64()) as u64)
        ));
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
) -> anyhow::Result<(u64, Duration)> {
    let mut total_bytes = 0;
    let mut total_duration = Duration::ZERO;
    let mut size = config.min_size;
    while size <= config.max_size {
        pb.set_length(size);
        pb.set_position(0);
        pb.set_message("echo");
        let (mut send, mut recv) = connection.open_bi().await?;
        send_test_request(&mut send, &TestStreamRequest::Echo).await?;
        let (mut sink, mut updates) = ProgressWriter::new(tokio::io::sink());
        let copying = tokio::spawn(async move { tokio::io::copy(&mut recv, &mut sink).await });
        let pb2 = pb.clone();
        let progress = tokio::spawn(async move {
            while let Some(position) = updates.recv().await {
                pb2.set_position(position);
            }
        });
        let t0 = Instant::now();
        send_blocks(&mut send, size, 1024 * 1024).await?;
        send.finish().await?;
        let received = copying.await??;
        anyhow::ensure!(received == size);
        total_duration += t0.elapsed();
        total_bytes += received;
        progress.await?;
        size *= config.size_multiplier;
    }
    Ok((total_bytes, total_duration))
}

async fn send_test(
    connection: &quinn::Connection,
    config: &TestConfig,
    pb: &indicatif::ProgressBar,
) -> anyhow::Result<(u64, Duration)> {
    let mut total_bytes = 0;
    let mut total_duration = Duration::ZERO;
    let mut size = config.min_size;
    while size <= config.max_size {
        pb.set_length(size);
        pb.set_position(0);
        pb.set_message("send");
        let (mut send, mut recv) = connection.open_bi().await?;
        send_test_request(&mut send, &TestStreamRequest::Drain).await?;
        let (mut send_with_progress, mut updates) = ProgressWriter::new(&mut send);
        let copying =
            tokio::spawn(async move { tokio::io::copy(&mut recv, &mut tokio::io::sink()).await });
        let pb2 = pb.clone();
        let progress = tokio::spawn(async move {
            while let Some(position) = updates.recv().await {
                pb2.set_position(position);
            }
        });
        let t0 = Instant::now();
        send_blocks(&mut send_with_progress, size, 1024 * 1024).await?;
        drop(send_with_progress);
        send.finish().await?;
        drop(send);
        let received = copying.await??;
        anyhow::ensure!(received == 0);
        total_duration += t0.elapsed();
        total_bytes += size;
        progress.await?;
        size *= config.size_multiplier;
    }
    Ok((total_bytes, total_duration))
}

async fn recv_test(
    connection: &quinn::Connection,
    config: &TestConfig,
    pb: &indicatif::ProgressBar,
) -> anyhow::Result<(u64, Duration)> {
    let mut total_bytes = 0;
    let mut total_duration = Duration::ZERO;
    let mut size = config.min_size;
    while size <= config.max_size {
        pb.set_length(size);
        pb.set_position(0);
        pb.set_message("recv");
        let (mut send, mut recv) = connection.open_bi().await?;
        let t0 = Instant::now();
        let (mut sink, mut updates) = ProgressWriter::new(tokio::io::sink());
        send_test_request(
            &mut send,
            &TestStreamRequest::Send {
                bytes: size,
                block_size: 1024 * 1024,
            },
        )
        .await?;
        let copying = tokio::spawn(async move { tokio::io::copy(&mut recv, &mut sink).await });
        let pb2 = pb.clone();
        let progress = tokio::spawn(async move {
            while let Some(position) = updates.recv().await {
                pb2.set_position(position);
            }
        });
        send.finish().await?;
        let received = copying.await??;
        anyhow::ensure!(received == size);
        total_duration += t0.elapsed();
        total_bytes += received;
        progress.await?;
        size *= config.size_multiplier;
    }
    Ok((total_bytes, total_duration))
}

/// Passive side that just accepts connections and answers requests (echo, drain or send)
async fn passive_side(connection: quinn::Connection) -> anyhow::Result<()> {
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                if let Err(cause) = handle_test_request(send, recv).await {
                    eprintln!("Error handling test request {}", cause);
                }
            }
            Err(cause) => {
                eprintln!("error accepting bidi stream {}", cause);
                break Err(cause.into());
            }
        };
    }
}

fn configure_derp_map() -> DerpMap {
    let stun_port = 3478;
    let host_name = "derp.iroh.computer".into();
    let derp_port = 3340;
    let derp_ipv4 = UseIpv4::Some("35.175.99.113".parse().unwrap());
    let derp_ipv6: UseIpv6 = UseIpv6::None;
    DerpMap::default_from_node(host_name, stun_port, derp_port, derp_ipv4, derp_ipv6)
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
    local_derper: bool,
    private_key: SecretKey,
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
    let derp_map = if local_derper {
        configure_local_derp_map()
    } else {
        configure_derp_map()
    };
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

    conn.set_derp_map(Some(derp_map)).await?;
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
    local_derper: bool,
    remote_endpoints: Vec<SocketAddr>,
) -> anyhow::Result<()> {
    let (conn, endpoint) = make_endpoint(local_derper, private_key.clone()).await?;

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
                eprintln!("error handling connection: {}", cause);
            }
        }
        Err(cause) => {
            eprintln!("unable to connect to {}: {}", addr, cause);
        }
    }

    Ok(())
}

async fn accept(
    private_key: SecretKey,
    local_derper: bool,
    config: TestConfig,
) -> anyhow::Result<()> {
    let (conn, endpoint) = make_endpoint(local_derper, private_key.clone()).await?;

    let endpoints = conn.local_endpoints().await?;
    let remote_addrs = endpoints
        .iter()
        .map(|endpoint| format!("--remote-endpoint {}", endpoint.addr))
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
                    println!("error after {}: {}", t0.elapsed().as_secs_f64(), cause);
                }
            }
            Err(cause) => {
                eprintln!("error accepting connection {}", cause);
            }
        }
    }

    Ok(())
}

fn create_secret_key(private_key: Option<String>) -> anyhow::Result<SecretKey> {
    Ok(if let Some(key) = private_key {
        let bytes = hex::decode(key)?;
        let bytes: [u8; 32] = bytes.try_into().ok().context("unexpected key length")?;
        SecretKey::from(bytes)
    } else {
        SecretKey::generate()
    })
}

pub async fn run(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Report {
            host_name,
            stun_port,
        } => report(host_name, stun_port).await,
        Commands::Connect {
            dial,
            private_key,
            local_derper,
            remote_endpoint,
        } => {
            let private_key = create_secret_key(private_key)?;
            connect(dial, private_key, local_derper, remote_endpoint).await
        }
        Commands::Accept {
            private_key,
            local_derper,
            min_size,
            max_size,
            size_multiplier,
            iterations,
        } => {
            let private_key = create_secret_key(private_key)?;
            let iterations = if iterations < 0 {
                None
            } else {
                Some(iterations as u64)
            };
            let config = TestConfig {
                min_size,
                max_size,
                size_multiplier,
                iterations,
            };
            accept(private_key, local_derper, config).await
        }
    }
}

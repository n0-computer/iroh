use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use clap::{Parser, Subcommand};
use iroh::{
    hp::{
        self,
        derp::{DerpMap, UseIpv4, UseIpv6},
        key::node::SecretKey,
        magicsock,
    },
    tls,
};
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::sync;
use tracing_subscriber::{prelude::*, EnvFilter};

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    Report {
        #[clap(long, default_value = "derp.iroh.computer")]
        host_name: String,
        #[clap(long, default_value_t = 3478)]
        stun_port: u16,
    },
    Connect {
        /// hex peer id of the node to connect to
        dial: Option<String>,

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

#[derive(Parser, Debug, Clone)]
#[clap(version)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Serialize, Deserialize, MaxSize)]
enum TestStreamRequest {
    Echo,
    Drain,
    Send { bytes: u64, block_size: u32 },
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
    send: &mut quinn::SendStream,
    total_bytes: u64,
    block_size: u32,
) -> anyhow::Result<()> {
    // send the requested number of bytes, in blocks of the requested size
    let mut buf = vec![0u8; block_size as usize];
    let mut remaining = total_bytes;
    while remaining > 0 {
        let n = remaining.min(block_size as u64);
        send.write_all(&mut buf[..n as usize]).await?;
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

async fn active_side(connection: quinn::Connection) -> anyhow::Result<()> {
    loop {
        echo_test(&connection).await?;
        send_test(&connection).await?;
        recv_test(&connection).await?;
    }
}

async fn echo_test(connection: &quinn::Connection) -> anyhow::Result<()> {
    let mut size = 1;
    println!("performing echo test...");
    while size <= 1024 * 1024 {
        let (mut send, mut recv) = connection.open_bi().await?;
        let mut buf = [0u8; TestStreamRequest::POSTCARD_MAX_SIZE];
        postcard::to_slice(&TestStreamRequest::Echo, &mut buf)?;
        send.write_all(&buf).await?;
        let copying = tokio::spawn(async move {
            tracing::debug!("draining response");
            tokio::io::copy(&mut recv, &mut tokio::io::sink()).await
        });
        println!("sending {} bytes", size);
        let t0 = Instant::now();
        send_blocks(&mut send, size, 1024 * 1024).await?;
        send.finish().await?;
        let received = copying.await??;
        anyhow::ensure!(received == size);
        let elapsed = t0.elapsed().as_secs_f64();
        println!("done in {} s", elapsed);
        println!("speed {} bytes/s", (size as f64) / elapsed);
        size = size * 16;
    }
    println!("test done");
    println!("");
    Ok(())
}

async fn send_test(connection: &quinn::Connection) -> anyhow::Result<()> {
    let mut size = 1;
    println!("performing send test...");
    while size <= 1024 * 1024 {
        let (mut send, mut recv) = connection.open_bi().await?;
        let mut buf = [0u8; TestStreamRequest::POSTCARD_MAX_SIZE];
        postcard::to_slice(&TestStreamRequest::Drain, &mut buf)?;
        send.write_all(&buf).await?;
        let copying = tokio::spawn(async move {
            tracing::debug!("draining response");
            tokio::io::copy(&mut recv, &mut tokio::io::sink()).await
        });
        println!("sending {} bytes", size);
        let t0 = Instant::now();
        send_blocks(&mut send, size, 1024 * 1024).await?;
        send.finish().await?;
        let received = copying.await??;
        anyhow::ensure!(received == 0);
        let elapsed = t0.elapsed().as_secs_f64();
        println!("done in {} s", elapsed);
        println!("speed {} bytes/s", (size as f64) / elapsed);
        size = size * 16;
    }
    println!("test done");
    println!("");
    Ok(())
}

async fn recv_test(connection: &quinn::Connection) -> anyhow::Result<()> {
    let mut size = 1;
    println!("performing recv test...");
    while size <= 1024 * 1024 {
        let (mut send, mut recv) = connection.open_bi().await?;
        let mut buf = [0u8; TestStreamRequest::POSTCARD_MAX_SIZE];
        postcard::to_slice(
            &TestStreamRequest::Send {
                bytes: size,
                block_size: 1024 * 1024,
            },
            &mut buf,
        )?;
        println!("asking for {} bytes", size);
        let t0 = Instant::now();
        send.write_all(&buf).await?;
        let copying = tokio::spawn(async move {
            tracing::debug!("draining response");
            tokio::io::copy(&mut recv, &mut tokio::io::sink()).await
        });
        send.finish().await?;
        let received = copying.await??;
        anyhow::ensure!(received == size);
        let elapsed = t0.elapsed().as_secs_f64();
        println!("done in {} s", elapsed);
        println!("speed {} bytes/s", (size as f64) / elapsed);
        size = size * 16;
    }
    println!("test done");
    println!("");
    Ok(())
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

async fn connect(
    dial: Option<String>,
    private_key: Option<String>,
    local_derper: bool,
    remote_endpoints: Vec<SocketAddr>,
) -> anyhow::Result<()> {
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

    let private_key = if let Some(key) = private_key {
        let bytes = hex::decode(key)?;
        let bytes: [u8; 32] = bytes.try_into().ok().context("unexpected key length")?;
        SecretKey::from(bytes)
    } else {
        SecretKey::generate()
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

    if let Some(dial) = dial {
        let bytes = hex::decode(dial)?;
        let bytes: [u8; 32] = bytes.try_into().ok().context("unexpected key length")?;
        let key: hp::key::node::PublicKey = hp::key::node::PublicKey::from(bytes);

        let endpoints = remote_endpoints;
        let addresses = endpoints.iter().map(|a| a.ip().clone()).collect();
        conn.set_network_map(hp::netmap::NetworkMap {
            peers: vec![hp::cfg::Node {
                name: None,
                key: key.clone(),
                endpoints,
                addresses,
                derp: Some(SocketAddr::new(hp::cfg::DERP_MAGIC_IP, DEFAULT_DERP_REGION)),
                created: Instant::now(),
                hostinfo: crate::hp::hostinfo::Hostinfo::new(),
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
    } else {
        let endpoints = conn.local_endpoints().await?;
        let remote_addrs = endpoints
            .iter()
            .map(|endpoint| format!("--remote-endpoint {}", endpoint.addr))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "Run\n\ndrderp connect {} {}\n\nin another terminal or on another machine to connect by key and addr.",
            hex::encode(key.public_key().as_bytes()),
            remote_addrs,
        );
        println!("Omit the --remote-endpoint args to connect just by key.");
        while let Some(connecting) = endpoint.accept().await {
            match connecting.await {
                Ok(connection) => {
                    active_side(connection).await?;
                }
                Err(cause) => {
                    eprintln!("error accepting connection {}", cause);
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();

    let cli = Cli::parse();
    match cli.command {
        Commands::Report {
            host_name,
            stun_port,
        } => report(host_name, stun_port).await,
        Commands::Connect {
            dial,
            private_key,
            local_derper,
            remote_endpoint,
        } => connect(dial, private_key, local_derper, remote_endpoint).await,
    }
}

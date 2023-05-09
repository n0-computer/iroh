use std::{
    net::SocketAddr,
    sync::Arc,
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
        dial: Option<String>,
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
    println!("{:?}", request);
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
            let mut buf = vec![0u8; block_size as usize];
            let mut remaining = bytes;
            while remaining > 0 {
                let n = remaining.min(block_size as u64);
                send.write_all(&mut buf[..n as usize]).await?;
                remaining -= n;
            }
        }
    }
    send.finish().await?;
    Ok(())
}

async fn report(host_name: String, stun_port: u16) -> anyhow::Result<()> {
    let mut client = hp::netcheck::Client::new(None).await?;

    let derp_port = 0;
    let derp_ipv4 = UseIpv4::None;
    let derp_ipv6 = UseIpv6::None;
    let dm = DerpMap::default_from_node(host_name, stun_port, derp_port, derp_ipv4, derp_ipv6);
    println!("getting report using derp map {:#}", dm);

    let r = client.get_report(&dm, None, None).await?;
    println!("{:#}", r);
    Ok(())
}

pub fn configure_derp_map() -> DerpMap {
    // Use google stun server for now
    let stun_port = 3478;
    let host_name = "derp.iroh.computer".into();
    let derp_port = 3340;
    let derp_ipv4 = UseIpv4::Some("35.175.99.113".parse().unwrap());
    let derp_ipv6: UseIpv6 = UseIpv6::None;
    DerpMap::default_from_node(host_name, stun_port, derp_port, derp_ipv4, derp_ipv6)
}

const DR_DERP_ALPN: [u8; 11] = *b"n0/drderp/1";
const DEFAULT_DERP_REGION: u16 = 1;

async fn connect(dial: Option<String>) -> anyhow::Result<()> {
    let (on_derp_s, mut on_derp_r) = sync::mpsc::channel(8);
    let on_net_info = |ni: hp::cfg::NetInfo| {
        println!("got net info {:#?}", ni);
    };

    let on_endpoints = |ep: &[hp::cfg::Endpoint]| {
        println!("got endpoint {:#?}", ep);
    };

    let on_derp_active = move || {
        println!("got derp active");
        on_derp_s.try_send(()).ok();
    };

    let private_key = SecretKey::generate();
    tracing::info!(
        "public key: {}",
        hex::encode(private_key.public_key().as_bytes())
    );
    let derp_map = configure_derp_map();
    tracing::info!("derp map {:#?}", derp_map);
    let opts = magicsock::Options {
        port: 12345,
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

        conn.set_network_map(hp::netmap::NetworkMap {
            peers: vec![hp::cfg::Node {
                name: None,
                addresses: vec![],
                key: key.clone(),
                endpoints: vec![],
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
                tracing::info!("got connection");
                match connection.open_bi().await {
                    Ok((mut send, mut recv)) => {
                        let mut buf = [0u8; TestStreamRequest::POSTCARD_MAX_SIZE];
                        postcard::to_slice(&TestStreamRequest::Echo, &mut buf)?;
                        send.write_all(&buf).await?;
                        let copying = tokio::spawn(async move {
                            tracing::debug!("draining response");
                            tokio::io::copy(&mut recv, &mut tokio::io::sink()).await
                        });
                        let t0 = Instant::now();
                        for _ in 0..1000 {
                            send.write_all(&[0u8; 1024]).await?;
                        }
                        send.finish().await?;
                        copying.await??;
                        println!("done in {} s", t0.elapsed().as_secs_f64());
                    }
                    Err(cause) => {
                        println!("got error {:?}", cause);
                    }
                }
            }
            Err(cause) => {
                println!("got error {:?}", cause);
            }
        }
    } else {
        println!(
            "run drderp connect {} in another terminal or on another machine",
            hex::encode(key.public_key().as_bytes())
        );
        while let Some(connecting) = endpoint.accept().await {
            println!("got connecting");
            match connecting.await {
                Ok(connection) => {
                    tokio::task::spawn(async move {
                        match connection.accept_bi().await {
                            Ok((send, recv)) => {
                                handle_test_request(send, recv).await?;
                            }
                            Err(cause) => {
                                println!("got error {:?}", cause);
                            }
                        };
                        anyhow::Ok(())
                    });
                }
                Err(cause) => {
                    println!("got error {:?}", cause);
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
        Commands::Connect { dial } => connect(dial).await,
    }
}

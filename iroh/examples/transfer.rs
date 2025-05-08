use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use indicatif::HumanBytes;
use iroh::{
    discovery::{dns::DnsDiscovery, pkarr::PkarrPublisher},
    endpoint::{ConnectionError, PathSelection},
    Endpoint, NodeAddr, RelayMode, RelayUrl, SecretKey,
};
use iroh_base::ticket::NodeTicket;
use tracing::info;
// Transfer ALPN that we are using to communicate over the `Endpoint`
const TRANSFER_ALPN: &[u8] = b"n0/iroh/transfer/example/0";

#[derive(Parser, Debug)]
#[command(name = "transfer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Provide {
        #[clap(long, default_value = "1G", value_parser = parse_byte_size)]
        size: u64,
        #[clap(long)]
        relay_url: Option<String>,
        #[clap(long, default_value = "false")]
        relay_only: bool,
        #[clap(long)]
        pkarr_relay_url: Option<String>,
        #[clap(long)]
        dns_origin_domain: Option<String>,
    },
    Fetch {
        #[arg(index = 1)]
        ticket: String,
        #[clap(long)]
        relay_url: Option<String>,
        #[clap(long, default_value = "false")]
        relay_only: bool,
        #[clap(long)]
        pkarr_relay_url: Option<String>,
        #[clap(long)]
        dns_origin_domain: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Provide {
            size,
            relay_url,
            relay_only,
            pkarr_relay_url,
            dns_origin_domain,
        } => {
            provide(
                *size,
                relay_url.clone(),
                *relay_only,
                pkarr_relay_url.clone(),
                dns_origin_domain.clone(),
            )
            .await?
        }
        Commands::Fetch {
            ticket,
            relay_url,
            relay_only,
            pkarr_relay_url,
            dns_origin_domain,
        } => {
            fetch(
                ticket,
                relay_url.clone(),
                *relay_only,
                pkarr_relay_url.clone(),
                dns_origin_domain.clone(),
            )
            .await?
        }
    }

    Ok(())
}

async fn provide(
    size: u64,
    relay_url: Option<String>,
    relay_only: bool,
    pkarr_relay_url: Option<String>,
    dns_origin_domain: Option<String>,
) -> anyhow::Result<()> {
    let secret_key = SecretKey::generate(rand::rngs::OsRng);
    let relay_mode = match relay_url {
        Some(relay_url) => {
            let relay_url = RelayUrl::from_str(&relay_url)?;
            RelayMode::Custom(relay_url.into())
        }
        None => RelayMode::Default,
    };
    let path_selection = match relay_only {
        true => PathSelection::RelayOnly,
        false => PathSelection::default(),
    };

    let mut endpoint_builder = Endpoint::builder();

    if let Some(pkarr_relay_url) = pkarr_relay_url {
        let pkarr_relay_url = pkarr_relay_url
            .parse()
            .context("Invalid pkarr URL provided")?;

        let pkarr_discovery_closure = move |secret_key: &SecretKey| {
            let pkarr_d = PkarrPublisher::new(secret_key.clone(), pkarr_relay_url);
            Some(pkarr_d)
        };
        endpoint_builder = endpoint_builder.add_discovery(pkarr_discovery_closure);
    }

    if let Some(dns_origin_domain) = dns_origin_domain {
        let dns_discovery_closure = move |_: &SecretKey| Some(DnsDiscovery::new(dns_origin_domain));

        endpoint_builder = endpoint_builder.add_discovery(dns_discovery_closure);
    }

    let endpoint = endpoint_builder
        .secret_key(secret_key)
        .alpns(vec![TRANSFER_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .path_selection(path_selection)
        .bind()
        .await?;

    let node_id = endpoint.node_id();

    for local_endpoint in endpoint.direct_addresses().initialized().await? {
        println!("\t{}", local_endpoint.addr)
    }

    let relay_url = endpoint
        .home_relay()
        .get()?
        .expect("should be connected to a relay server");
    let local_addrs = endpoint
        .direct_addresses()
        .initialized()
        .await?
        .into_iter()
        .map(|endpoint| endpoint.addr)
        .collect::<Vec<_>>();

    let node_addr = NodeAddr::from_parts(node_id, Some(relay_url), local_addrs);
    let ticket = NodeTicket::new(node_addr);

    println!("NodeTicket: {}", ticket);

    // accept incoming connections, returns a normal QUIC connection
    while let Some(incoming) = endpoint.accept().await {
        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(err) => {
                tracing::warn!("incoming connection failed: {err:#}");
                // we can carry on in these cases:
                // this can be caused by retransmitted datagrams
                continue;
            }
        };
        let conn = connecting.await?;
        let node_id = conn.remote_node_id()?;
        info!(
            "new connection from {node_id} with ALPN {}",
            String::from_utf8_lossy(TRANSFER_ALPN),
        );

        // spawn a task to handle reading and writing off of the connection
        tokio::spawn(async move {
            // accept a bi-directional QUIC connection
            // use the `quinn` APIs to send and recv content
            let (mut send, mut recv) = conn.accept_bi().await?;
            tracing::debug!("accepted bi stream, waiting for data...");
            let message = recv.read_to_end(100).await?;
            let message = String::from_utf8(message)?;
            println!("received: {message}");

            send_data_on_stream(&mut send, size).await?;

            // We sent the last message, so wait for the client to close the connection once
            // it received this message.
            let res = tokio::time::timeout(Duration::from_secs(3), async move {
                let closed = conn.closed().await;
                if !matches!(closed, ConnectionError::ApplicationClosed(_)) {
                    println!("node {node_id} disconnected with an error: {closed:#}");
                }
            })
            .await;
            if res.is_err() {
                println!("node {node_id} did not disconnect within 3 seconds");
            }
            Ok::<_, anyhow::Error>(())
        });
    }

    // stop with SIGINT (ctrl-c)
    Ok(())
}

async fn fetch(
    ticket: &str,
    relay_url: Option<String>,
    relay_only: bool,
    pkarr_relay_url: Option<String>,
    dns_origin_domain: Option<String>,
) -> anyhow::Result<()> {
    let ticket: NodeTicket = ticket.parse()?;
    let secret_key = SecretKey::generate(rand::rngs::OsRng);
    let relay_mode = match relay_url {
        Some(relay_url) => {
            let relay_url = RelayUrl::from_str(&relay_url)?;
            RelayMode::Custom(relay_url.into())
        }
        None => RelayMode::Default,
    };
    let path_selection = match relay_only {
        true => PathSelection::RelayOnly,
        false => PathSelection::default(),
    };
    let mut endpoint_builder = Endpoint::builder();

    if let Some(pkarr_relay_url) = pkarr_relay_url {
        let pkarr_relay_url = pkarr_relay_url
            .parse()
            .context("Invalid pkarr URL provided")?;

        let pkarr_discovery_closure = move |secret_key: &SecretKey| {
            let pkarr_d = PkarrPublisher::new(secret_key.clone(), pkarr_relay_url);
            Some(pkarr_d)
        };
        endpoint_builder = endpoint_builder.add_discovery(pkarr_discovery_closure);
    }

    if let Some(dns_origin_domain) = dns_origin_domain {
        let dns_discovery_closure = move |_: &SecretKey| Some(DnsDiscovery::new(dns_origin_domain));

        endpoint_builder = endpoint_builder.add_discovery(dns_discovery_closure);
    }

    let endpoint = endpoint_builder
        .secret_key(secret_key)
        .alpns(vec![TRANSFER_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .path_selection(path_selection)
        .bind()
        .await?;

    let start = Instant::now();

    let me = endpoint.node_id();
    println!("node id: {me}");
    println!("node listening addresses:");
    for local_endpoint in endpoint.direct_addresses().initialized().await? {
        println!("\t{}", local_endpoint.addr)
    }

    let relay_url = endpoint
        .home_relay()
        .get()?
        .expect("should be connected to a relay server, try calling `endpoint.local_endpoints()` or `endpoint.connect()` first, to ensure the endpoint has actually attempted a connection before checking for the connected relay server");
    println!("node relay server url: {relay_url}\n");

    // Attempt to connect, over the given ALPN.
    // Returns a Quinn connection.
    let conn = endpoint
        .connect(ticket.node_addr().clone(), TRANSFER_ALPN)
        .await?;
    info!("connected");

    // Use the Quinn API to send and recv content.
    let (mut send, mut recv) = conn.open_bi().await?;

    let message = format!("{me} is saying 'hello!'");
    send.write_all(message.as_bytes()).await?;

    // Call `finish` to signal no more data will be sent on this stream.
    send.finish()?;

    let (len, time_to_first_byte, chnk) = drain_stream(&mut recv, false).await?;

    // We received the last message: close all connections and allow for the close
    // message to be sent.
    tokio::time::timeout(Duration::from_secs(3), endpoint.close()).await?;

    let duration = start.elapsed();
    println!(
        "Received {} in {:.4}s with time to first byte {}s in {} chunks",
        HumanBytes(len as u64),
        duration.as_secs_f64(),
        time_to_first_byte.as_secs_f64(),
        chnk
    );
    println!(
        "Transferred {} in {:.4}, {}/s",
        HumanBytes(len as u64),
        duration.as_secs_f64(),
        HumanBytes((len as f64 / duration.as_secs_f64()) as u64)
    );

    Ok(())
}

async fn drain_stream(
    stream: &mut iroh::endpoint::RecvStream,
    read_unordered: bool,
) -> Result<(usize, Duration, u64)> {
    let mut read = 0;

    let download_start = Instant::now();
    let mut first_byte = true;
    let mut time_to_first_byte = download_start.elapsed();

    let mut num_chunks: u64 = 0;

    if read_unordered {
        while let Some(chunk) = stream.read_chunk(usize::MAX, false).await? {
            if first_byte {
                time_to_first_byte = download_start.elapsed();
                first_byte = false;
            }
            read += chunk.bytes.len();
            num_chunks += 1;
        }
    } else {
        // These are 32 buffers, for reading approximately 32kB at once
        #[rustfmt::skip]
        let mut bufs = [
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        ];

        while let Some(n) = stream.read_chunks(&mut bufs[..]).await? {
            if first_byte {
                time_to_first_byte = download_start.elapsed();
                first_byte = false;
            }
            read += bufs.iter().take(n).map(|buf| buf.len()).sum::<usize>();
            num_chunks += 1;
        }
    }

    Ok((read, time_to_first_byte, num_chunks))
}

async fn send_data_on_stream(
    stream: &mut iroh::endpoint::SendStream,
    stream_size: u64,
) -> Result<()> {
    const DATA: &[u8] = &[0xAB; 1024 * 1024];
    let bytes_data = Bytes::from_static(DATA);

    let full_chunks = stream_size / (DATA.len() as u64);
    let remaining = (stream_size % (DATA.len() as u64)) as usize;

    for _ in 0..full_chunks {
        stream
            .write_chunk(bytes_data.clone())
            .await
            .context("failed sending data")?;
    }

    if remaining != 0 {
        stream
            .write_chunk(bytes_data.slice(0..remaining))
            .await
            .context("failed sending data")?;
    }

    stream.finish().context("failed finishing stream")?;
    stream
        .stopped()
        .await
        .context("failed to wait for stream to be stopped")?;

    Ok(())
}

fn parse_byte_size(s: &str) -> Result<u64> {
    let cfg = parse_size::Config::new().with_binary();
    cfg.parse_size(s).map_err(|e| anyhow::anyhow!(e))
}

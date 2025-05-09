use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use indicatif::HumanBytes;
use iroh::{
    discovery::{
        dns::DnsDiscovery,
        pkarr::{PkarrPublisher, N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING},
    },
    dns::{N0_DNS_NODE_ORIGIN_PROD, N0_DNS_NODE_ORIGIN_STAGING},
    endpoint::ConnectionError,
    Endpoint, NodeAddr, RelayMap, RelayMode, RelayUrl, SecretKey,
};
use iroh_base::ticket::NodeTicket;
use tokio_stream::StreamExt;
use tracing::{info, warn};
use url::Url;
// Transfer ALPN that we are using to communicate over the `Endpoint`
const TRANSFER_ALPN: &[u8] = b"n0/iroh/transfer/example/0";

/// Transfer data between iroh nodes.
///
/// This is a useful example to test connection establishment and transfer speed.
///
/// Note that some options are only available with optional features:
///
/// --relay-only needs the `test-utils` feature
///
/// --mdns needs the `discovery-local-network` feature
///
/// To enable all features, run the example with --all-features:
///
/// cargo run --release --example transfer --all-features -- ARGS
#[derive(Parser, Debug)]
#[command(name = "transfer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Default, Debug, clap::ValueEnum)]
enum Env {
    /// Use the production servers hosted by n0.
    #[default]
    Prod,
    /// Use the staging servers hosted by n0.
    Staging,
}

#[derive(Debug, clap::Parser)]
struct EndpointArgs {
    /// Set the environment for relay, pkarr, and DNS servers.
    ///
    /// If other options are set, those will override the environment defaults.
    #[clap(short, long, value_enum, default_value_t)]
    environment: Env,
    /// Set one or more relay servers to use.
    #[clap(long)]
    relay_url: Vec<String>,
    /// Disable relays completely.
    #[clap(long)]
    no_relay: bool,
    /// If set no direct connections will be established.
    #[clap(long, default_value = "false")]
    relay_only: bool,
    /// Use a custom pkarr server.
    #[clap(long)]
    pkarr_relay_url: Option<String>,
    /// Disable publishing node info to pkarr.
    #[clap(long)]
    no_pkarr_publish: bool,
    /// Use a custom domain when resolving node info via DNS.
    #[clap(long)]
    dns_origin_domain: Option<String>,
    /// Do not resolve node info via DNS.
    #[clap(long)]
    no_dns_resolve: bool,
    #[cfg(feature = "discovery-local-network")]
    #[clap(long)]
    /// Enable mDNS discovery,
    mdns: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Provide data.
    Provide {
        #[clap(long, default_value = "100M", value_parser = parse_byte_size)]
        size: u64,
        #[clap(flatten)]
        endpoint_args: EndpointArgs,
    },
    /// Fetch data.
    Fetch {
        #[arg(index = 1)]
        ticket: String,
        #[clap(flatten)]
        endpoint_args: EndpointArgs,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Provide {
            size,
            endpoint_args,
        } => {
            let endpoint = endpoint_args.into_endpoint().await?;
            provide(endpoint, size).await?
        }
        Commands::Fetch {
            ticket,
            endpoint_args,
        } => {
            let endpoint = endpoint_args.into_endpoint().await?;
            fetch(endpoint, &ticket).await?
        }
    }

    Ok(())
}

impl EndpointArgs {
    async fn into_endpoint(self) -> anyhow::Result<Endpoint> {
        let secret_key = match std::env::var("IROH_SECRET") {
            Ok(s) => SecretKey::from_str(&s)
                .context("failed to parse IROH_SECRET environment variable as iroh secret key")?,
            Err(_) => {
                let s = SecretKey::generate(rand::rngs::OsRng);
                println!("Generated a new node secret. To reuse, set");
                println!("\tIROH_SECRET={s}");
                s
            }
        };

        let relay_mode = if self.no_relay {
            RelayMode::Disabled
        } else {
            match (self.relay_url.is_empty(), self.environment) {
                (true, Env::Prod) => RelayMode::Default,
                (true, Env::Staging) => RelayMode::Staging,
                (false, _) => {
                    let urls: Result<Vec<_>, _> = self
                        .relay_url
                        .iter()
                        .map(|u| RelayUrl::from_str(u))
                        .collect();
                    let urls = urls.context("failed to parse relay URL")?;
                    RelayMode::Custom(RelayMap::from_iter(urls))
                }
            }
        };

        let mut endpoint_builder = Endpoint::builder();

        if !self.no_pkarr_publish {
            let url = match (&self.pkarr_relay_url, self.environment) {
                (None, Env::Prod) => N0_DNS_PKARR_RELAY_PROD,
                (None, Env::Staging) => N0_DNS_PKARR_RELAY_STAGING,
                (Some(url), _) => url,
            };
            let url = Url::from_str(url).context("failed to parse pkarr relay url")?;
            endpoint_builder = endpoint_builder
                .add_discovery(|secret_key| Some(PkarrPublisher::new(secret_key.clone(), url)));
        }

        if !self.no_dns_resolve {
            let origin_domain = match (self.dns_origin_domain, self.environment) {
                (None, Env::Prod) => N0_DNS_NODE_ORIGIN_PROD.to_string(),
                (None, Env::Staging) => N0_DNS_NODE_ORIGIN_STAGING.to_string(),
                (Some(domain), _) => domain,
            };
            endpoint_builder =
                endpoint_builder.add_discovery(|_| Some(DnsDiscovery::new(origin_domain)));
        }

        #[cfg(feature = "discovery-local-network")]
        if self.mdns {
            endpoint_builder = endpoint_builder.add_discovery(|secret_key| {
                Some(
                    iroh::discovery::mdns::MdnsDiscovery::new(secret_key.public())
                        .expect("Failed to create mDNS discovery"),
                )
            });
        }

        #[cfg(feature = "test-utils")]
        if self.relay_only {
            endpoint_builder =
                endpoint_builder.path_selection(iroh::endpoint::PathSelection::RelayOnly)
        }

        let endpoint = endpoint_builder
            .secret_key(secret_key)
            .alpns(vec![TRANSFER_ALPN.to_vec()])
            .relay_mode(relay_mode.clone())
            .bind()
            .await?;

        let node_id = endpoint.node_id();
        println!("Our node id:\n\t{node_id}");

        println!("Our direct addresses:");
        for local_endpoint in endpoint.direct_addresses().initialized().await? {
            println!("\t{} (type: {:?})", local_endpoint.addr, local_endpoint.typ)
        }

        if !matches!(relay_mode, RelayMode::Disabled) {
            let relay_url = endpoint
                .home_relay()
                .get()?
                .expect("should be connected to a relay server, try calling `endpoint.local_endpoints()` or `endpoint.connect()` first, to ensure the endpoint has actually attempted a connection before checking for the connected relay server");
            println!("Our home relay server:\n\t{relay_url}");
        }

        println!();

        Ok(endpoint)
    }
}

async fn provide(endpoint: Endpoint, size: u64) -> anyhow::Result<()> {
    let node_id = endpoint.node_id();
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

    let node_addr = NodeAddr::from_parts(node_id, Some(relay_url.clone()), local_addrs);
    let ticket = NodeTicket::new(node_addr);
    println!(
        "Ticket with our home relay and direct addresses:\n{}\n",
        ticket
    );
    let node_addr = NodeAddr::from_parts(node_id, Some(relay_url), vec![]);
    let ticket = NodeTicket::new(node_addr);
    println!(
        "Ticket with our home relay but no direct addresses:\n{}\n",
        ticket
    );
    let node_addr = NodeAddr::from_parts(node_id, None, vec![]);
    let ticket = NodeTicket::new(node_addr);
    println!("Ticket with only our node id:\n{}\n", ticket);

    // accept incoming connections, returns a normal QUIC connection
    while let Some(incoming) = endpoint.accept().await {
        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(err) => {
                warn!("incoming connection failed: {err:#}");
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
        let endpoint_clone = endpoint.clone();
        tokio::spawn(async move {
            let remote = node_id.fmt_short();
            println!("[{remote}] Connected");

            let mut conn_type_stream = endpoint_clone.conn_type(node_id).unwrap().stream();
            let conn_type_task = tokio::task::spawn(async move {
                let remote = node_id.fmt_short();
                while let Some(conn_type) = conn_type_stream.next().await {
                    println!("[{remote}] Connection type changed to `{conn_type}`");
                }
            });

            // accept a bi-directional QUIC connection
            // use the `quinn` APIs to send and recv content
            let (mut send, mut recv) = conn.accept_bi().await?;
            tracing::debug!("accepted bi stream, waiting for data...");
            let message = recv.read_to_end(100).await?;
            let message = String::from_utf8(message)?;
            println!("[{remote}] Received: \"{message}\"");

            let start = Instant::now();
            send_data_on_stream(&mut send, size).await?;

            // We sent the last message, so wait for the client to close the connection once
            // it received this message.
            let res = tokio::time::timeout(Duration::from_secs(3), async move {
                let closed = conn.closed().await;
                let remote = node_id.fmt_short();
                if !matches!(closed, ConnectionError::ApplicationClosed(_)) {
                    println!("[{remote}] Node disconnected with an error: {closed:#}");
                }
            })
            .await;
            let duration = start.elapsed();

            println!(
                "[{remote}] Transferred {} in {:.4}, {}/s",
                HumanBytes(size),
                duration.as_secs_f64(),
                HumanBytes((size as f64 / duration.as_secs_f64()) as u64)
            );
            if res.is_err() {
                println!("[{remote}] Did not disconnect within 3 seconds");
            } else {
                println!("[{remote}] Disconnected");
            }
            conn_type_task.abort();
            Ok::<_, anyhow::Error>(())
        });
    }

    // stop with SIGINT (ctrl-c)
    Ok(())
}

async fn fetch(endpoint: Endpoint, ticket: &str) -> anyhow::Result<()> {
    let me = endpoint.node_id().fmt_short();
    let ticket: NodeTicket = ticket.parse()?;
    let start = Instant::now();

    let remote = ticket.node_addr().node_id;

    // Attempt to connect, over the given ALPN.
    // Returns a Quinn connection.
    let conn = endpoint
        .connect(ticket.node_addr().clone(), TRANSFER_ALPN)
        .await?;
    println!("Connected to {remote}");
    let mut conn_type_stream = endpoint.conn_type(remote).unwrap().stream();
    let conn_type_task = tokio::task::spawn(async move {
        while let Some(conn_type) = conn_type_stream.next().await {
            println!("Connection type changed to `{conn_type}`");
        }
    });

    // Use the Quinn API to send and recv content.
    let (mut send, mut recv) = conn.open_bi().await?;

    let message = format!("{me} is saying hello!");
    send.write_all(message.as_bytes()).await?;
    // Call `finish` to signal no more data will be sent on this stream.
    send.finish()?;
    println!("Sent: \"{message}\"");

    let (len, time_to_first_byte, chnk) = drain_stream(&mut recv, false).await?;

    // We received the last message: close all connections and allow for the close
    // message to be sent.
    tokio::time::timeout(Duration::from_secs(3), endpoint.close()).await?;

    let duration = start.elapsed();
    println!(
        "Received {} in {:.4}s ({}/s, time to first byte {}s, {} chunks)",
        HumanBytes(len as u64),
        duration.as_secs_f64(),
        HumanBytes((len as f64 / duration.as_secs_f64()) as u64),
        time_to_first_byte.as_secs_f64(),
        chnk
    );
    conn_type_task.abort();
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

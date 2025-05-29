use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use clap::{Parser, Subcommand};
use indicatif::HumanBytes;
use iroh::{
    discovery::{
        dns::DnsDiscovery,
        pkarr::{PkarrPublisher, N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING},
    },
    dns::{DnsResolver, N0_DNS_NODE_ORIGIN_PROD, N0_DNS_NODE_ORIGIN_STAGING},
    endpoint::ConnectionError,
    watcher::Watcher as _,
    Endpoint, NodeAddr, NodeId, RelayMap, RelayMode, RelayUrl, SecretKey,
};
use iroh_base::ticket::NodeTicket;
use n0_future::task::AbortOnDropHandle;
use n0_snafu::{Result, ResultExt};
use tokio_stream::StreamExt;
use tracing::{info, warn};
use url::Url;

// Transfer ALPN that we are using to communicate over the `Endpoint`
const TRANSFER_ALPN: &[u8] = b"n0/iroh/transfer/example/0";

const DEV_RELAY_URL: &str = "http://localhost:3340";
const DEV_PKARR_RELAY_URL: &str = "http://localhost:8080/pkarr";
const DEV_DNS_ORIGIN_DOMAIN: &str = "irohdns.example";
const DEV_DNS_SERVER: &str = "127.0.0.1:5300";

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

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, clap::ValueEnum)]
enum Env {
    /// Use the production servers hosted by number0.
    Prod,
    /// Use the staging servers hosted by number0.
    #[default]
    Staging,
    /// Use localhost servers.
    ///
    /// To run the DNS server:
    ///     cargo run --bin iroh-dns-server
    /// To run the relay server:
    ///     cargo run --bin iroh-relay --features server -- --dev
    Dev,
}

impl Env {
    fn relay_mode(self) -> RelayMode {
        match self {
            Env::Prod => RelayMode::Default,
            Env::Staging => RelayMode::Staging,
            Env::Dev => RelayMode::Custom(RelayMap::from(
                RelayUrl::from_str(DEV_RELAY_URL).expect("valid url"),
            )),
        }
    }

    fn pkarr_relay_url(self) -> Url {
        match self {
            Env::Prod => N0_DNS_PKARR_RELAY_PROD.parse(),
            Env::Staging => N0_DNS_PKARR_RELAY_STAGING.parse(),
            Env::Dev => DEV_PKARR_RELAY_URL.parse(),
        }
        .expect("valid url")
    }

    fn dns_origin_domain(self) -> String {
        match self {
            Env::Prod => N0_DNS_NODE_ORIGIN_PROD.to_string(),
            Env::Staging => N0_DNS_NODE_ORIGIN_STAGING.to_string(),
            Env::Dev => DEV_DNS_ORIGIN_DOMAIN.to_string(),
        }
    }
}

#[derive(Debug, clap::Parser)]
struct EndpointArgs {
    /// Set the environment for relay, pkarr, and DNS servers.
    ///
    /// If other options are set, those will override the environment defaults.
    #[clap(short, long, value_enum, default_value_t)]
    env: Env,
    /// Set one or more relay servers to use.
    #[clap(long)]
    relay_url: Vec<RelayUrl>,
    /// Disable relays completely.
    #[clap(long, conflicts_with = "relay_url")]
    no_relay: bool,
    /// If set no direct connections will be established.
    #[clap(long)]
    relay_only: bool,
    /// Use a custom pkarr server.
    #[clap(long)]
    pkarr_relay_url: Option<Url>,
    /// Disable publishing node info to pkarr.
    #[clap(long, conflicts_with = "pkarr_relay_url")]
    no_pkarr_publish: bool,
    /// Use a custom domain when resolving node info via DNS.
    #[clap(long)]
    dns_origin_domain: Option<String>,
    /// Use a custom DNS server for resolving relay and node info domains.
    #[clap(long)]
    dns_server: Option<String>,
    /// Do not resolve node info via DNS.
    #[clap(long)]
    no_dns_resolve: bool,
    #[cfg(feature = "discovery-local-network")]
    #[clap(long)]
    /// Enable mDNS discovery.
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
        ticket: String,
        #[clap(flatten)]
        endpoint_args: EndpointArgs,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Provide {
            size,
            endpoint_args,
        } => {
            let endpoint = endpoint_args.bind_endpoint().await?;
            provide(endpoint, size).await?
        }
        Commands::Fetch {
            ticket,
            endpoint_args,
        } => {
            let endpoint = endpoint_args.bind_endpoint().await?;
            fetch(endpoint, &ticket).await?
        }
    }

    Ok(())
}

impl EndpointArgs {
    async fn bind_endpoint(self) -> Result<Endpoint> {
        let mut builder = Endpoint::builder();

        let secret_key = match std::env::var("IROH_SECRET") {
            Ok(s) => SecretKey::from_str(&s)
                .context("Failed to parse IROH_SECRET environment variable as iroh secret key")?,
            Err(_) => {
                let s = SecretKey::generate(rand::rngs::OsRng);
                println!("Generated a new node secret. To reuse, set");
                println!("\tIROH_SECRET={s}");
                s
            }
        };
        builder = builder.secret_key(secret_key);

        let relay_mode = if self.no_relay {
            RelayMode::Disabled
        } else if !self.relay_url.is_empty() {
            RelayMode::Custom(RelayMap::from_iter(self.relay_url))
        } else {
            self.env.relay_mode()
        };
        builder = builder.relay_mode(relay_mode);

        if !self.no_pkarr_publish {
            let url = self
                .pkarr_relay_url
                .unwrap_or_else(|| self.env.pkarr_relay_url());
            builder = builder
                .add_discovery(|secret_key| Some(PkarrPublisher::new(secret_key.clone(), url)));
        }

        if !self.no_dns_resolve {
            let domain = self
                .dns_origin_domain
                .unwrap_or_else(|| self.env.dns_origin_domain());
            builder = builder.add_discovery(|_| Some(DnsDiscovery::new(domain)));
        }

        #[cfg(feature = "discovery-local-network")]
        if self.mdns {
            builder = builder.add_discovery(|secret_key| {
                Some(
                    iroh::discovery::mdns::MdnsDiscovery::new(secret_key.public())
                        .expect("Failed to create mDNS discovery"),
                )
            });
        }

        #[cfg(feature = "test-utils")]
        if self.relay_only {
            builder = builder.path_selection(iroh::endpoint::PathSelection::RelayOnly)
        }

        if let Some(host) = self.dns_server {
            let addr = tokio::net::lookup_host(host)
                .await
                .context("Failed to resolve DNS server address")?
                .next()
                .context("Failed to resolve DNS server address")?;
            builder = builder.dns_resolver(DnsResolver::with_nameserver(addr));
        } else if self.env == Env::Dev {
            let addr = DEV_DNS_SERVER.parse().expect("valid addr");
            builder = builder.dns_resolver(DnsResolver::with_nameserver(addr));
        }

        let endpoint = builder.alpns(vec![TRANSFER_ALPN.to_vec()]).bind().await?;

        let node_id = endpoint.node_id();
        println!("Our node id:\n\t{node_id}");
        println!("Our direct addresses:");
        for local_endpoint in endpoint.direct_addresses().initialized().await? {
            println!("\t{} (type: {:?})", local_endpoint.addr, local_endpoint.typ)
        }
        if !self.no_relay {
            let relay_url = endpoint
                .home_relay()
                .get()?
                .context("Failed to resolve our home relay")?;
            println!("Our home relay server:\n\t{relay_url}");
        }

        println!();
        Ok(endpoint)
    }
}

async fn provide(endpoint: Endpoint, size: u64) -> Result<()> {
    let node_id = endpoint.node_id();

    let node_addr = endpoint.node_addr().initialized().await?;
    let ticket = NodeTicket::new(node_addr);
    println!("Ticket with our home relay and direct addresses:\n{ticket}\n",);

    let mut node_addr = endpoint.node_addr().initialized().await?;
    node_addr.direct_addresses = Default::default();
    let ticket = NodeTicket::new(node_addr);
    println!("Ticket with our home relay but no direct addresses:\n{ticket}\n",);

    let ticket = NodeTicket::new(NodeAddr::new(node_id));
    println!("Ticket with only our node id:\n{ticket}\n");

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
        // spawn a task to handle reading and writing off of the connection
        let endpoint_clone = endpoint.clone();
        tokio::spawn(async move {
            let conn = connecting.await.e()?;
            let node_id = conn.remote_node_id()?;
            info!(
                "new connection from {node_id} with ALPN {}",
                String::from_utf8_lossy(TRANSFER_ALPN),
            );

            let remote = node_id.fmt_short();
            println!("[{remote}] Connected");

            // Spawn a background task that prints connection type changes. Will be aborted on drop.
            let _guard = watch_conn_type(&endpoint_clone, node_id);

            // accept a bi-directional QUIC connection
            // use the `quinn` APIs to send and recv content
            let (mut send, mut recv) = conn.accept_bi().await.e()?;
            tracing::debug!("accepted bi stream, waiting for data...");
            let message = recv.read_to_end(100).await.e()?;
            let message = String::from_utf8(message).e()?;
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
                "[{remote}] Transferred {} in {:.4}s, {}/s",
                HumanBytes(size),
                duration.as_secs_f64(),
                HumanBytes((size as f64 / duration.as_secs_f64()) as u64)
            );
            if res.is_err() {
                println!("[{remote}] Did not disconnect within 3 seconds");
            } else {
                println!("[{remote}] Disconnected");
            }
            Ok::<_, n0_snafu::Error>(())
        });
    }

    // stop with SIGINT (ctrl-c)
    Ok(())
}

async fn fetch(endpoint: Endpoint, ticket: &str) -> Result<()> {
    let me = endpoint.node_id().fmt_short();
    let ticket: NodeTicket = ticket.parse()?;
    let remote_node_id = ticket.node_addr().node_id;
    let start = Instant::now();

    // Attempt to connect, over the given ALPN.
    // Returns a Quinn connection.
    let conn = endpoint
        .connect(NodeAddr::from(ticket), TRANSFER_ALPN)
        .await?;
    println!("Connected to {remote_node_id}");
    // Spawn a background task that prints connection type changes. Will be aborted on drop.
    let _guard = watch_conn_type(&endpoint, remote_node_id);

    // Use the Quinn API to send and recv content.
    let (mut send, mut recv) = conn.open_bi().await.e()?;

    let message = format!("{me} is saying hello!");
    send.write_all(message.as_bytes()).await.e()?;
    // Call `finish` to signal no more data will be sent on this stream.
    send.finish().e()?;
    println!("Sent: \"{message}\"");

    let (len, time_to_first_byte, chnk) = drain_stream(&mut recv, false).await?;

    // We received the last message: close all connections and allow for the close
    // message to be sent.
    tokio::time::timeout(Duration::from_secs(3), endpoint.close())
        .await
        .e()?;

    let duration = start.elapsed();
    println!(
        "Received {} in {:.4}s ({}/s, time to first byte {}s, {} chunks)",
        HumanBytes(len as u64),
        duration.as_secs_f64(),
        HumanBytes((len as f64 / duration.as_secs_f64()) as u64),
        time_to_first_byte.as_secs_f64(),
        chnk
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
        while let Some(chunk) = stream.read_chunk(usize::MAX, false).await.e()? {
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

        while let Some(n) = stream.read_chunks(&mut bufs[..]).await.e()? {
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

fn parse_byte_size(s: &str) -> std::result::Result<u64, parse_size::Error> {
    let cfg = parse_size::Config::new().with_binary();
    cfg.parse_size(s)
}

fn watch_conn_type(endpoint: &Endpoint, node_id: NodeId) -> AbortOnDropHandle<()> {
    let mut stream = endpoint.conn_type(node_id).unwrap().stream();
    let task = tokio::task::spawn(async move {
        while let Some(conn_type) = stream.next().await {
            println!(
                "[{}] Connection type changed to: {conn_type}",
                node_id.fmt_short()
            );
        }
    });
    AbortOnDropHandle::new(task)
}

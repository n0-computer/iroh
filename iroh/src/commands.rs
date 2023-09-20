use std::str::FromStr;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use comfy_table::presets::NOTHING;
use comfy_table::{Cell, Table};
use futures::stream::BoxStream;
use futures::StreamExt;
use human_time::ToHumanTimeString;
use iroh::client::quic::{Iroh, RpcClient};
use iroh::dial::Ticket;
use iroh::rpc_protocol::*;
use iroh_bytes::util::RpcError;
use iroh_bytes::{protocol::RequestToken, util::runtime, Hash};
use iroh_net::{
    key::{PublicKey, SecretKey},
    magic_endpoint::ConnectionInfo,
};
use quic_rpc::client::StreamingResponseItemError;
use quic_rpc::transport::ConnectionErrors;

use crate::commands::sync::fmt_short;
use crate::config::{ConsoleEnv, NodeConfig};

use self::provide::{ProvideOptions, ProviderRpcPort};
use self::sync::{AuthorCommands, DocCommands};

const DEFAULT_RPC_PORT: u16 = 0x1337;
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;

pub mod add;
pub mod delete;
pub mod doctor;
pub mod get;
pub mod list;
pub mod provide;
pub mod repl;
pub mod sync;
pub mod validate;

/// Iroh is a tool for syncing bytes.
/// https://iroh.computer/docs
#[derive(Parser, Debug, Clone)]
#[clap(version, verbatim_doc_comment)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,

    #[clap(flatten)]
    #[clap(next_help_heading = "Options for console, doc, author, blob, node")]
    pub rpc_args: RpcArgs,

    #[clap(flatten)]
    #[clap(next_help_heading = "Options for start, get, doctor")]
    pub full_args: FullArgs,
}

/// Options for commands that talk to a running Iroh node over RPC
#[derive(Args, Debug, Clone)]
pub struct RpcArgs {
    /// RPC port of the Iroh node
    #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
    pub rpc_port: u16,
}

/// Options for commands that may start an Iroh node
#[derive(Args, Debug, Clone)]
pub struct FullArgs {
    /// Log SSL pre-master key to file in SSLKEYLOGFILE environment variable.
    #[clap(long)]
    pub keylog: bool,
    /// Bind address on which to serve Prometheus metrics
    #[cfg(feature = "metrics")]
    #[clap(long)]
    pub metrics_addr: Option<SocketAddr>,
    #[clap(long)]
    pub cfg: Option<PathBuf>,
}

impl Cli {
    pub async fn run(self, rt: &runtime::Handle) -> Result<()> {
        match self.command {
            Commands::Console => {
                let client = iroh::client::quic::connect_raw(self.rpc_args.rpc_port).await?;
                let env = ConsoleEnv::for_console()?;
                repl::run(client, env).await
            }
            Commands::Rpc(command) => {
                let client = iroh::client::quic::connect_raw(self.rpc_args.rpc_port).await?;
                let env = ConsoleEnv::for_cli()?;
                command.run(client, env).await
            }
            Commands::Full(command) => {
                let FullArgs {
                    cfg,
                    metrics_addr,
                    keylog,
                } = self.full_args;

                let config = NodeConfig::from_env(cfg.as_deref())?;

                #[cfg(feature = "metrics")]
                let metrics_fut = start_metrics_server(metrics_addr, rt);

                let res = command.run(rt, &config, keylog).await;

                #[cfg(feature = "metrics")]
                if let Some(metrics_fut) = metrics_fut {
                    metrics_fut.abort();
                }

                res
            }
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub enum Commands {
    /// Start the Iroh console
    Console,
    #[clap(flatten)]
    Full(#[clap(subcommand)] FullCommands),
    #[clap(flatten)]
    Rpc(#[clap(subcommands)] RpcCommands),
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug, Clone)]
pub enum FullCommands {
    /// Start a Iroh node
    ///
    /// If PATH is a folder all files in that folder will be served.  If no PATH is
    /// specified reads from STDIN.
    Start {
        /// Path to initial file or directory to provide
        path: Option<PathBuf>,
        /// Serve data in place
        ///
        /// Set this to true only if you are sure that the data in its current location
        /// will not change.
        #[clap(long, default_value_t = false)]
        in_place: bool,
        #[clap(long, short)]
        /// Listening address to bind to
        #[clap(long, short, default_value_t = SocketAddr::from(iroh::node::DEFAULT_BIND_ADDR))]
        addr: SocketAddr,
        /// RPC port, set to "disabled" to disable RPC
        #[clap(long, default_value_t = ProviderRpcPort::Enabled(DEFAULT_RPC_PORT))]
        rpc_port: ProviderRpcPort,
        /// Use a token to authenticate requests for data
        ///
        /// Pass "random" to generate a random token, or base32-encoded bytes to use as a token
        #[clap(long)]
        request_token: Option<RequestTokenOptions>,

        #[clap(long)]
        tag: Option<String>,
    },
    /// Fetch data from a provider
    ///
    /// Starts a temporary Iroh node and fetches the content identified by HASH.
    Get {
        /// The hash to retrieve, as a Blake3 CID
        #[clap(conflicts_with = "ticket", required_unless_present = "ticket")]
        hash: Option<Hash>,
        /// PublicKey of the provider
        #[clap(
            long,
            short,
            conflicts_with = "ticket",
            required_unless_present = "ticket"
        )]
        peer: Option<PublicKey>,
        /// Addresses of the provider
        #[clap(long, short)]
        addrs: Vec<SocketAddr>,
        /// base32-encoded Request token to use for authentication, if any
        #[clap(long)]
        token: Option<RequestToken>,
        /// DERP region of the provider
        #[clap(long)]
        region: Option<u16>,
        /// Directory in which to save the file(s), defaults to writing to STDOUT
        ///
        /// If the directory exists and contains a partial download, the download will
        /// be resumed.
        ///
        /// Otherwise, all files in the collection will be overwritten. Other files
        /// in the directory will be left untouched.
        #[clap(long, short)]
        out: Option<PathBuf>,
        #[clap(conflicts_with_all = &["hash", "peer", "addrs", "token"])]
        /// Ticket containing everything to retrieve the data from a provider.
        #[clap(long)]
        ticket: Option<Ticket>,
        /// True to download a single blob, false (default) to download a collection and its children.
        #[clap(long, default_value_t = false)]
        single: bool,
    },
    /// Diagnostic commands for the derp relay protocol.
    Doctor {
        /// Commands for doctor - defined in the mod
        #[clap(subcommand)]
        command: self::doctor::Commands,
    },
}

impl FullCommands {
    pub async fn run(self, rt: &runtime::Handle, config: &NodeConfig, keylog: bool) -> Result<()> {
        match self {
            FullCommands::Start {
                path,
                in_place,
                addr,
                rpc_port,
                request_token,
                tag,
            } => {
                let request_token = match request_token {
                    Some(RequestTokenOptions::Random) => Some(RequestToken::generate()),
                    Some(RequestTokenOptions::Token(token)) => Some(token),
                    None => None,
                };
                self::provide::run(
                    rt,
                    path,
                    in_place,
                    tag.map(String::into_bytes),
                    ProvideOptions {
                        addr,
                        rpc_port,
                        keylog,
                        request_token,
                        derp_map: config.derp_map()?,
                        gc_period: config.gc_period,
                    },
                )
                .await
            }
            FullCommands::Get {
                hash,
                peer,
                addrs,
                region,
                ticket,
                token,
                out,
                single,
            } => {
                let get = if let Some(ticket) = ticket {
                    self::get::GetInteractive {
                        rt: rt.clone(),
                        hash: ticket.hash(),
                        opts: ticket.as_get_options(SecretKey::generate(), config.derp_map()?),
                        token: ticket.token().cloned(),
                        single: !ticket.recursive(),
                    }
                } else if let (Some(peer), Some(hash)) = (peer, hash) {
                    self::get::GetInteractive {
                        rt: rt.clone(),
                        hash,
                        opts: iroh::dial::Options {
                            addrs,
                            peer_id: peer,
                            keylog,
                            derp_region: region,
                            derp_map: config.derp_map()?,
                            secret_key: SecretKey::generate(),
                        },
                        token,
                        single,
                    }
                } else {
                    anyhow::bail!("Either ticket or hash and peer must be specified")
                };
                tokio::select! {
                    biased;
                    res = get.get_interactive(out) => res,
                    _ = tokio::signal::ctrl_c() => {
                        println!("Ending transfer early...");
                        Ok(())
                    }
                }
            }
            FullCommands::Doctor { command } => self::doctor::run(command, config).await,
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RpcCommands {
    /// Manage documents
    Doc {
        #[clap(subcommand)]
        command: DocCommands,
    },

    /// Manage document authors
    Author {
        #[clap(subcommand)]
        command: AuthorCommands,
    },
    /// Manage blobs
    Blob {
        #[clap(subcommand)]
        command: BlobCommands,
    },
    /// Manage a running Iroh node
    Node {
        #[clap(subcommand)]
        command: NodeCommands,
    },
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum NodeCommands {
    /// Get information about the different connections we have made
    Connections,
    /// Get connection information about a particular node
    Connection { node_id: PublicKey },
    /// Get status of the running node.
    Status,
    /// Get statistics and metrics from the running node.
    Stats,
    /// Shutdown the running node.
    Shutdown {
        /// Shutdown mode.
        ///
        /// Hard shutdown will immediately terminate the process, soft shutdown will wait
        /// for all connections to close.
        #[clap(long, default_value_t = false)]
        force: bool,
    },
}

impl NodeCommands {
    pub async fn run(self, client: RpcClient) -> Result<()> {
        match self {
            Self::Connections => {
                let connections = client.server_streaming(ConnectionsRequest).await?;
                println!("{}", fmt_connections(connections).await);
            }
            Self::Connection { node_id } => {
                let conn_info = client
                    .rpc(ConnectionInfoRequest { node_id })
                    .await??
                    .conn_info;
                match conn_info {
                    Some(info) => println!("{}", fmt_connection(info)),
                    None => println!("Not Found"),
                }
            }
            Self::Shutdown { force } => {
                client.rpc(ShutdownRequest { force }).await?;
            }
            Self::Stats => {
                let response = client.rpc(StatsGetRequest {}).await??;
                for (name, details) in response.stats.iter() {
                    println!(
                        "{:23} : {:>6}    ({})",
                        name, details.value, details.description
                    );
                }
            }
            Self::Status => {
                let response = client.rpc(StatusRequest).await?;

                println!("Listening addresses: {:#?}", response.listen_addrs);
                println!("PeerID: {}", response.peer_id);
            }
        }
        Ok(())
    }
}

impl RpcCommands {
    pub async fn run(self, client: RpcClient, env: ConsoleEnv) -> Result<()> {
        let iroh = Iroh::new(client.clone());
        match self {
            Self::Node { command } => command.run(client).await,
            Self::Blob { command } => command.run(client).await,
            Self::Doc { command } => command.run(&iroh, env).await,
            Self::Author { command } => command.run(&iroh, env).await,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug, Clone)]
pub enum BlobCommands {
    /// Add data from PATH to the running provider's database.
    Add {
        /// The path to the file or folder to add
        path: PathBuf,
        /// Add in place
        ///
        /// Set this to true only if you are sure that the data in its current location
        /// will not change.
        #[clap(long, default_value_t = false)]
        in_place: bool,
        /// Tag to store the data under
        #[clap(long)]
        tag: Option<String>,
    },
    /// Download data to the running provider's database and provide it.
    ///
    /// In addition to downloading the data, you can also specify an optional output directory
    /// where the data will be exported to after it has been downloaded.
    Share {
        /// Hash to get, required unless ticket is specified
        #[clap(long, conflicts_with = "ticket", required_unless_present = "ticket")]
        hash: Option<Hash>,
        /// treat as collection, required unless ticket is specified
        #[clap(long, conflicts_with = "ticket", required_unless_present = "ticket")]
        recursive: Option<bool>,
        /// PublicKey of the provider
        #[clap(
            long,
            short,
            conflicts_with = "ticket",
            required_unless_present = "ticket"
        )]
        peer: Option<PublicKey>,
        /// Addresses of the provider
        #[clap(
            long,
            short,
            conflicts_with = "ticket",
            required_unless_present = "ticket"
        )]
        addr: Vec<SocketAddr>,
        /// base32-encoded Request token to use for authentication, if any
        #[clap(long, conflicts_with = "ticket")]
        token: Option<RequestToken>,
        /// base32-encoded Request token to use for authentication, if any
        #[clap(long, conflicts_with = "ticket")]
        derp_region: Option<u16>,
        #[clap(long, conflicts_with_all = &["peer", "hash", "recursive"])]
        ticket: Option<Ticket>,
        /// Directory in which to save the file(s)
        #[clap(long, short)]
        out: Option<PathBuf>,
        /// If this is set to true, the data will be moved to the output directory,
        /// and iroh will assume that it will not change.
        #[clap(long, default_value_t = false)]
        stable: bool,
        /// Tag to store the data under
        #[clap(long)]
        tag: Option<String>,
    },
    /// List availble content on the node.
    #[clap(subcommand)]
    Delete(self::delete::Commands),
    /// List availble content on the node.
    #[clap(subcommand)]
    List(self::list::Commands),
    /// Validate hashes on the running node.
    Validate {
        /// Repair the store by removing invalid data
        #[clap(long, default_value_t = false)]
        repair: bool,
    },
}

impl BlobCommands {
    pub async fn run(self, client: RpcClient) -> Result<()> {
        match self {
            Self::Share {
                hash,
                recursive,
                peer,
                addr,
                token,
                ticket,
                derp_region,
                mut out,
                stable: in_place,
                tag,
            } => {
                if let Some(out) = out.as_mut() {
                    tracing::info!("canonicalizing output path");
                    let absolute = std::env::current_dir()?.join(&out);
                    tracing::info!("output path is {} -> {}", out.display(), absolute.display());
                    *out = absolute;
                }
                let (peer, addr, token, derp_region, hash, recursive) =
                    if let Some(ticket) = ticket.as_ref() {
                        (
                            ticket.peer(),
                            ticket.addrs().to_vec(),
                            ticket.token(),
                            ticket.derp_region(),
                            ticket.hash(),
                            ticket.recursive(),
                        )
                    } else {
                        (
                            peer.unwrap(),
                            addr,
                            token.as_ref(),
                            derp_region,
                            hash.unwrap(),
                            recursive.unwrap_or_default(),
                        )
                    };
                let mut stream = client
                    .server_streaming(ShareRequest {
                        hash,
                        recursive,
                        peer,
                        addrs: addr,
                        derp_region,
                        token: token.cloned(),
                        out: out.map(|x| x.display().to_string()),
                        in_place,
                        tag: tag.map(|x| x.into_bytes()),
                    })
                    .await?;
                while let Some(item) = stream.next().await {
                    let item = item?;
                    println!("{:?}", item);
                }
                Ok(())
            }
            Self::List(cmd) => cmd.run(client).await,
            Self::Delete(cmd) => cmd.run(client).await,
            Self::Validate { repair } => self::validate::run(client, repair).await,
            Self::Add {
                path,
                in_place,
                tag,
            } => self::add::run(client, path, in_place, tag.map(String::into_bytes)).await,
        }
    }
}

#[cfg(feature = "metrics")]
pub fn start_metrics_server(
    metrics_addr: Option<SocketAddr>,
    rt: &iroh_bytes::util::runtime::Handle,
) -> Option<tokio::task::JoinHandle<()>> {
    // doesn't start the server if the address is None
    if let Some(metrics_addr) = metrics_addr {
        // metrics are initilaized in iroh::node::Node::spawn
        // here we only start the server
        return Some(rt.main().spawn(async move {
            if let Err(e) = iroh_metrics::metrics::start_metrics_server(metrics_addr).await {
                eprintln!("Failed to start metrics server: {e}");
            }
        }));
    }
    tracing::info!("Metrics server not started, no address provided");
    None
}

#[derive(Debug, Clone)]
pub enum RequestTokenOptions {
    Random,
    Token(RequestToken),
}

impl FromStr for RequestTokenOptions {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.to_lowercase().trim() == "random" {
            return Ok(Self::Random);
        }
        let token = RequestToken::from_str(s)?;
        Ok(Self::Token(token))
    }
}

fn bold_cell(s: &str) -> Cell {
    Cell::new(s).add_attribute(comfy_table::Attribute::Bold)
}

async fn fmt_connections<C: ConnectionErrors>(
    mut infos: BoxStream<
        'static,
        Result<Result<ConnectionsResponse, RpcError>, StreamingResponseItemError<C>>,
    >,
) -> String {
    let mut table = Table::new();
    table.load_preset(NOTHING).set_header(
        vec!["node id", "region", "conn type", "latency"]
            .into_iter()
            .map(bold_cell),
    );
    while let Some(Ok(Ok(ConnectionsResponse { conn_info }))) = infos.next().await {
        let node_id = conn_info.public_key.to_string();
        let region = conn_info
            .derp_region
            .map_or(String::new(), |region| region.to_string());
        let conn_type = conn_info.conn_type.to_string();
        let latency = match conn_info.latency {
            Some(latency) => latency.to_human_time_string(),
            None => String::from("unknown"),
        };
        table.add_row(vec![node_id, region, conn_type, latency]);
    }
    table.to_string()
}

fn fmt_connection(info: ConnectionInfo) -> String {
    format!(
        "node_id: {}\nderp_region: {}\nconnection type: {}\nlatency: {}\n\n{}",
        fmt_short(info.public_key),
        info.derp_region
            .map_or(String::from("unknown"), |r| r.to_string()),
        info.conn_type,
        fmt_latency(info.latency),
        fmt_addrs(info.addrs)
    )
}

fn fmt_addrs(addrs: Vec<(SocketAddr, Option<Duration>)>) -> String {
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_header(vec!["addr", "latency"].into_iter().map(bold_cell));
    for addr in addrs {
        table.add_row(vec![addr.0.to_string(), fmt_latency(addr.1)]);
    }
    table.to_string()
}

fn fmt_latency(latency: Option<Duration>) -> String {
    match latency {
        Some(latency) => latency.to_human_time_string(),
        None => String::from("unknown"),
    }
}

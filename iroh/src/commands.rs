use std::collections::BTreeMap;
use std::str::FromStr;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::Result;
use bytes::Bytes;
use clap::{Args, Parser, Subcommand};
use comfy_table::presets::NOTHING;
use comfy_table::{Cell, Table};
use console::style;
use futures::{Stream, StreamExt};
use human_time::ToHumanTimeString;
use indicatif::{
    HumanBytes, HumanDuration, ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle,
};
use iroh::client::quic::Iroh;
use iroh::dial::Ticket;
use iroh::rpc_protocol::*;
use iroh_bytes::util::{BlobFormat, SetTagOption, Tag};
use iroh_bytes::{protocol::RequestToken, util::runtime, Hash};
use iroh_net::PeerAddr;
use iroh_net::{
    key::{PublicKey, SecretKey},
    magic_endpoint::ConnectionInfo,
};

use crate::commands::sync::fmt_short;
use crate::config::{ConsoleEnv, NodeConfig};

use self::add::{BlobSource, TicketOption};
use self::node::{RpcPort, StartOptions};
use self::sync::{AuthorCommands, DocCommands};

const DEFAULT_RPC_PORT: u16 = 0x1337;
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;

pub mod add;
pub mod delete;
pub mod doctor;
pub mod get;
pub mod list;
pub mod node;
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
                let iroh = iroh::client::quic::connect(self.rpc_args.rpc_port).await?;
                let env = ConsoleEnv::for_console()?;
                repl::run(&iroh, &env).await
            }
            Commands::Rpc(command) => {
                let iroh = iroh::client::quic::connect(self.rpc_args.rpc_port).await?;
                let env = ConsoleEnv::for_cli()?;
                command.run(&iroh, &env).await
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
        #[clap(long, default_value_t = RpcPort::Enabled(DEFAULT_RPC_PORT))]
        rpc_port: RpcPort,
        /// Use a token to authenticate requests for data
        ///
        /// Pass "random" to generate a random token, or base32-encoded bytes to use as a token
        #[clap(long)]
        request_token: Option<RequestTokenOptions>,
        /// Tag to tag the data with
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
        /// If set assume that the hash refers to a collection and download it with all children.
        #[clap(long, default_value_t = false)]
        collection: bool,
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
                let tag = match tag {
                    Some(tag) => SetTagOption::Named(Tag::from(tag)),
                    None => SetTagOption::Auto,
                };
                self::node::run(
                    rt,
                    path,
                    in_place,
                    tag,
                    StartOptions {
                        addr,
                        rpc_port,
                        keylog,
                        request_token,
                        derp_map: config.derp_map()?,
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
                collection,
            } => {
                let get = if let Some(ticket) = ticket {
                    self::get::GetInteractive {
                        rt: rt.clone(),
                        hash: ticket.hash(),
                        opts: ticket.as_get_options(SecretKey::generate(), config.derp_map()?),
                        token: ticket.token().cloned(),
                        format: ticket.format(),
                    }
                } else if let (Some(peer), Some(hash)) = (peer, hash) {
                    let format = match collection {
                        true => BlobFormat::COLLECTION,
                        false => BlobFormat::RAW,
                    };
                    self::get::GetInteractive {
                        rt: rt.clone(),
                        hash,
                        opts: iroh::dial::Options {
                            peer: PeerAddr::from_parts(peer, region, addrs),
                            keylog,
                            derp_map: config.derp_map()?,
                            secret_key: SecretKey::generate(),
                        },
                        token,
                        format,
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
    /// Manage a running Iroh node
    Tag {
        #[clap(subcommand)]
        command: TagCommands,
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
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Connections => {
                let connections = iroh.node.connections().await?;
                println!("{}", fmt_connections(connections).await);
            }
            Self::Connection { node_id } => {
                let conn_info = iroh.node.connection_info(node_id).await?;
                match conn_info {
                    Some(info) => println!("{}", fmt_connection(info)),
                    None => println!("Not Found"),
                }
            }
            Self::Shutdown { force } => {
                iroh.node.shutdown(force).await?;
            }
            Self::Stats => {
                let stats = iroh.node.stats().await?;
                for (name, details) in stats.iter() {
                    println!(
                        "{:23} : {:>6}    ({})",
                        name, details.value, details.description
                    );
                }
            }
            Self::Status => {
                let response = iroh.node.status().await?;
                println!("Listening addresses: {:#?}", response.listen_addrs);
                println!("Node public key: {}", response.addr.peer_id);
                println!("Version: {}", response.version);
            }
        }
        Ok(())
    }
}

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum TagCommands {
    /// List all tags
    List,
    /// Delete a tag
    Delete {
        tag: String,
        #[clap(long, default_value_t = false)]
        hex: bool,
    },
}

impl TagCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::List => {
                let mut response = iroh.tags.list().await?;
                while let Some(res) = response.next().await {
                    let res = res?;
                    println!("{}: {} ({:?})", res.name, res.hash, res.format,);
                }
            }
            Self::Delete { tag, hex } => {
                let tag = if hex {
                    Tag::from(Bytes::from(hex::decode(tag)?))
                } else {
                    Tag::from(tag)
                };
                iroh.tags.delete(tag).await?;
            }
        }
        Ok(())
    }
}

impl RpcCommands {
    pub async fn run(self, iroh: &Iroh, env: &ConsoleEnv) -> Result<()> {
        match self {
            Self::Node { command } => command.run(iroh).await,
            Self::Blob { command } => command.run(iroh).await,
            Self::Doc { command } => command.run(iroh, env).await,
            Self::Author { command } => command.run(iroh, env).await,
            Self::Tag { command } => command.run(iroh).await,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug, Clone)]
pub enum BlobCommands {
    /// Add data from PATH to the running provider's database.
    Add {
        /// The path to the file or folder to add.
        ///
        /// If no path is specified, data will be read from STDIN.
        path: Option<PathBuf>,
        /// Add in place
        ///
        /// Set this to true only if you are sure that the data in its current location
        /// will not change.
        #[clap(long, default_value_t = false)]
        in_place: bool,
        /// Tag to tag the data with
        #[clap(long)]
        tag: Option<String>,
        /// Print an all-in-one ticket to get the added data from this node.
        #[clap(long)]
        ticket: bool,
    },
    /// Download data to the running provider's database and provide it.
    ///
    /// In addition to downloading the data, you can also specify an optional output directory
    /// where the data will be exported to after it has been downloaded.
    Download {
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
        /// Tag to tag the data with
        #[clap(long)]
        tag: Option<String>,
    },
    /// List availble content on the node.
    #[clap(subcommand)]
    List(self::list::Commands),
    /// Validate hashes on the running node.
    Validate {
        /// Repair the store by removing invalid data
        #[clap(long, default_value_t = false)]
        repair: bool,
    },
    /// Delete content on the node.
    #[clap(subcommand)]
    Delete(self::delete::Commands),
}

impl BlobCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Download {
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
                let (peer, hash, format, token) = if let Some(ticket) = ticket {
                    ticket.into_parts()
                } else {
                    let format = match recursive {
                        Some(false) | None => BlobFormat::RAW,
                        Some(true) => BlobFormat::COLLECTION,
                    };
                    (
                        PeerAddr::from_parts(peer.unwrap(), derp_region, addr),
                        hash.unwrap(),
                        format,
                        token,
                    )
                };
                let out = match out {
                    None => DownloadLocation::Internal,
                    Some(path) => DownloadLocation::External {
                        path: path.display().to_string(),
                        in_place,
                    },
                };
                let tag = match tag {
                    Some(tag) => SetTagOption::Named(Tag::from(tag)),
                    None => SetTagOption::Auto,
                };
                let mut stream = iroh
                    .blobs
                    .download(BlobDownloadRequest {
                        hash,
                        format,
                        peer,
                        token,
                        out,
                        tag,
                    })
                    .await?;

                show_download_progress(hash, &mut stream).await?;
                Ok(())
            }
            Self::List(cmd) => cmd.run(iroh).await,
            Self::Delete(cmd) => cmd.run(iroh).await,
            Self::Validate { repair } => self::validate::run(iroh, repair).await,
            Self::Add {
                path,
                in_place,
                tag,
                ticket,
            } => {
                let tag = match tag {
                    Some(tag) => SetTagOption::Named(Tag::from(tag)),
                    None => SetTagOption::Auto,
                };
                let ticket = match ticket {
                    false => TicketOption::None,
                    // TODO: This is where we are missing the request token from the running
                    // node.
                    true => TicketOption::Print(None),
                };
                let source = BlobSource::from_path_or_stdin(path, in_place, true);
                self::add::run(iroh, source, tag, ticket).await
            }
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

async fn fmt_connections(
    mut infos: impl Stream<Item = Result<ConnectionInfo, anyhow::Error>> + Unpin,
) -> String {
    let mut table = Table::new();
    table.load_preset(NOTHING).set_header(
        vec!["node id", "region", "conn type", "latency"]
            .into_iter()
            .map(bold_cell),
    );
    while let Some(Ok(conn_info)) = infos.next().await {
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

const PROGRESS_STYLE: &str =
    "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})";

fn make_download_pb() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.set_draw_target(ProgressDrawTarget::stderr());
    pb.enable_steady_tick(std::time::Duration::from_millis(50));
    pb.set_style(
        ProgressStyle::with_template(PROGRESS_STYLE)
            .unwrap()
            .with_key(
                "eta",
                |state: &ProgressState, w: &mut dyn std::fmt::Write| {
                    write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
                },
            )
            .progress_chars("#>-"),
    );
    pb
}

fn init_download_progress(pb: &ProgressBar, count: u64, missing_bytes: u64) -> Result<()> {
    pb.set_message(format!(
        "{} Downloading {} file(s) with total transfer size {}",
        style("[3/3]").bold().dim(),
        count,
        HumanBytes(missing_bytes),
    ));
    pb.set_length(missing_bytes);
    pb.reset();

    Ok(())
}

pub async fn show_download_progress(
    hash: Hash,
    mut stream: impl Stream<Item = Result<GetProgress>> + Unpin,
) -> Result<()> {
    eprintln!("Fetching: {}", hash);
    let pb = make_download_pb();
    pb.set_message(format!("{} Connecting ...", style("[1/3]").bold().dim()));
    let mut sizes = BTreeMap::new();
    while let Some(x) = stream.next().await {
        match x? {
            GetProgress::Connected => {
                pb.set_message(format!("{} Requesting ...", style("[2/3]").bold().dim()));
            }
            GetProgress::FoundCollection {
                total_blobs_size,
                num_blobs,
                ..
            } => {
                init_download_progress(
                    &pb,
                    num_blobs.unwrap_or_default(),
                    total_blobs_size.unwrap_or_default(),
                )?;
            }
            GetProgress::Found { id, size, .. } => {
                sizes.insert(id, (size, 0));
            }
            GetProgress::Progress { id, offset } => {
                if let Some((_, current)) = sizes.get_mut(&id) {
                    *current = offset;
                    let total = sizes.values().map(|(_, current)| current).sum::<u64>();
                    pb.set_position(total);
                }
            }
            GetProgress::Done { id } => {
                if let Some((size, current)) = sizes.get_mut(&id) {
                    *current = *size;
                    let total = sizes.values().map(|(_, current)| current).sum::<u64>();
                    pb.set_position(total);
                }
            }
            GetProgress::NetworkDone {
                bytes_read,
                elapsed,
                ..
            } => {
                pb.finish_and_clear();
                eprintln!(
                    "Transferred {} in {}, {}/s",
                    HumanBytes(bytes_read),
                    HumanDuration(elapsed),
                    HumanBytes((bytes_read as f64 / elapsed.as_secs_f64()) as u64)
                );
            }
            GetProgress::AllDone => {
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

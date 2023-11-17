use std::str::FromStr;
use std::{net::SocketAddr, path::PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use console::style;
use futures::{Stream, StreamExt};
use indicatif::{
    HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressState,
    ProgressStyle,
};
use iroh::rpc_protocol::*;
use iroh::ticket::blob::Ticket;
use iroh_bytes::{protocol::RequestToken, util::runtime, Hash};
use iroh_net::key::PublicKey;

use crate::config::{get_iroh_data_root_with_env, ConsoleEnv, NodeConfig};

use self::blob::{BlobAddOptions, DownloadOpts};
use self::get::GetArgs;
use self::node::StartOptions;
use self::rpc::{RpcCommands, RpcStatus};

const DEFAULT_RPC_PORT: u16 = 0x1337;
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;

pub mod author;
pub mod blob;
pub mod doc;
pub mod doctor;
pub mod get;
pub mod node;
pub mod repl;
pub mod tag;

mod rpc;

/// iroh is a tool for syncing bytes
/// https://iroh.computer/docs
#[derive(Parser, Debug, Clone)]
#[clap(version, verbatim_doc_comment)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,

    #[clap(flatten)]
    #[clap(next_help_heading = "Options for start, get, doctor")]
    pub full_args: FullArgs,
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

    /// RPC port of the Iroh node.
    #[clap(long, global = true, default_value_t = DEFAULT_RPC_PORT)]
    pub rpc_port: u16,
}

async fn iroh_quic_connect(rt: runtime::Handle) -> Result<iroh::client::quic::Iroh> {
    let root = get_iroh_data_root_with_env()?;
    let rpc_status = RpcStatus::load(root).await?;
    match rpc_status {
        RpcStatus::Stopped => {
            bail!("iroh is not running, please start it");
        }
        RpcStatus::Running(rpc_port) => {
            let iroh = iroh::client::quic::connect(rpc_port, Some(rt))
                .await
                .context("quic::connect")?;
            Ok(iroh)
        }
    }
}

impl Cli {
    pub async fn run(self, rt: runtime::Handle) -> Result<()> {
        match self.command {
            Commands::Console => {
                let iroh = iroh_quic_connect(rt).await.context("rpc connect")?;
                let env = ConsoleEnv::for_console()?;
                repl::run(&iroh, &env).await
            }
            Commands::Rpc(command) => {
                let iroh = iroh_quic_connect(rt).await.context("rpc connect")?;
                let env = ConsoleEnv::for_cli()?;
                command.run(&iroh, &env).await
            }
            Commands::Full(command) => {
                let FullArgs {
                    cfg,
                    metrics_addr,
                    keylog,
                    rpc_port,
                } = self.full_args;

                let config = NodeConfig::from_env(cfg.as_deref())?;

                #[cfg(feature = "metrics")]
                let metrics_fut = start_metrics_server(metrics_addr, &rt);

                let res = command.run(&rt, &config, keylog, rpc_port).await;

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
    /// Open the iroh console
    ///
    /// The console is a REPL for interacting with a running iroh node.
    /// For more info on available commands, see https://iroh.computer/docs/api
    Console,
    #[clap(flatten)]
    Full(#[clap(subcommand)] FullCommands),
    #[clap(flatten)]
    Rpc(#[clap(subcommands)] RpcCommands),
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug, Clone)]
pub enum FullCommands {
    /// Start an iroh node
    ///
    /// A node is a long-running process that serves data and connects to other nodes.
    /// The console, doc, author, blob, node, and tag commands require a running node.
    ///
    /// start optionally takes a PATH argument, which can be a file or a folder to serve on startup.
    /// If PATH is a folder all files in that folder will be served. If no PATH is specified start
    /// reads from STDIN.
    /// Data can be added after startup with commands like `iroh blob add`
    /// or by adding content to documents.
    Start {
        /// Listening address to bind to
        #[clap(long, short, default_value_t = SocketAddr::from(iroh::node::DEFAULT_BIND_ADDR))]
        addr: SocketAddr,
        /// Use a token to authenticate requests for data
        ///
        /// Pass "random" to generate a random token, or base32-encoded bytes to use as a token
        #[clap(long)]
        request_token: Option<RequestTokenOptions>,

        /// Add data when starting the node
        #[clap(flatten)]
        add_options: BlobAddOptions,
    },
    /// Fetch data from a provider
    ///
    /// Fetches the content identified by HASH.
    /// `iroh start` does not need to be running to use `iroh get`. Get starts a temporary iroh
    /// node to fetch the data, and shuts it down when done.
    Get(GetArgs),
    /// Diagnostic commands for the derp relay protocol.
    Doctor {
        /// Commands for doctor - defined in the mod
        #[clap(subcommand)]
        command: self::doctor::Commands,
    },
}

impl FullCommands {
    pub async fn run(
        self,
        rt: &runtime::Handle,
        config: &NodeConfig,
        keylog: bool,
        rpc_port: u16,
    ) -> Result<()> {
        match self {
            FullCommands::Start {
                addr,
                request_token,
                add_options,
            } => {
                let request_token = match request_token {
                    Some(RequestTokenOptions::Random) => Some(RequestToken::generate()),
                    Some(RequestTokenOptions::Token(token)) => Some(token),
                    None => None,
                };
                self::node::run(
                    rt,
                    StartOptions {
                        addr,
                        rpc_port,
                        keylog,
                        request_token,
                        derp_map: config.derp_map()?,
                    },
                    add_options,
                )
                .await
            }
            FullCommands::Get(get) => get.run(config, rt, keylog).await,
            FullCommands::Doctor { command } => self::doctor::run(command, config).await,
        }
    }
}

/// An argument that can be either "none" or a value of type `T`.
#[derive(Debug, Clone)]
pub enum Optional<T: FromStr> {
    None,
    Some(T),
}

impl<T: FromStr> FromStr for Optional<T> {
    type Err = <T as FromStr>::Err;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            _ => T::from_str(s).map(Self::Some),
        }
    }
}

// Helper struct to model a ticket or the arguments that would make a ticket. This works as a
// subcommand.
#[derive(Subcommand, Debug, Clone)]
pub enum TicketOrArgs {
    /// Use a blob ticket to download the data.
    #[command(arg_required_else_help = true)]
    Ticket {
        /// Ticket to use.
        ticket: Ticket,
        /// Additonal socket address to use to contact the node. Can be used multiple times.
        #[clap(long)]
        address: Vec<SocketAddr>,
        /// Override the Derp region to use to contact the node.
        #[clap(long, value_name = "\"none\" | DERP_REGION")]
        derp_region: Option<Optional<u16>>,
        /// Override to treat the blob as a raw blob or a hash sequence.
        #[clap(long)]
        recursive: Option<bool>,
        /// Override the ticket token.
        #[clap(long, value_name = "\"none\" | TOKEN")]
        request_token: Option<Optional<RequestToken>>,
        /// If set, the ticket's direct addresses will not be used.
        #[clap(long)]
        override_addresses: bool,
        #[command(flatten)]
        ops: DownloadOpts,
    },
    /// Supply the content and node-addressing information directly to perform a download.
    #[command(arg_required_else_help = true)]
    Hash {
        /// Hash of the content to download.
        hash: Hash,
        /// NodeId of the provider.
        #[clap(long, required = true)]
        node: PublicKey,
        /// Additonal socket address to use to contact the node. Can be used multiple times.
        /// Necessary if no derp region provided.
        #[clap(long, required_unless_present = "derp_region")]
        address: Vec<SocketAddr>,
        /// Derp region to use to contact the node. Necessary if no addresses provided.
        #[clap(long, required_unless_present = "address")]
        derp_region: Option<u16>,
        /// Whether to treat the blob as a raw blob or a hash sequence.
        #[clap(long)]
        recursive: bool,
        /// Token to use.
        #[clap(long)]
        request_token: Option<RequestToken>,
        #[command(flatten)]
        ops: DownloadOpts,
    },
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

fn make_overall_progress() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template(
            "{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );
    pb
}

fn make_individual_progress() -> ProgressBar {
    let pb = ProgressBar::hidden();
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_style(
        ProgressStyle::with_template("{msg}{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
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

pub async fn show_download_progress(
    hash: Hash,
    mut stream: impl Stream<Item = Result<DownloadProgress>> + Unpin,
) -> Result<()> {
    eprintln!("Fetching: {}", hash);
    let mp = MultiProgress::new();
    mp.set_draw_target(ProgressDrawTarget::stderr());
    let op = mp.add(make_overall_progress());
    let ip = mp.add(make_individual_progress());
    op.set_message(format!("{} Connecting ...\n", style("[1/3]").bold().dim()));
    let mut seq = false;
    while let Some(x) = stream.next().await {
        match x? {
            DownloadProgress::Connected => {
                op.set_message(format!("{} Requesting ...\n", style("[2/3]").bold().dim()));
            }
            DownloadProgress::FoundHashSeq { children, .. } => {
                op.set_message(format!(
                    "{} Downloading {} blob(s)\n",
                    style("[3/3]").bold().dim(),
                    children + 1,
                ));
                op.set_length(children + 1);
                op.reset();
                seq = true;
            }
            DownloadProgress::Found { size, child, .. } => {
                if seq {
                    op.set_position(child);
                } else {
                    op.finish_and_clear();
                }
                ip.set_length(size);
                ip.reset();
            }
            DownloadProgress::Progress { offset, .. } => {
                ip.set_position(offset);
            }
            DownloadProgress::Done { .. } => {
                ip.finish_and_clear();
            }
            DownloadProgress::NetworkDone {
                bytes_read,
                elapsed,
                ..
            } => {
                op.finish_and_clear();
                eprintln!(
                    "Transferred {} in {}, {}/s",
                    HumanBytes(bytes_read),
                    HumanDuration(elapsed),
                    HumanBytes((bytes_read as f64 / elapsed.as_secs_f64()) as u64)
                );
            }
            DownloadProgress::AllDone => {
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

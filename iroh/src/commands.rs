use std::str::FromStr;
use std::{net::SocketAddr, path::PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use iroh_bytes::{protocol::RequestToken, util::runtime};

use crate::config::{get_iroh_data_root_with_env, ConsoleEnv, NodeConfig};

use self::rpc::{RpcCommands, RpcStatus};
use self::start::StartArgs;

const DEFAULT_RPC_PORT: u16 = 0x1337;
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u64 = 1024;

pub mod author;
pub mod blob;
pub mod doc;
pub mod doctor;
pub mod node;
pub mod repl;
pub mod start;
pub mod tag;

mod rpc;

/// iroh is a tool for syncing bytes
/// https://iroh.computer/docs
#[derive(Parser, Debug, Clone)]
#[clap(version, verbatim_doc_comment)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,

    /// Path to the configuration file.
    #[clap(long)]
    pub config: Option<PathBuf>,

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
                let config = NodeConfig::from_env(self.config.as_deref())?;

                #[cfg(feature = "metrics")]
                let metrics_fut = start_metrics_server(config.metrics_addr, &rt);

                let res = command.run(&rt, &config, self.rpc_port).await;

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
    Start(StartArgs),
    /// Diagnostic commands for the derp relay protocol.
    Doctor {
        /// Commands for doctor - defined in the mod
        #[clap(subcommand)]
        command: self::doctor::Commands,
    },
}

impl FullCommands {
    pub async fn run(self, rt: &runtime::Handle, config: &NodeConfig, rpc_port: u16) -> Result<()> {
        match self {
            FullCommands::Start(start_args) => start_args.run(rt, config, rpc_port).await,
            FullCommands::Doctor { command } => self::doctor::run(command, config).await,
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

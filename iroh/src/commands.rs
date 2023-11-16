use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use iroh_bytes::{protocol::RequestToken, util::runtime};

use crate::config::{iroh_data_root, ConsoleEnv, NodeConfig};

use self::blob::{BlobAddOptions, BlobSource};
use self::rpc::{RpcCommands, RpcStatus};
use self::start::{RunType, StartArgs};

pub mod author;
pub mod blob;
pub mod console;
pub mod doc;
pub mod doctor;
pub mod node;
pub mod rpc;
pub mod start;
pub mod tag;

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

    /// Start an iroh node in the background.
    #[clap(long, global = true)]
    start: bool,

    #[clap(flatten)]
    start_args: StartArgs,
}

#[derive(Parser, Debug, Clone)]
pub enum Commands {
    /// Start an iroh node
    ///
    /// A node is a long-running process that serves data and connects to other nodes.
    /// The console, doc, author, blob, node, and tag commands require a running node.
    ///
    /// start optionally takes a `--add SOURCE` option, which can be a file or a folder
    /// to serve on startup. Data can also be added after startup with commands like
    /// `iroh blob add` or by adding content to documents.
    Start {
        /// Execute console commands on the running node
        ///
        /// All commands expect `start`, `console`, and `doctor` are valid.
        #[clap(short, long)]
        exec: Vec<String>,

        /// Optionally add a file or folder to the node.
        ///
        /// If set to `STDIN`, the data will be read from stdin.
        ///
        /// When left empty no content is added.
        #[clap(long)]
        add: Option<BlobSource>,

        /// Options when adding data.
        #[clap(flatten)]
        add_options: BlobAddOptions,
    },

    /// Open the iroh console
    ///
    /// The console is a REPL for interacting with a running iroh node.
    /// For more info on available commands, see https://iroh.computer/docs/api
    Console,

    #[clap(flatten)]
    Rpc(#[clap(subcommand)] RpcCommands),

    /// Diagnostic commands for the derp relay protocol.
    Doctor {
        /// Commands for doctor - defined in the mod
        #[clap(subcommand)]
        command: self::doctor::Commands,
    },
}

impl Cli {
    pub async fn run(self, rt: runtime::Handle) -> Result<()> {
        match self.command {
            Commands::Console => {
                let env = ConsoleEnv::for_console()?;
                if self.start {
                    let config = NodeConfig::from_env(self.config.as_deref())?;
                    self.start_args
                        .run_with_command(&rt, &config, RunType::SingleCommand, |iroh| async move {
                            console::run(&iroh, &env).await
                        })
                        .await
                } else {
                    let iroh = iroh_quic_connect(rt).await.context("rpc connect")?;
                    console::run(&iroh, &env).await
                }
            }
            Commands::Rpc(command) => {
                let env = ConsoleEnv::for_cli()?;
                if self.start {
                    let config = NodeConfig::from_env(self.config.as_deref())?;
                    self.start_args
                        .run_with_command(&rt, &config, RunType::SingleCommand, |iroh| async move {
                            command.run(&iroh, &env).await
                        })
                        .await
                } else {
                    let iroh = iroh_quic_connect(rt).await.context("rpc connect")?;
                    command.run(&iroh, &env).await
                }
            }
            Commands::Start {
                add,
                add_options,
                exec,
            } => {
                // if adding data on start, exit early if the path doesn't exist
                if let Some(BlobSource::Path(ref path)) = add {
                    ensure!(
                        path.exists(),
                        "Cannot provide nonexistent path: {}",
                        path.display()
                    );
                }
                let config = NodeConfig::from_env(self.config.as_deref())?;

                let add_command = add.map(|source| blob::BlobCommands::Add {
                    source,
                    options: add_options,
                });

                self.start_args
                    .run_with_command(&rt, &config, RunType::UntilStopped, |client| async move {
                        if let Some(command) = add_command {
                            command.run(&client).await?;
                        }
                        if !exec.is_empty() {
                            let env = ConsoleEnv::for_cli()?;
                            for line in exec {
                                let cmd = console::try_parse_cmd::<RpcCommands>(&line)
                                    .with_context(|| {
                                        format!("Failed to parse --exec command `{line}`")
                                    })?;
                                cmd.run(&client, &env).await?;
                            }
                        }
                        Ok(())
                    })
                    .await
            }
            Commands::Doctor { command } => {
                let config = NodeConfig::from_env(self.config.as_deref())?;
                self::doctor::run(command, &config).await
            }
        }
    }
}

async fn iroh_quic_connect(rt: runtime::Handle) -> Result<iroh::client::quic::Iroh> {
    let root = iroh_data_root()?;
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

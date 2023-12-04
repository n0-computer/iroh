use std::path::PathBuf;

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use iroh_sync::NamespaceId;
use tokio_util::task::LocalPoolHandle;

use crate::config::{iroh_data_root, ConsoleEnv, NodeConfig};

use self::blob::{BlobAddOptions, BlobSource};
use self::rpc::{RpcCommands, RpcStatus};
use self::runtime::IrohWrapper;
use self::start::RunType;

pub mod author;
pub mod blob;
pub mod console;
pub mod doc;
pub mod doctor;
pub mod mount;
mod mount_runner;
pub mod node;
pub mod rpc;
pub mod runtime;
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
    Runtime {
        path: PathBuf,
    },
    Mount {
        /// The document to mount.
        #[clap(long)]
        doc: NamespaceId,
        /// Mount target.
        path: PathBuf,
    },
}

impl Cli {
    pub async fn run(self, rt: LocalPoolHandle) -> Result<()> {
        match self.command {
            Commands::Console => {
                let env = ConsoleEnv::for_console()?;
                if self.start {
                    let config = NodeConfig::from_env(self.config.as_deref())?;
                    start::run_with_command(
                        &rt,
                        &config,
                        RunType::SingleCommand,
                        |iroh| async move { console::run(&iroh, &env).await },
                    )
                    .await
                } else {
                    let iroh = iroh_quic_connect().await.context("rpc connect")?;
                    console::run(&iroh, &env).await
                }
            }
            Commands::Rpc(command) => {
                let env = ConsoleEnv::for_cli()?;
                if self.start {
                    let config = NodeConfig::from_env(self.config.as_deref())?;
                    start::run_with_command(
                        &rt,
                        &config,
                        RunType::SingleCommand,
                        |iroh| async move { command.run(&iroh, &env).await },
                    )
                    .await
                } else {
                    let iroh = iroh_quic_connect().await.context("rpc connect")?;
                    command.run(&iroh, &env).await
                }
            }
            Commands::Start { add, add_options } => {
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

                start::run_with_command(&rt, &config, RunType::UntilStopped, |client| async move {
                    match add_command {
                        None => Ok(()),
                        Some(command) => command.run(&client).await,
                    }
                })
                .await
            }
            Commands::Doctor { command } => {
                let config = NodeConfig::from_env(self.config.as_deref())?;
                self::doctor::run(command, &config).await
            }
            Commands::Runtime { path } => {
                let _env = ConsoleEnv::for_cli()?;
                if self.start {
                    let config = NodeConfig::from_env(self.config.as_deref())?;
                    start::run_with_command(
                        &rt,
                        &config,
                        RunType::SingleCommand,
                        |iroh| async move {
                            self::runtime::exec(IrohWrapper::Mem(iroh.clone()), path).await
                        },
                    )
                    .await
                } else {
                    let iroh = iroh_quic_connect().await.context("rpc connect")?;
                    self::runtime::exec(IrohWrapper::Quic(iroh), path).await
                }
            }
            Commands::Mount { doc, path } => {
                let _env = ConsoleEnv::for_cli()?;
                if self.start {
                    let config = NodeConfig::from_env(self.config.as_deref())?;
                    let lt = rt.clone();
                    start::run_with_command(
                        &rt,
                        &config,
                        RunType::SingleCommand,
                        move |iroh| async move { self::mount::exec(&iroh, doc, path, lt).await },
                    )
                    .await
                } else {
                    let iroh = iroh_quic_connect().await.context("rpc connect")?;
                    self::mount::exec(&iroh, doc, path, rt).await
                }
            }
        }
    }
}

async fn iroh_quic_connect() -> Result<iroh::client::quic::Iroh> {
    let root = iroh_data_root()?;
    let rpc_status = RpcStatus::load(root).await?;
    match rpc_status {
        RpcStatus::Stopped => {
            bail!("iroh is not running, please start it");
        }
        RpcStatus::Running(rpc_port) => {
            let iroh = iroh::client::quic::connect(rpc_port)
                .await
                .context("quic::connect")?;
            Ok(iroh)
        }
    }
}

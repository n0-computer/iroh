use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use clap::Parser;
use derive_more::FromStr;
use iroh::client::Iroh;

use crate::config::{ConsoleEnv, NodeConfig};

use self::blobs::{BlobAddOptions, BlobSource};
use self::rpc::RpcCommands;
use self::start::RunType;

pub(crate) mod authors;
pub(crate) mod blobs;
pub(crate) mod console;
pub(crate) mod docs;
pub(crate) mod doctor;
pub(crate) mod gossip;
pub(crate) mod node;
pub(crate) mod rpc;
pub(crate) mod start;
pub(crate) mod tags;

/// iroh is a tool for building distributed apps
/// https://iroh.computer/docs
#[derive(Parser, Debug, Clone)]
#[clap(version, verbatim_doc_comment)]
pub(crate) struct Cli {
    #[clap(subcommand)]
    pub(crate) command: Commands,

    /// Path to the configuration file, see https://iroh.computer/docs/reference/config.
    #[clap(long)]
    pub(crate) config: Option<PathBuf>,

    /// Start an iroh node in the background.
    #[clap(long, global = true)]
    start: bool,

    /// Port to serve metrics on. Disabled by default.
    #[clap(long)]
    pub(crate) metrics_port: Option<MetricsPort>,

    /// Address to serve RPC on.
    #[clap(long)]
    pub(crate) rpc_addr: Option<SocketAddr>,

    /// Write metrics in CSV format at 100ms intervals. Disabled by default.
    #[clap(long)]
    pub(crate) metrics_dump_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) enum MetricsPort {
    Disabled,
    Port(u16),
}

impl FromStr for MetricsPort {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.to_ascii_lowercase() == "disabled" {
            Ok(MetricsPort::Disabled)
        } else {
            let port = s.parse()?;
            Ok(MetricsPort::Port(port))
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub(crate) enum Commands {
    /// Start an iroh node
    ///
    /// A node is a long-running process that serves data and connects to other nodes.
    /// The console, doc, author, blob, node, and tag commands require a running node.
    ///
    /// start optionally takes a `--add SOURCE` option, which can be a file or a folder
    /// to serve on startup. Data can also be added after startup with commands like
    /// `iroh blob add` or by adding content to documents.
    ///
    /// For general configuration options see <https://iroh.computer/docs/reference/config>.
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
    ///
    /// For general configuration options see <https://iroh.computer/docs/reference/config>.
    Console,

    #[clap(flatten)]
    Rpc(#[clap(subcommand)] RpcCommands),

    /// Diagnostic commands for the relay protocol.
    Doctor {
        /// Commands for doctor - defined in the mod
        #[clap(subcommand)]
        command: self::doctor::Commands,
    },
}

impl Cli {
    pub(crate) async fn run(self, data_dir: &Path) -> Result<()> {
        // Initialize the metrics collection.
        //
        // The metrics are global per process. Subsequent calls do not change the metrics
        // collection and will return an error. We ignore this error. This means that if you'd
        // spawn multiple Iroh nodes in the same process, the metrics would be shared between the
        // nodes.
        #[cfg(feature = "metrics")]
        iroh::metrics::try_init_metrics_collection().ok();

        match self.command {
            Commands::Console => {
                let data_dir_owned = data_dir.to_owned();
                if self.start {
                    let config = Self::load_config(self.config, self.metrics_port).await?;
                    start::run_with_command(
                        &config,
                        data_dir,
                        self.rpc_addr,
                        RunType::SingleCommandNoAbort,
                        |iroh| async move {
                            let env = ConsoleEnv::for_console(data_dir_owned, &iroh).await?;
                            console::run(&iroh, &env).await
                        },
                    )
                    .await
                } else {
                    crate::logging::init_terminal_logging()?;
                    let iroh = if let Some(addr) = self.rpc_addr {
                        Iroh::connect_addr(addr).await.context("rpc connect")?
                    } else {
                        Iroh::connect_path(data_dir).await.context("rpc connect")?
                    };
                    let env = ConsoleEnv::for_console(data_dir_owned, &iroh).await?;
                    console::run(&iroh, &env).await
                }
            }
            Commands::Rpc(command) => {
                let data_dir_owned = data_dir.to_owned();
                if self.start {
                    let config = Self::load_config(self.config, self.metrics_port).await?;
                    start::run_with_command(
                        &config,
                        data_dir,
                        self.rpc_addr,
                        RunType::SingleCommandAbortable,
                        move |iroh| async move {
                            let env = ConsoleEnv::for_cli(data_dir_owned, &iroh).await?;
                            command.run(&iroh, &env).await
                        },
                    )
                    .await
                } else {
                    crate::logging::init_terminal_logging()?;
                    let iroh = if let Some(addr) = self.rpc_addr {
                        Iroh::connect_addr(addr).await.context("rpc connect")?
                    } else {
                        Iroh::connect_path(data_dir).await.context("rpc connect")?
                    };
                    let env = ConsoleEnv::for_cli(data_dir_owned, &iroh).await?;
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
                let config = Self::load_config(self.config, self.metrics_port).await?;

                let add_command = add.map(|source| blobs::BlobCommands::Add {
                    source,
                    options: add_options,
                });

                start::run_with_command(
                    &config,
                    data_dir,
                    self.rpc_addr,
                    RunType::UntilStopped,
                    |client| async move {
                        match add_command {
                            None => Ok(()),
                            Some(command) => command.run(&client).await,
                        }
                    },
                )
                .await
            }
            Commands::Doctor { command } => {
                let config = Self::load_config(self.config, self.metrics_port).await?;
                self::doctor::run(command, &config).await
            }
        }
    }

    async fn load_config(
        config: Option<PathBuf>,
        metrics_port: Option<MetricsPort>,
    ) -> Result<NodeConfig> {
        let mut config = NodeConfig::load(config.as_deref()).await?;
        if let Some(metrics_port) = metrics_port {
            config.metrics_addr = match metrics_port {
                MetricsPort::Disabled => None,
                MetricsPort::Port(port) => Some(([127, 0, 0, 1], port).into()),
            };
        }
        Ok(config)
    }
}

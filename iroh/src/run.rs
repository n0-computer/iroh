use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(feature = "testing")]
use crate::fixture::get_fixture_api;
use crate::p2p::{run_command as run_p2p_command, P2p};
use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh_api::{Api, ApiExt, IpfsPath, Iroh};
use iroh_metrics::config::Config as MetricsConfig;

#[derive(Parser, Debug, Clone)]
#[clap(version, long_about = None, propagate_version = true)]
#[clap(about = "A next generation IPFS implementation: https://iroh.computer")]
#[clap(
    after_help = "Iroh is a next-generation implementation the Interplanetary File System (IPFS).
IPFS is a networking protocol for exchanging content-addressed blocks of
immutable data. 'content-addressed' means referring to data by the hash of it's
content, which makes the reference both unique and verifiable. These two
properties make it possible to get data from any node in the network that speaks
the IPFS protocol, including IPFS content being served by other implementations
of the protocol.

For more info see https://iroh.computer/docs"
)]
pub struct Cli {
    #[clap(long)]
    cfg: Option<PathBuf>,
    /// Do not track metrics
    #[clap(long)]
    no_metrics: bool,
    #[clap(subcommand)]
    command: Commands,
}

impl Cli {
    fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("metrics.debug".to_string(), (self.no_metrics).to_string());
        map
    }
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    // status checks the health of the different processes
    #[clap(about = "Check the health of the different iroh processes.")]
    #[clap(
        after_help = "status reports the current operational setup of iroh. Use status as a go-to
command for understanding where iroh commands are being processed. different
ops configurations utilize different network and service implementations
under the hood, which can lead to varying performance characteristics.

Status reports connectivity, which is either offline or online:

  offline: iroh is not connected to any background process, all commands
           are one-off, any network connections are closed when a command
           completes. Some network duties may be delegated to remote hosts.

  online:  iroh has found a long-running process to issue commands to. Any
           comand issued will be deletegated to the long-running process as a
           remote procedure call

If iroh is online, status also reports the service configuration of the
long running process, including the health of the configured subsystem(s).
Possible configurations fall into two buckets:

  one:     Iroh is running with all services bundled into one single process,
           this setup is common in desktop enviornments.

  cloud:   Iroh is running with services split into separate processes, which
           are speaking to each other via remote procedure calls.

Use the --watch flag to continually poll for changes.

Status reports no metrics about the running system aside from current service
health. Instead all metrics are emitted through uniform tracing collection &
reporting, which is intended to be consumed by tools like prometheus and
grafana. For more info on metrics collection, see
https://iroh.computer/docs/metrics"
    )]
    Status {
        #[clap(short, long)]
        /// Poll process for changes
        watch: bool,
    },
    P2p(P2p),
    #[clap(about = "Add a file or directory to iroh & make it available on IPFS")]
    Add {
        /// The path to a file or directory to be added
        path: PathBuf,
        /// Required to add a directory
        #[clap(long, short)]
        recursive: bool,
        /// Do not wrap added content with a directory
        #[clap(long)]
        no_wrap: bool,
    },
    #[clap(about = "Fetch IPFS content and write it to disk")]
    #[clap(
        after_help = "Download file or directory specified by <ipfs-path> from IPFS into [path]. If
path already exists and is a file then it's overwritten with the new downloaded
file. If path already exists and is a directory, the command fails with an
error. If path already exists, is a file and the downloaded data is a directory,
that's an error.

By default, the output will be written to the working directory. If no file or
directory name can be derived from the <ipfs-path>, the output will be written
to the given path's CID.

If <ipfs-path> is already present in the iroh store, no network call will
be made."
    )]
    Get {
        /// CID or CID/with/path/qualifier to get
        ipfs_path: IpfsPath,
        /// filesystem path to write to. Optional and defaults to $CID
        output: Option<PathBuf>,
    },
}

impl Cli {
    // Rust analyzer sees this function as unused, because in development
    // mode the `testing` feature is enabled. This needs to be done in order
    // to compile the CLI with the testing feature, which is needed to create
    // trycmd tests.
    #[cfg(not(feature = "testing"))]
    pub async fn run(&self) -> Result<()> {
        // extracted the function body into its own function so it's
        // not all considered unused
        self.run_impl().await
    }

    // this version of the CLI runs in testing mode only
    #[cfg(feature = "testing")]
    pub async fn run(&self) -> Result<()> {
        let api = get_fixture_api();
        self.cli_command(&api).await
    }

    // this is a separate function and marked `allow[unused]` so
    // that we don't get Rust analyzer unused code warnings, which we do get if
    // we inline this code inside of run.
    #[allow(unused)]
    async fn run_impl(&self) -> Result<()> {
        let metrics_handler = iroh_metrics::MetricsHandle::new(MetricsConfig::default())
            .await
            .expect("failed to initialize metrics");

        let api = Iroh::new(self.cfg.as_deref(), self.make_overrides_map()).await?;

        self.cli_command(&api).await?;

        metrics_handler.shutdown();

        Ok(())
    }

    async fn cli_command(&self, api: &impl Api) -> Result<()> {
        match &self.command {
            Commands::Status { watch } => {
                crate::status::status(api, *watch).await?;
            }
            Commands::P2p(p2p) => run_p2p_command(&api.p2p()?, p2p).await?,
            Commands::Add {
                path,
                recursive,
                no_wrap,
            } => {
                let cid = api.add(path, *recursive, *no_wrap).await?;
                println!("/ipfs/{}", cid);
            }
            Commands::Get {
                ipfs_path: path,
                output,
            } => {
                let root_path = api.get(path, output.as_deref()).await?;
                println!("Saving file(s) to {}", root_path.to_str().unwrap());
            }
        };

        Ok(())
    }
}

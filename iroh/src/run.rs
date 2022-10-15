use std::collections::HashMap;
use std::path::PathBuf;

use crate::doc;
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
#[clap(after_help = doc::IROH_LONG_DESCRIPTION)]
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
    #[clap(after_help = doc::STATUS_LONG_DESCRIPTION)]
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
    #[clap(after_help = doc::GET_LONG_DESCRIPTION )]
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

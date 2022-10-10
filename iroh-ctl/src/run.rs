use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(feature = "testing")]
use crate::fixture::get_fixture_api;
use crate::p2p::{run_command as run_p2p_command, P2p};
use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh::{Api, CidOrDomain, IpfsPath, Iroh};
use iroh_metrics::config::Config as MetricsConfig;

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None, propagate_version = true)]
pub struct Cli {
    #[clap(long)]
    cfg: Option<PathBuf>,
    /// Track metrics
    #[clap(long, action = clap::ArgAction::Set, default_value_t=true)]
    metrics: bool,
    #[clap(subcommand)]
    command: Commands,
}

impl Cli {
    fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("metrics.debug".to_string(), (!self.metrics).to_string());
        map
    }
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    // status checks the health of the different processes
    #[clap(about = "Check the health of the different iroh processes.")]
    Status {
        #[clap(short, long)]
        /// when true, updates the status table whenever a change in a process's status occurs
        watch: bool,
    },
    P2p(P2p),
    #[clap(about = "break up a file into block and provide those blocks on the ipfs network")]
    Add {
        path: PathBuf,
        #[clap(long, short)]
        recursive: bool,
        #[clap(long, short)]
        no_wrap: bool,
    },
    #[clap(
        about = "get content based on a Content Identifier from the ipfs network, and save it "
    )]
    Get {
        /// CID or CID/with/path/qualifier to get
        path: IpfsPath,
        /// filesystem path to write to. Defaults to CID
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
            Commands::Get { path, output } => {
                let cid = if let CidOrDomain::Cid(cid) = path.root() {
                    cid
                } else {
                    return Err(anyhow::anyhow!("ipfs path must refer to a CID"));
                };
                api.get(path, output.as_deref()).await?;
                let real_output = output
                    .as_deref()
                    .map(|path| path.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from(&cid.to_string()));
                println!("Saving file(s) to {}", real_output.to_str().unwrap());
            }
        };

        Ok(())
    }
}

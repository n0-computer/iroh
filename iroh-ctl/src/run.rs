use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use crate::config::{Config, CONFIG_FILE_NAME, ENV_PREFIX};
#[cfg(feature = "testing")]
use crate::fixture::get_fixture_api;
use crate::{
    gateway::{run_command as run_gateway_command, Gateway},
    p2p::{run_command as run_p2p_command, P2p},
    store::{run_command as run_store_command, Store},
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh::{Api, Iroh};
use iroh_metrics::config::Config as MetricsConfig;
use iroh_resolver::resolver;
use iroh_rpc_client::Client;
use iroh_util::{iroh_config_path, make_config};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None, propagate_version = true)]
pub struct Cli {
    #[clap(long)]
    cfg: Option<PathBuf>,
    #[clap(long = "no-metrics")]
    no_metrics: bool,
    #[clap(subcommand)]
    command: Commands,
}

impl Cli {
    fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("metrics.debug".to_string(), self.no_metrics.to_string());
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
    Version,
    P2p(P2p),
    Store(Store),
    Gateway(Gateway),
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
        path: resolver::Path,
        #[clap(long, short)]
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

    #[cfg(feature = "testing")]
    pub async fn run(&self) -> Result<()> {
        let api = get_fixture_api();
        self.cli_command(&api).await
    }

    // extracted this into function and marked it `pub` so that we don't get
    // Rust analyzer unused code warnings, which we do get if we inline
    // this code inside of run. `pub(crate)` unfortunately has the same effect.
    pub async fn run_impl(&self) -> Result<()> {
        let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
        let sources = vec![Some(cfg_path), self.cfg.clone()];
        let config = make_config(
            // default
            Config::default(),
            // potential config files
            sources,
            // env var prefix for this config
            ENV_PREFIX,
            // map of present command line arguments
            self.make_overrides_map(),
        )
        .unwrap();

        let metrics_handler = iroh_metrics::MetricsHandle::new(MetricsConfig::default())
            .await
            .expect("failed to initialize metrics");

        let client = Client::new(config.rpc_client).await?;

        let api = Iroh::new(&client);

        self.cli_command(&api).await?;

        metrics_handler.shutdown();

        Ok(())
    }

    async fn cli_command(&self, api: &impl Api) -> Result<()> {
        match &self.command {
            Commands::Status { watch } => {
                crate::status::status(api, *watch).await?;
            }
            Commands::Version => {
                println!("v{}", env!("CARGO_PKG_VERSION"));
            }
            Commands::P2p(p2p) => run_p2p_command(&api.p2p()?, p2p).await?,
            Commands::Store(store) => run_store_command(&api.store()?, store).await?,
            Commands::Gateway(gateway) => run_gateway_command(gateway).await?,
            Commands::Add {
                path,
                recursive,
                no_wrap,
            } => {
                let cid = api.add(path, *recursive, *no_wrap).await?;
                println!("/ipfs/{}", cid);
            }
            Commands::Get { path, output } => {
                api.get(path, output.as_deref()).await?;
            }
        };

        Ok(())
    }
}

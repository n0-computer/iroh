use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use cid::Cid;
use clap::{Parser, Subcommand};
use futures::Stream;
use futures::StreamExt;
use iroh_ctl::{
    gateway::{run_command as run_gateway_command, Gateway},
    p2p::{run_command as run_p2p_command, P2p},
    store::{run_command as run_store_command, Store},
};
use iroh_resolver::{
    resolver::{Out, OutMetrics},
    unixfs_builder,
};
use iroh_rpc_client::Client;
use iroh_util::{iroh_config_path, make_config};

use iroh_ctl::{
    config::{Config, CONFIG_FILE_NAME, ENV_PREFIX},
    status,
};

use iroh_metrics::config::Config as MetricsConfig;

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None, propagate_version = true)]
struct Cli {
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
    /// status checks the health of the different processes
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
        wrap: bool,
    },
    #[clap(
        about = "get content based on a Content Identifier from the ipfs network, and save it "
    )]
    Get {
        cid: Cid,
        #[clap(long, short)]
        output: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path), cli.cfg.clone()];
    let config = make_config(
        // default
        Config::default(),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        cli.make_overrides_map(),
    )
    .unwrap();

    let metrics_handle = iroh_metrics::MetricsHandle::new(MetricsConfig::default())
        .await
        .expect("failed to initialize metrics");

    let client = Client::new(config.rpc_client).await?;

    match cli.command {
        Commands::Status { watch } => {
            crate::status::status(client, watch).await?;
        }
        Commands::Version => {
            println!("v{}", env!("CARGO_PKG_VERSION"));
        }
        Commands::P2p(p2p) => run_p2p_command(client, p2p).await?,
        Commands::Store(store) => run_store_command(client, store).await?,
        Commands::Gateway(gateway) => run_gateway_command(client, gateway).await?,
        Commands::Add {
            path,
            recursive,
            wrap,
        } => {
            let providing_client = iroh_resolver::unixfs_builder::StoreAndProvideClient {
                client: Box::new(&client),
            };
            if path.is_dir() {
                let cid = unixfs_builder::add_dir(Some(&providing_client), &path, wrap, recursive)
                    .await?;
                println!("/ipfs/{}", cid);
            } else if path.is_file() {
                let cid = unixfs_builder::add_file(Some(&providing_client), &path, wrap).await?;
                println!("/ipfs/{}", cid);
            } else {
                anyhow::bail!("can only add files or directories");
            }
        }
        Commands::Get { cid, output } => {
            let blocks = get(client.clone(), cid, output).await;
            tokio::pin!(blocks);
            while let Some(block) = blocks.next().await {
                let (path, out) = block?;
                if out.is_dir() {
                    tokio::fs::create_dir_all(path).await?;
                } else {
                    let resolver = iroh_resolver::resolver::Resolver::new(client.clone());
                    let mut f = tokio::fs::File::create(path).await?;
                    let mut reader = out.pretty(resolver, OutMetrics::default())?;
                    tokio::io::copy(&mut reader, &mut f).await?;
                }
            }
        }
    };

    metrics_handle.shutdown();

    Ok(())
}

async fn get(
    client: Client,
    cid: Cid,
    outpath: Option<PathBuf>,
) -> impl Stream<Item = Result<(PathBuf, Out)>> {
    tracing::debug!(target: "resolve", "get cid {:?}", cid);
    let resolver = iroh_resolver::resolver::Resolver::new(client);
    resolver.resolve_recursive_with_filepaths(iroh_resolver::resolver::Path::from_cid(cid), outpath)
}

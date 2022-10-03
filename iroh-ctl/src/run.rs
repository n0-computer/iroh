use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use crate::{
    config::{Config, CONFIG_FILE_NAME, ENV_PREFIX},
    status,
};
use crate::{
    gateway::{run_command as run_gateway_command, Gateway},
    p2p::{run_command as run_p2p_command, P2p},
    store::{run_command as run_store_command, Store},
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh::api::{Api, ClientApi, MockApi};
use iroh::p2p;
use iroh::store;
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
    /// status checks the health of the different processes
    // #[clap(about = "Check the health of the different iroh processes.")]
    // Status {
    //     #[clap(short, long)]
    //     /// when true, updates the status table whenever a change in a process's status occurs
    //     watch: bool,
    // },
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

#[cfg(not(feature = "fake"))]
pub async fn run_cli(cli: Cli) -> Result<()> {
    run_cli_impl(cli).await
}

// extracted this into a public function so that we don't get a lot of
// rust analyzer unused code errors, which we do if we inline this code inside
// of run_cli
pub async fn run_cli_impl(cli: Cli) -> Result<()> {
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

    let metrics_handler = iroh_metrics::MetricsHandle::new(MetricsConfig::default())
        .await
        .expect("failed to initialize metrics");

    let client = Client::new(config.rpc_client).await?;

    let api = ClientApi::new(&client);

    run_cli_command(&api, cli).await?;

    metrics_handler.shutdown();

    Ok(())
}

type FixtureApi = MockApi;
type GetFixture = fn() -> FixtureApi;
type FixtureRegistry = HashMap<String, GetFixture>;

fn fixture_peer_ids() -> FixtureApi {
    let mut api = MockApi::default();
    api.expect_p2p().returning(|| {
        use libp2p::PeerId;
        let mut mock_p2p = p2p::MockP2p::default();

        mock_p2p.expect_peer_ids().returning(|| {
            let peer_id0 = PeerId::from_bytes(&[
                0, 32, 15, 231, 162, 148, 52, 155, 40, 187, 217, 170, 125, 185, 68, 142, 156, 196,
                145, 178, 64, 74, 19, 27, 9, 171, 111, 35, 88, 236, 103, 150, 96, 66,
            ])?;
            let peer_id1 = PeerId::from_bytes(&[
                0, 32, 144, 137, 53, 144, 57, 13, 191, 157, 254, 110, 136, 212, 131, 241, 179, 29,
                38, 29, 207, 62, 126, 215, 213, 49, 248, 43, 143, 40, 123, 93, 248, 222,
            ])?;
            Ok(vec![peer_id0, peer_id1])
        });
        Ok(mock_p2p)
    });
    api
}

#[cfg(feature = "fake")]
fn register_fixtures() -> FixtureRegistry {
    let mut registry = FixtureRegistry::new();
    registry.insert("peer_ids".to_string(), fixture_peer_ids);
    registry
}

#[cfg(feature = "fake")]
pub async fn run_cli(cli: Cli) -> Result<()> {
    let registry = register_fixtures();
    let fixture_name = env::var("IROH_CTL_FIXTURE").expect("IROH_CTL_FIXTURE must be set");
    let fixture = registry
        .get(&fixture_name)
        .unwrap_or_else(|| panic!("unknown fixture: {}", fixture_name));
    let api = fixture();
    run_cli_command(&api, cli).await
}

pub async fn run_cli_command(
    api: &impl Api<P = impl p2p::P2p, S = impl store::Store>,
    cli: Cli,
) -> Result<()> {
    match cli.command {
        // Commands::Status { watch } => {
        //     crate::status::status(client, watch).await?;
        // }
        Commands::Version => {
            println!("v{}", env!("CARGO_PKG_VERSION"));
        }
        Commands::P2p(p2p) => run_p2p_command(api.p2p()?, p2p).await?,
        Commands::Store(store) => run_store_command(api.store()?, store).await?,
        Commands::Gateway(gateway) => run_gateway_command(gateway).await?,
        Commands::Add {
            path,
            recursive,
            no_wrap,
        } => {
            let cid = api.add(&path, recursive, no_wrap).await?;
            println!("/ipfs/{}", cid);
        }
        Commands::Get { path, output } => {
            api.get(&path, output.as_deref()).await?;
        }
    };

    Ok(())
}

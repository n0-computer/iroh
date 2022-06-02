use std::path::PathBuf;

use clap::Parser;
use iroh_p2p::Libp2pConfig;
use iroh_p2p::{metrics, Libp2pService};
use iroh_util::{from_toml_file, iroh_home_path};
use libp2p::identity::{ed25519, Keypair};
use libp2p::metrics::Metrics;
use prometheus_client::registry::Registry;
use tokio::task;
use tracing::error;

const CONFIG: &str = "p2p.config.toml";

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long = "no-metrics")]
    no_metrics: bool,
    #[clap(long)]
    cfg: Option<PathBuf>,
}

/// Starts daemon process
#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut prom_registry = Registry::default();
    let libp2p_metrics = Metrics::new(&mut prom_registry);

    let version = option_env!("IROH_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));

    println!("Starting iroh-p2p, version {version}");

    // TODO: read keypair from disk
    // TODO: configurable keypair
    let net_keypair = {
        // Keypair not found, generate and save generated keypair
        let gen_keypair = ed25519::Keypair::generate();
        // TODO: Save Ed25519 keypair to file
        Keypair::Ed25519(gen_keypair)
    };

    // TODO: configurable network

    let network_config = {
        // pass in optional paths where we may be able to load a config file
        if let Some(cfg) = from_toml_file::<Libp2pConfig>(vec![args.cfg, iroh_home_path(CONFIG)]) {
            cfg?
            // flags should override config files
        } else {
            // otherwise, use a default
            Libp2pConfig::default()
        }
    };

    let mut p2p_service = Libp2pService::new(
        network_config,
        net_keypair,
        &mut prom_registry,
        libp2p_metrics,
    )
    .await?;

    let metrics_handle =
        iroh_metrics::init_with_registry(metrics::metrics_config(args.no_metrics), prom_registry)
            .await
            .expect("failed to initialize metrics");

    // Start services
    let p2p_task = task::spawn(async move {
        if let Err(err) = p2p_service.run().await {
            error!("{:?}", err);
        }
    });

    iroh_util::block_until_sigint().await;

    // Cancel all async services
    p2p_task.abort();

    metrics_handle.shutdown();
    Ok(())
}

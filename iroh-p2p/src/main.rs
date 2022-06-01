use std::path::Path;

use clap::Parser;
use dirs::home_dir;
use iroh_p2p::{metrics, Libp2pService};
use iroh_rpc_client::RpcClientConfig;
use libp2p::identity::{ed25519, Keypair};
use libp2p::metrics::Metrics;
use prometheus_client::registry::Registry;
use tokio::task;
use tracing::error;

const IROH_DIR: &str = ".iroh";
const CONFIG: &str = "p2p.config.toml";

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long = "no-metrics")]
    no_metrics: bool,
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

    let mut network_config = iroh_p2p::Libp2pConfig::default();

    if let Ok(rpc_client_config) = RpcClientConfig::from_file(Path::new(
        &home_dir()
            .expect("Error locating home directory.")
            .join(IROH_DIR)
            .join(CONFIG),
    )) {
        network_config.rpc_addr = rpc_client_config.p2p_addr;
        network_config.rpc_client = rpc_client_config;
    }

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

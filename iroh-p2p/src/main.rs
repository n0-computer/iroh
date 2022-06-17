use std::collections::HashMap;
use std::path::PathBuf;

use clap::Parser;
use iroh_p2p::config::{Libp2pConfig, CONFIG_FILE_NAME, ENV_PREFIX};
use iroh_p2p::{metrics, Libp2pService};
use iroh_util::{iroh_home_path, make_config};
use libp2p::metrics::Metrics;
use prometheus_client::registry::Registry;
use tokio::task;
use tracing::error;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long = "no-metrics")]
    no_metrics: bool,
    #[clap(long)]
    cfg: Option<PathBuf>,
}

impl Args {
    fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("metrics.debug".to_string(), self.no_metrics.to_string());
        map
    }
}

/// Starts daemon process
#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let version = option_env!("IROH_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
    println!("Starting iroh-p2p, version {version}");

    let args = Args::parse();

    // TODO: configurable network
    let sources = vec![iroh_home_path(CONFIG_FILE_NAME), args.cfg.clone()];
    let network_config = make_config(
        // default
        Libp2pConfig::default(),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .unwrap();

    let mut prom_registry = Registry::default();
    let libp2p_metrics = Metrics::new(&mut prom_registry);
    let metrics_config =
        metrics::metrics_config_with_compile_time_info(network_config.metrics.clone());
    iroh_metrics::init_tracer(metrics_config.clone()).expect("failed to initialize tracer");

    let mut p2p_service =
        Libp2pService::new(network_config, &mut prom_registry, libp2p_metrics).await?;

    let metrics_handle = iroh_metrics::MetricsHandle::from_registry(metrics_config, prom_registry)
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

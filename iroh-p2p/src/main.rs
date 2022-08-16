use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::anyhow;
use clap::Parser;
use iroh_p2p::config::{Config, CONFIG_FILE_NAME, ENV_PREFIX};
#[cfg(feature = "metrics")]
use iroh_p2p::metrics;
use iroh_p2p::{DiskStorage, Keychain, Node};
use iroh_util::{iroh_home_path, make_config};
#[cfg(feature = "metrics")]
use prometheus_client::registry::Registry;
use tokio::task;
use tracing::error;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long = "metrics")]
    #[cfg(feature = "metrics")]
    metrics: bool,
    #[clap(long = "tracing")]
    tracing: bool,
    #[clap(long)]
    cfg: Option<PathBuf>,
}

impl Args {
    fn make_overrides_map(&self) -> HashMap<String, String> {
        #[allow(unused_mut)]
        let mut map = HashMap::new();
        #[cfg(feature = "metrics")]
        map.insert("metrics.collect".to_string(), self.metrics.to_string());
        #[cfg(feature = "metrics")]
        map.insert("metrics.tracing".to_string(), self.tracing.to_string());
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
        Config::default_grpc(),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .unwrap();

    #[cfg(feature = "metrics")]
    let mut prom_registry = Registry::default();
    #[cfg(feature = "metrics")]
    let metrics_config =
        metrics::metrics_config_with_compile_time_info(network_config.metrics.clone());
    #[cfg(feature = "metrics")]
    iroh_metrics::init_tracer(metrics_config.clone()).expect("failed to initialize tracer");

    let kc = Keychain::<DiskStorage>::new().await?;
    let rpc_addr = network_config
        .server_rpc_addr()?
        .ok_or_else(|| anyhow!("missing p2p rpc addr"))?;
    let mut p2p = Node::new(
        network_config,
        rpc_addr,
        kc,
        #[cfg(feature = "metrics")]
        &mut prom_registry,
    )
    .await?;

    #[cfg(feature = "metrics")]
    let metrics_handle = iroh_metrics::MetricsHandle::from_registry(metrics_config, prom_registry)
        .await
        .expect("failed to initialize metrics");

    // Start services
    let p2p_task = task::spawn(async move {
        if let Err(err) = p2p.run().await {
            error!("{:?}", err);
        }
    });

    iroh_util::block_until_sigint().await;

    // Cancel all async services
    p2p_task.abort();

    #[cfg(feature = "metrics")]
    metrics_handle.shutdown();
    Ok(())
}

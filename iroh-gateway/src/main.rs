use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::Parser;
use iroh_gateway::{
    bad_bits::{self, BadBits},
    config::{Config, CONFIG_FILE_NAME, ENV_PREFIX},
    core::Core,
    metrics,
};
use iroh_metrics::gateway::Metrics;
use iroh_rpc_types::Addr;
use iroh_util::{iroh_home_path, make_config};
use prometheus_client::registry::Registry;
use tokio::sync::RwLock;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    port: Option<u16>,
    #[clap(short, long)]
    writeable: Option<bool>,
    #[clap(short, long)]
    fetch: Option<bool>,
    #[clap(short, long)]
    cache: Option<bool>,
    #[clap(long)]
    metrics: bool,
    #[clap(long)]
    tracing: bool,
    #[clap(long)]
    cfg: Option<PathBuf>,
    #[clap(long)]
    denylist: bool,
}

impl Args {
    fn make_overrides_map(&self) -> HashMap<&str, String> {
        let mut map: HashMap<&str, String> = HashMap::new();
        if let Some(port) = self.port {
            map.insert("port", port.to_string());
        }
        if let Some(writable) = self.writeable {
            map.insert("writable", writable.to_string());
        }
        if let Some(fetch) = self.fetch {
            map.insert("fetch", fetch.to_string());
        }
        if let Some(cache) = self.cache {
            map.insert("cache", cache.to_string());
        }
        map.insert("denylist", self.denylist.to_string());
        map.insert("metrics.collect", self.metrics.to_string());
        map.insert("metrics.tracing", self.tracing.to_string());
        map
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    let sources = vec![iroh_home_path(CONFIG_FILE_NAME), args.cfg.clone()];
    let mut config = make_config(
        // default
        Config::default(),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .unwrap();

    // When running in ipfsd mode, update the rpc client config to setup
    // memory addresses for the p2p and store modules.
    #[cfg(feature = "ipfsd")]
    let (store_rpc, p2p_rpc) = {
        let (store_recv, store_sender) = Addr::new_mem();
        config.rpc_client.store_addr = Some(store_sender);
        let store_rpc = iroh_gateway::mem_store::start(store_recv).await?;

        let (p2p_recv, p2p_sender) = Addr::new_mem();
        config.rpc_client.p2p_addr = Some(p2p_sender);
        let p2p_rpc = iroh_gateway::mem_p2p::start(p2p_recv).await?;
        (store_rpc, p2p_rpc)
    };

    config.metrics = metrics::metrics_config_with_compile_time_info(config.metrics);
    println!("{:#?}", config);

    let metrics_config = config.metrics.clone();
    let mut prom_registry = Registry::default();
    let gw_metrics = Metrics::new(&mut prom_registry);
    let bad_bits = match config.denylist {
        true => Arc::new(Some(RwLock::new(BadBits::new()))),
        false => Arc::new(None),
    };
    let rpc_addr = config
        .server_rpc_addr()?
        .ok_or_else(|| anyhow!("missing gateway rpc addr"))?;
    let handler = Core::new(
        config,
        rpc_addr,
        gw_metrics,
        &mut prom_registry,
        Arc::clone(&bad_bits),
    )
    .await?;

    let bad_bits_handle = bad_bits::spawn_bad_bits_updater(Arc::clone(&bad_bits));

    let metrics_handle =
        iroh_metrics::MetricsHandle::from_registry_with_tracer(metrics_config, prom_registry)
            .await
            .expect("failed to initialize metrics");
    let server = handler.server();
    println!("listening on {}", server.local_addr());
    let core_task = tokio::spawn(async move {
        server.await.unwrap();
    });

    iroh_util::block_until_sigint().await;

    #[cfg(feature = "ipfsd")]
    {
        store_rpc.abort();
        p2p_rpc.abort();
    }

    core_task.abort();

    metrics_handle.shutdown();
    if let Some(handle) = bad_bits_handle {
        handle.abort();
    }

    Ok(())
}

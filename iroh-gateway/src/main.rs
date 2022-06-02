use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use iroh_gateway::{
    config::{Config, RpcConfig},
    core::Core,
    metrics,
};
use iroh_metrics::gateway::Metrics;
use iroh_util::{from_toml_file, iroh_home_path};
use prometheus_client::registry::Registry;

const CONFIG: &str = "gateway.config.toml";

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
    #[clap(long = "no-metrics")]
    no_metrics: bool,
    #[clap(long)]
    cfg: Option<PathBuf>,
}

impl Args {
    fn override_config(&self, mut cfg: Config) -> Config {
        if self.port.is_some() {
            cfg.port = self.port.unwrap();
        };
        if self.writeable.is_some() {
            cfg.writeable = self.writeable.unwrap();
        };
        if self.fetch.is_some() {
            cfg.fetch = self.fetch.unwrap();
        };
        if self.cache.is_some() {
            cfg.cache = self.cache.unwrap();
        };
        if self.port.is_some() {
            cfg.port = self.port.unwrap();
        }
        cfg
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut config = {
        // pass in optional paths where we may be able to load a config file
        if let Some(cfg) = from_toml_file::<Config>(vec![args.cfg.clone(), iroh_home_path(CONFIG)])
        {
            let cfg = cfg?;
            // flags should override config files
            args.override_config(cfg)
        } else {
            // otherwise, use a default config with the given store path
            let rpc_config = RpcConfig::default();
            Config::new(
                args.writeable.map_or(false, |b| b),
                args.fetch.map_or(false, |b| b),
                args.cache.map_or(false, |f| f),
                args.port.map_or(9050, |p| p),
                rpc_config,
            )
        }
    };
    config.set_default_headers();
    println!("{:#?}", config);

    let mut prom_registry = Registry::default();
    let gw_metrics = Metrics::new(&mut prom_registry);
    let handler = Core::new(config, gw_metrics, &mut prom_registry).await?;

    let metrics_handle =
        iroh_metrics::init_with_registry(metrics::metrics_config(args.no_metrics), prom_registry)
            .await
            .expect("failed to initialize metrics");
    let server = handler.server();
    println!("listening on {}", server.local_addr());
    let core_task = tokio::spawn(async move {
        server.await.unwrap();
    });

    iroh_util::block_until_sigint().await;
    core_task.abort();

    metrics_handle.shutdown();
    Ok(())
}

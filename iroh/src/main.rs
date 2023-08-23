use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::{prelude::*, EnvFilter};

mod commands;
mod config;

use crate::{
    commands::{start_metrics_server, Cli},
    config::{iroh_config_path, Config, CONFIG_FILE_NAME, ENV_PREFIX},
};

fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_name("main-runtime")
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(main_impl())?;
    // give the runtime some time to finish, but do not wait indefinitely.
    // there are cases where the a runtime thread is blocked doing io.
    // e.g. reading from stdin.
    rt.shutdown_timeout(Duration::from_millis(500));
    Ok(())
}

async fn main_impl() -> Result<()> {
    let tokio = tokio::runtime::Handle::current();
    let tpc = tokio_util::task::LocalPoolHandle::new(num_cpus::get());
    let rt = iroh::bytes::util::runtime::Handle::new(tokio, tpc);
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let config_path = iroh_config_path(CONFIG_FILE_NAME).context("invalid config path")?;
    let sources = [Some(config_path.as_path()), cli.cfg.as_deref()];
    let config = Config::load(
        // potential config files
        &sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        // args.make_overrides_map(),
        HashMap::<String, String>::new(),
    )?;

    #[cfg(feature = "metrics")]
    let metrics_fut = start_metrics_server(cli.metrics_addr, &rt);

    let r = cli.run(&rt, &config).await;

    #[cfg(feature = "metrics")]
    if let Some(metrics_fut) = metrics_fut {
        metrics_fut.abort();
        drop(metrics_fut);
    }
    r
}

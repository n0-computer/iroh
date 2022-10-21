use anyhow::{Context, Result};
use clap::Parser;
use iroh_p2p::cli::Args;
use iroh_p2p::config::{Config, CONFIG_FILE_NAME, ENV_PREFIX};
use iroh_p2p::run;
use iroh_util::{iroh_config_path, make_config};

/// Starts daemon process
fn main() -> Result<()> {
    let args = Args::parse();

    // TODO: configurable network
    let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path), args.cfg.clone()];
    let config = make_config(
        // default
        Config::default_grpc(),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .context("invalid config")?;
    run(config)
}

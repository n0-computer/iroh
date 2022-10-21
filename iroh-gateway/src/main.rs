use anyhow::Result;
use clap::Parser;
use iroh_gateway::{
    cli::Args,
    config::{Config, CONFIG_FILE_NAME, ENV_PREFIX},
    metrics, run,
};
use iroh_util::{iroh_config_path, make_config};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path), args.cfg.clone()];
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
    config.metrics = metrics::metrics_config_with_compile_time_info(config.metrics);
    println!("{:#?}", config);
    run(config).await
}

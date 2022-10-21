use clap::Parser;
use iroh_store::{
    cli::Args,
    config::{config_data_path, CONFIG_FILE_NAME, ENV_PREFIX},
    run, Config,
};
use iroh_util::{iroh_config_path, make_config};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = vec![Some(config_path), args.cfg.clone()];
    let config_data_path = config_data_path(args.path.clone())?;
    let config = make_config(
        // default
        Config::new_grpc(config_data_path),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .unwrap();
    run(config).await
}

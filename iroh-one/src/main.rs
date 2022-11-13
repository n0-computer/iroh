use anyhow::Result;
use clap::Parser;
#[cfg(feature = "uds-gateway")]
use iroh_one::uds;
use iroh_one::{
    cli::Args,
    config::{Config, CONFIG_FILE_NAME, ENV_PREFIX},
};
use iroh_util::lock::ProgramLock;
use iroh_util::{iroh_config_path, make_config};
#[cfg(feature = "uds-gateway")]
use tempdir::TempDir;

use iroh_one::iroh::Iroh;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let mut lock = ProgramLock::new("iroh-one")?;
    lock.acquire_or_exit();

    let args = Args::parse();

    let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path.as_path()), args.cfg.as_deref()];
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

    #[cfg(unix)]
    {
        match iroh_util::increase_fd_limit() {
            Ok(soft) => tracing::debug!("NOFILE limit: soft = {}", soft),
            Err(err) => tracing::error!("Error increasing NOFILE limit: {}", err),
        }
    }

    let mut iroh = Iroh::new(&mut config)?;
    iroh.start().await?;

    iroh_util::block_until_sigint().await;

    iroh.stop()?;

    Ok(())
}

use anyhow::Context;
use clap::Parser;
use iroh_util::{iroh_config_path, make_config};

#[derive(Parser, Debug)]
enum Subcommands {
    Gateway(iroh_gateway::cli::Args),
    P2p(iroh_p2p::cli::Args),
    Store(iroh_store::cli::Args),
    Cli(iroh::run::Cli),
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    subcommands: Option<Subcommands>,
}

async fn run_gateway(args: iroh_gateway::cli::Args) -> anyhow::Result<()> {
    let cfg_path = iroh_config_path(iroh_gateway::config::CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path), args.cfg.clone()];
    let mut config = make_config(
        // default
        iroh_gateway::config::Config::default(),
        // potential config files
        sources,
        // env var prefix for this config
        iroh_gateway::config::ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .context("invalid config")?;
    config.metrics = iroh_gateway::metrics::metrics_config_with_compile_time_info(config.metrics);
    iroh_gateway::run(config).await
}

async fn run_p2p(args: iroh_p2p::cli::Args) -> anyhow::Result<()> {
    // TODO: configurable network
    let cfg_path = iroh_config_path(iroh_p2p::CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path), args.cfg.clone()];
    let config = make_config(
        // default
        iroh_p2p::Config::default_grpc(),
        // potential config files
        sources,
        // env var prefix for this config
        iroh_p2p::ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .context("invalid config")?;
    iroh_p2p::run(config)
}

async fn run_store(args: iroh_store::cli::Args) -> anyhow::Result<()> {
    let config_path = iroh_config_path(iroh_store::config::CONFIG_FILE_NAME)?;
    let sources = vec![Some(config_path), args.cfg.clone()];
    let config_data_path = iroh_store::config::config_data_path(args.path.clone())?;
    let config = make_config(
        // default
        iroh_store::Config::new_grpc(config_data_path),
        // potential config files
        sources,
        // env var prefix for this config
        iroh_store::config::ENV_PREFIX,
        // map of present command line arguments
        args.make_overrides_map(),
    )
    .context("invalid config")?;
    iroh_store::run(config).await
}

async fn run_cli(args: iroh::run::Cli) -> anyhow::Result<()> {
    use anyhow::{anyhow, Result};
    use std::io;

    fn transform_error(r: Result<()>) -> Result<()> {
        match r {
            Ok(_) => Ok(()),
            Err(e) => {
                let io_error = e.root_cause().downcast_ref::<io::Error>();
                if let Some(io_error) = io_error {
                    if io_error.kind() == io::ErrorKind::ConnectionRefused {
                        return Err(anyhow!(
                            "Connection refused. Are `iroh-p2p` and `iroh-store` running?"
                        ));
                    }
                }
                Err(e)
            }
        }
    }

    // the `run` method exists in two versions:
    // When using the `testing` feature, the
    // version of `run` designed for testing purposes using mocked test
    // fixtures is invoked.
    // Without the `testing` feature, the version of
    // `run` that interacts with the real Iroh API is used.
    let r = args.run().await;
    let r = transform_error(r);
    match r {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(subcommands) = args.subcommands {
        match subcommands {
            Subcommands::Gateway(args) => {
                run_gateway(args).await?;
            }
            Subcommands::P2p(args) => {
                run_p2p(args).await?;
            }
            Subcommands::Store(args) => {
                run_store(args).await?;
            }
            Subcommands::Cli(args) => {
                run_cli(args).await?;
            }
        }
    }
    Ok(())
}

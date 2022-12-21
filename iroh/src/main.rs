use anyhow::{anyhow, Result};
use clap::Parser;
use crossterm::style::Stylize;
use iroh_api::ApiError;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = iroh::run::Cli::parse();
    // the `run` method exists in two versions:
    // When using the `testing` feature, the
    // version of `run` designed for testing purposes using mocked test
    // fixtures is invoked.
    // Without the `testing` feature, the version of
    // `run` that interacts with the real Iroh API is used.
    let r = cli.run().await;
    let r = transform_error(r);
    match r {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Error: {:?}", e);
            std::process::exit(1);
        }
    }
}

fn transform_error(r: Result<()>) -> Result<()> {
    match r {
        Ok(_) => Ok(()),
        Err(e) => {
            let rpc_error = e
                .root_cause()
                .downcast_ref::<iroh_rpc_client::ClientError>();
            if let Some(iroh_rpc_client::ClientError::Open(_)) = rpc_error {
                return Err(anyhow!(
                    "Connection refused. Are services running?\n{}",
                    "hint: see 'iroh start' for more on starting services".yellow(),
                ));
            }

            let api_error = e.root_cause().downcast_ref::<ApiError>();
            if let Some(ApiError::ConnectionRefused { service }) = api_error {
                return Err(anyhow!(
                    "Connection refused. This command requires a running {} service.\n{}",
                    service,
                    format!("hint: try 'iroh start {}'", service).yellow(),
                ));
            }
            Err(e)
        }
    }
}

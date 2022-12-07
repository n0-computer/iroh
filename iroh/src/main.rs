use anyhow::{anyhow, Result};
use clap::Parser;
use crossterm::style::Stylize;
use iroh_api::ApiError;
use std::io;

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
            let io_error = e.root_cause().downcast_ref::<io::Error>();
            if let Some(io_error) = io_error {
                if io_error.kind() == io::ErrorKind::ConnectionRefused {
                    return Err(anyhow!(
                        "Connection refused. Are services running?\n{}",
                        "hint: see 'iroh start' for more on starting services".yellow(),
                    ));
                }
            }
            let api_error = e.root_cause().downcast_ref::<ApiError>();
            if let Some(api_error) = api_error {
                match api_error {
                    ApiError::ConnectionRefused { service } => {
                        return Err(anyhow!(
                            "Connection refused. This command requires a running {} service.\n{}",
                            service,
                            format!("hint: try 'iroh start {}'", service).yellow(),
                        ));
                    }
                    _ => {
                        return Err(e);
                    }
                }
            }
            Err(e)
        }
    }
}

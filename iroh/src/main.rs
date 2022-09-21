mod api;
mod cli;
mod clientapi;
mod fake;

use std::collections::HashMap;
use std::env;

use crate::cli::run_cli_command;
use crate::cli::Cli;
use crate::clientapi::{create_client, ClientApi};
use crate::fake::FakeApi;
use anyhow::Result;

use clap::Parser;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match env::var("IROH_CTL_TESTING") {
        Ok(_) => {
            let fake_api = FakeApi::default();
            run_cli_command(cli, &fake_api).await?;
        }
        Err(_) => {
            let client = create_client(cli.cfg.clone(), HashMap::new()).await?;
            let api = ClientApi::new(&client).await?;
            run_cli_command(cli, &api).await?;
        }
    }
    Ok(())
}

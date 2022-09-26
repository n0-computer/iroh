use anyhow::Result;
use clap::Parser;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = iroh_ctl::run::Cli::parse();
    // run_cli exists in two versions, one for real client interaction,
    // and one for testing purposes using a fake API implementation
    iroh_ctl::run::run_cli(cli).await
}

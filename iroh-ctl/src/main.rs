use anyhow::Result;
use clap::Parser;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = iroh_ctl::run::Cli::parse();
    // `run_cli` exists in two versions:
    // When using the `fixture` feature, the
    // version of `run_cli` designed for testing purposes using mocked test
    // fixtures is invoked.
    // Without the `fixture` feature, the version of
    // `run_cli` that interacts with the real Iroh API is used.
    iroh_ctl::run::run_cli(cli).await
}

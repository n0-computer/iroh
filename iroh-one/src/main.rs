use anyhow::Result;
use clap::Parser;
use iroh_one::cli::Cli;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // the `run` method exists in two versions:
    // When using the `testing` feature, the
    // version of `run` designed for testing purposes using mocked test
    // fixtures is invoked.
    // Without the `testing` feature, the version of
    // `run` that interacts with the real Iroh API is used.
    cli.run().await
}

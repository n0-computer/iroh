use anyhow::Result;
use clap::Parser;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = iroh_ctl::run::Cli::parse();
    // the `run` method exists in two versions:
    // When using the `testing` feature, the
    // version of `run` designed for testing purposes using mocked test
    // fixtures is invoked.
    // Without the `testing` feature, the version of
    // `run` that interacts with the real Iroh API is used.
    cli.run().await
}

use anyhow::Result;
use iroh_one::{config::Config, Iroh};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let mut cfg = Config::default();
    let mut iroh = Iroh::new(&mut cfg)?;
    iroh.start().await?;

    let cli = iroh.api().await?;
    let table = cli.check().await;
    println!("{:#?}", table);

    iroh.stop()
}

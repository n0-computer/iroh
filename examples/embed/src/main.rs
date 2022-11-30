use anyhow::{bail, Result};
use futures_util::StreamExt;
use iroh_api::{IpfsPath, OutType};
use iroh_embed::{Config, Iroh};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cfg = Config::default();
    let iroh = Iroh::new(cfg).await?;

    let quick_start: IpfsPath =
        "/ipfs/QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc/quick-start".parse()?;
    let mut stream = iroh.api().get(&quick_start)?;

    // We only expect a single item here.
    while let Some(item) = stream.next().await {
        let (rel_path, data) = item?;
        println!("PATH: {rel_path}");
        println!("----");
        match data {
            OutType::Dir => bail!("found unexpected dir"),
            OutType::Symlink(_) => bail!("found unexpected symlink"),
            OutType::Reader(mut reader) => {
                let mut stdout = tokio::io::stdout();
                tokio::io::copy(&mut reader, &mut stdout).await?;
            }
        }
    }
    Ok(())
}

use anyhow::{bail, Result};
use futures_util::StreamExt;
use iroh_api::{IpfsPath, OutType};
use iroh_embed::{IrohBuilder, P2pService, RocksStoreService};
use testdir::testdir;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let dir = testdir!();
    println!("using directory: {}", dir.display());

    let store = RocksStoreService::new(dir.join("store")).await?;
    let p2p = P2pService::new(Default::default(), dir, store.addr()).await?;

    // TODO: make it easy to add default http_resolvers and indexer.
    let iroh = IrohBuilder::new()
        .with_store(store)
        .with_p2p(p2p)
        .build()
        .await?;

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

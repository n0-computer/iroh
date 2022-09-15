use anyhow::Result;
use cid::Cid;
use iroh_resolver::resolver;
use iroh_resolver::resolver::{ContentLoader, OutMetrics, Resolver};
use std::path::Path;

fn main() {
    println!("Hello world!");
}

// XXX not sure why Unpin is needed
async fn get<T: ContentLoader + std::marker::Unpin>(
    content_loader: T,
    cid: Cid,
    path: &Path,
) -> Result<()> {
    let resolver = Resolver::new(content_loader);
    let out = resolver.resolve(resolver::Path::from_cid(cid)).await?;
    let mut r = out.pretty(resolver, OutMetrics::default())?;
    let mut file = tokio::fs::File::create(path).await?;
    tokio::io::copy(&mut r, &mut file).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use async_trait::async_trait;
    use bytes::Bytes;
    use iroh_resolver::resolver::{LoadedCid, Source};
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    struct MyHashMap(HashMap<Cid, Bytes>);

    #[async_trait]
    impl ContentLoader for MyHashMap {
        async fn load_cid(&self, cid: &Cid) -> Result<LoadedCid> {
            match self.0.get(cid) {
                Some(b) => Ok(LoadedCid {
                    data: b.clone(),
                    source: Source::Bitswap,
                }),
                None => bail!("not found"),
            }
        }
    }

    async fn load_fixture(p: &str) -> Bytes {
        Bytes::from(tokio::fs::read(format!("./fixtures/{p}")).await.unwrap())
    }

    #[tokio::test]
    async fn test_get() {
        let cid_str = "QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN";
        let cid: Cid = cid_str.parse().unwrap();
        let data = load_fixture(cid_str).await;

        let loader: MyHashMap = MyHashMap([(cid, data)].into_iter().collect());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");

        get(loader, cid, &path).await.unwrap();

        let saved = std::fs::read_to_string(&path).unwrap();

        assert_eq!(saved, "hello\n");
    }
}

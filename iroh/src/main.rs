use anyhow::Result;
use async_trait::async_trait;
use cid::Cid;
use iroh_resolver::resolver;
use iroh_resolver::resolver::LoadedCid;
use iroh_resolver::resolver::{ContentLoader, OutMetrics, Resolver};
use iroh_resolver::unixfs_builder;
use iroh_rpc_client::Client;
use std::path::Path;

fn main() {
    println!("Hello world!");
}

#[async_trait]
pub trait P2p {
    async fn start_providing(&self, key: &Cid) -> Result<()>;
}

// XXX not sure why Unpin is needed
// XXX doesn't handle a directory yet, should it?
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

async fn add<S: unixfs_builder::Store, P: P2p>(store: S, p2p: &P, path: &Path) -> Result<Cid> {
    let cid = unixfs_builder::add_file(path, Some(store)).await?;
    p2p.start_providing(&cid).await?;
    Ok(cid)
}

// in the end, Client provides ContentLoader, a way to get a P2p client (not the same
// // as the P2p trait here but can be used to implement it), and implements Store too
// struct Client {}

struct Api<'a> {
    client: &'a Client,
}

#[async_trait]
impl P2p for Client {
    async fn start_providing(&self, key: &Cid) -> Result<()> {
        // self.try_p2p().start_providing(key).await
        Ok(())
    }
}

impl<'a> Api<'a> {
    fn new(client: &'a Client) -> Self {
        Self { client }
    }

    async fn get(&self, cid: Cid, path: &Path) -> Result<()> {
        // XXX ugh clone. Should we have an Arc client?
        get(self.client.clone(), cid, path).await
    }

    async fn add(&self, path: &Path) -> Result<Cid> {
        add(self.client, self.client, path).await
    }
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

    // tests for nested structures could exploit the symmetry:  add a directory and
    // try to get it and see whether it's the same
    // This could also be part of a property test which generates random file
    // structures and see whether we can get them back
    // That does require the test store to actually store the data and the
    // resolver to work with it. Would it make sense to create a special "in memory store"
    // for this purpose?

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

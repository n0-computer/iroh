use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use iroh_resolver::resolver;
use iroh_resolver::resolver::{ContentLoader, OutMetrics, Resolver};
use iroh_resolver::unixfs_builder;
use iroh_rpc_client::Client;
use libp2p::gossipsub::MessageId;
use libp2p::{Multiaddr, PeerId};

use std::path::Path;

fn main() {
    println!("Hello world!");
}

#[async_trait]
pub trait P2pFacilities {
    // this is an internal api helpful to implement this API
    async fn start_providing(&self, cid: &Cid) -> Result<()>;
}

// pub struct Id {
//     peer_id: PeerId,
//     listen_addrs: Vec<Multiaddr>,
//     local_addrs: Vec<Multiaddr>,
// }

// #[async_trait]
// pub trait Main {
//     async fn version(&self) -> Result<String>;
//     // add, get, connect, disconnect, peers, ping
// }

// #[async_trait]
// pub trait P2pId {
//     // this is an API almost identical to what we want to expose to the user
//     async fn p2p_version(&self) -> Result<String>;
//     async fn local_peer_id(&self) -> Result<PeerId>;
//     async fn addrs_listen(&self) -> Result<Vec<Multiaddr>>;
//     async fn addrs_local(&self) -> Result<Vec<Multiaddr>>;
//     // can be implemented on the trait itself as it combines others
//     async fn id(&self) -> Result<Id>;
//     // async fn addrs gets a map right now
// }

// #[async_trait]
// pub trait P2pFetch {
//     async fn fetch_bitswap(&self, cid: Cid, providers: Vec<PeerId>) -> Result<Bytes>;
//     async fn fetch_providers(&self, cid: Cid) -> Result<Vec<PeerId>>;
// }

// #[async_trait]
// pub trait P2pGossipsub {
//     async fn publish(topic: &str, file: Option<&Path>) -> Result<MessageId>;
//     async fn subscribe(topic: &str) -> Result<()>;
//     async fn unsubscribe(topic: &str) -> Result<()>;
// }

// #[async_trait]
// pub trait Store {
//     async fn store_version(&self) -> Result<String>;
//     async fn get_links(&self, cid: Cid) -> Result<Vec<Cid>>;
// }

// #[async_trait]
// pub trait StoreBlock {
//     async fn block_get(&self, cid: Cid) -> Result<Bytes>;
//     async fn block_put(&self, data: &Bytes) -> Result<Cid>;
//     async fn block_has(&self, cid: Cid) -> Result<bool>;
// }

// XXX not sure why Unpin is needed
// XXX doesn't handle a directory yet, should it?

// each API function requires certain capabilities (the store, the a content
// loader, p2p functionality, etc). We can express these capabilities as
// traits. I think it's better for those traits are defined near where they are
// provided, but especially if they don't exist yet we could express them here.
// To encourage loose coupling it is best for the traits to declare just what's
// needed for the API layer to work.

// How do we determine what should live in the API layer and what should live
// in the underlying layers? During development it's handy to sketch any new
// functionality in the API layer, but we should keep in mind to move it within
// an underlying crate where that makes sense. The API layer should primarily
// be about coordination, so if if new functionality is required that is
// primarily about such coordination, we could consider keeping it here.

// get needs to support directories and files; the resolver does appear to be
// capable of directories, but what kind of data do we get then?
// it appears to need some kind of resume; and does not download everything
// again if it's restarted
// the original ipfs get also seems to support getting cids, not just paths,
// unless a cid is a path somehow?

// this gets a directory with some NASA images
// /ipfs/QmQwhnitZWNrVQQ1G8rL4FRvvZBUvHcxCtUreskfnBzvD8
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

// there should be a get that gets a stream of file descriptions

async fn add<S: unixfs_builder::Store, P: P2pFacilities>(
    store: S,
    p2p: &P,
    path: &Path,
) -> Result<Cid> {
    // unixfs_builder needs to be extended in ways I don't understand yet
    let cid = unixfs_builder::add_file(path, Some(store)).await?;

    // start providing is new infrastructure that p2p needs to support
    p2p.start_providing(&cid).await?;
    Ok(cid)
}

// in the end, Client provides ContentLoader, a way to get a P2p client (not the same
// as the P2p trait here but can be used to implement it), and implements Store too
// struct Client {}

struct Api<'a> {
    client: &'a Client,
}

// iroh-share has its own P2pNode structure, how does it relate to this one?
#[async_trait]
impl P2pFacilities for Client {
    async fn start_providing(&self, cid: &Cid) -> Result<()> {
        // self.try_p2p().start_providing(key).await
        Ok(())
    }
}

// testing this directly means we need a full-fledged client, which is
// more difficult than testing the underlying functions
// we could make the client a generic type and say it needs to support
// Store + ContentLoader + P2p + more instead of requiring a concrete client
impl<'a> Api<'a> {
    fn new(client: &'a Client) -> Self {
        Self { client }
    }

    async fn get(&self, cid: Cid, path: &Path) -> Result<()> {
        // XXX ugh clone. Should we have an Arc client? the trait
        // appears to be defined for it
        get(self.client.clone(), cid, path).await
    }

    async fn add(&self, path: &Path) -> Result<Cid> {
        // XXX passing the client twice here is weird, but we really want
        // different traits that just happen to be implemented by the same thing
        // alternatively we could request a Store + P2p, and perhaps that easily
        // enough to construct for testing purposes.
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

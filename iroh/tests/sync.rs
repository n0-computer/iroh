use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, Result};
use futures::StreamExt;
use iroh::{
    client::mem::Doc,
    collection::IrohCollectionParser,
    node::{Builder, Node},
    rpc_protocol::ShareMode,
};
use quic_rpc::transport::misc::DummyServerEndpoint;
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::util::runtime;
use iroh_sync::store::{self, GetFilter};

/// Pick up the tokio runtime from the thread local and add a
/// thread per core runtime.
fn test_runtime() -> runtime::Handle {
    runtime::Handle::from_currrent(1).unwrap()
}

fn test_node(
    rt: runtime::Handle,
    addr: SocketAddr,
) -> Builder<
    iroh::baomap::mem::Store,
    store::memory::Store,
    DummyServerEndpoint,
    IrohCollectionParser,
> {
    let db = iroh::baomap::mem::Store::new(rt.clone());
    let store = iroh_sync::store::memory::Store::default();
    Node::builder(db, store)
        .collection_parser(IrohCollectionParser)
        .runtime(&rt)
        .bind_addr(addr)
}

async fn spawn_node(
    rt: runtime::Handle,
) -> anyhow::Result<Node<iroh::baomap::mem::Store, store::memory::Store>> {
    let node = test_node(rt, "127.0.0.1:0".parse()?);
    let node = node.spawn().await?;
    Ok(node)
}

async fn spawn_nodes(
    rt: runtime::Handle,
    n: usize,
) -> anyhow::Result<Vec<Node<iroh::baomap::mem::Store, store::memory::Store>>> {
    let mut nodes = vec![];
    for _i in 0..n {
        let node = spawn_node(rt.clone()).await?;
        nodes.push(node);
    }
    Ok(nodes)
}

#[tokio::test]
async fn sync_full_basic() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
    let nodes = spawn_nodes(rt, 3).await?;
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    // node1: create doc and ticket
    let (ticket, doc1) = {
        let iroh = &clients[0];
        let author = iroh.create_author().await?;
        let doc = iroh.create_doc().await?;
        let key = b"k1";
        let value = b"v1";
        doc.set_bytes(author, key.to_vec(), value.to_vec()).await?;
        assert_latest(&doc, key, value).await;
        let ticket = doc.share(ShareMode::Write).await?;
        (ticket, doc)
    };

    // node2: join in
    let _doc2 = {
        let iroh = &clients[1];
        let author = iroh.create_author().await?;
        let doc = iroh.import_doc(ticket.clone()).await?;

        // todo: events over rpc to not use sleep...
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_latest(&doc, b"k1", b"v1").await;

        let key = b"k2";
        let value = b"v2";
        doc.set_bytes(author, key.to_vec(), value.to_vec()).await?;
        assert_latest(&doc, key, value).await;
        // todo: events
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_latest(&doc1, key, value).await;
        doc
    };

    //  node 3 joins & imports the doc from peer 1
    let _doc3 = {
        let iroh = &clients[2];
        println!("!!!! DOC 3 JOIN !!!!!");
        let doc = iroh.import_doc(ticket).await?;

        // todo: events
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_latest(&doc, b"k1", b"v1").await;
        assert_latest(&doc, b"k2", b"v2").await;
        doc
    };

    // TODO:
    // - gossiping between multiple peers
    // - better test utils
    // - ...

    for node in nodes {
        node.shutdown();
    }

    Ok(())
}

async fn assert_latest(doc: &Doc, key: &[u8], value: &[u8]) {
    let content = get_latest(doc, key).await.unwrap();
    assert_eq!(content, value.to_vec());
}

async fn get_latest(doc: &Doc, key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let filter = GetFilter::new().with_key(key.to_vec());
    let entry = doc
        .get(filter)
        .await?
        .next()
        .await
        .ok_or_else(|| anyhow!("entry not found"))??;
    let content = doc.get_content_bytes(&entry).await?;
    Ok(content.to_vec())
}

fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

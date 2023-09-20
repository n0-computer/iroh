#![cfg(feature = "mem-db")]

use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, Result};
use futures::{StreamExt, TryStreamExt};
use iroh::{
    client::mem::Doc,
    collection::IrohCollectionParser,
    node::{Builder, Node},
    rpc_protocol::ShareMode,
    sync_engine::{LiveEvent, Origin, SyncEvent, SyncReason},
};
use quic_rpc::transport::misc::DummyServerEndpoint;
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::util::runtime;
use iroh_sync::store::{self, GetFilter};

/// Pick up the tokio runtime from the thread local and add a
/// thread per core runtime.
fn test_runtime() -> runtime::Handle {
    runtime::Handle::from_current(1).unwrap()
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
        .enable_derp(iroh_net::defaults::default_derp_map())
        .runtime(&rt)
        .bind_addr(addr)
}

async fn spawn_node(
    rt: runtime::Handle,
    i: usize,
) -> anyhow::Result<Node<iroh::baomap::mem::Store, store::memory::Store>> {
    let node = test_node(rt, "127.0.0.1:0".parse()?);
    let node = node.spawn().await?;
    tracing::info!("spawned node {i} {:?}", node.peer_id());
    Ok(node)
}

async fn spawn_nodes(
    rt: runtime::Handle,
    n: usize,
) -> anyhow::Result<Vec<Node<iroh::baomap::mem::Store, store::memory::Store>>> {
    futures::future::join_all((0..n).map(|i| spawn_node(rt.clone(), i)))
        .await
        .into_iter()
        .collect()
}

/// This tests the simplest scenario: A node connects to another node, and performs sync.
#[tokio::test]
async fn sync_simple() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
    let nodes = spawn_nodes(rt, 2).await?;
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    // create doc on node0
    let (ticket, doc0) = {
        let iroh = &clients[0];
        let author = iroh.authors.create().await?;
        let doc = iroh.docs.create().await?;
        doc.set_bytes(author, b"k1".to_vec(), b"v1".to_vec())
            .await?;
        assert_latest(&doc, b"k1", b"v1").await;
        let ticket = doc.share(ShareMode::Write).await?;
        (ticket, doc)
    };

    let mut events0 = doc0.subscribe().await?;

    // node1: join in
    let iroh = &clients[1];
    let doc = iroh.docs.import(ticket.clone()).await?;
    let mut events = doc.subscribe().await?;
    let event = events.try_next().await?.unwrap();
    assert!(matches!(event, LiveEvent::InsertRemote { .. }));
    let event = events.try_next().await?.unwrap();
    let LiveEvent::SyncFinished(event) = event else {
        panic!("expected LiveEvent::SyncFinished, but got {event:?}");
    };
    assert_eq!(event.namespace, doc.id());
    assert_eq!(event.peer, nodes[0].peer_id());
    assert_eq!(event.result, Ok(()));
    let event = events.try_next().await?.unwrap();
    assert!(matches!(event, LiveEvent::ContentReady { .. }));
    assert_latest(&doc, b"k1", b"v1").await;

    // check sync event on node0
    let event = events0.try_next().await?.unwrap();
    let LiveEvent::SyncFinished(event) = event else {
        panic!("expected LiveEvent::SyncFinished, but got {event:?}");
    };
    assert_eq!(event.namespace, doc0.id());
    assert_eq!(event.peer, nodes[1].peer_id());
    assert_eq!(event.result, Ok(()));

    for node in nodes {
        node.shutdown();
    }
    Ok(())
}

/// Test subscribing to replica events (without sync)
#[tokio::test]
async fn sync_subscribe() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
    let node = spawn_node(rt, 0).await?;
    let client = node.client();
    let doc = client.docs.create().await?;
    let mut sub = doc.subscribe().await?;
    let author = client.authors.create().await?;
    doc.set_bytes(author, b"k".to_vec(), b"v".to_vec()).await?;
    let event = tokio::time::timeout(Duration::from_millis(100), sub.next()).await?;
    assert!(
        matches!(event, Some(Ok(LiveEvent::InsertLocal { .. }))),
        "expected InsertLocal but got {event:?}"
    );
    node.shutdown();
    Ok(())
}

#[tokio::test]
async fn sync_full_basic() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
    let mut nodes = spawn_nodes(rt.clone(), 2).await?;
    let mut clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    // node1: create doc and ticket
    let (ticket, doc1) = {
        let iroh = &clients[0];
        let author = iroh.authors.create().await?;
        let doc = iroh.docs.create().await?;
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
        let author = iroh.authors.create().await?;
        let doc = iroh.docs.import(ticket.clone()).await?;

        // wait for remote insert on doc2
        let mut events = doc.subscribe().await?;
        let event = events.try_next().await?.unwrap();
        assert!(
            matches!(event, LiveEvent::InsertRemote { .. }),
            "expected InsertRemote but got {event:?}"
        );
        let event = events.try_next().await?.unwrap();
        assert!(
            matches!(event, LiveEvent::SyncFinished(_)),
            "expected SyncFinished but got {event:?}"
        );
        let event = events.try_next().await?.unwrap();
        assert!(
            matches!(event, LiveEvent::ContentReady { .. }),
            "expected ContentReady but got {event:?}"
        );

        assert_latest(&doc, b"k1", b"v1").await;

        // setup event channel on on doc1
        let mut events = doc1.subscribe().await?;

        let key = b"k2";
        let value = b"v2";
        doc.set_bytes(author, key.to_vec(), value.to_vec()).await?;
        assert_latest(&doc, key, value).await;

        // wait for remote insert on doc1
        let event = events.try_next().await?.unwrap();
        assert!(
            matches!(event, LiveEvent::InsertRemote { .. }),
            "expected InsertRemote but got {event:?}"
        );
        let event = events.try_next().await?.unwrap();
        assert!(
            matches!(event, LiveEvent::ContentReady { .. }),
            "expected ContentReady but got {event:?}"
        );

        assert_latest(&doc1, key, value).await;
        doc
    };

    // node 3 joins & imports the doc from peer 1
    nodes.push(spawn_node(rt.clone(), nodes.len()).await?);
    clients.push(nodes.last().unwrap().client());
    let iroh = &clients[2];
    let doc = iroh.docs.import(ticket).await?;

    // expect 2 times InsertRemote
    let mut events = doc.subscribe().await?;
    let event = events.try_next().await?.unwrap();
    assert!(
        matches!(event, LiveEvent::InsertRemote { .. }),
        "expected InsertRemote but got {event:?}"
    );
    let event = events.try_next().await?.unwrap();
    assert!(
        matches!(event, LiveEvent::InsertRemote { .. }),
        "expected InsertRemote but got {event:?}"
    );

    // now expect SyncFinished
    let event = events.try_next().await?.unwrap();
    let LiveEvent::SyncFinished(event) = event else {
            panic!("expected SyncFinished but got {event:?}");
        };
    let expected = SyncEvent {
        peer: nodes[0].peer_id(),
        namespace: doc.id(),
        result: Ok(()),
        origin: event.origin.clone(),
        finished: event.finished,
    };
    assert_eq!(event, expected, "expected {expected:?} but got {event:?}");

    // expect 2 times ContentReady
    let event = events.try_next().await?.unwrap();
    assert!(
        matches!(event, LiveEvent::ContentReady { .. }),
        "expected ContentReady but got {event:?}"
    );
    let event = events.try_next().await?.unwrap();
    assert!(
        matches!(event, LiveEvent::ContentReady { .. }),
        "expected ContentReady but got {event:?}"
    );

    assert_latest(&doc, b"k1", b"v1").await;
    assert_latest(&doc, b"k2", b"v2").await;

    for node in nodes {
        node.shutdown();
    }

    Ok(())
}

#[tokio::test]
async fn sync_subscribe_stop() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
    let node = spawn_node(rt, 0).await?;
    let client = node.client();

    let doc = client.docs.create().await?;
    let author = client.authors.create().await?;
    doc.start_sync(vec![]).await?;

    let status = doc.status().await?;
    assert!(status.active);
    assert_eq!(status.subscriptions, 0);

    let sub = doc.subscribe().await?;
    let status = doc.status().await?;
    assert_eq!(status.subscriptions, 1);
    drop(sub);

    doc.set_bytes(author, b"x".to_vec(), b"x".to_vec()).await?;
    let status = doc.status().await?;
    assert_eq!(status.subscriptions, 0);

    node.shutdown();

    Ok(())
}

async fn assert_latest(doc: &Doc, key: &[u8], value: &[u8]) {
    let content = get_latest(doc, key).await.unwrap();
    assert_eq!(content, value.to_vec());
}

async fn get_latest(doc: &Doc, key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let filter = GetFilter::Key(key.to_vec());
    let entry = doc
        .get_many(filter)
        .await?
        .next()
        .await
        .ok_or_else(|| anyhow!("entry not found"))??;
    let content = doc.read_to_bytes(&entry).await?;
    Ok(content.to_vec())
}

fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

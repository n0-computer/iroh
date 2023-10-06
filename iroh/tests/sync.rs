#![cfg(feature = "mem-db")]

use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, bail, Result};
use futures::{Stream, StreamExt, TryStreamExt};
use iroh::{
    client::mem::Doc,
    node::{Builder, Node},
    rpc_protocol::ShareMode,
    sync_engine::{LiveEvent, SyncEvent},
};
use iroh_net::key::PublicKey;
use quic_rpc::transport::misc::DummyServerEndpoint;
use tracing::{debug, info};
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::util::runtime;
use iroh_sync::{
    store::{self, GetFilter},
    ContentStatus, NamespaceId,
};

const LIMIT: Duration = Duration::from_secs(15);

/// Pick up the tokio runtime from the thread local and add a
/// thread per core runtime.
fn test_runtime() -> runtime::Handle {
    runtime::Handle::from_current(1).unwrap()
}

fn test_node(
    rt: runtime::Handle,
    addr: SocketAddr,
) -> Builder<iroh::baomap::mem::Store, store::memory::Store, DummyServerEndpoint> {
    let db = iroh::baomap::mem::Store::new(rt.clone());
    let store = iroh_sync::store::memory::Store::default();
    Node::builder(db, store).runtime(&rt).bind_addr(addr)
}

async fn spawn_node(
    rt: runtime::Handle,
    i: usize,
) -> anyhow::Result<Node<iroh::baomap::mem::Store, store::memory::Store>> {
    let node = test_node(rt, "127.0.0.1:0".parse()?);
    let node = node.spawn().await?;
    info!("spawned node {i} {:?}", node.peer_id());
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
    let peer0 = nodes[0].peer_id();
    let author0 = clients[0].authors.create().await?;
    let doc0 = clients[0].docs.create().await?;
    let doc_id = doc0.id();
    let hash0 = doc0
        .set_bytes(author0, b"k1".to_vec(), b"v1".to_vec())
        .await?;
    assert_latest(&doc0, b"k1", b"v1").await;
    let ticket = doc0.share(ShareMode::Write).await?;

    let mut events0 = doc0.subscribe().await?;

    info!("node1: join");
    let peer1 = nodes[1].peer_id();
    let doc1 = clients[1].docs.import(ticket.clone()).await?;
    let mut events1 = doc1.subscribe().await?;
    info!("node1: assert 4 events");
    assert_each_unordered(
        collect_some(&mut events1, 4, LIMIT).await?,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer0)),
            Box::new(move |e| matches!(e, LiveEvent::InsertRemote { from, .. } if *from == peer0 )),
            Box::new(move |e| match_sync_finished(e, peer0, doc_id)),
            Box::new(move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == hash0)),
        ],
    );
    assert_latest(&doc1, b"k1", b"v1").await;

    info!("node0: assert 2 events");
    assert_each_unordered(
        collect_some(&mut events0, 2, LIMIT).await?,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer1)),
            Box::new(move |e| match_sync_finished(e, peer1, doc_id)),
        ],
    );

    for node in nodes {
        node.shutdown();
    }
    Ok(())
}

/// Test subscribing to replica events (without sync)
#[tokio::test]
async fn sync_subscribe_no_sync() -> Result<()> {
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

/// This tests basic sync and gossip with 3 peers.
#[tokio::test]
async fn sync_full_basic() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
    let mut nodes = spawn_nodes(rt.clone(), 2).await?;
    let mut clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    // peer0: create doc and ticket
    let peer0 = nodes[0].peer_id();
    let author0 = clients[0].authors.create().await?;
    let doc0 = clients[0].docs.create().await?;
    let mut events0 = doc0.subscribe().await?;
    let doc_id = doc0.id();
    let key0 = b"k1";
    let value0 = b"v1";
    let hash0 = doc0
        .set_bytes(author0, key0.to_vec(), value0.to_vec())
        .await?;

    info!("peer0: wait for 1 event (local insert)");
    let e = next(&mut events0).await;
    assert!(
        matches!(&e, LiveEvent::InsertLocal { entry } if entry.content_hash() == hash0),
        "expected LiveEvent::InsertLocal but got {e:?}",
    );
    assert_latest(&doc0, key0, value0).await;
    let ticket = doc0.share(ShareMode::Write).await?;

    info!("peer1: spawn");
    let peer1 = nodes[1].peer_id();
    let author1 = clients[1].authors.create().await?;
    info!("peer1: join doc");
    let doc1 = clients[1].docs.import(ticket.clone()).await?;

    info!("peer1: wait for 4 events (for sync and join with peer0)");
    let mut events1 = doc1.subscribe().await?;
    assert_each_unordered(
        collect_some(&mut events1, 4, LIMIT).await?,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer0)),
            Box::new(move |e| matches!(e, LiveEvent::InsertRemote { from, .. } if *from == peer0 )),
            Box::new(move |e| match_sync_finished(e, peer0, doc_id)),
            Box::new(move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == hash0)),
        ],
    );

    info!("peer0: wait for 2 events (join & accept sync finished from peer1)");
    assert_each_unordered(
        collect_some(&mut events0, 2, LIMIT).await?,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer1)),
            Box::new(move |e| match_sync_finished(e, peer1, doc_id)),
        ],
    );

    info!("peer1: insert entry");
    let key1 = b"k2";
    let value1 = b"v2";
    let hash1 = doc1
        .set_bytes(author1, key1.to_vec(), value1.to_vec())
        .await?;
    assert_latest(&doc1, key1, value1).await;
    info!("peer1: wait for 1 event (local insert)");
    let e = next(&mut events1).await;
    assert!(
        matches!(&e, LiveEvent::InsertLocal { entry } if entry.content_hash() == hash1),
        "expected LiveEvent::InsertLocal but got {e:?}",
    );

    // peer0: assert events for entry received via gossip
    info!("peer0: wait for 2 events (gossip'ed entry from peer1)");
    assert_each_unordered(
        collect_some(&mut events0, 2, LIMIT).await?,
        vec![
            Box::new(
                move |e| matches!(e, LiveEvent::InsertRemote { from, content_status: ContentStatus::Missing, .. } if *from == peer1),
            ),
            Box::new(move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == hash1)),
        ],
    );
    assert_latest(&doc0, key1, value1).await;

    // Note: If we could check gossip messages directly here (we can't easily), we would notice
    // that peer1 will receive a `Op::ContentReady` gossip message, broadcast
    // by peer0 with neighbor scope. This message is superflous, and peer0 could know that, however
    // our gossip implementation does not allow us to filter message receivers this way.

    info!("peer2: spawn");
    nodes.push(spawn_node(rt.clone(), nodes.len()).await?);
    clients.push(nodes.last().unwrap().client());
    let doc2 = clients[2].docs.import(ticket).await?;
    let peer2 = nodes[2].peer_id();
    let mut events2 = doc2.subscribe().await?;

    info!("peer2: wait for 8 events (from sync with peers)");
    let actual = collect_some(&mut events2, 8, LIMIT).await?;
    assert_each_unordered(
        actual,
        vec![
            // 2 NeighborUp events
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer0)),
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer1)),
            // 2 SyncFinished events
            Box::new(move |e| match_sync_finished(e, peer0, doc_id)),
            Box::new(move |e| match_sync_finished(e, peer1, doc_id)),
            // 2 InsertRemote events
            Box::new(
                move |e| matches!(e, LiveEvent::InsertRemote { entry, content_status: ContentStatus::Missing, .. } if entry.content_hash() == hash0),
            ),
            Box::new(
                move |e| matches!(e, LiveEvent::InsertRemote { entry, content_status: ContentStatus::Missing, .. } if entry.content_hash() == hash1),
            ),
            // 2 ContentReady events
            Box::new(move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == hash0)),
            Box::new(move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == hash1)),
        ],
    );
    assert_latest(&doc2, b"k1", b"v1").await;
    assert_latest(&doc2, b"k2", b"v2").await;

    info!("peer0: wait for 2 events (join & accept sync finished from peer2)");
    assert_each_unordered(
        collect_some(&mut events0, 2, LIMIT).await?,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer2)),
            Box::new(move |e| match_sync_finished(e, peer2, doc_id)),
        ],
    );

    info!("peer1: wait for 2 events (join & accept sync finished from peer2)");
    assert_each_unordered(
        collect_some(&mut events1, 2, LIMIT).await?,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer2)),
            Box::new(move |e| match_sync_finished(e, peer2, doc_id)),
        ],
    );

    info!("shutdown");
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

#[tokio::test]
async fn doc_delete() -> Result<()> {
    let rt = test_runtime();
    let db = iroh::baomap::mem::Store::new(rt.clone());
    let store = iroh_sync::store::memory::Store::default();
    let addr = "127.0.0.1:0".parse().unwrap();
    let node = Node::builder(db, store)
        .gc_policy(iroh::node::GcPolicy::Interval(Duration::from_millis(100)))
        .runtime(&rt)
        .bind_addr(addr)
        .spawn()
        .await?;
    let client = node.client();
    let doc = client.docs.create().await?;
    let author = client.authors.create().await?;
    let hash = doc
        .set_bytes(author, b"foo".to_vec(), b"hi".to_vec())
        .await?;
    assert_latest(&doc, b"foo", b"hi").await;
    let deleted = doc.delete(author, b"foo".to_vec()).await?;
    assert_eq!(deleted, 1);

    let entry = doc.get_one(author, b"foo".to_vec()).await?;
    assert!(entry.is_none());

    // wait for gc
    // TODO: allow to manually trigger gc
    tokio::time::sleep(Duration::from_millis(200)).await;
    let bytes = client.blobs.read_to_bytes(hash).await;
    assert!(bytes.is_err());
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

async fn next<T: std::fmt::Debug>(mut stream: impl Stream<Item = Result<T>> + Unpin) -> T {
    let event = stream
        .next()
        .await
        .expect("stream ended")
        .expect("stream produced error");
    debug!("Event: {event:?}");
    event
}

/// Collect the next n elements of a [`TryStream`]
///
/// If `timeout` is exceeded before n elements are collected an error is returned.
async fn collect_some<T: std::fmt::Debug>(
    mut stream: impl Stream<Item = Result<T>> + Unpin,
    n: usize,
    timeout: Duration,
) -> Result<Vec<T>> {
    let mut res = Vec::with_capacity(n);
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    while res.len() < n {
        tokio::select! {
            () = &mut sleep => {
                bail!("Failed to collect {n} elements in {timeout:?} (collected only {})", res.len());
            },
            event = stream.try_next() => {
                let event = event?;
                match event {
                    None => bail!("stream ended after {} items, but expected {n}", res.len()),
                    Some(event) => res.push(event),
                }
            }
        }
    }
    Ok(res)
}

/// Assert that each item in the iterator is matched by one of the functions in `fns`.
///
/// The iterator must yield exactly as many elements as are in the function list.
/// Order is not imporant. Once a function matched an item, it is removed from the function list.
#[allow(clippy::type_complexity)]
fn assert_each_unordered<T: std::fmt::Debug>(
    items: impl IntoIterator<Item = T>,
    mut fns: Vec<Box<dyn Fn(&T) -> bool>>,
) {
    let len = fns.len();
    let iter = items.into_iter();
    for item in iter {
        if fns.is_empty() {
            panic!("iterator is longer than expected length of {len}");
        }
        let mut ok = false;
        for i in 0..fns.len() {
            if fns[i](&item) {
                ok = true;
                let _ = fns.remove(i);
                break;
            }
        }
        if !ok {
            panic!("no rule matched item {item:?}");
        }
    }
    if !fns.is_empty() {
        panic!(
            "expected {len} elements but stream stopped after {}",
            len - fns.len()
        );
    }
}

/// Asserts that the event is a [`LiveEvent::SyncFinished`] and that the contained [`SyncEvent`]
/// has no error and matches `peer` and `namespace`.
fn match_sync_finished(event: &LiveEvent, peer: PublicKey, namespace: NamespaceId) -> bool {
    let LiveEvent::SyncFinished(e) = event else {
        return false;
    };
    e == &SyncEvent {
        peer,
        namespace,
        result: Ok(()),
        origin: e.origin.clone(),
        finished: e.finished,
    }
}

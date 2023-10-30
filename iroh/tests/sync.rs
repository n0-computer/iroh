use std::{
    future::Future,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use iroh::{
    client::mem::Doc,
    node::{Builder, Node},
    rpc_protocol::ShareMode,
    sync_engine::{LiveEvent, SyncEvent},
};
use iroh_net::key::{PublicKey, SecretKey};
use quic_rpc::transport::misc::DummyServerEndpoint;
use rand::{CryptoRng, Rng, SeedableRng};
use tracing::{debug, info};
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::{util::runtime, Hash};
use iroh_net::derp::DerpMode;
use iroh_sync::{
    store::{self, View, Query},
    AuthorId, ContentStatus, Entry, NamespaceId,
};

const TIMEOUT: Duration = Duration::from_secs(60);

/// Pick up the tokio runtime from the thread local and add a
/// thread per core runtime.
fn test_runtime() -> runtime::Handle {
    runtime::Handle::from_current(1).unwrap()
}

fn test_node(
    rt: runtime::Handle,
    addr: SocketAddr,
    secret_key: SecretKey,
) -> Builder<iroh_bytes::store::mem::Store, store::memory::Store, DummyServerEndpoint> {
    let db = iroh_bytes::store::mem::Store::new(rt.clone());
    let store = iroh_sync::store::memory::Store::default();
    Node::builder(db, store)
        .secret_key(secret_key)
        .derp_mode(DerpMode::Disabled)
        .runtime(&rt)
        .bind_addr(addr)
}

// The function is not `async fn` so that we can take a `&mut` borrow on the `rng` without
// capturing that `&mut` lifetime in the returned future. This allows to call it in a loop while
// still collecting the futures before awaiting them alltogether (see [`spawn_nodes`])
fn spawn_node(
    rt: runtime::Handle,
    i: usize,
    rng: &mut (impl CryptoRng + Rng),
) -> impl Future<Output = anyhow::Result<Node<iroh_bytes::store::mem::Store>>> + 'static {
    let secret_key = SecretKey::generate_with_rng(rng);
    async move {
        let node = test_node(rt, "127.0.0.1:0".parse()?, secret_key);
        let node = node.spawn().await?;
        info!(?i, me = %node.peer_id().fmt_short(), "node spawned");
        Ok(node)
    }
}

async fn spawn_nodes(
    rt: runtime::Handle,
    n: usize,
    mut rng: &mut (impl CryptoRng + Rng),
) -> anyhow::Result<Vec<Node<iroh_bytes::store::mem::Store>>> {
    let mut futs = vec![];
    for i in 0..n {
        futs.push(spawn_node(rt.clone(), i, &mut rng));
    }
    futures::future::join_all(futs).await.into_iter().collect()
}

pub fn test_rng(seed: &[u8]) -> rand_chacha::ChaCha12Rng {
    rand_chacha::ChaCha12Rng::from_seed(*Hash::new(seed).as_bytes())
}

/// This tests the simplest scenario: A node connects to another node, and performs sync.
#[tokio::test]
async fn sync_simple() -> Result<()> {
    setup_logging();
    let mut rng = test_rng(b"sync_simple");
    let rt = test_runtime();
    let nodes = spawn_nodes(rt, 2, &mut rng).await?;
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
    assert_next_unordered(
        &mut events1,
        TIMEOUT,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer0)),
            Box::new(move |e| matches!(e, LiveEvent::InsertRemote { from, .. } if *from == peer0 )),
            Box::new(move |e| match_sync_finished(e, peer0, doc_id)),
            Box::new(move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == hash0)),
        ],
    )
    .await;
    assert_latest(&doc1, b"k1", b"v1").await;

    info!("node0: assert 2 events");
    assert_next_unordered(
        &mut events0,
        TIMEOUT,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer1)),
            Box::new(move |e| match_sync_finished(e, peer1, doc_id)),
        ],
    )
    .await;

    for node in nodes {
        node.shutdown();
    }
    Ok(())
}

/// Test subscribing to replica events (without sync)
#[tokio::test]
async fn sync_subscribe_no_sync() -> Result<()> {
    let mut rng = test_rng(b"sync_subscribe");
    setup_logging();
    let rt = test_runtime();
    let node = spawn_node(rt, 0, &mut rng).await?;
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
async fn sync_gossip_bulk() -> Result<()> {
    let n_entries: usize = std::env::var("N_ENTRIES")
        .map(|x| x.parse().expect("N_ENTRIES must be a number"))
        .unwrap_or(1000);
    let mut rng = test_rng(b"sync_gossip_bulk");
    setup_logging();

    let rt = test_runtime();
    let nodes = spawn_nodes(rt.clone(), 2, &mut rng).await?;
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    let _peer0 = nodes[0].peer_id();
    let author0 = clients[0].authors.create().await?;
    let doc0 = clients[0].docs.create().await?;
    let mut ticket = doc0.share(ShareMode::Write).await?;
    // unset peers to not yet start sync
    let peers = ticket.peers.clone();
    ticket.peers = vec![];
    let doc1 = clients[1].docs.import(ticket).await?;
    let mut events = doc1.subscribe().await?;

    // create entries for initial sync.
    let now = Instant::now();
    let value = b"foo";
    for i in 0..n_entries {
        let key = format!("init/{i}");
        doc0.set_bytes(author0, key.as_bytes().to_vec(), value.to_vec())
            .await?;
    }
    let elapsed = now.elapsed();
    info!(
        "insert took {elapsed:?} for {n_entries} ({:?} per entry)",
        elapsed / n_entries as u32
    );

    let now = Instant::now();
    let mut count = 0;
    doc0.start_sync(vec![]).await?;
    doc1.start_sync(peers).await?;
    while let Some(event) = events.next().await {
        let event = event?;
        if matches!(event, LiveEvent::InsertRemote { .. }) {
            count += 1;
        }
        if count == n_entries {
            break;
        }
    }
    let elapsed = now.elapsed();
    info!(
        "initial sync took {elapsed:?} for {n_entries} ({:?} per entry)",
        elapsed / n_entries as u32
    );

    // publish another 1000 entries
    let mut count = 0;
    let value = b"foo";
    let now = Instant::now();
    for i in 0..n_entries {
        let key = format!("gossip/{i}");
        doc0.set_bytes(author0, key.as_bytes().to_vec(), value.to_vec())
            .await?;
    }
    let elapsed = now.elapsed();
    info!(
        "insert took {elapsed:?} for {n_entries} ({:?} per entry)",
        elapsed / n_entries as u32
    );

    while let Some(event) = events.next().await {
        let event = event?;
        if matches!(event, LiveEvent::InsertRemote { .. }) {
            count += 1;
        }
        if count == n_entries {
            break;
        }
    }
    let elapsed = now.elapsed();
    info!(
        "gossip recv took {elapsed:?} for {n_entries} ({:?} per entry)",
        elapsed / n_entries as u32
    );

    Ok(())
}

/// This tests basic sync and gossip with 3 peers.
#[tokio::test]
async fn sync_full_basic() -> Result<()> {
    let mut rng = test_rng(b"sync_full_basic");
    setup_logging();
    let rt = test_runtime();
    let mut nodes = spawn_nodes(rt.clone(), 2, &mut rng).await?;
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
    assert_next_unordered(
        &mut events1,
        TIMEOUT,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer0)),
            Box::new(move |e| matches!(e, LiveEvent::InsertRemote { from, .. } if *from == peer0 )),
            Box::new(move |e| match_sync_finished(e, peer0, doc_id)),
            Box::new(move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == hash0)),
        ],
    )
    .await;

    info!("peer0: wait for 2 events (join & accept sync finished from peer1)");
    assert_next_unordered(
        &mut events0,
        TIMEOUT,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer1)),
            Box::new(move |e| match_sync_finished(e, peer1, doc_id)),
        ],
    )
    .await;

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
    assert_next_unordered(
        &mut events0,
        TIMEOUT,
        vec![
            Box::new(
                move |e| matches!(e, LiveEvent::InsertRemote { from, content_status: ContentStatus::Missing, .. } if *from == peer1),
            ),
            Box::new(move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == hash1)),
        ],
    ).await;
    assert_latest(&doc0, key1, value1).await;

    // Note: If we could check gossip messages directly here (we can't easily), we would notice
    // that peer1 will receive a `Op::ContentReady` gossip message, broadcast
    // by peer0 with neighbor scope. This message is superflous, and peer0 could know that, however
    // our gossip implementation does not allow us to filter message receivers this way.

    info!("peer2: spawn");
    nodes.push(spawn_node(rt.clone(), nodes.len(), &mut rng).await?);
    clients.push(nodes.last().unwrap().client());
    let doc2 = clients[2].docs.import(ticket).await?;
    let peer2 = nodes[2].peer_id();
    let mut events2 = doc2.subscribe().await?;

    info!("peer2: wait for 8 events (from sync with peers)");
    assert_next_unordered_with_optionals(
        &mut events2,
        TIMEOUT,
        // required events
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
        // optional events
        // it may happen that we run sync two times against our two peers:
        // if the first sync (as a result of us joining the peer manually through the ticket) completes
        // before the peer shows up as a neighbor, we run sync again for the NeighborUp event.
        vec![
            // 2 SyncFinished events
            Box::new(move |e| match_sync_finished(e, peer0, doc_id)),
            Box::new(move |e| match_sync_finished(e, peer1, doc_id)),
        ]
    ).await;
    assert_latest(&doc2, b"k1", b"v1").await;
    assert_latest(&doc2, b"k2", b"v2").await;

    info!("peer0: wait for 2 events (join & accept sync finished from peer2)");
    assert_next_unordered(
        &mut events0,
        TIMEOUT,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer2)),
            Box::new(move |e| match_sync_finished(e, peer2, doc_id)),
        ],
    )
    .await;

    info!("peer1: wait for 2 events (join & accept sync finished from peer2)");
    assert_next_unordered(
        &mut events1,
        TIMEOUT,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer2)),
            Box::new(move |e| match_sync_finished(e, peer2, doc_id)),
        ],
    )
    .await;

    info!("shutdown");
    for node in nodes {
        node.shutdown();
    }

    Ok(())
}

#[tokio::test]
async fn sync_open_close() -> Result<()> {
    let mut rng = test_rng(b"sync_subscribe_stop_close");
    setup_logging();
    let rt = test_runtime();
    let node = spawn_node(rt, 0, &mut rng).await?;
    let client = node.client();

    let doc = client.docs.create().await?;
    let status = doc.status().await?;
    assert_eq!(status.handles, 1);

    let doc2 = client.docs.open(doc.id()).await?.unwrap();
    let status = doc2.status().await?;
    assert_eq!(status.handles, 2);

    doc.close().await?;
    assert!(doc.status().await.is_err());

    let status = doc2.status().await?;
    assert_eq!(status.handles, 1);

    Ok(())
}

#[tokio::test]
async fn sync_subscribe_stop_close() -> Result<()> {
    let mut rng = test_rng(b"sync_subscribe_stop_close");
    setup_logging();
    let rt = test_runtime();
    let node = spawn_node(rt, 0, &mut rng).await?;
    let client = node.client();

    let doc = client.docs.create().await?;
    let author = client.authors.create().await?;

    let status = doc.status().await?;
    assert_eq!(status.subscribers, 0);
    assert_eq!(status.handles, 1);
    assert!(!status.sync);

    doc.start_sync(vec![]).await?;
    let status = doc.status().await?;
    assert!(status.sync);
    assert_eq!(status.handles, 2);
    assert_eq!(status.subscribers, 1);

    let sub = doc.subscribe().await?;
    let status = doc.status().await?;
    assert_eq!(status.subscribers, 2);
    drop(sub);
    // trigger an event that makes the actor check if the event channels are still connected
    doc.set_bytes(author, b"x".to_vec(), b"x".to_vec()).await?;
    let status = doc.status().await?;
    assert_eq!(status.subscribers, 1);

    doc.leave().await?;
    let status = doc.status().await?;
    assert_eq!(status.subscribers, 0);
    assert_eq!(status.handles, 1);
    assert!(!status.sync);

    Ok(())
}

#[derive(Debug, Ord, Eq, PartialEq, PartialOrd, Clone)]
struct ExpectedEntry {
    author: AuthorId,
    key: String,
    value: String,
}

impl PartialEq<Entry> for ExpectedEntry {
    fn eq(&self, other: &Entry) -> bool {
        self.key.as_bytes() == other.key()
            && Hash::new(&self.value) == other.content_hash()
            && self.author == other.author()
    }
}
impl PartialEq<(Entry, Bytes)> for ExpectedEntry {
    fn eq(&self, (entry, content): &(Entry, Bytes)) -> bool {
        self.key.as_bytes() == entry.key()
            && Hash::new(&self.value) == entry.content_hash()
            && self.author == entry.author()
            && self.value.as_bytes() == content.as_ref()
    }
}
impl PartialEq<ExpectedEntry> for Entry {
    fn eq(&self, other: &ExpectedEntry) -> bool {
        other.eq(self)
    }
}
impl PartialEq<ExpectedEntry> for (Entry, Bytes) {
    fn eq(&self, other: &ExpectedEntry) -> bool {
        other.eq(self)
    }
}

#[tokio::test]
async fn doc_delete() -> Result<()> {
    let rt = test_runtime();
    let db = iroh_bytes::store::mem::Store::new(rt.clone());
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
    let deleted = doc.del(author, b"foo".to_vec()).await?;
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

#[tokio::test]
async fn sync_drop_doc() -> Result<()> {
    let mut rng = test_rng(b"sync_drop_doc");
    setup_logging();
    let rt = test_runtime();
    let node = spawn_node(rt, 0, &mut rng).await?;
    let client = node.client();

    let doc = client.docs.create().await?;
    let author = client.authors.create().await?;

    let mut sub = doc.subscribe().await?;
    doc.set_bytes(author, b"foo".to_vec(), b"bar".to_vec())
        .await?;
    let ev = sub.next().await;
    assert!(matches!(ev, Some(Ok(LiveEvent::InsertLocal { .. }))));

    client.docs.drop_doc(doc.id()).await?;
    let res = doc.get_one(author, b"foo".to_vec()).await;
    assert!(res.is_err());
    let res = doc
        .set_bytes(author, b"foo".to_vec(), b"bar".to_vec())
        .await;
    assert!(res.is_err());
    let res = client.docs.open(doc.id()).await;
    assert!(res.is_err());
    let ev = sub.next().await;
    assert!(ev.is_none());

    Ok(())
}

async fn assert_latest(doc: &Doc, key: &[u8], value: &[u8]) {
    let content = get_latest(doc, key).await.unwrap();
    assert_eq!(content, value.to_vec());
}

async fn get_latest(doc: &Doc, key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let query = Query::key(key.to_vec());
    let entry = doc
        .get_many(query, View::LatestByKeyAndAuthor)
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

#[allow(clippy::type_complexity)]
fn apply_matchers<T>(item: &T, matchers: &mut Vec<Box<dyn Fn(&T) -> bool>>) -> bool {
    for i in 0..matchers.len() {
        if matchers[i](item) {
            let _ = matchers.remove(i);
            return true;
        }
    }
    false
}

/// Receive `matchers.len()` elements from a stream and assert that each element matches one of the
/// functions in `matchers`.
///
/// Order of the matchers is not relevant.
///
/// Returns all received events.
#[allow(clippy::type_complexity)]
async fn assert_next_unordered<T: std::fmt::Debug + Clone>(
    stream: impl Stream<Item = Result<T>> + Unpin,
    timeout: Duration,
    matchers: Vec<Box<dyn Fn(&T) -> bool>>,
) -> Vec<T> {
    assert_next_unordered_with_optionals(stream, timeout, matchers, vec![]).await
}

/// Receive between `min` and `max` elements from the stream and assert that each element matches
/// either one of the matchers in `required_matchers` or in `optional_matchers`.
///
/// Order of the matchers is not relevant.
///
/// Will return an error if:
/// * Any element fails to match one of the required or optional matchers
/// * More than `max` elements were received, but not all required matchers were used yet
/// * The timeout completes before all required matchers were used
///
/// Returns all received events.
#[allow(clippy::type_complexity)]
async fn assert_next_unordered_with_optionals<T: std::fmt::Debug + Clone>(
    mut stream: impl Stream<Item = Result<T>> + Unpin,
    timeout: Duration,
    mut required_matchers: Vec<Box<dyn Fn(&T) -> bool>>,
    mut optional_matchers: Vec<Box<dyn Fn(&T) -> bool>>,
) -> Vec<T> {
    let max = required_matchers.len() + optional_matchers.len();
    let required = required_matchers.len();
    // we have to use a mutex because rustc is not intelligent enough to realize
    // that the mutable borrow terminates when the future completes
    let events = Arc::new(parking_lot::Mutex::new(vec![]));
    let fut = async {
        while let Some(event) = stream.next().await {
            let event = event.context("failed to read from stream")?;
            let len = {
                let mut events = events.lock();
                events.push(event.clone());
                events.len()
            };
            if !apply_matchers(&event, &mut required_matchers)
                && !apply_matchers(&event, &mut optional_matchers)
            {
                bail!("Event didn't match any matcher: {event:?}");
            }
            if required_matchers.is_empty() || len == max {
                break;
            }
        }
        if !required_matchers.is_empty() {
            bail!(
                "Matched only {} of {required} required matchers",
                required - required_matchers.len()
            );
        }
        Ok(())
    };
    tokio::pin!(fut);
    let res = tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow!("Timeout reached ({timeout:?})"))
        .and_then(|res| res);
    let events = events.lock().clone();
    if let Err(err) = &res {
        println!("Received events: {events:#?}");
        println!(
            "Received {} events, expected between {required} and {max}",
            events.len()
        );
        panic!("Failed to receive or match all events: {err:?}");
    }
    events
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

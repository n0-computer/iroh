#![cfg(feature = "mem-db")]

use std::{future::Future, net::SocketAddr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures::{FutureExt, Stream, StreamExt, TryStreamExt};
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
    store::{self, GetFilter},
    AuthorId, ContentStatus, Entry, NamespaceId,
};

/// Time limit for event collection in sync tests.
const LIMIT: Duration = Duration::from_secs(30);

/// Pick up the tokio runtime from the thread local and add a
/// thread per core runtime.
fn test_runtime() -> runtime::Handle {
    runtime::Handle::from_current(1).unwrap()
}

fn test_node(
    rt: runtime::Handle,
    addr: SocketAddr,
    secret_key: SecretKey,
) -> Builder<iroh::baomap::mem::Store, store::memory::Store, DummyServerEndpoint> {
    let db = iroh::baomap::mem::Store::new(rt.clone());
    let store = iroh_sync::store::memory::Store::default();
    Node::builder(db, store)
        .secret_key(secret_key)
        .derp_mode(DerpMode::Disabled)
        .runtime(&rt)
        .bind_addr(addr)
}

fn spawn_node(
    rt: runtime::Handle,
    i: usize,
    rng: &mut (impl CryptoRng + Rng),
) -> impl Future<Output = anyhow::Result<Node<iroh::baomap::mem::Store, store::memory::Store>>> + 'static
{
    let secret_key = SecretKey::generate_with_rng(rng);
    async move {
        let node = test_node(rt, "127.0.0.1:0".parse()?, secret_key);
        let node = node.spawn().await?;
        info!("spawned node {i} {:?}", node.peer_id());
        Ok(node)
    }
}

async fn spawn_nodes(
    rt: runtime::Handle,
    n: usize,
    mut rng: &mut (impl CryptoRng + Rng),
) -> anyhow::Result<Vec<Node<iroh::baomap::mem::Store, store::memory::Store>>> {
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
    nodes.push(spawn_node(rt.clone(), nodes.len(), &mut rng).await?);
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
    let mut rng = test_rng(b"sync_subscribe_stop");
    setup_logging();
    let rt = test_runtime();
    let node = spawn_node(rt, 0, &mut rng).await?;
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

// #[tokio::test(flavor = "multi_thread")]
#[tokio::test]
async fn sync_big() -> Result<()> {
    #[cfg(tokio_unstable)]
    console_subscriber::init();
    let mut rng = test_rng(b"sync_big");
    setup_logging();
    let rt = test_runtime();
    let n_nodes = std::env::var("NODES")
        .map(|v| v.parse().expect("NODES must be a number"))
        .unwrap_or(20);
    let n_entries_init = 1;
    // let n_entries_live = 2;
    // let n_entries_phase2 = 5;

    tokio::task::spawn(async move {
        for i in 0.. {
            tokio::time::sleep(Duration::from_secs(1)).await;
            info!("tick {i}");
        }
    });

    let nodes = spawn_nodes(rt, n_nodes, &mut rng).await?;
    let peer_ids = nodes.iter().map(|node| node.peer_id()).collect::<Vec<_>>();
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();
    let authors = collect_futures(clients.iter().map(|c| c.authors.create())).await?;

    let doc0 = clients[0].docs.create().await?;
    let mut ticket = doc0.share(ShareMode::Write).await?;
    // do not join for now, just import without any peer info
    let peer0 = ticket.peers[0].clone();
    ticket.peers = vec![];

    let mut docs = vec![];
    docs.push(doc0);
    docs.extend_from_slice(
        &collect_futures(
            clients
                .iter()
                .skip(1)
                .map(|c| c.docs.import(ticket.clone())),
        )
        .await?,
    );

    let mut expected = vec![];

    // create initial data on each node
    publish(&docs, &mut expected, n_entries_init, |i, j| {
        (
            authors[i],
            format!("init/{:?}/{j}", peer_ids[i]),
            format!("init:{i}:{j}"),
        )
    })
    .await?;

    // assert initial data
    for (i, doc) in docs.iter().enumerate() {
        let entries = get_all_with_content(doc).await?;
        let mut expected = expected
            .iter()
            .filter(|e| e.author == authors[i])
            .cloned()
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(entries, expected, "phase1 pre-sync correct");
    }

    // setup event streams
    let events = collect_futures(docs.iter().map(|d| d.subscribe())).await?;

    // join nodes together
    for (i, doc) in docs.iter().enumerate().skip(1) {
        info!(me = ?peer_ids[i], peer = ?peer0.peer_id, "join");
        doc.start_sync(vec![peer0.clone()]).await?;
    }

    // wait for InsertRemote events stuff to happen
    info!("wait for all peers to receive insert events");
    let expected_inserts = (n_nodes - 1) * n_entries_init;
    let mut futs = vec![];
    for (i, events) in events.into_iter().enumerate() {
        let doc = docs[i].clone();
        let expected = expected.clone();
        let me = peer_ids[i];
        let fut = async move {
            wait_for_events(events, expected_inserts, Duration::from_secs(30), me, |e| {
                matches!(e, LiveEvent::InsertRemote { .. })
            })
            .await?;
            let entries = get_all(&doc).await?;
            if entries != expected {
                Err(anyhow!(
                    "node {i} failed (have {} but expected {})",
                    entries.len(),
                    expected.len()
                ))
            } else {
                info!(?me, "All done, all good");
                Ok(())
            }
        };
        let fut = fut.map(move |r| r.with_context(move || format!("node {i}")));
        futs.push(fut);
    }
    futures::future::try_join_all(futs).await?;

    assert_all_docs(&docs, &peer_ids, &expected, "after initial sync").await;

    // the latter part of the test is working already.
    // disabled for now - will move into another test.
    //
    // add entries while everyone is live.
    // create initial data on each node
    // info!("publish {n_entries_live} entries on each node");
    // publish(&docs, &mut expected, n_entries_live, |i, j| {
    //     (authors[i], format!("live/{j}"), format!("live:{i}:{j}"))
    // })
    // .await?;
    //
    // // wait for stuff to happen!
    // info!("sleep 3s");
    // tokio::time::sleep(Duration::from_secs(3)).await;
    //
    // // assert that everyone has everything...
    // assert_all_docs(&docs, &peer_ids, &expected, "after gossip").await;
    //
    // info!(
    //     "peer1 {:?} goes offline and adds a new entry",
    //     nodes[1].peer_id()
    // );
    // docs[1].stop_sync().await?;
    // publish(&[docs[1].clone()], &mut expected, 1, |i, j| {
    //     (authors[1], format!("change/{j}"), format!("change:{i}:{j}"))
    // })
    // .await?;
    // info!(
    //     "peer1 {:?} goes online again and joins peer0 {:?}",
    //     nodes[1].peer_id(),
    //     nodes[0].peer_id(),
    // );
    // docs[1].start_sync(vec![peer0.clone()]).await?;
    //
    // info!("sleep 3s");
    // tokio::time::sleep(Duration::from_secs(3)).await;
    // assert_all_docs(&docs, &peer_ids, &expected, "after peer1 published").await;

    info!("shutdown");
    for node in nodes {
        node.shutdown();
    }

    Ok(())
}

async fn wait_for_events(
    mut events: impl Stream<Item = Result<LiveEvent>> + Send + Unpin + 'static,
    expected_n: usize,
    timeout_per_event: Duration,
    me: PublicKey,
    matcher: impl Fn(LiveEvent) -> bool,
) -> anyhow::Result<()> {
    let mut i = 0;
    while i < expected_n {
        let event = tokio::time::timeout(timeout_per_event, events.next())
            .await
            .map_err(|_| anyhow!("timeout while getting InsertRemote event after {i}"))?
            .ok_or_else(|| anyhow!("end of event stream for after {i}"))??;
        if matcher(event) {
            i += 1;
            debug!(?me, "recv event {i} of {expected_n}");
        }
    }
    Ok(())
}

async fn assert_all_docs(
    docs: &[Doc],
    peer_ids: &[PublicKey],
    expected: &Vec<ExpectedEntry>,
    label: &str,
) {
    info!("validate all peers: {label}");
    for (i, doc) in docs.iter().enumerate() {
        let entries = get_all(doc).await.unwrap_or_else(|err| {
            panic!("failed to get entries for peer {:?}: {err:?}", peer_ids[i])
        });
        assert_eq!(
            &entries,
            expected,
            "{label}: peer {i} {:?} failed (have {} but expected {})",
            peer_ids[i],
            entries.len(),
            expected.len()
        );
    }
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

async fn publish(
    docs: &[Doc],
    expected: &mut Vec<ExpectedEntry>,
    n: usize,
    cb: impl Fn(usize, usize) -> (AuthorId, String, String),
) -> anyhow::Result<()> {
    for (i, doc) in docs.iter().enumerate() {
        for j in 0..n {
            let (author, key, value) = cb(i, j);
            doc.set_bytes(author, key.as_bytes().to_vec(), value.as_bytes().to_vec())
                .await?;
            expected.push(ExpectedEntry { author, key, value });
        }
    }
    expected.sort();
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

/// Collect an iterator into futures by joining them all and failing if any future failed.
async fn collect_futures<T>(
    futs: impl IntoIterator<Item = impl Future<Output = anyhow::Result<T>>>,
) -> anyhow::Result<Vec<T>> {
    futures::future::join_all(futs)
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()
}

/// Get all entries of a document.
async fn get_all(doc: &Doc) -> anyhow::Result<Vec<Entry>> {
    let entries = doc.get_many(GetFilter::All).await?;
    let entries = entries.collect::<Vec<_>>().await;
    entries.into_iter().collect()
}

/// Get all entries of a document with the blob content.
async fn get_all_with_content(doc: &Doc) -> anyhow::Result<Vec<(Entry, Bytes)>> {
    let entries = doc.get_many(GetFilter::All).await?;
    let entries = entries.and_then(|entry| async {
        let content = doc.read_to_bytes(&entry).await;
        content.map(|c| (entry, c))
    });
    let entries = entries.collect::<Vec<_>>().await;
    let entries = entries.into_iter().collect::<Result<Vec<_>>>()?;
    Ok(entries)
}

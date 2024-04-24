use std::{
    collections::HashMap,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures_lite::Stream;
use futures_util::{FutureExt, StreamExt, TryStreamExt};
use iroh::{
    client::{mem::Doc, Entry, LiveEvent},
    node::{Builder, Node},
    rpc_protocol::ShareMode,
};
use iroh_net::key::{PublicKey, SecretKey};
use quic_rpc::transport::misc::DummyServerEndpoint;
use rand::{CryptoRng, Rng, SeedableRng};
use tracing::{debug, error_span, info, Instrument};
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::Hash;
use iroh_net::relay::RelayMode;
use iroh_sync::{
    store::{DownloadPolicy, FilterKind, Query},
    AuthorId, ContentStatus,
};

const TIMEOUT: Duration = Duration::from_secs(60);

fn test_node(secret_key: SecretKey) -> Builder<iroh_bytes::store::mem::Store, DummyServerEndpoint> {
    Node::memory()
        .secret_key(secret_key)
        .relay_mode(RelayMode::Disabled)
}

// The function is not `async fn` so that we can take a `&mut` borrow on the `rng` without
// capturing that `&mut` lifetime in the returned future. This allows to call it in a loop while
// still collecting the futures before awaiting them altogether (see [`spawn_nodes`])
fn spawn_node(
    i: usize,
    rng: &mut (impl CryptoRng + Rng),
) -> impl Future<Output = anyhow::Result<Node<iroh_bytes::store::mem::Store>>> + 'static {
    let secret_key = SecretKey::generate_with_rng(rng);
    async move {
        let node = test_node(secret_key);
        let node = node.spawn().await?;
        info!(?i, me = %node.node_id().fmt_short(), "node spawned");
        Ok(node)
    }
}

async fn spawn_nodes(
    n: usize,
    mut rng: &mut (impl CryptoRng + Rng),
) -> anyhow::Result<Vec<Node<iroh_bytes::store::mem::Store>>> {
    let mut futs = vec![];
    for i in 0..n {
        futs.push(spawn_node(i, &mut rng));
    }
    futures_buffered::join_all(futs).await.into_iter().collect()
}

pub fn test_rng(seed: &[u8]) -> rand_chacha::ChaCha12Rng {
    rand_chacha::ChaCha12Rng::from_seed(*Hash::new(seed).as_bytes())
}

/// This tests the simplest scenario: A node connects to another node, and performs sync.
#[tokio::test]
async fn sync_simple() -> Result<()> {
    setup_logging();
    let mut rng = test_rng(b"sync_simple");
    let nodes = spawn_nodes(2, &mut rng).await?;
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    // create doc on node0
    let peer0 = nodes[0].node_id();
    let author0 = clients[0].authors.create().await?;
    let doc0 = clients[0].docs.create().await?;
    let hash0 = doc0
        .set_bytes(author0, b"k1".to_vec(), b"v1".to_vec())
        .await?;
    assert_latest(&doc0, b"k1", b"v1").await;
    let ticket = doc0.share(ShareMode::Write).await?;

    let mut events0 = doc0.subscribe().await?;

    info!("node1: join");
    let peer1 = nodes[1].node_id();
    let doc1 = clients[1].docs.import(ticket.clone()).await?;
    let mut events1 = doc1.subscribe().await?;
    info!("node1: assert 4 events");
    assert_next_unordered(
        &mut events1,
        TIMEOUT,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer0)),
            Box::new(move |e| matches!(e, LiveEvent::InsertRemote { from, .. } if *from == peer0 )),
            Box::new(move |e| match_sync_finished(e, peer0)),
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
            Box::new(move |e| match_sync_finished(e, peer1)),
        ],
    )
    .await;

    for node in nodes {
        node.shutdown().await?;
    }
    Ok(())
}

/// Test subscribing to replica events (without sync)
#[tokio::test]
async fn sync_subscribe_no_sync() -> Result<()> {
    let mut rng = test_rng(b"sync_subscribe");
    setup_logging();
    let node = spawn_node(0, &mut rng).await?;
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
    node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn sync_gossip_bulk() -> Result<()> {
    let n_entries: usize = std::env::var("N_ENTRIES")
        .map(|x| x.parse().expect("N_ENTRIES must be a number"))
        .unwrap_or(1000);
    let mut rng = test_rng(b"sync_gossip_bulk");
    setup_logging();

    let nodes = spawn_nodes(2, &mut rng).await?;
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    let _peer0 = nodes[0].node_id();
    let author0 = clients[0].authors.create().await?;
    let doc0 = clients[0].docs.create().await?;
    let mut ticket = doc0.share(ShareMode::Write).await?;
    // unset peers to not yet start sync
    let peers = ticket.nodes.clone();
    ticket.nodes = vec![];
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
    let mut nodes = spawn_nodes(2, &mut rng).await?;
    let mut clients = nodes
        .iter()
        .map(|node| node.client().clone())
        .collect::<Vec<_>>();

    // peer0: create doc and ticket
    let peer0 = nodes[0].node_id();
    let author0 = clients[0].authors.create().await?;
    let doc0 = clients[0].docs.create().await?;
    let mut events0 = doc0.subscribe().await?;
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
    let peer1 = nodes[1].node_id();
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
            Box::new(move |e| match_sync_finished(e, peer0)),
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
            Box::new(move |e| match_sync_finished(e, peer1)),
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
    // by peer0 with neighbor scope. This message is superfluous, and peer0 could know that, however
    // our gossip implementation does not allow us to filter message receivers this way.

    info!("peer2: spawn");
    nodes.push(spawn_node(nodes.len(), &mut rng).await?);
    clients.push(nodes.last().unwrap().client().clone());
    let doc2 = clients[2].docs.import(ticket).await?;
    let peer2 = nodes[2].node_id();
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
            Box::new(move |e| match_sync_finished(e, peer0)),
            Box::new(move |e| match_sync_finished(e, peer1)),
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
            Box::new(move |e| match_sync_finished(e, peer0)),
            Box::new(move |e| match_sync_finished(e, peer1)),
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
            Box::new(move |e| match_sync_finished(e, peer2)),
        ],
    )
    .await;

    info!("peer1: wait for 2 events (join & accept sync finished from peer2)");
    assert_next_unordered(
        &mut events1,
        TIMEOUT,
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(peer) if *peer == peer2)),
            Box::new(move |e| match_sync_finished(e, peer2)),
        ],
    )
    .await;

    info!("shutdown");
    for node in nodes {
        node.shutdown().await?;
    }

    Ok(())
}

#[tokio::test]
async fn sync_open_close() -> Result<()> {
    let mut rng = test_rng(b"sync_subscribe_stop_close");
    setup_logging();
    let node = spawn_node(0, &mut rng).await?;
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
    let node = spawn_node(0, &mut rng).await?;
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

#[tokio::test]
#[cfg(feature = "test-utils")]
async fn test_sync_via_relay() -> Result<()> {
    let _guard = iroh_test::logging::setup();
    let (relay_map, _relay_url, _guard) = iroh_net::test_utils::run_relay_server().await?;

    let node1 = Node::memory()
        .bind_port(0)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .insecure_skip_relay_cert_verify(true)
        .spawn()
        .await?;
    let node1_id = node1.node_id();
    let node2 = Node::memory()
        .bind_port(0)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .insecure_skip_relay_cert_verify(true)
        .spawn()
        .await?;

    let doc1 = node1.docs.create().await?;
    let author1 = node1.authors.create().await?;
    let inserted_hash = doc1
        .set_bytes(author1, b"foo".to_vec(), b"bar".to_vec())
        .await?;
    let mut ticket = doc1.share(ShareMode::Write).await?;

    // remove direct addrs to force connect via relay
    ticket.nodes[0].info.direct_addresses = Default::default();

    // join
    let doc2 = node2.docs.import(ticket).await?;
    let mut events = doc2.subscribe().await?;

    assert_next_unordered_with_optionals(
        &mut events,
        Duration::from_secs(2),
        vec![
            Box::new(move |e| matches!(e, LiveEvent::NeighborUp(n) if *n== node1_id)),
            Box::new(move |e| match_sync_finished(e, node1_id)),
            Box::new(
                move |e| matches!(e, LiveEvent::InsertRemote { from, content_status: ContentStatus::Missing, .. } if *from == node1_id),
            ),
            Box::new(
                move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == inserted_hash),
            ),
        ],
        vec![Box::new(move |e| match_sync_finished(e, node1_id))],
    ).await;
    let actual = doc2
        .get_exact(author1, b"foo", false)
        .await?
        .expect("entry to exist")
        .content_bytes(&doc2)
        .await?;
    assert_eq!(actual.as_ref(), b"bar");

    // update
    let updated_hash = doc1
        .set_bytes(author1, b"foo".to_vec(), b"update".to_vec())
        .await?;
    assert_next_unordered_with_optionals(
        &mut events,
        Duration::from_secs(2),
        vec![
            Box::new(
                move |e| matches!(e, LiveEvent::InsertRemote { from, content_status: ContentStatus::Missing, .. } if *from == node1_id),
            ),
            Box::new(
                move |e| matches!(e, LiveEvent::ContentReady { hash } if *hash == updated_hash),
            ),
        ],
        vec![Box::new(move |e| match_sync_finished(e, node1_id))],
    ).await;
    let actual = doc2
        .get_exact(author1, b"foo", false)
        .await?
        .expect("entry to exist")
        .content_bytes(&doc2)
        .await?;
    assert_eq!(actual.as_ref(), b"update");
    Ok(())
}

/// Joins two nodes that write to the same document but have differing download policies and tests
/// that they both synced the key info but not the content.
#[tokio::test]
async fn test_download_policies() -> Result<()> {
    // keys node a has
    let star_wars_movies = &[
        "star_wars/prequel/the_phantom_menace",
        "star_wars/prequel/attack_of_the_clones",
        "star_wars/prequel/revenge_of_the_sith",
        "star_wars/og/a_new_hope",
        "star_wars/og/the_empire_strikes_back",
        "star_wars/og/return_of_the_jedi",
    ];
    // keys node b has
    let lotr_movies = &[
        "lotr/fellowship_of_the_ring",
        "lotr/the_two_towers",
        "lotr/return_of_the_king",
    ];

    // content policy for what b wants
    let policy_b =
        DownloadPolicy::EverythingExcept(vec![FilterKind::Prefix("star_wars/og".into())]);
    // content policy for what a wants
    let policy_a = DownloadPolicy::NothingExcept(vec![FilterKind::Exact(
        "lotr/fellowship_of_the_ring".into(),
    )]);

    // a will sync all lotr keys but download a single key
    const EXPECTED_A_SYNCED: usize = 3;
    const EXPECTED_A_DOWNLOADED: usize = 1;

    // b will sync all star wars content but download only the prequel keys
    const EXPECTED_B_SYNCED: usize = 6;
    const EXPECTED_B_DOWNLOADED: usize = 3;

    let mut rng = test_rng(b"sync_download_policies");
    setup_logging();
    let nodes = spawn_nodes(2, &mut rng).await?;
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    let doc_a = clients[0].docs.create().await?;
    let author_a = clients[0].authors.create().await?;
    let ticket = doc_a.share(ShareMode::Write).await?;

    let doc_b = clients[1].docs.import(ticket).await?;
    let author_b = clients[1].authors.create().await?;

    doc_a.set_download_policy(policy_a).await?;
    doc_b.set_download_policy(policy_b).await?;

    let mut events_a = doc_a.subscribe().await?;
    let mut events_b = doc_b.subscribe().await?;

    let mut key_hashes: HashMap<iroh_bytes::Hash, &'static str> = HashMap::default();

    // set content in a
    for k in star_wars_movies.iter() {
        let hash = doc_a
            .set_bytes(author_a, k.to_owned(), k.to_owned())
            .await?;
        key_hashes.insert(hash, k);
    }

    // set content in b
    for k in lotr_movies.iter() {
        let hash = doc_b
            .set_bytes(author_b, k.to_owned(), k.to_owned())
            .await?;
        key_hashes.insert(hash, k);
    }

    assert_eq!(key_hashes.len(), star_wars_movies.len() + lotr_movies.len());

    let fut = async {
        use LiveEvent::*;
        let mut downloaded_a: Vec<&'static str> = Vec::new();
        let mut downloaded_b: Vec<&'static str> = Vec::new();
        let mut synced_a = 0usize;
        let mut synced_b = 0usize;
        loop {
            tokio::select! {
                Some(Ok(ev)) = events_a.next() => {
                    match ev {
                        InsertRemote { content_status, entry, .. } => {
                            synced_a += 1;
                            if let ContentStatus::Complete = content_status {
                                downloaded_a.push(key_hashes.get(&entry.content_hash()).unwrap())
                            }
                        },
                        ContentReady { hash } => {
                            downloaded_a.push(key_hashes.get(&hash).unwrap());
                        },
                        _ => {}
                    }
                }
                Some(Ok(ev)) = events_b.next() => {
                    match ev {
                        InsertRemote { content_status, entry, .. } => {
                            synced_b += 1;
                            if let ContentStatus::Complete = content_status {
                                downloaded_b.push(key_hashes.get(&entry.content_hash()).unwrap())
                            }
                        },
                        ContentReady { hash } => {
                            downloaded_b.push(key_hashes.get(&hash).unwrap());
                        },
                        _ => {}
                    }
                }
            }

            if synced_a == EXPECTED_A_SYNCED
                && downloaded_a.len() == EXPECTED_A_DOWNLOADED
                && synced_b == EXPECTED_B_SYNCED
                && downloaded_b.len() == EXPECTED_B_DOWNLOADED
            {
                break;
            }
        }
        (downloaded_a, downloaded_b)
    };

    let (downloaded_a, mut downloaded_b) = tokio::time::timeout(TIMEOUT, fut)
        .await
        .context("timeout elapsed")?;

    downloaded_b.sort();
    assert_eq!(downloaded_a, vec!["lotr/fellowship_of_the_ring"]);
    assert_eq!(
        downloaded_b,
        vec![
            "star_wars/prequel/attack_of_the_clones",
            "star_wars/prequel/revenge_of_the_sith",
            "star_wars/prequel/the_phantom_menace",
        ]
    );

    Ok(())
}

/// Test sync between many nodes with propagation through sync reports.
#[tokio::test(flavor = "multi_thread")]
async fn sync_big() -> Result<()> {
    setup_logging();
    let mut rng = test_rng(b"sync_big");
    let n_nodes = std::env::var("NODES")
        .map(|v| v.parse().expect("NODES must be a number"))
        .unwrap_or(10);
    let n_entries_init = 1;

    tokio::task::spawn(async move {
        for i in 0.. {
            tokio::time::sleep(Duration::from_secs(1)).await;
            info!("tick {i}");
        }
    });

    let nodes = spawn_nodes(n_nodes, &mut rng).await?;
    let node_ids = nodes.iter().map(|node| node.node_id()).collect::<Vec<_>>();
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();
    let authors = collect_futures(clients.iter().map(|c| c.authors.create())).await?;

    let doc0 = clients[0].docs.create().await?;
    let mut ticket = doc0.share(ShareMode::Write).await?;
    // do not join for now, just import without any peer info
    let peer0 = ticket.nodes[0].clone();
    ticket.nodes = vec![];

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
            format!("init/{}/{j}", node_ids[i].fmt_short()),
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
        info!(me = %node_ids[i].fmt_short(), peer = %peer0.node_id.fmt_short(), "join");
        doc.start_sync(vec![peer0.clone()]).await?;
    }

    // wait for InsertRemote events stuff to happen
    info!("wait for all peers to receive insert events");
    let expected_inserts = (n_nodes - 1) * n_entries_init;
    let mut tasks = tokio::task::JoinSet::default();
    for (i, events) in events.into_iter().enumerate() {
        let doc = docs[i].clone();
        let me = doc.id().fmt_short();
        let expected = expected.clone();
        let fut = async move {
            wait_for_events(events, expected_inserts, TIMEOUT, |e| {
                matches!(e, LiveEvent::InsertRemote { .. })
            })
            .await?;
            let entries = get_all(&doc).await?;
            if entries != expected {
                Err(anyhow!(
                    "node {i} failed (has {} entries but expected to have {})",
                    entries.len(),
                    expected.len()
                ))
            } else {
                info!(
                    "received and checked all {} expected entries",
                    expected.len()
                );
                Ok(())
            }
        }
        .instrument(error_span!("sync-test", %me));
        let fut = fut.map(move |r| r.with_context(move || format!("node {i} ({me})")));
        tasks.spawn(fut);
    }

    while let Some(res) = tasks.join_next().await {
        res??;
    }

    assert_all_docs(&docs, &node_ids, &expected, "after initial sync").await;

    info!("shutdown");
    for node in nodes {
        node.shutdown().await?;
    }

    Ok(())
}

/// Get all entries of a document.
async fn get_all(doc: &Doc) -> anyhow::Result<Vec<Entry>> {
    let entries = doc.get_many(Query::all()).await?;
    let entries = entries.collect::<Vec<_>>().await;
    entries.into_iter().collect()
}

/// Get all entries of a document with the blob content.
async fn get_all_with_content(doc: &Doc) -> anyhow::Result<Vec<(Entry, Bytes)>> {
    let entries = doc.get_many(Query::all()).await?;
    let entries = entries.and_then(|entry| async {
        let content = entry.content_bytes(doc).await;
        content.map(|c| (entry, c))
    });
    let entries = entries.collect::<Vec<_>>().await;
    let entries = entries.into_iter().collect::<Result<Vec<_>>>()?;
    Ok(entries)
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

/// Collect an iterator into futures by joining them all and failing if any future failed.
async fn collect_futures<T>(
    futs: impl IntoIterator<Item = impl Future<Output = anyhow::Result<T>>>,
) -> anyhow::Result<Vec<T>> {
    futures_buffered::join_all(futs)
        .await
        .into_iter()
        .collect::<Result<Vec<_>>>()
}

/// Collect `count` events from the `events` stream, only collecting events for which `matcher`
/// returns true.
async fn wait_for_events(
    mut events: impl Stream<Item = Result<LiveEvent>> + Send + Unpin + 'static,
    count: usize,
    timeout: Duration,
    matcher: impl Fn(&LiveEvent) -> bool,
) -> anyhow::Result<Vec<LiveEvent>> {
    let mut res = Vec::with_capacity(count);
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    while res.len() < count {
        tokio::select! {
            () = &mut sleep => {
                bail!("Failed to collect {count} elements in {timeout:?} (collected only {})", res.len());
            },
            event = events.try_next() => {
                let event = event?;
                match event {
                    None => bail!("stream ended after {} items, but expected {count}", res.len()),
                    Some(event) => if matcher(&event) {
                        res.push(event);
                        debug!("recv event {} of {count}", res.len());
                    }
                }
            }
        }
    }
    Ok(res)
}

async fn assert_all_docs(
    docs: &[Doc],
    node_ids: &[PublicKey],
    expected: &Vec<ExpectedEntry>,
    label: &str,
) {
    info!("validate all peers: {label}");
    for (i, doc) in docs.iter().enumerate() {
        let entries = get_all(doc).await.unwrap_or_else(|err| {
            panic!("failed to get entries for peer {:?}: {err:?}", node_ids[i])
        });
        assert_eq!(
            &entries,
            expected,
            "{label}: peer {i} {:?} failed (have {} but expected {})",
            node_ids[i],
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

#[tokio::test]
async fn doc_delete() -> Result<()> {
    let node = Node::memory()
        .gc_policy(iroh::node::GcPolicy::Interval(Duration::from_millis(100)))
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

    let entry = doc.get_exact(author, b"foo".to_vec(), false).await?;
    assert!(entry.is_none());

    // wait for gc
    // TODO: allow to manually trigger gc
    tokio::time::sleep(Duration::from_millis(200)).await;
    let bytes = client.blobs.read_to_bytes(hash).await;
    assert!(bytes.is_err());
    node.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn sync_drop_doc() -> Result<()> {
    let mut rng = test_rng(b"sync_drop_doc");
    setup_logging();
    let node = spawn_node(0, &mut rng).await?;
    let client = node.client();

    let doc = client.docs.create().await?;
    let author = client.authors.create().await?;

    let mut sub = doc.subscribe().await?;
    doc.set_bytes(author, b"foo".to_vec(), b"bar".to_vec())
        .await?;
    let ev = sub.next().await;
    assert!(matches!(ev, Some(Ok(LiveEvent::InsertLocal { .. }))));

    client.docs.drop_doc(doc.id()).await?;
    let res = doc.get_exact(author, b"foo".to_vec(), true).await;
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
    let query = Query::single_latest_per_key().key_exact(key);
    let entry = doc
        .get_many(query)
        .await?
        .next()
        .await
        .ok_or_else(|| anyhow!("entry not found"))??;
    let content = entry.content_bytes(doc).await?;
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
fn apply_matchers<T>(item: &T, matchers: &mut Vec<Box<dyn Fn(&T) -> bool + Send>>) -> bool {
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
    stream: impl Stream<Item = Result<T>> + Unpin + Send,
    timeout: Duration,
    matchers: Vec<Box<dyn Fn(&T) -> bool + Send>>,
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
    mut stream: impl Stream<Item = Result<T>> + Unpin + Send,
    timeout: Duration,
    mut required_matchers: Vec<Box<dyn Fn(&T) -> bool + Send>>,
    mut optional_matchers: Vec<Box<dyn Fn(&T) -> bool + Send>>,
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
fn match_sync_finished(event: &LiveEvent, peer: PublicKey) -> bool {
    let LiveEvent::SyncFinished(e) = event else {
        return false;
    };
    e.peer == peer && e.result.is_ok()
}

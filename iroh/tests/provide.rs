use std::{
    collections::BTreeMap,
    net::SocketAddr,
    ops::Range,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::FutureExt;
use iroh::{
    dial::Options,
    node::{Builder, Event},
};
use iroh_net::{key::SecretKey, NodeId};
use quic_rpc::transport::misc::DummyServerEndpoint;
use rand::RngCore;
use tokio::sync::mpsc;

use bao_tree::{blake3, ChunkNum, ChunkRanges};
use iroh_bytes::{
    format::collection::Collection,
    get::{
        fsm::ConnectedNext,
        fsm::{self, DecodeError},
        Stats,
    },
    protocol::{GetRequest, RangeSpecSeq},
    provider,
    store::{MapMut, Store},
    BlobFormat, Hash,
};
use iroh_sync::store;

fn test_node<D: Store>(db: D) -> Builder<D, store::memory::Store, DummyServerEndpoint> {
    let store = iroh_sync::store::memory::Store::default();
    iroh::node::Builder::with_db_and_store(db, store, iroh::node::StorageConfig::Mem).bind_port(0)
}

#[tokio::test]
#[ignore = "flaky"]
async fn basics() -> Result<()> {
    let _guard = iroh_test::logging::setup();
    transfer_data(vec![("hello_world", "hello world!".as_bytes().to_vec())]).await
}

#[tokio::test]
#[ignore = "flaky"]
async fn multi_file() -> Result<()> {
    let _guard = iroh_test::logging::setup();

    let file_opts = vec![
        ("1", 10),
        ("2", 1024),
        ("3", 1024 * 1024),
        // overkill, but it works! Just annoying to wait for
        // ("4", 1024 * 1024 * 90),
    ];
    transfer_random_data(file_opts).await
}

#[tokio::test]
#[ignore = "flaky"]
async fn many_files() -> Result<()> {
    let _guard = iroh_test::logging::setup();
    let num_files = [10, 100];
    for num in num_files {
        println!("NUM_FILES: {num}");
        let file_opts = (0..num)
            .map(|i| {
                // use a long file name to test large collections
                let name = i.to_string().repeat(50);
                (name, 10)
            })
            .collect();
        transfer_random_data(file_opts).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "flaky"]
async fn sizes() -> Result<()> {
    let _guard = iroh_test::logging::setup();

    let sizes = [
        0,
        10,
        100,
        1024,
        1024 * 100,
        1024 * 500,
        1024 * 1024,
        1024 * 1024 + 10,
        1024 * 1024 * 9,
    ];

    for size in sizes {
        let now = Instant::now();
        transfer_random_data(vec![("hello_world", size)]).await?;
        println!("  took {}ms", now.elapsed().as_millis());
    }

    Ok(())
}

#[tokio::test]
#[ignore = "flaky"]
async fn empty_files() -> Result<()> {
    // try to transfer as many files as possible without hitting a limit
    // booo 400 is too small :(
    let num_files = 400;
    let mut file_opts = Vec::new();
    for i in 0..num_files {
        file_opts.push((i.to_string(), 0));
    }
    transfer_random_data(file_opts).await
}

/// Create new get options with the given node id and addresses, using a
/// randomly generated secret key.
fn get_options(node_id: NodeId, addrs: Vec<SocketAddr>) -> iroh::dial::Options {
    let derp_map = iroh_net::defaults::default_derp_map();
    let peer = iroh_net::NodeAddr::from_parts(
        node_id,
        derp_map.nodes().next().map(|n| n.url.clone()),
        addrs,
    );
    iroh::dial::Options {
        secret_key: SecretKey::generate(),
        peer,
        keylog: false,
        derp_map: Some(derp_map),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn multiple_clients() -> Result<()> {
    let content = b"hello world!";

    let mut db = iroh_bytes::store::readonly_mem::Store::default();
    let expect_hash = db.insert(content.as_slice());
    let expect_name = "hello_world";
    let collection = Collection::from_iter([(expect_name, expect_hash)]);
    let hash = db.insert_many(collection.to_blobs()).unwrap();
    let node = test_node(db).spawn().await?;
    let mut tasks = Vec::new();
    for _i in 0..3 {
        let file_hash: Hash = expect_hash;
        let name = expect_name;
        let addrs = node.local_address().unwrap();
        let peer_id = node.node_id();
        let content = content.to_vec();

        tasks.push(node.local_pool_handle().spawn_pinned(move || {
            async move {
                let opts = get_options(peer_id, addrs);
                let expected_data = &content;
                let expected_name = name;
                let request = GetRequest::all(hash);
                let (collection, children, _stats) =
                    run_collection_get_request(opts, request).await?;
                assert_eq!(expected_name, &collection[0].0);
                assert_eq!(&file_hash, &collection[0].1);
                assert_eq!(expected_data, &children[&0]);

                anyhow::Ok(())
            }
            .boxed_local()
        }));
    }

    futures::future::try_join_all(tasks).await?;
    Ok(())
}

// Run the test creating random data for each blob, using the size specified by the file
// options
async fn transfer_random_data<S>(file_opts: Vec<(S, usize)>) -> Result<()>
where
    S: Into<String> + std::fmt::Debug + std::cmp::PartialEq + Clone,
{
    let file_opts = file_opts
        .into_iter()
        .map(|(name, size)| {
            let mut content = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut content);
            (name, content)
        })
        .collect();
    transfer_data(file_opts).await
}

// Run the test for a vec of filenames and blob data
async fn transfer_data<S>(file_opts: Vec<(S, Vec<u8>)>) -> Result<()>
where
    S: Into<String> + std::fmt::Debug + std::cmp::PartialEq + Clone,
{
    let mut expects = Vec::new();
    let num_blobs = file_opts.len();

    let (mut mdb, _lookup) = iroh_bytes::store::readonly_mem::Store::new(file_opts.clone());
    let mut blobs = Vec::new();

    for opt in file_opts.into_iter() {
        let (name, data) = opt;
        let name: String = name.into();
        println!("Sending {}: {}b", name, data.len());

        // get expected hash of file
        let hash = blake3::hash(&data);
        let hash = Hash::from(hash);
        let blob = (name.clone(), hash);
        blobs.push(blob);

        // keep track of expected values
        expects.push((name, hash));
    }
    let collection_orig = Collection::from_iter(blobs);
    let collection_hash = mdb.insert_many(collection_orig.to_blobs()).unwrap();

    let node = test_node(mdb.clone()).spawn().await?;

    let (events_sender, mut events_recv) = mpsc::unbounded_channel();

    node.subscribe(move |event| {
        let events_sender = events_sender.clone();
        async move {
            events_sender.send(event).ok();
        }
        .boxed()
    })
    .await?;

    let addrs = node.local_endpoint_addresses().await?;
    let opts = get_options(node.node_id(), addrs);
    let request = GetRequest::all(collection_hash);
    let (collection, children, _stats) = run_collection_get_request(opts, request).await?;
    assert_eq!(num_blobs, collection.len());
    for (i, (expected_name, expected_hash)) in expects.iter().enumerate() {
        let (name, hash) = &collection[i];
        let got = &children[&(i as u64)];
        let expected = mdb.get(expected_hash).unwrap();
        assert_eq!(expected_name, name);
        assert_eq!(expected_hash, hash);
        assert_eq!(expected, got);
    }

    // We have to wait for the completed event before shutting down the node.
    let events = tokio::time::timeout(Duration::from_secs(30), async move {
        let mut events = Vec::new();
        while let Some(event) = events_recv.recv().await {
            match event {
                Event::ByteProvide(provider::Event::TransferCompleted { .. })
                | Event::ByteProvide(provider::Event::TransferAborted { .. }) => {
                    events.push(event);
                    break;
                }
                _ => events.push(event),
            }
        }
        events
    })
    .await
    .expect("duration expired");

    node.shutdown();
    node.await?;

    assert_events(events, num_blobs + 1);

    Ok(())
}

fn assert_events(events: Vec<Event>, num_blobs: usize) {
    let num_basic_events = 4;
    let num_total_events = num_basic_events + num_blobs;
    assert_eq!(
        events.len(),
        num_total_events,
        "missing events, only got {:#?}",
        events
    );
    assert!(matches!(
        events[0],
        Event::ByteProvide(provider::Event::ClientConnected { .. })
    ));
    assert!(matches!(
        events[1],
        Event::ByteProvide(provider::Event::GetRequestReceived { .. })
    ));
    assert!(matches!(
        events[2],
        Event::ByteProvide(provider::Event::TransferHashSeqStarted { .. })
    ));
    for (i, event) in events[3..num_total_events - 1].iter().enumerate() {
        match event {
            Event::ByteProvide(provider::Event::TransferBlobCompleted { index, .. }) => {
                assert_eq!(*index, i as u64);
            }
            _ => panic!("unexpected event {:?}", event),
        }
    }
    assert!(matches!(
        events.last().unwrap(),
        Event::ByteProvide(provider::Event::TransferCompleted { .. })
    ));
}

#[tokio::test]
async fn test_server_close() {
    // Prepare a Provider transferring a file.
    let _guard = iroh_test::logging::setup();
    let mut db = iroh_bytes::store::readonly_mem::Store::default();
    let child_hash = db.insert(b"hello there");
    let collection = Collection::from_iter([("hello", child_hash)]);
    let hash = db.insert_many(collection.to_blobs()).unwrap();
    let mut node = test_node(db).spawn().await.unwrap();
    let node_addr = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.node_id();

    let (events_sender, mut events_recv) = mpsc::unbounded_channel();
    node.subscribe(move |event| {
        let events_sender = events_sender.clone();
        async move {
            events_sender.send(event).ok();
        }
        .boxed()
    })
    .await
    .unwrap();
    let opts = get_options(peer_id, node_addr);
    let request = GetRequest::all(hash);
    let (_collection, _children, _stats) = run_collection_get_request(opts, request).await.unwrap();

    // Unwrap the JoinHandle, then the result of the Provider
    tokio::time::timeout(Duration::from_secs(10), async move {
        loop {
            tokio::select! {
                biased;
                res = &mut node => break res.context("provider failed"),
                maybe_event = events_recv.recv() => {
                    match maybe_event {
                        Some(event) => match event {
                            Event::ByteProvide(provider::Event::TransferCompleted { .. }) => node.shutdown(),
                            Event::ByteProvide(provider::Event::TransferAborted { .. }) => {
                                break Err(anyhow!("transfer aborted"));
                            }
                            _ => (),
                        }
                        None => break Err(anyhow!("events ended")),
                    }
                }
            }
        }
    })
        .await
        .expect("supervisor timeout")
        .expect("supervisor failed");
}

/// create an in memory test database containing the given entries and an iroh collection of all entries
///
/// returns the database and the root hash of the collection
fn create_test_db(
    entries: impl IntoIterator<Item = (impl Into<String>, impl AsRef<[u8]>)>,
) -> (iroh_bytes::store::readonly_mem::Store, Hash) {
    let (mut db, hashes) = iroh_bytes::store::readonly_mem::Store::new(entries);
    let collection = Collection::from_iter(hashes);
    let hash = db.insert_many(collection.to_blobs()).unwrap();
    (db, hash)
}

#[tokio::test]
#[ignore = "flaky"]
async fn test_ipv6() {
    let _guard = iroh_test::logging::setup();

    let (db, hash) = create_test_db([("test", b"hello")]);
    let node = match test_node(db).spawn().await {
        Ok(provider) => provider,
        Err(_) => {
            // We assume the problem here is IPv6 on this host.  If the problem is
            // not IPv6 then other tests will also fail.
            return;
        }
    };
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.node_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let opts = get_options(peer_id, addrs);
        let request = GetRequest::all(hash);
        run_collection_get_request(opts, request).await
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

/// Simulate a node that has nothing
#[tokio::test]
#[ignore = "flaky"]
async fn test_not_found() {
    let _ = iroh_test::logging::setup();

    let db = iroh_bytes::store::readonly_mem::Store::default();
    let hash = blake3::hash(b"hello").into();
    let node = match test_node(db).spawn().await {
        Ok(provider) => provider,
        Err(_) => {
            // We assume the problem here is IPv6 on this host.  If the problem is
            // not IPv6 then other tests will also fail.
            return;
        }
    };
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.node_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let opts = get_options(peer_id, addrs);
        let request = GetRequest::single(hash);
        let res = run_collection_get_request(opts, request).await;
        if let Err(cause) = res {
            if let Some(e) = cause.downcast_ref::<DecodeError>() {
                if let DecodeError::NotFound = e {
                    Ok(())
                } else {
                    anyhow::bail!("expected DecodeError::NotFound, got {:?}", e);
                }
            } else {
                anyhow::bail!("expected DecodeError, got {:?}", cause);
            }
        } else {
            anyhow::bail!("expected error when getting non-existent blob");
        }
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

/// Simulate a node that has just begun downloading a blob, but does not yet have any data
#[tokio::test]
#[ignore = "flaky"]
async fn test_chunk_not_found_1() {
    let _ = iroh_test::logging::setup();

    let db = iroh_bytes::store::mem::Store::new();
    let data = (0..1024 * 64).map(|i| i as u8).collect::<Vec<_>>();
    let hash = blake3::hash(&data).into();
    let _entry = db.get_or_create(hash, data.len() as u64).await.unwrap();
    let node = match test_node(db).spawn().await {
        Ok(provider) => provider,
        Err(_) => {
            // We assume the problem here is IPv6 on this host.  If the problem is
            // not IPv6 then other tests will also fail.
            return;
        }
    };
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.node_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let opts = get_options(peer_id, addrs);
        let request = GetRequest::single(hash);
        let res = run_collection_get_request(opts, request).await;
        if let Err(cause) = res {
            if let Some(e) = cause.downcast_ref::<DecodeError>() {
                if let DecodeError::ParentNotFound(_) = e {
                    Ok(())
                } else {
                    anyhow::bail!("expected DecodeError::ParentNotFound, got {:?}", e);
                }
            } else {
                anyhow::bail!("expected DecodeError, got {:?}", cause);
            }
        } else {
            anyhow::bail!("expected error when getting non-existent blob");
        }
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

#[tokio::test]
async fn test_run_ticket() {
    let (db, hash) = create_test_db([("test", b"hello")]);
    let node = test_node(db).spawn().await.unwrap();
    let _drop_guard = node.cancel_token().drop_guard();

    let ticket = node.ticket(hash, BlobFormat::HashSeq).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let request = GetRequest::all(hash);
        run_collection_get_request(
            Options {
                secret_key: SecretKey::generate(),
                peer: ticket.node_addr().clone(),
                keylog: false,
                derp_map: Some(iroh_net::defaults::default_derp_map()),
            },
            request,
        )
        .await
    })
    .await
    .expect("timeout")
    .expect("get ticket failed");
}

/// Utility to validate that the children of a collection are correct
fn validate_children(collection: Collection, children: BTreeMap<u64, Bytes>) -> anyhow::Result<()> {
    let blobs = collection.into_iter().collect::<Vec<_>>();
    anyhow::ensure!(blobs.len() == children.len());
    for (child, (_name, hash)) in blobs.into_iter().enumerate() {
        let child = child as u64;
        let data = children.get(&child).unwrap();
        anyhow::ensure!(hash == blake3::hash(data).into());
    }
    Ok(())
}

async fn run_collection_get_request(
    opts: iroh::dial::Options,
    request: GetRequest,
) -> anyhow::Result<(Collection, BTreeMap<u64, Bytes>, Stats)> {
    let connection = iroh::dial::dial(opts).await?;
    let initial = fsm::start(connection, request);
    let connected = initial.next().await?;
    let ConnectedNext::StartRoot(fsm_at_start_root) = connected.next().await? else {
        anyhow::bail!("request did not include collection");
    };
    Collection::read_fsm_all(fsm_at_start_root).await
}

#[tokio::test]
#[ignore = "flaky"]
async fn test_run_fsm() {
    let (db, hash) = create_test_db([("a", b"hello"), ("b", b"world")]);
    let node = test_node(db).spawn().await.unwrap();
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.node_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let opts = get_options(peer_id, addrs);
        let request = GetRequest::all(hash);
        let (collection, children, _) = run_collection_get_request(opts, request).await?;
        validate_children(collection, children)?;
        anyhow::Ok(())
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

/// compute the range of the last chunk of a blob of the given size
fn last_chunk_range(size: usize) -> Range<usize> {
    const CHUNK_LEN: usize = 1024;
    const MASK: usize = CHUNK_LEN - 1;
    if (size & MASK) == 0 {
        size - CHUNK_LEN..size
    } else {
        (size & !MASK)..size
    }
}

fn last_chunk(data: &[u8]) -> &[u8] {
    let range = last_chunk_range(data.len());
    &data[range]
}

fn make_test_data(n: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(n);
    for i in 0..n {
        data.push((i / 1024) as u8);
    }
    data
}

/// Ask for the last chunk of a blob, even if we don't know the size yet.
///
/// The verified last chunk also verifies the size.
#[tokio::test]
async fn test_size_request_blob() {
    let expected = make_test_data(1024 * 64 + 1234);
    let last_chunk = last_chunk(&expected);
    let (db, hashes) = iroh_bytes::store::readonly_mem::Store::new([("test", &expected)]);
    let hash = Hash::from(*hashes.values().next().unwrap());
    let node = test_node(db).spawn().await.unwrap();
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.node_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let request = GetRequest::last_chunk(hash);
        let connection = iroh::dial::dial(get_options(peer_id, addrs)).await?;
        let response = fsm::start(connection, request);
        let connected = response.next().await?;
        let ConnectedNext::StartRoot(start) = connected.next().await? else {
            panic!()
        };
        let header = start.next();
        let (_, actual) = header.concatenate_into_vec().await?;
        assert_eq!(actual, last_chunk);
        anyhow::Ok(())
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

#[tokio::test]
#[ignore = "flaky"]
async fn test_collection_stat() {
    let child1 = make_test_data(123456);
    let child2 = make_test_data(345678);
    let (db, hash) = create_test_db([("a", &child1), ("b", &child2)]);
    let node = test_node(db.clone()).spawn().await.unwrap();
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.node_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        // first 1024 bytes
        let header = ChunkRanges::from(..ChunkNum(1));
        // last chunk, whatever it is, to verify the size
        let end = ChunkRanges::from(ChunkNum(u64::MAX)..);
        // combine them
        let ranges = &header | &end;
        let request = GetRequest::new(
            hash,
            RangeSpecSeq::from_ranges_infinite([ChunkRanges::all(), ranges]),
        );
        let opts = get_options(peer_id, addrs);
        let (_collection, items, _stats) = run_collection_get_request(opts, request).await?;
        // we should get the first <=1024 bytes and the last chunk of each child
        // so now we know the size and can guess the type by inspecting the header
        assert_eq!(items.len(), 2);
        assert_eq!(&items[&0][..1024], &child1[..1024]);
        assert!(items[&0].ends_with(last_chunk(&child1)));
        assert_eq!(&items[&1][..1024], &child2[..1024]);
        assert!(items[&1].ends_with(last_chunk(&child2)));
        anyhow::Ok(())
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

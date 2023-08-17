#![cfg(all(feature = "mem-db", feature = "iroh-collection"))]
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures::{
    future::{self, BoxFuture, LocalBoxFuture},
    FutureExt,
};
use iroh::{
    collection::{ArrayLinkStream, Blob, Collection, IrohCollectionParser},
    node::{Builder, Event, Node, StaticTokenAuthHandler},
};
use iroh_io::{AsyncSliceReader, AsyncSliceReaderExt};
use iroh_net::{
    key::{Keypair, PeerId},
    MagicEndpoint,
};
use quic_rpc::transport::misc::DummyServerEndpoint;
use rand::RngCore;
use tokio::sync::mpsc;
use tracing_subscriber::{prelude::*, EnvFilter};

use bao_tree::blake3;
use iroh_bytes::{
    baomap::Store,
    collection::{CollectionParser, CollectionStats, LinkStream},
    get::{fsm, fsm::ConnectedNext, Stats},
    protocol::{AnyGetRequest, CustomGetRequest, GetRequest, RequestToken},
    provider::{self, CustomGetHandler, RequestAuthorizationHandler},
    util::runtime,
    Hash,
};

/// Pick up the tokio runtime from the thread local and add a
/// thread per core runtime.
fn test_runtime() -> runtime::Handle {
    runtime::Handle::from_currrent(1).unwrap()
}

fn test_node<D: Store>(
    db: D,
    addr: SocketAddr,
) -> Builder<D, DummyServerEndpoint, IrohCollectionParser> {
    Node::builder(db)
        .collection_parser(IrohCollectionParser)
        .bind_addr(addr)
}

#[tokio::test]
async fn basics() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
    transfer_data(
        vec![("hello_world", "hello world!".as_bytes().to_vec())],
        &rt,
    )
    .await
}

#[tokio::test]
async fn multi_file() -> Result<()> {
    setup_logging();
    let rt = test_runtime();

    let file_opts = vec![
        ("1", 10),
        ("2", 1024),
        ("3", 1024 * 1024),
        // overkill, but it works! Just annoying to wait for
        // ("4", 1024 * 1024 * 90),
    ];
    transfer_random_data(file_opts, &rt).await
}

#[tokio::test]
async fn many_files() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
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
        transfer_random_data(file_opts, &rt).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sizes() -> Result<()> {
    setup_logging();
    let rt = test_runtime();

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
        transfer_random_data(vec![("hello_world", size)], &rt).await?;
        println!("  took {}ms", now.elapsed().as_millis());
    }

    Ok(())
}

#[tokio::test]
async fn empty_files() -> Result<()> {
    let rt = test_runtime();
    // try to transfer as many files as possible without hitting a limit
    // booo 400 is too small :(
    let num_files = 400;
    let mut file_opts = Vec::new();
    for i in 0..num_files {
        file_opts.push((i.to_string(), 0));
    }
    transfer_random_data(file_opts, &rt).await
}

/// Create new get options with the given peer id and addresses, using a
/// randomly generated keypair.
fn get_options(peer_id: PeerId, addrs: Vec<SocketAddr>) -> iroh::dial::Options {
    iroh::dial::Options {
        keypair: Keypair::generate(),
        peer_id,
        addrs,
        derp_region: None,
        keylog: false,
        derp_map: None,
    }
}

#[cfg(feature = "mem-db")]
#[tokio::test(flavor = "multi_thread")]
async fn multiple_clients() -> Result<()> {
    let content = b"hello world!";
    let addr = "127.0.0.1:0".parse().unwrap();

    let mut db = iroh::baomap::readonly_mem::Store::default();
    let expect_hash = db.insert(content.as_slice());
    let expect_name = "hello_world".to_string();
    let collection = Collection::new(
        vec![Blob {
            name: expect_name.clone(),
            hash: expect_hash,
        }],
        0,
    )?;
    let hash = db.insert(collection.to_bytes()?);
    let rt = test_runtime();
    let node = test_node(db, addr).runtime(&rt).spawn().await?;

    let mut tasks = Vec::new();
    for _i in 0..3 {
        let file_hash: Hash = expect_hash;
        let name = expect_name.clone();
        let addrs = node.local_address().unwrap();
        let peer_id = node.peer_id();
        let content = content.to_vec();

        tasks.push(rt.local_pool().spawn_pinned(move || {
            async move {
                let opts = get_options(peer_id, addrs);
                let expected_data = &content;
                let expected_name = &name;
                let request = GetRequest::all(hash).into();
                let (root, children, _stats) = run_get_request(opts, request).await?;
                let collection = Collection::from_bytes(&root)?;
                assert_eq!(expected_name, &collection.blobs()[0].name);
                assert_eq!(&file_hash, &collection.blobs()[0].hash);
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
async fn transfer_random_data<S>(
    file_opts: Vec<(S, usize)>,
    rt: &crate::runtime::Handle,
) -> Result<()>
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
    transfer_data(file_opts, rt).await
}

// Run the test for a vec of filenames and blob data
async fn transfer_data<S>(file_opts: Vec<(S, Vec<u8>)>, rt: &crate::runtime::Handle) -> Result<()>
where
    S: Into<String> + std::fmt::Debug + std::cmp::PartialEq + Clone,
{
    let mut expects = Vec::new();
    let num_blobs = file_opts.len();

    let (mut mdb, lookup) = iroh::baomap::readonly_mem::Store::new(file_opts.clone());
    let mut blobs = Vec::new();
    let mut total_blobs_size = 0u64;

    for opt in file_opts.into_iter() {
        let (name, data) = opt;
        let name = name.into();
        println!("Sending {}: {}b", name, data.len());

        let path = PathBuf::from(&name);
        // get expected hash of file
        let hash = blake3::hash(&data);
        let hash = Hash::from(hash);
        let blob = Blob {
            name: name.clone(),
            hash,
        };
        blobs.push(blob);
        total_blobs_size += data.len() as u64;

        // keep track of expected values
        expects.push((name, path, hash));
    }
    let collection = Collection::new(blobs, total_blobs_size)?;
    let collection_bytes = collection.to_bytes()?;
    let collection_hash = mdb.insert(collection_bytes);

    // sort expects by name to match the canonical order of blobs
    expects.sort_by(|a, b| a.0.cmp(&b.0));

    let addr = "127.0.0.1:0".parse().unwrap();
    let node = test_node(mdb.clone(), addr).runtime(rt).spawn().await?;

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
    let opts = get_options(node.peer_id(), addrs);
    let request = GetRequest::all(collection_hash).into();
    let (root, children, _stats) = run_get_request(opts, request).await?;
    let collection = Collection::from_bytes(&root)?;
    assert_eq!(num_blobs, collection.blobs().len());
    for (i, (name, hash)) in lookup.into_iter().enumerate() {
        let hash = Hash::from(hash);
        let blob = &collection.blobs()[i];
        let expect = mdb.get(&hash).unwrap();
        let got = &children[&(i as u64)];
        assert_eq!(name, blob.name);
        assert_eq!(hash, blob.hash);
        assert_eq!(&expect, got);
    }

    // We have to wait for the completed event before shutting down the node.
    let events = tokio::time::timeout(Duration::from_secs(30), async move {
        let mut events = Vec::new();
        while let Some(event) = events_recv.recv().await {
            match event {
                Event::ByteProvide(provider::Event::TransferCollectionCompleted { .. })
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

    assert_events(events, num_blobs);

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
        Event::ByteProvide(provider::Event::TransferCollectionStarted { .. })
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
        Event::ByteProvide(provider::Event::TransferCollectionCompleted { .. })
    ));
}

fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

#[cfg(feature = "mem-db")]
#[tokio::test]
async fn test_server_close() {
    let rt = test_runtime();
    // Prepare a Provider transferring a file.
    setup_logging();
    let mut db = iroh::baomap::readonly_mem::Store::default();
    let child_hash = db.insert(b"hello there");
    let collection = Collection::new(
        vec![Blob {
            name: "hello".to_string(),
            hash: child_hash,
        }],
        0,
    )
    .unwrap();
    let hash = db.insert(collection.to_bytes().unwrap());
    let addr = "127.0.0.1:0".parse().unwrap();
    let mut node = test_node(db, addr).runtime(&rt).spawn().await.unwrap();
    let node_addr = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.peer_id();

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
    let request = GetRequest::all(hash).into();
    let (_collection, _children, _stats) = run_get_request(opts, request).await.unwrap();

    // Unwrap the JoinHandle, then the result of the Provider
    tokio::time::timeout(Duration::from_secs(10), async move {
        loop {
            tokio::select! {
                biased;
                res = &mut node => break res.context("provider failed"),
                maybe_event = events_recv.recv() => {
                    match maybe_event {
                        Some(event) => match event {
                            Event::ByteProvide(provider::Event::TransferCollectionCompleted { .. }) => node.shutdown(),
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
) -> (iroh::baomap::readonly_mem::Store, Hash) {
    let (mut db, hashes) = iroh::baomap::readonly_mem::Store::new(entries);
    let collection = Collection::new(
        hashes
            .into_iter()
            .map(|(name, hash)| Blob {
                name,
                hash: hash.into(),
            })
            .collect(),
        0,
    )
    .unwrap();
    let hash = db.insert(collection.to_bytes().unwrap());
    (db, hash)
}

#[tokio::test]
async fn test_ipv6() {
    setup_logging();
    let rt = test_runtime();

    let (db, hash) = create_test_db([("test", b"hello")]);
    let addr = (Ipv6Addr::UNSPECIFIED, 0).into();
    let node = match test_node(db, addr).runtime(&rt).spawn().await {
        Ok(provider) => provider,
        Err(_) => {
            // We assume the problem here is IPv6 on this host.  If the problem is
            // not IPv6 then other tests will also fail.
            return;
        }
    };
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.peer_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let opts = get_options(peer_id, addrs);
        let request = GetRequest::all(hash).into();
        run_get_request(opts, request).await
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

#[tokio::test]
async fn test_run_ticket() {
    let rt = test_runtime();
    let (db, hash) = create_test_db([("test", b"hello")]);
    let token = Some(RequestToken::generate());
    let addr = (Ipv4Addr::UNSPECIFIED, 0).into();
    let node = test_node(db, addr)
        .custom_auth_handler(Arc::new(StaticTokenAuthHandler::new(token.clone())))
        .runtime(&rt)
        .spawn()
        .await
        .unwrap();
    let _drop_guard = node.cancel_token().drop_guard();

    let no_token_ticket = node.ticket(hash).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let opts = no_token_ticket.as_get_options(Keypair::generate(), None);
        let request = GetRequest::all(no_token_ticket.hash()).into();
        let response = run_get_request(opts, request).await;
        assert!(response.is_err());
        anyhow::Result::<_>::Ok(())
    })
    .await
    .expect("timeout")
    .expect("getting without token failed in an unexpected way");

    let ticket = node.ticket(hash).await.unwrap().with_token(token);
    tokio::time::timeout(Duration::from_secs(10), async move {
        let request = GetRequest::all(hash)
            .with_token(ticket.token().cloned())
            .into();
        run_get_request(ticket.as_get_options(Keypair::generate(), None), request).await
    })
    .await
    .expect("timeout")
    .expect("get ticket failed");
}

/// Utility to validate that the children of a collection are correct
fn validate_children(collection: Collection, children: BTreeMap<u64, Bytes>) -> anyhow::Result<()> {
    let blobs = collection.into_inner();
    anyhow::ensure!(blobs.len() == children.len());
    for (child, blob) in blobs.into_iter().enumerate() {
        let child = child as u64;
        let data = children.get(&child).unwrap();
        anyhow::ensure!(blob.hash == blake3::hash(data).into());
    }
    Ok(())
}

/// Run a get request with the default collection parser
async fn run_get_request(
    opts: iroh::dial::Options,
    request: AnyGetRequest,
) -> anyhow::Result<(Bytes, BTreeMap<u64, Bytes>, Stats)> {
    run_custom_get_request(opts, request, IrohCollectionParser).await
}

/// Run a get request with a custom collection parser
async fn run_custom_get_request<C: CollectionParser>(
    opts: iroh::dial::Options,
    request: AnyGetRequest,
    collection_parser: C,
) -> anyhow::Result<(Bytes, BTreeMap<u64, Bytes>, Stats)> {
    let connection = iroh::dial::dial(opts).await?;
    let initial = fsm::start(connection, request);
    use fsm::*;
    let mut items = BTreeMap::new();
    let connected = initial.next().await?;
    println!("I am connected");
    // we assume that the request includes the entire collection
    let (mut next, root, mut c) = {
        let ConnectedNext::StartRoot(sc) = connected.next().await? else {
                panic!("request did not include collection");
            };
        println!("getting collection");
        let (done, data) = sc.next().concatenate_into_vec().await?;
        let mut data = Bytes::from(data);
        println!("got collection {}", data.len());
        let (stream, _stats) = collection_parser.parse(0, &mut data).await?;
        (done.next(), data, stream)
    };
    // the previous *overall* offset, not child offset
    let mut prev = 0;
    // read all the children
    let finishing = loop {
        let start = match next {
            EndBlobNext::MoreChildren(start) => start,
            EndBlobNext::Closing(finishing) => break finishing,
        };
        let child_offset = start.child_offset();
        let offset = child_offset + 1;
        // skip to the next blob if there is a gap
        if prev < offset - 1 {
            c.skip(offset - prev - 1).await?;
        }
        // get the hash of the next blob, or finish if there are no more
        let Some(hash) = c.next().await? else {
            break start.finish();
        };
        let (done, data) = start.next(hash).concatenate_into_vec().await?;
        items.insert(child_offset, data.into());
        next = done.next();
        prev = offset;
    };
    let stats = finishing.next().await?;
    Ok((root, items, stats))
}

#[tokio::test]
async fn test_run_fsm() {
    let rt = test_runtime();
    let (db, hash) = create_test_db([("a", b"hello"), ("b", b"world")]);
    let addr = (Ipv4Addr::UNSPECIFIED, 0).into();
    let node = test_node(db, addr).runtime(&rt).spawn().await.unwrap();
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.peer_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let opts = get_options(peer_id, addrs);
        let request = GetRequest::all(hash).into();
        let (root, children, _) = run_get_request(opts, request).await?;
        let collection = Collection::from_bytes(&root)?;
        validate_children(collection, children)?;
        anyhow::Ok(())
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

/// A collection parser that assumes that collections are just links
#[derive(Clone, Debug, Default)]
pub struct CollectionsAreJustLinks;

impl CollectionParser for CollectionsAreJustLinks {
    fn parse<'a, R: AsyncSliceReader + 'a>(
        &'a self,
        _format: u64,
        mut reader: R,
    ) -> LocalBoxFuture<'_, anyhow::Result<(Box<dyn LinkStream>, CollectionStats)>> {
        async move {
            let data = reader.read_to_end().await?;
            let collection = postcard::from_bytes::<Vec<Hash>>(&data)?;
            let iter: Box<dyn LinkStream> = Box::new(ArrayLinkStream::new(collection.into()));
            Ok((iter, Default::default()))
        }
        .boxed_local()
    }
}

#[tokio::test]
async fn test_custom_collection_parser() {
    let rt = test_runtime();
    // create a collection consisting of 2 leafs
    let leaf1_data = vec![0u8; 12345];
    let leaf2_data = vec![1u8; 67890];
    let mut db = iroh::baomap::readonly_mem::Store::default();
    let leaf1_hash = db.insert(leaf1_data.clone());
    let leaf2_hash = db.insert(leaf2_data.clone());
    let collection = vec![leaf1_hash, leaf2_hash];
    let collection_bytes = postcard::to_allocvec(&collection).unwrap();
    let collection_hash = db.insert(collection_bytes.clone());
    let addr = "127.0.0.1:0".parse().unwrap();
    let node = Node::builder(db)
        .collection_parser(CollectionsAreJustLinks)
        .bind_addr(addr)
        .runtime(&rt)
        .spawn()
        .await
        .unwrap();
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.peer_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let request = GetRequest::all(collection_hash).into();
        let (root, children, _stats) = run_custom_get_request(
            get_options(peer_id, addrs),
            request,
            CollectionsAreJustLinks,
        )
        .await?;
        assert_eq!(root, collection_bytes);
        assert_eq!(children.len(), 2);
        assert_eq!(children[&0], leaf1_data);
        assert_eq!(children[&1], leaf2_data);
        anyhow::Ok(())
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

#[derive(Clone, Debug)]
struct CollectionCustomHandler {
    // the hash to respond with when getting a custom request
    hash: Hash,
}

impl CustomGetHandler for CollectionCustomHandler {
    fn handle(
        &self,
        _token: Option<RequestToken>,
        _data: Bytes,
    ) -> BoxFuture<'static, anyhow::Result<GetRequest>> {
        // return a request for the collection at self.hash
        future::ok(GetRequest::all(self.hash)).boxed()
    }
}

#[derive(Clone, Debug)]
struct BlobCustomHandler {
    // the hash to respond with when getting a custom request
    hash: Hash,
}

impl CustomGetHandler for BlobCustomHandler {
    fn handle(
        &self,
        _token: Option<RequestToken>,
        _data: Bytes,
    ) -> BoxFuture<'static, anyhow::Result<GetRequest>> {
        // return a request for the collection at self.hash
        future::ok(GetRequest::single(self.hash)).boxed()
    }
}

#[tokio::test]
async fn test_custom_request_blob() {
    let rt = test_runtime();
    let expected = b"hello".to_vec();
    let (db, hashes) = iroh::baomap::readonly_mem::Store::new([("test", &expected)]);
    let hash = Hash::from(*hashes.values().next().unwrap());
    let addr = "127.0.0.1:0".parse().unwrap();
    let node = test_node(db, addr)
        .runtime(&rt)
        .custom_get_handler(Arc::new(BlobCustomHandler { hash }))
        .spawn()
        .await
        .unwrap();
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.peer_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let request: AnyGetRequest = iroh_bytes::protocol::Request::CustomGet(CustomGetRequest {
            token: None,
            data: Bytes::from(&b"hello"[..]),
        });
        let connection = iroh::dial::dial(get_options(peer_id, addrs)).await?;
        let response = fsm::start(connection, request);
        let connected = response.next().await?;
        let ConnectedNext::StartRoot(start) = connected.next().await? else { panic!() };
        let header = start.next();
        let (_, actual) = header.concatenate_into_vec().await?;
        assert_eq!(actual, expected);
        anyhow::Ok(())
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

#[tokio::test]
async fn test_custom_request_collection() {
    let rt = test_runtime();
    let child1 = b"hello".to_vec();
    let child2 = b"world".to_vec();
    let (db, hash) = create_test_db([("a", &child1), ("b", &child2)]);
    let addr = "127.0.0.1:0".parse().unwrap();
    let node = test_node(db.clone(), addr)
        .runtime(&rt)
        .custom_get_handler(Arc::new(CollectionCustomHandler { hash }))
        .spawn()
        .await
        .unwrap();
    let addrs = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.peer_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let request: AnyGetRequest = CustomGetRequest {
            token: None,
            data: Bytes::from(&b"hello"[..]),
        }
        .into();
        let opts = get_options(peer_id, addrs);
        let (_collection, items, _stats) = run_get_request(opts, request).await?;
        assert_eq!(items.len(), 2);
        assert_eq!(items[&0], child1);
        assert_eq!(items[&1], child2);
        anyhow::Ok(())
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

#[derive(Clone, Debug)]
struct CustomAuthHandler;

impl RequestAuthorizationHandler for CustomAuthHandler {
    fn authorize(
        &self,
        token: Option<RequestToken>,
        _request: &iroh_bytes::protocol::Request,
    ) -> BoxFuture<'static, Result<()>> {
        async move {
            match token {
                Some(token) => {
                    if token.as_bytes() != &[1, 2, 3, 4, 5, 6][..] {
                        bail!("bad token")
                    }
                    Ok(())
                }
                None => {
                    bail!("give token plz")
                }
            }
        }
        .boxed()
    }
}

#[tokio::test]
async fn test_token_passthrough() -> Result<()> {
    let rt = test_runtime();
    let expected = b"hello".to_vec();
    let (db, hash) = create_test_db([("test", expected.clone())]);
    let addr = "0.0.0.0:0".parse().unwrap();
    let node = test_node(db, addr)
        .custom_auth_handler(Arc::new(CustomAuthHandler))
        .runtime(&rt)
        .spawn()
        .await?;

    let token = Some(RequestToken::new(vec![1, 2, 3, 4, 5, 6])?);
    let (events_sender, mut events_recv) = mpsc::unbounded_channel();
    node.subscribe(move |event| {
        let events_sender = events_sender.clone();
        async move {
            match event {
                Event::ByteProvide(bp_msg) => {
                    if let iroh_bytes::provider::Event::GetRequestReceived { token: tok, .. } =
                        bp_msg
                    {
                        events_sender.send(tok).ok();
                    }
                }
            }
        }
        .boxed()
    })
    .await?;

    let addrs = node.local_endpoint_addresses().await?;
    let peer_id = node.peer_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let endpoint = MagicEndpoint::builder()
            .keypair(Keypair::generate())
            .keylog(true)
            .bind(0)
            .await?;
        endpoint
            .connect(peer_id, &iroh_bytes::protocol::ALPN, None, &addrs)
            .await
            .context("failed to connect to provider")?;
        let request = GetRequest::all(hash).with_token(token).into();
        let opts = get_options(peer_id, addrs);
        let (_collection, items, _stats) = run_get_request(opts, request).await?;
        let actual = &items[&0];
        assert_eq!(actual, &expected);
        anyhow::Ok(())
    })
    .await
    .context("timeout")?
    .context("get failed")?;

    let token = events_recv.recv().await.unwrap().expect("missing token");
    assert_eq!(token.as_bytes(), &[1, 2, 3, 4, 5, 6][..]);

    Ok(())
}

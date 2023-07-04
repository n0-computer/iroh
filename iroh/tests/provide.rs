use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures::{future::BoxFuture, FutureExt};
use iroh::node::{Event, Node};
use iroh_net::MagicEndpoint;
use rand::RngCore;
use testdir::testdir;
use tokio::{fs, io::AsyncWriteExt, sync::broadcast};
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::{
    blobs::{Blob, Collection},
    get::{self, get_response_machine, get_response_machine::ConnectedNext, Stats},
    protocol::{AnyGetRequest, CustomGetRequest, GetRequest, RequestToken},
    provider::{
        self, create_collection, database::InMemDatabase, CustomGetHandler, DataSource, Database,
        RequestAuthorizationHandler,
    },
    runtime,
    util::Hash,
};

/// Pick up the tokio runtime from the thread local and add a
/// thread per core runtime.
fn test_runtime() -> runtime::Handle {
    runtime::Handle::from_currrent(1).unwrap()
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

#[tokio::test(flavor = "multi_thread")]
async fn multiple_clients() -> Result<()> {
    let dir: PathBuf = testdir!();
    let filename = "hello_world";
    let path = dir.join(filename);
    let content = b"hello world!";
    let addr = "127.0.0.1:0".parse().unwrap();

    tokio::fs::write(&path, content).await?;
    // hash of the transfer file
    let expect_data = tokio::fs::read(&path).await?;
    let expect_hash = blake3::hash(&expect_data);
    let expect_name = filename.to_string();

    let (db, hash) = provider::create_collection(vec![DataSource::new(path)]).await?;

    let rt = test_runtime();
    let node = Node::builder(db)
        .runtime(&rt)
        .bind_addr(addr)
        .spawn()
        .await?;

    let mut tasks = Vec::new();
    for _i in 0..3 {
        let file_hash: Hash = expect_hash.into();
        let name = expect_name.clone();
        let addrs = node.local_address().unwrap();
        let peer_id = node.peer_id();
        let content = content.to_vec();

        tasks.push(rt.local_pool().spawn_pinned(move || {
            async move {
                let opts = get::Options {
                    addrs,
                    peer_id,
                    keylog: true,
                    derp_map: None,
                };
                let expected_data = &content;
                let expected_name = &name;
                let response = get::run(GetRequest::all(hash).into(), opts).await?;
                let (collection, children, _stats) = aggregate_get_response(response).await?;
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

    let (mut mdb, lookup) = InMemDatabase::new(file_opts.clone());
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
    let node = Node::builder(mdb.clone())
        .runtime(rt)
        .bind_addr(addr)
        .spawn()
        .await?;
    let mut provider_events = node.subscribe();
    let events_task = tokio::task::spawn(async move {
        let mut events = Vec::new();
        loop {
            match provider_events.recv().await {
                Ok(event) => match event {
                    Event::ByteProvide(provider::Event::TransferCollectionCompleted { .. })
                    | Event::ByteProvide(provider::Event::TransferAborted { .. }) => {
                        events.push(event);
                        break;
                    }
                    _ => events.push(event),
                },
                Err(e) => match e {
                    broadcast::error::RecvError::Closed => {
                        break;
                    }
                    broadcast::error::RecvError::Lagged(num) => {
                        panic!("unable to keep up, skipped {num} messages");
                    }
                },
            }
        }
        events
    });

    let addrs = node.local_endpoint_addresses().await?;
    let opts = get::Options {
        addrs,
        peer_id: node.peer_id(),
        keylog: true,
        derp_map: None,
    };

    let response = get::run(GetRequest::all(collection_hash).into(), opts).await?;
    let (collection, children, _stats) = aggregate_get_response(response).await?;
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
    let events = tokio::time::timeout(Duration::from_secs(30), events_task)
        .await
        .expect("duration expired")
        .expect("events task failed");
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

#[tokio::test]
async fn test_server_close() {
    let rt = test_runtime();
    // Prepare a Provider transferring a file.
    setup_logging();
    let dir = testdir!();
    let src = dir.join("src");
    fs::write(&src, "hello there").await.unwrap();
    let (db, hash) = create_collection(vec![src.into()]).await.unwrap();
    let mut node = Node::builder(db)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .runtime(&rt)
        .spawn()
        .await
        .unwrap();
    let node_addr = node.local_endpoint_addresses().await.unwrap();
    let peer_id = node.peer_id();

    // This tasks closes the connection on the provider side as soon as the transfer
    // completes.
    let supervisor = tokio::spawn(async move {
        let mut events = node.subscribe();
        loop {
            tokio::select! {
                biased;
                res = &mut node => break res.context("provider failed"),
                maybe_event = events.recv() => {
                    match maybe_event {
                        Ok(event) => {
                            match event {
                                Event::ByteProvide(provider::Event::TransferCollectionCompleted { .. }) => node.shutdown(),
                                Event::ByteProvide(provider::Event::TransferAborted { .. }) => {
                                    break Err(anyhow!("transfer aborted"));
                                }
                                _ => (),
                            }
                        }
                        Err(err) => break Err(anyhow!("event failed: {err:#}")),
                    }
                }
            }
        }
    });

    let response = get::run(
        GetRequest::all(hash).into(),
        get::Options {
            addrs: node_addr,
            peer_id,
            keylog: true,
            derp_map: None,
        },
    )
    .await
    .unwrap();
    let (_collection, _children, _stats) = aggregate_get_response(response).await.unwrap();

    // Unwrap the JoinHandle, then the result of the Provider
    tokio::time::timeout(Duration::from_secs(10), supervisor)
        .await
        .expect("supervisor timeout")
        .expect("supervisor failed")
        .expect("supervisor error");
}

#[tokio::test]
async fn test_blob_reader_partial() -> Result<()> {
    let rt = test_runtime();
    // Prepare a Provider transferring a file.
    let dir = testdir!();
    let src0 = dir.join("src0");
    let src1 = dir.join("src1");
    {
        let content = vec![1u8; 1000];
        let mut f = tokio::fs::File::create(&src0).await?;
        for _ in 0..10 {
            f.write_all(&content).await?;
        }
    }
    fs::write(&src1, "hello world").await?;
    let (db, hash) = create_collection(vec![src0.into(), src1.into()]).await?;
    let node = Node::builder(db)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .runtime(&rt)
        .spawn()
        .await?;
    let node_addr = node.local_endpoint_addresses().await?;
    let peer_id = node.peer_id();

    let timeout = tokio::time::timeout(std::time::Duration::from_secs(10), async move {
        let request = get::run(
            GetRequest::all(hash).into(),
            get::Options {
                addrs: node_addr,
                peer_id,
                keylog: true,
                derp_map: None,
            },
        )
        .await
        .unwrap();
        // connect
        let connected = request.next().await.unwrap();
        // send the request
        let _start = connected.next().await.unwrap();
        // and then just hang
    })
    .await;

    timeout.expect(
        "`get` function is hanging, make sure we are handling misbehaving `on_blob` functions",
    );
    Ok(())
}

#[tokio::test]
async fn test_ipv6() {
    setup_logging();
    let rt = test_runtime();

    let readme = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let (db, hash) = create_collection(vec![readme.into()]).await.unwrap();
    let node = match Node::builder(db)
        .bind_addr((Ipv6Addr::UNSPECIFIED, 0).into())
        .runtime(&rt)
        .spawn()
        .await
    {
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
        let request = get::run(
            GetRequest::all(hash).into(),
            get::Options {
                addrs,
                peer_id,
                keylog: true,
                derp_map: None,
            },
        )
        .await
        .unwrap();
        aggregate_get_response(request).await
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

#[tokio::test]
async fn test_run_ticket() {
    let rt = test_runtime();
    let readme = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let (db, hash) = create_collection(vec![readme.into()]).await.unwrap();
    let node = Node::builder(db)
        .bind_addr((Ipv4Addr::UNSPECIFIED, 0).into())
        .runtime(&rt)
        .spawn()
        .await
        .unwrap();
    let _drop_guard = node.cancel_token().drop_guard();
    let ticket = node.ticket(hash).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async move {
        let response =
            get::run_ticket(&ticket, GetRequest::all(ticket.hash()).into(), true, None).await?;
        aggregate_get_response(response).await
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

// helper to aggregate a get response and return all relevant data
async fn aggregate_get_response(
    initial: get_response_machine::AtInitial,
) -> anyhow::Result<(Collection, BTreeMap<u64, Bytes>, Stats)> {
    use get_response_machine::*;
    let mut items = BTreeMap::new();
    let connected = initial.next().await?;
    println!("I am connected");
    // we assume that the request includes the entire collection
    let (mut next, collection) = {
        let ConnectedNext::StartRoot(sc) = connected.next().await? else {
                panic!("request did not include collection");
            };
        println!("getting collection");
        let (done, data) = sc.next().concatenate_into_vec().await?;
        println!("got collection {}", data.len());
        (done.next(), Collection::from_bytes(&data)?)
    };
    // read all the children
    let finishing = loop {
        let start = match next {
            EndBlobNext::MoreChildren(start) => start,
            EndBlobNext::Closing(finishing) => break finishing,
        };
        let child = start.child_offset();
        let Some(blob) = collection.blobs().get(child as usize) else {
                break start.finish();
            };
        let (done, data) = start.next(blob.hash).concatenate_into_vec().await?;
        items.insert(child, data.into());
        next = done.next();
    };
    let stats = finishing.next().await?;
    Ok((collection, items, stats))
}

#[tokio::test]
async fn test_run_fsm() {
    let rt = test_runtime();
    let readme = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let (db, hash) = create_collection(vec![readme.into()]).await.unwrap();
    let node = match Node::builder(db)
        .bind_addr("[::1]:0".parse().unwrap())
        .runtime(&rt)
        .spawn()
        .await
    {
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
        let connection =
            MagicEndpoint::dial_peer(peer_id, &iroh_bytes::P2P_ALPN, &addrs, None, true).await?;
        let request = GetRequest::all(hash).into();
        let stream = get::run_connection(connection, request);
        let (collection, children, _) = aggregate_get_response(stream).await?;
        validate_children(collection, children)?;
        anyhow::Ok(())
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

fn readme_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")
}

#[derive(Clone, Debug)]
struct CollectionCustomHandler;

impl CustomGetHandler<Database> for CollectionCustomHandler {
    fn handle(
        &self,
        _token: Option<RequestToken>,
        _data: Bytes,
        database: Database,
    ) -> BoxFuture<'static, anyhow::Result<GetRequest>> {
        async move {
            let readme = readme_path();
            let sources = vec![DataSource::new(readme)];
            let (new_db, hash) = create_collection(sources).await?;
            let new_db = new_db.to_inner();
            database.union_with(new_db);
            let request = GetRequest::all(hash);
            Ok(request)
        }
        .boxed()
    }
}

#[derive(Clone, Debug)]
struct BlobCustomHandler;

impl CustomGetHandler<Database> for BlobCustomHandler {
    fn handle(
        &self,
        _token: Option<RequestToken>,
        _data: Bytes,
        database: Database,
    ) -> BoxFuture<'static, anyhow::Result<GetRequest>> {
        async move {
            let readme = readme_path();
            let sources = vec![DataSource::new(readme)];
            let (new_db, c_hash) = create_collection(sources).await?;
            let mut new_db = new_db.to_inner();
            new_db.remove(&c_hash);
            let file_hash = *new_db.iter().next().unwrap().0;
            database.union_with(new_db);
            let request = GetRequest::single(file_hash);
            println!("{:?}", request);
            Ok(request)
        }
        .boxed()
    }
}

#[tokio::test]
async fn test_custom_request_blob() {
    let rt = test_runtime();
    let db = Database::default();
    let node = Node::builder(db)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .runtime(&rt)
        .custom_get_handler(BlobCustomHandler)
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
        let response = get::run(
            request,
            get::Options {
                addrs,
                peer_id,
                keylog: true,
                derp_map: None,
            },
        )
        .await?;
        let connected = response.next().await?;
        let ConnectedNext::StartRoot(start) = connected.next().await? else { panic!() };
        let header = start.next();
        let (_, actual) = header.concatenate_into_vec().await?;
        let expected = tokio::fs::read(readme_path()).await?;
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
    let db = Database::default();
    let node = Node::builder(db)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .runtime(&rt)
        .custom_get_handler(CollectionCustomHandler)
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
        let response = get::run(
            request,
            get::Options {
                addrs,
                peer_id,
                keylog: true,
                derp_map: None,
            },
        )
        .await?;
        let (_collection, items, _stats) = aggregate_get_response(response).await?;
        let actual = &items[&0];
        let expected = tokio::fs::read(readme_path()).await?;
        assert_eq!(actual, &expected);
        anyhow::Ok(())
    })
    .await
    .expect("timeout")
    .expect("get failed");
}

#[derive(Clone, Debug)]
struct CustomAuthHandler;

impl<D> RequestAuthorizationHandler<D> for CustomAuthHandler {
    fn authorize(
        &self,
        _db: D,
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
    let readme = readme_path();
    let (db, hash) = create_collection(vec![readme.into()]).await.unwrap();
    let provider = Node::builder(db)
        .bind_addr("0.0.0.0:0".parse().unwrap())
        .custom_auth_handler(CustomAuthHandler)
        .runtime(&rt)
        .spawn()
        .await?;

    let token = Some(RequestToken::new(vec![1, 2, 3, 4, 5, 6])?);
    let mut events = provider.subscribe();
    let event_handle = rt.main().spawn(async move {
        while let Ok(msg) = events.recv().await {
            match msg {
                Event::ByteProvide(bp_msg) => {
                    if let iroh_bytes::provider::Event::GetRequestReceived { token: tok, .. } =
                        bp_msg
                    {
                        // println!("token: {:?}", token);
                        return tok;
                    }
                }
            }
        }
        None
    });

    let addrs = provider.local_endpoint_addresses().await?;
    let peer_id = provider.peer_id();
    tokio::time::timeout(Duration::from_secs(10), async move {
        MagicEndpoint::dial_peer(peer_id, &iroh_bytes::P2P_ALPN, &addrs, None, true).await?;
        let request = GetRequest::all(hash).with_token(token).into();
        let response = get::run(
            request,
            get::Options {
                addrs,
                peer_id,
                keylog: true,
                derp_map: None,
            },
        )
        .await?;
        let (_collection, items, _stats) = aggregate_get_response(response).await?;
        let actual = &items[&0];
        let expected = tokio::fs::read(readme_path()).await?;
        assert_eq!(actual, &expected);
        anyhow::Ok(())
    })
    .await
    .context("timeout")?
    .context("get failed")?;

    let token = event_handle.await?.expect("missing token");
    assert_eq!(token.as_bytes(), &[1, 2, 3, 4, 5, 6][..]);

    Ok(())
}

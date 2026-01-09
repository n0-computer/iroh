use std::{
    alloc::{GlobalAlloc, Layout},
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use human_bytes::human_bytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, Watcher,
    endpoint::{Incoming, PathInfoList},
};
use n0_error::Result;
use n0_future::StreamExt;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

struct TrackingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let size = layout.size();
            let ptr = std::alloc::System.alloc(layout);
            if !ptr.is_null() {
                ALLOCATED.fetch_add(size, Ordering::SeqCst);
            }
            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe {
            std::alloc::System.dealloc(ptr, layout);
        }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn print_usage() {
    let alloc = ALLOCATED.load(Ordering::SeqCst);
    println!("current mem usage: {}", human_bytes(alloc as f64));
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let mut with_peer_manager = false;
    if args.len() > 1 {
        println!("running the example with a peer manager");
        with_peer_manager = true;
    }

    println!("start");
    print_usage();
    // create server endpoint
    // run it
    // after each connection, add all the path infos to the peermanager
    // loop that creates client endpoints and connects to the server ep
    let server = Endpoint::empty_builder(iroh::RelayMode::Disabled)
        .alpns(vec![b"test".into()])
        .bind()
        .await?;

    println!("built endpoint");
    print_usage();

    let peer_manager: PeerManager = if with_peer_manager {
        Arc::new(Mutex::new(Some(HashMap::new())))
    } else {
        Arc::new(Mutex::new(None))
    };
    let ep = server.clone();
    let pm = Arc::clone(&peer_manager);
    tokio::spawn(run_server(ep, pm));

    println!("after server start");
    print_usage();
    let server_addr = server.addr();
    let mut client_set = JoinSet::new();
    let cancel = CancellationToken::new();
    {
        for _ in 0..100 {
            client_set.spawn(run_client(server_addr.clone(), cancel.child_token()));
        }
        // give time for the server to accept
        tokio::time::sleep(Duration::from_secs(3)).await;
        println!("before cancel");
        print_usage();

        cancel.cancel();
        client_set.join_all().await;
    }
    println!("after clients close");
    print_usage();

    server.close().await;
    drop(server);
    println!("closed server");
    print_usage();

    {
        let pm = peer_manager.lock().expect("not poisoned");
        println!("peer_manager: {:#?}", pm);
    }
    drop(peer_manager);
    println!("dropped peer_manager");
    print_usage();

    Ok(())
}

type PeerManager = Arc<Mutex<Option<HashMap<EndpointId, PathInfoList>>>>;

async fn run_server(ep: Endpoint, pm: PeerManager) {
    let mut set = JoinSet::new();
    while let Some(incoming) = ep.accept().await {
        let pm = Arc::clone(&pm);
        set.spawn(handle_incoming(incoming, pm));
    }
    set.join_all().await;
}

async fn run_client(server_addr: EndpointAddr, cancel: CancellationToken) -> Result<()> {
    let client = Endpoint::empty_builder(iroh::RelayMode::Disabled)
        .bind()
        .await?;
    let conn = match client.connect(server_addr, b"test").await {
        Err(e) => {
            println!("error connecting: {e}");
            return Ok(());
        }
        Ok(c) => c,
    };

    cancel.cancelled().await;
    conn.close(iroh::endpoint::VarInt::from_u32(0), b"closed");
    client.close().await;
    Ok(())
}

async fn handle_incoming(incoming: Incoming, peer_manager: PeerManager) -> Result<()> {
    let conn = match incoming.await {
        Err(e) => {
            println!("error with incoming: {e:?}");
            return Ok(());
        }
        Ok(c) => c,
    };
    let remote_id = conn.remote_id();
    let mut paths = conn.paths().stream();
    while let Some(path_infos) = paths.next().await {
        let mut pm = peer_manager.lock().expect("peer manager lock poisoned");
        if let Some(pm) = pm.as_mut() {
            pm.insert(remote_id, path_infos);
        }
    }
    conn.closed().await;
    Ok(())
}

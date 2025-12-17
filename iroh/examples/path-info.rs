use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use human_bytes::human_bytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, Watcher,
    endpoint::{Incoming, PathInfoList},
};
use memory_stats::memory_stats;
use n0_error::Result;
use n0_future::StreamExt;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    println!("start");
    if let Some(usage) = memory_stats() {
        println!(
            "Current physical memory usage: {}",
            human_bytes(usage.physical_mem as f64)
        );
    } else {
        println!("Couldn't get the current memory usage :(");
    }
    // create server endpoint
    // run it
    // after each connection, add all the path infos to the peermanager
    // loop that creates client endpoints and connects to the server ep
    let server = Endpoint::empty_builder(iroh::RelayMode::Disabled)
        .alpns(vec![b"test".into()])
        .bind()
        .await?;
    let peer_manager: PeerManager = Arc::new(Mutex::new(HashMap::new()));
    let ep = server.clone();
    let pm = Arc::clone(&peer_manager);
    tokio::spawn(run_server(ep, pm));

    println!("after server start");
    if let Some(usage) = memory_stats() {
        println!(
            "Current physical memory usage: {}",
            human_bytes(usage.physical_mem as f64)
        );
    } else {
        println!("Couldn't get the current memory usage :(");
    }
    let server_addr = server.addr();
    let mut client_set = JoinSet::new();
    let cancel = CancellationToken::new();
    for _ in 0..100 {
        client_set.spawn(run_client(server_addr.clone(), cancel.child_token()));
    }
    // give time for the server to accept
    tokio::time::sleep(Duration::from_secs(3)).await;
    println!("before cancel");
    if let Some(usage) = memory_stats() {
        println!(
            "Current physical memory usage: {}",
            human_bytes(usage.physical_mem as f64)
        );
    } else {
        println!("Couldn't get the current memory usage :(");
    }

    cancel.cancel();
    client_set.join_all().await;

    println!("after clients close");
    if let Some(usage) = memory_stats() {
        println!(
            "Current physical memory usage: {}",
            human_bytes(usage.physical_mem as f64)
        );
    } else {
        println!("Couldn't get the current memory usage :(");
    }

    server.close().await;

    println!("after server close");
    if let Some(usage) = memory_stats() {
        println!(
            "Current physical memory usage: {}",
            human_bytes(usage.physical_mem as f64)
        );
    } else {
        println!("Couldn't get the current memory usage :(");
    }
    drop(peer_manager);
    println!("after peer manager dropped");
    if let Some(usage) = memory_stats() {
        println!(
            "Current physical memory usage: {}",
            human_bytes(usage.physical_mem as f64)
        );
    } else {
        println!("Couldn't get the current memory usage :(");
    }
    Ok(())
}

type PeerManager = Arc<Mutex<HashMap<EndpointId, PathInfoList>>>;

async fn run_server(ep: Endpoint, pm: PeerManager) {
    println!("running server");
    let mut set = JoinSet::new();
    while let Some(incoming) = ep.accept().await {
        // println!("accepted incoming");
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
    // println!("handling incoming");
    let conn = match incoming.await {
        Err(e) => {
            println!("error with incoming: {e:?}");
            return Ok(());
        }
        Ok(c) => c,
    };
    // println!("got connection from {:?}", conn.remote_id());
    let remote_id = conn.remote_id();
    let mut paths = conn.paths().stream();
    while let Some(path_infos) = paths.next().await {
        // println!("{remote_id:?}: insert {} path infos", path_infos.len());
        let mut pm = peer_manager.lock().expect("peer manager lock poisoned");
        pm.insert(remote_id, path_infos);
    }
    conn.closed().await;
    Ok(())
}

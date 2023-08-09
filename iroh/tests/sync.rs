#![cfg(all(feature = "sync"))]

use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use futures::StreamExt;
use iroh::{
    client::Iroh,
    collection::IrohCollectionParser,
    database::flat::{writable::WritableFileDatabase, Database},
    node::{Builder, Node},
    rpc_protocol::{ProviderService, ShareMode},
};
use quic_rpc::{transport::misc::DummyServerEndpoint, ServiceConnection};
use tempfile::TempDir;
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::{provider::BaoReadonlyDb, util::runtime};
use iroh_sync::{
    store::{self, GetFilter, KeyFilter},
    sync::NamespaceId,
};

/// Pick up the tokio runtime from the thread local and add a
/// thread per core runtime.
fn test_runtime() -> runtime::Handle {
    runtime::Handle::from_currrent(1).unwrap()
}

struct Cancel(TempDir);

fn test_node<D: BaoReadonlyDb>(
    rt: runtime::Handle,
    db: D,
    writable_db_path: PathBuf,
    addr: SocketAddr,
) -> Builder<D, store::memory::Store, DummyServerEndpoint, IrohCollectionParser> {
    let store = iroh_sync::store::memory::Store::default();
    Node::builder(db, store, writable_db_path)
        .collection_parser(IrohCollectionParser)
        .runtime(&rt)
        .bind_addr(addr)
}

struct NodeDropGuard {
    _dir: TempDir,
    node: Node<Database, store::memory::Store>,
}
impl Drop for NodeDropGuard {
    fn drop(&mut self) {
        self.node.shutdown();
    }
}

async fn spawn_node(
    rt: runtime::Handle,
) -> anyhow::Result<(Node<Database, store::memory::Store>, NodeDropGuard)> {
    let dir = tempfile::tempdir()?;
    let db = WritableFileDatabase::new(dir.path().into()).await?;
    let node = test_node(
        rt,
        db.db().clone(),
        dir.path().into(),
        "127.0.0.1:0".parse()?,
    );
    let node = node.spawn().await?;
    Ok((node.clone(), NodeDropGuard { node, _dir: dir }))
}

async fn spawn_nodes(
    rt: runtime::Handle,
    n: usize,
) -> anyhow::Result<(
    Vec<Node<Database, store::memory::Store>>,
    Vec<NodeDropGuard>,
)> {
    let mut nodes = vec![];
    let mut guards = vec![];
    for _i in 0..n {
        let (node, guard) = spawn_node(rt.clone()).await?;
        nodes.push(node);
        guards.push(guard);
    }
    Ok((nodes, guards))
}

#[tokio::test]
async fn sync_full_basic() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
    let (nodes, drop_guard) = spawn_nodes(rt, 3).await?;
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    for (i, node) in nodes.iter().enumerate() {
        println!(
            "node {i}: {} {:?}",
            node.peer_id(),
            node.local_endpoints().await
        );
    }

    // node1: create doc and ticket
    let (id, ticket) = {
        let iroh = &clients[0];
        let author = iroh.create_author().await?;
        let doc = iroh.create_doc().await?;
        let key = b"p1";
        let value = b"1";
        doc.set_bytes(author, key.to_vec(), value.to_vec()).await?;
        let res = doc.get_bytes_latest(author, key.to_vec()).await?;
        assert_eq!(res.to_vec(), value.to_vec());
        let ticket = doc.share(ShareMode::Write).await?;
        (doc.id(), ticket)
    };

    // node2: join in
    {
        let iroh = &clients[1];
        let author = iroh.create_author().await?;
        println!("\n\n!!!! peer 1 joins !!!!");
        let doc = iroh
            .import_doc(ticket.key, vec![ticket.peer.clone()])
            .await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        for (i, client) in clients.iter().enumerate() {
            report(&client, id, format!("node{i}")).await;
        }

        println!("\n\n!!!! peer 1 publishes !!!!");

        let key = b"p2";
        let value = b"22";
        doc.set_bytes(author, key.to_vec(), value.to_vec()).await?;
        // todo: events
        tokio::time::sleep(Duration::from_secs(2)).await;
        for (i, client) in clients.iter().enumerate() {
            report(&client, id, format!("node{i}")).await;
        }
    }

    println!("\n\n!!!! peer 2 joins !!!!");
    {
        // node 3 joins & imports the doc from peer 1
        let iroh = &clients[2];
        let author = iroh.create_author().await?;
        let doc = iroh
            .import_doc(ticket.key, vec![ticket.peer.clone()])
            .await?;

        // now wait...
        tokio::time::sleep(Duration::from_secs(5)).await;
        println!("\n\n!!!! peer 2 publishes !!!!");
        let key = b"p3";
        let value = b"333";
        doc.set_bytes(author, key.to_vec(), value.to_vec()).await?;
    }

    tokio::time::sleep(Duration::from_secs(5)).await;
    for (i, client) in clients.iter().enumerate() {
        report(&client, id, format!("node{i}")).await;
    }

    drop(drop_guard);

    Ok(())
}

async fn report<C: ServiceConnection<ProviderService>>(
    client: &Iroh<C>,
    id: NamespaceId,
    label: impl ToString,
) {
    let label = label.to_string();
    println!("report: {label} {id}");
    match try_report(client, id).await {
        Ok(_) => {}
        Err(err) => println!("  failed: {err}"),
    }
}

async fn try_report<C: ServiceConnection<ProviderService>>(
    client: &Iroh<C>,
    id: NamespaceId,
) -> anyhow::Result<()> {
    let doc = client.get_doc(id)?;
    let filter = GetFilter {
        latest: false,
        author: None,
        key: KeyFilter::All,
    };
    let mut stream = doc.get(filter).await?;
    while let Some(entry) = stream.next().await {
        let entry = entry?;
        let text = match client.get_bytes(*entry.content_hash()).await {
            Ok(bytes) => String::from_utf8(bytes.to_vec())?,
            Err(err) => format!("<{err}>"),
        };
        println!(
            "    @{} {} {:4} -- {}",
            entry.author(),
            entry.content_hash(),
            entry.content_len(),
            text
        );
    }
    Ok(())
}

fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

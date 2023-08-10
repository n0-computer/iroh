#![cfg(all(feature = "sync"))]

use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use futures::StreamExt;
use iroh::{
    collection::IrohCollectionParser,
    node::{Builder, Node},
    rpc_protocol::ShareMode,
};
use quic_rpc::transport::misc::DummyServerEndpoint;
use tracing_subscriber::{prelude::*, EnvFilter};

use iroh_bytes::util::runtime;
use iroh_sync::store::{self, GetFilter};

/// Pick up the tokio runtime from the thread local and add a
/// thread per core runtime.
fn test_runtime() -> runtime::Handle {
    runtime::Handle::from_currrent(1).unwrap()
}

fn test_node(
    rt: runtime::Handle,
    addr: SocketAddr,
) -> Builder<
    iroh::baomap::mem::Store,
    store::memory::Store,
    DummyServerEndpoint,
    IrohCollectionParser,
> {
    let db = iroh::baomap::mem::Store::new(rt.clone());
    let store = iroh_sync::store::memory::Store::default();
    Node::builder(db, store)
        .collection_parser(IrohCollectionParser)
        .runtime(&rt)
        .bind_addr(addr)
}

async fn spawn_node(
    rt: runtime::Handle,
) -> anyhow::Result<Node<iroh::baomap::mem::Store, store::memory::Store>> {
    let node = test_node(rt, "127.0.0.1:0".parse()?);
    let node = node.spawn().await?;
    Ok(node)
}

async fn spawn_nodes(
    rt: runtime::Handle,
    n: usize,
) -> anyhow::Result<Vec<Node<iroh::baomap::mem::Store, store::memory::Store>>> {
    let mut nodes = vec![];
    for _i in 0..n {
        let node = spawn_node(rt.clone()).await?;
        nodes.push(node);
    }
    Ok(nodes)
}

#[tokio::test]
async fn sync_full_basic() -> Result<()> {
    setup_logging();
    let rt = test_runtime();
    let nodes = spawn_nodes(rt, 3).await?;
    let clients = nodes.iter().map(|node| node.client()).collect::<Vec<_>>();

    // for (i, node) in nodes.iter().enumerate() {
    //     println!(
    //         "node {i}: {} {:?}",
    //         node.peer_id(),
    //         node.local_endpoints().await
    //     );
    // }

    // node1: create doc and ticket
    let (ticket, doc2) = {
        let iroh = &clients[0];
        let author = iroh.create_author().await?;
        let doc = iroh.create_doc().await?;
        let key = b"k1";
        let value = b"v1";
        doc.set_bytes(author, key.to_vec(), value.to_vec()).await?;
        let entry = doc.get_latest(author, key.to_vec()).await?;
        let res = doc.get_content_bytes(&entry).await?;
        assert_eq!(res.to_vec(), value.to_vec());
        let ticket = doc.share(ShareMode::Write).await?;
        (ticket, doc)
    };

    // node2: join in
    {
        let iroh = &clients[1];
        let author = iroh.create_author().await?;
        let doc = iroh.import_doc(ticket.clone()).await?;
        // todo: events over rpc to not use sleep...
        tokio::time::sleep(Duration::from_secs(3)).await;

        let key = b"k1".to_vec();
        let filter = GetFilter::new().with_key(key);
        let entry = doc.get(filter).await?.next().await.unwrap()?;
        let res = doc.get_content_bytes(&entry).await?;
        assert_eq!(res.to_vec(), b"v1".to_vec());

        let key = b"k2";
        let value = b"v2";
        doc.set_bytes(author, key.to_vec(), value.to_vec()).await?;
        // todo: events
        tokio::time::sleep(Duration::from_secs(3)).await;

        for doc in &[doc, doc2] {
            let filter = GetFilter::new().with_key(key.to_vec());
            let entry = doc.get(filter).await?.next().await.unwrap()?;
            let res = doc.get_content_bytes(&entry).await?;
            assert_eq!(res.to_vec(), value.to_vec());
        }
    }

    {
        //  node 3 joins & imports the doc from peer 1
        let iroh = &clients[2];
        let doc = iroh.import_doc(ticket).await?;

        // todo: events
        tokio::time::sleep(Duration::from_secs(3)).await;

        let key = b"k1";
        let value = b"v1";
        let filter = GetFilter::new().with_key(key.to_vec());
        let entry = doc.get(filter).await?.next().await.unwrap()?;
        let res = doc.get_content_bytes(&entry).await?;
        assert_eq!(res.to_vec(), value.to_vec());

        let key = b"k2";
        let value = b"v2";
        let filter = GetFilter::new().with_key(key.to_vec());
        let entry = doc.get(filter).await?.next().await.unwrap()?;
        let res = doc.get_content_bytes(&entry).await?;
        // TODO: This fails! seems reproviding is not working?
        assert_eq!(res.to_vec(), value.to_vec());
    }

    // TODO:
    // - gossiping between multiple peers
    // - better test utils
    // - ...

    for node in nodes {
        node.shutdown();
    }

    Ok(())
}

// async fn report<C: ServiceConnection<ProviderService>>(
//     client: &Iroh<C>,
//     id: NamespaceId,
//     label: impl ToString,
// ) {
//     let label = label.to_string();
//     println!("report: {label} {id}");
//     match try_report(client, id).await {
//         Ok(_) => {}
//         Err(err) => println!("  failed: {err}"),
//     }
// }
//
// async fn try_report<C: ServiceConnection<ProviderService>>(
//     client: &Iroh<C>,
//     id: NamespaceId,
// ) -> anyhow::Result<()> {
//     let doc = client.get_doc(id)?;
//     let filter = GetFilter {
//         latest: false,
//         author: None,
//         key: KeyFilter::All,
//     };
//     let mut stream = doc.get(filter).await?;
//     while let Some(entry) = stream.next().await {
//         let entry = entry?;
//         let text = match doc.get_content_bytes(&entry).await {
//             Ok(bytes) => String::from_utf8(bytes.to_vec())?,
//             Err(err) => format!("<{err}>"),
//         };
//         println!(
//             "    @{} {} {:4} -- {}",
//             entry.author(),
//             entry.content_hash(),
//             entry.content_len(),
//             text
//         );
//     }
//     Ok(())
// }

fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

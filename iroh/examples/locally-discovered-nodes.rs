//! A small example showing how to get a list of nodes that were discovered via [`iroh::discovery::MdnsDiscovery`]. MdnsDiscovery uses [`swarm-discovery`](https://crates.io/crates/swarm-discovery), an opinionated implementation of mDNS to discover other nodes in the local network.
//!
//! This example creates an iroh endpoint, a few additional iroh endpoints to discover, waits a few seconds, and reports all of the iroh NodeIds (also called `[iroh::key::PublicKey]`s) it has discovered.
//!
//! This is an async, non-determinate process, so the number of NodeIDs discovered each time may be different. If you have other iroh endpoints or iroh nodes with [`MdnsDiscovery`] enabled, it may discover those nodes as well.
use std::time::Duration;

use anyhow::Result;
use iroh::{node_info::UserData, Endpoint, NodeId};
use n0_future::StreamExt;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    println!("Discovering Local Nodes Example!");

    let ep = Endpoint::builder().discovery_local_network().bind().await?;
    let node_id = ep.node_id();
    println!("Created endpoint {}", node_id.fmt_short());

    let user_data = UserData::try_from(String::from("local-nodes-example"))?;

    let mut discovery_stream = ep.discovery_stream();

    let ud = user_data.clone();
    let discovery_stream_task = tokio::spawn(async move {
        let mut discovered_nodes: Vec<NodeId> = vec![];
        while let Some(item) = discovery_stream.next().await {
            match item {
                Err(e) => {
                    tracing::error!("{e}");
                    return;
                }
                Ok(item) => {
                    // if there is no user data, or the user data
                    // does not indicate that the discovered node
                    // is a part of the example, ignore it
                    match item.node_info().data.user_data() {
                        Some(user_data) if &ud == user_data => {}
                        _ => {
                            tracing::error!("found node with unexpected user data, ignoring it");
                            continue;
                        }
                    }

                    // if we've already found this node, ignore it
                    // otherwise announce that we have found a new node
                    if discovered_nodes.contains(&item.node_id()) {
                        continue;
                    } else {
                        discovered_nodes.push(item.node_id());
                        println!("Found node {}!", item.node_id().fmt_short());
                    }
                }
            };
        }
    });

    let mut set = JoinSet::new();
    let node_count = 5;
    for _ in 0..node_count {
        let ud = user_data.clone();
        set.spawn(async move {
            let ep = Endpoint::builder().discovery_local_network().bind().await?;
            ep.set_user_data_for_discovery(Some(ud));
            tokio::time::sleep(Duration::from_secs(3)).await;
            ep.close().await;
            anyhow::Ok(())
        });
    }

    set.join_all().await.iter().for_each(|res| {
        if let Err(e) = res {
            tracing::error!("{e}");
        }
    });
    ep.close().await;
    discovery_stream_task.abort();
    Ok(())
}

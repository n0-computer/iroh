//! A small example showing how to get a list of endpoints that were discovered via [`iroh::address_lookup::MdnsAddressLookup`]. Mdns Address Lookup uses [`swarm-discovery`](https://crates.io/crates/swarm-discovery), an opinionated implementation of mDNS to discover other endpoints in the local network.
//!
//! This example creates an iroh endpoint, a few additional iroh endpoints to discover, waits a few seconds, and reports all of the iroh EndpointIds (also called `[iroh::key::PublicKey]`s) it has discovered.
//!
//! This is an async, non-determinate process, so the number of EndpointIDs discovered each time may be different. If you have other iroh endpoints or iroh endpoints with [`address_lookup::MdnsAddressLookup`] enabled, it may discover those endpoints as well.
use std::time::Duration;

use iroh::{Endpoint, EndpointId, address_lookup, endpoint_info::UserData};
use n0_error::Result;
use n0_future::StreamExt;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    println!("Discovering Local Endpoints Example!");

    let ep = Endpoint::bind().await?;
    let endpoint_id = ep.id();

    let mdns = address_lookup::MdnsAddressLookup::builder().build(endpoint_id)?;
    ep.address_lookup().add(mdns.clone());

    println!("Created endpoint {}", endpoint_id.fmt_short());

    let user_data = UserData::try_from(String::from("local-endpoints-example"))?;

    let ud = user_data.clone();
    let address_lookup_stream_task = tokio::spawn(async move {
        let mut address_lookup_stream = mdns.subscribe().await;
        let mut discovered_endpoints: Vec<EndpointId> = vec![];
        while let Some(event) = address_lookup_stream.next().await {
            match event {
                address_lookup::DiscoveryEvent::Discovered { endpoint_info, .. } => {
                    // if there is no user data, or the user data
                    // does not indicate that the discovered endpoint
                    // is a part of the example, ignore it
                    match endpoint_info.data.user_data() {
                        Some(user_data) if &ud == user_data => {}
                        _ => {
                            tracing::error!(
                                "found endpoint with unexpected user data, ignoring it"
                            );
                            continue;
                        }
                    }

                    // if we've already found this endpoint, ignore it
                    // otherwise announce that we have found a new endpoint
                    if discovered_endpoints.contains(&endpoint_info.endpoint_id) {
                        continue;
                    } else {
                        discovered_endpoints.push(endpoint_info.endpoint_id);
                        println!("Found endpoint {}!", endpoint_info.endpoint_id.fmt_short());
                    }
                }
                address_lookup::DiscoveryEvent::Expired { .. } => {}
            };
        }
    });

    let mut set = JoinSet::new();
    let endpoint_count = 5;
    for _ in 0..endpoint_count {
        let ud = user_data.clone();
        set.spawn(async move {
            let ep = Endpoint::bind().await?;
            ep.address_lookup()
                .add(address_lookup::MdnsAddressLookup::builder().build(ep.id())?);
            ep.set_user_data_for_address_lookup(Some(ud));
            tokio::time::sleep(Duration::from_secs(3)).await;
            ep.close().await;
            n0_error::Ok(())
        });
    }

    set.join_all().await.iter().for_each(|res| {
        if let Err(e) = res {
            tracing::error!("{e}");
        }
    });
    ep.close().await;
    address_lookup_stream_task.abort();
    Ok(())
}

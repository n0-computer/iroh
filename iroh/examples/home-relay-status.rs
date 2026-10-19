//! Tests connection to a home relay server and reports the status.
//!
//! Also shows how to specifically test if a connection fails due to authentication.

use clap::Parser;
use iroh::{Endpoint, RelayMap, RelayUrl, Watcher, endpoint::presets};
use n0_future::StreamExt;

#[derive(clap::Parser, Debug)]
struct Args {
    /// Pass one or more relay URLs.
    ///
    /// If unset will use the public default relays.
    relays: Vec<RelayUrl>,
}

#[tokio::main]
async fn main() -> n0_error::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let relay_map = if args.relays.is_empty() {
        iroh::defaults::prod::default_relay_map()
    } else {
        RelayMap::from_iter(args.relays)
    };

    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(iroh::RelayMode::Custom(relay_map))
        .bind()
        .await?;

    println!("endpoint bound");

    // Spawn a task to report the home relay status.
    //
    // You could pass a channel here if you wanted to abort something in case the
    // home relay connection fails.
    tokio::spawn(report_home_relay_status(endpoint.clone()));

    // Wait for the endpoint to be online, i.e. connected to a home relay.
    //
    // Internally, this works like simplified version of the loop in `report_home_relay_status`,
    // only reporting about whether a connection was established and not exposing any
    // details in case of failure.
    endpoint.online().await;
    println!(
        "Endpoint is online. Home relay: {}",
        endpoint.addr().relay_urls().next().expect("has relay")
    );

    tokio::signal::ctrl_c().await.ok();

    endpoint.close().await;

    Ok(())
}

async fn report_home_relay_status(endpoint: Endpoint) {
    let mut home_relay_status = endpoint.home_relay_status().stream();
    // The stream moves to the next item whenever the home relay status changes in any way.
    while let Some(status_list) = home_relay_status.next().await {
        // The stream's item is a list of status entries, one per home relay. Today the list
        // never holds more than one entry, because iroh only connects to a single home
        // relay. It is a list so that iroh could support multiple home relays without an API
        // change, so we may as well iterate it.
        for status in status_list {
            let url = status.url();
            if status.is_connected() {
                // We are connected!
                // When we reach this line, `Endpoint::online` also resolves.
                println!("Relay {url}: Connected");
            } else if let Some(reason) = status.auth_denied_reason() {
                // The relay server denied our authentication. Retrying will not help: we
                // would present the same credentials again. Report this prominently in
                // our app instead of waiting to come online.
                println!("Relay {url}: Authentication denied ({reason})");
            } else if let Some(error) = status.last_error() {
                // The connection failed for another reason, for example a network issue.
                // iroh keeps retrying with a backoff, so let's just print it.
                println!("Relay {url}: Connection failed ({error:#})");
            } else {
                // We are not connected, and there is no error to report: either no
                // connection has been attempted yet, or one is in progress. You should
                // usually just loop over this and wait for the next update.
                println!("Relay {url}: Disconnected")
            }
        }
    }
}

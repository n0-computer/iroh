//! Tests connection to a home relay server and reports the status.
//!
//! Also shows how to specifically test if a connection fails due to authentication.

use clap::Parser;
use iroh::{Endpoint, RelayMap, RelayUrl, Watcher, endpoint::presets};
use iroh_relay::protos::handshake;
use n0_error::{AnyError, StackError};
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
    // This is like a simplified version of the above loop, only caring about
    // whether a connection was established and not reporting any details in case
    // of failure.
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
        // The stream's item is a list of status items for each home relay.
        // Currently, it is always a single item only, because iroh only connects to a single
        // home relay. It is a list so that iroh could in the future have multiple home relays
        // without API change.
        let Some(status) = status_list.into_iter().next() else {
            continue;
        };
        let url = status.url();
        if status.is_connected() {
            // We are connected!
            // When we reach this line, `Endpoint::online` also resolves.
            println!("Relay {url}: Connected");
        } else if let Some(error) = status.last_error() {
            // We are not connected, and we have an error from the last connection failure
            // or failed connection attempt. The error is a `AnyError`. We can try to downcast
            // it to a more specific type!
            if let Some(auth_denial_reason) = is_auth_denied(&error) {
                // The home relay connection failed due to authentication. We could report this
                // prominently in our app.
                println!("Relay {url}: Authentication denied ({auth_denial_reason})");
            } else {
                // The home relay connection failed due to another error, for example network
                // issues. Let's just print it.
                println!("Relay {url}: Connection failed ({error:#})");
            }
        } else {
            // We are disconnected without an error state. This is the state before a
            // connection attempt. You should usually just loop over it and wait for
            // the next error.
            println!("Relay {url}: Disconnected")
        }
    }
}

/// Returns the reason if `error` was caused by the relay server denying our authentication.
///
/// Relay connection errors are reported as an [`AnyError`] that wraps a chain of
/// crate-private error types from `iroh`. The innermost source, however, is the public
/// [`handshake::Error`] from `iroh-relay`, so we walk the source chain and downcast to
/// find a [`handshake::Error::ServerDeniedAuth`].
fn is_auth_denied(error: &AnyError) -> Option<String> {
    error
        .stack()
        .find_map(|error| match error.downcast_ref::<handshake::Error>()? {
            handshake::Error::ServerDeniedAuth { reason, .. } => Some(reason.clone()),
            _ => None,
        })
}

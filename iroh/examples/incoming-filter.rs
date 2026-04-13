//! Example demonstrating the [`IncomingFilter`] hook.
//!
//! This example requires all direct (UDP) connections to pass QUIC address
//! validation via a retry token before being accepted. Relay connections are
//! accepted without validation since the relay already vouches for the source.
//!
//! ## Usage
//!
//! ```sh
//! cargo run --example incoming-filter
//! ```
//!
//! To test, connect from another process using:
//! ```sh
//! cargo run --example connect -- <NODE_ID>
//! ```
use std::sync::Arc;

use iroh::{
    Endpoint,
    endpoint::{Connection, Incoming, IncomingAddr, presets},
    protocol::{AcceptError, IncomingFilterOutcome, ProtocolHandler, Router},
};
use n0_error::{Result, StdResultExt};

const ALPN: &[u8] = b"iroh-example/incoming-filter/0";

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        tokio::io::copy(&mut recv, &mut send).await?;
        send.finish()?;
        Ok(())
    }
}

/// Require address validation for direct connections.
///
/// If the address is not yet validated, return `Retry` so the client has to
/// prove it owns the source address before we do any further work. Validated
/// connections and relay connections are accepted.
fn filter(incoming: &Incoming) -> IncomingFilterOutcome {
    match incoming.remote_addr() {
        IncomingAddr::Ip(_) if !incoming.remote_addr_validated() => IncomingFilterOutcome::Retry,
        _ => IncomingFilterOutcome::Accept,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let endpoint = Endpoint::bind(presets::N0).await?;

    endpoint.online().await;
    let addr = endpoint.addr();
    println!("Node ID: {}", endpoint.id());
    println!("Listening on: {addr:?}");
    println!("All direct connections require address validation via retry.\n");

    let router = Router::builder(endpoint)
        .incoming_filter(Arc::new(filter))
        .accept(ALPN, Echo)
        .spawn();

    tokio::signal::ctrl_c().await.anyerr()?;
    router.shutdown().await.anyerr()?;
    Ok(())
}

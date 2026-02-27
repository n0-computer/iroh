//! Example demonstrating [`ConnectionFilter`] with rate limiting.
//!
//! This example shows how to limit connections at different stages:
//! - By socket address (with retry validation)
//! - By endpoint ID
//! - By ALPN
//!
//! Rate limiting is implemented using the `governor` crate to prevent overwhelming
//! the server with too many connections.
//!
//! ## Usage
//!
//! ```sh
//! cargo run --example connection-filter
//! ```
//!
//! To test, connect from another process using:
//! ```sh
//! cargo run --example connect -- <NODE_ID>
//! ```
use std::{net::SocketAddr, sync::Arc};

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use iroh::{
    Endpoint,
    endpoint::Connection,
    protocol::{
        AcceptAddrOutcome, AcceptAlpnOutcome, AcceptError, AcceptOutcome, ConnectionFilter,
        ProtocolHandler, Router,
    },
};
use n0_error::{Result, StdResultExt};

const ALPN: &[u8] = b"iroh-example/connection-filter/0";

// -- Protocol Handler --

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        println!("✓ Connection accepted, starting echo protocol");
        let (mut send, mut recv) = connection.accept_bi().await?;
        tokio::io::copy(&mut recv, &mut send).await?;
        send.finish()?;
        Ok(())
    }
}

// -- Connection Filters --

/// Rate-limited filter that demonstrates limiting by socket address and endpoint ID.
///
/// This filter uses separate rate limiters for:
/// - Initial socket addresses (pre-validation)
/// - Validated socket addresses (after retry)
/// - Endpoint IDs (post-TLS handshake)
/// - ALPNs (final stage)
#[derive(Debug)]
struct RateLimitedFilter {
    /// Rate limiter for initial (unvalidated) addresses
    addr_limiter: Arc<RateLimiter<SocketAddr, DashMapStateStore<SocketAddr>, DefaultClock>>,
    /// Rate limiter for validated addresses
    validated_limiter: Arc<RateLimiter<SocketAddr, DashMapStateStore<SocketAddr>, DefaultClock>>,
    /// Rate limiter for endpoint IDs
    endpoint_limiter:
        Arc<RateLimiter<iroh::EndpointId, DashMapStateStore<iroh::EndpointId>, DefaultClock>>,
    /// Rate limiter for ALPN strings
    alpn_limiter: Arc<RateLimiter<Vec<u8>, DashMapStateStore<Vec<u8>>, DefaultClock>>,
}

impl RateLimitedFilter {
    fn new() -> Self {
        // Allow 5 connections per second for unvalidated addresses
        let addr_quota = Quota::per_second(std::num::NonZeroU32::new(5).unwrap());
        let addr_limiter = Arc::new(RateLimiter::keyed(addr_quota));

        // Allow 10 connections per second for validated addresses
        let validated_quota = Quota::per_second(std::num::NonZeroU32::new(10).unwrap());
        let validated_limiter = Arc::new(RateLimiter::keyed(validated_quota));

        // Allow 20 connections per second per endpoint ID
        let endpoint_quota = Quota::per_second(std::num::NonZeroU32::new(20).unwrap());
        let endpoint_limiter = Arc::new(RateLimiter::keyed(endpoint_quota));

        // Allow 30 connections per second per ALPN
        let alpn_quota = Quota::per_second(std::num::NonZeroU32::new(30).unwrap());
        let alpn_limiter = Arc::new(RateLimiter::keyed(alpn_quota));

        Self {
            addr_limiter,
            validated_limiter,
            endpoint_limiter,
            alpn_limiter,
        }
    }
}

impl ConnectionFilter for RateLimitedFilter {
    fn accept_addr(&self, addr: SocketAddr, validated: bool) -> AcceptAddrOutcome {
        if validated {
            // Address has been validated via retry packet
            match self.validated_limiter.check_key(&addr) {
                Ok(_) => {
                    println!("✓ Validated address accepted: {}", addr);
                    AcceptAddrOutcome::Accept
                }
                Err(_) => {
                    println!("✗ Validated address rate-limited: {}", addr);
                    AcceptAddrOutcome::Reject
                }
            }
        } else {
            // Initial unvalidated connection - require validation
            match self.addr_limiter.check_key(&addr) {
                Ok(_) => {
                    println!("⟳ Address requires validation: {}", addr);
                    AcceptAddrOutcome::Retry
                }
                Err(_) => {
                    println!("✗ Unvalidated address rate-limited (ignored): {}", addr);
                    AcceptAddrOutcome::Ignore
                }
            }
        }
    }

    fn accept_endpoint_id(&self, endpoint_id: iroh::EndpointId) -> AcceptOutcome {
        match self.endpoint_limiter.check_key(&endpoint_id) {
            Ok(_) => {
                println!("✓ Endpoint ID accepted: {}", endpoint_id);
                AcceptOutcome::Accept
            }
            Err(_) => {
                println!("✗ Endpoint ID rate-limited: {}", endpoint_id);
                AcceptOutcome::Reject
            }
        }
    }

    fn accept_alpn(&self, endpoint_id: iroh::EndpointId, alpn: &[u8]) -> AcceptAlpnOutcome {
        let alpn_vec = alpn.to_vec();
        match self.alpn_limiter.check_key(&alpn_vec) {
            Ok(_) => {
                println!(
                    "✓ ALPN accepted: {} from endpoint {}",
                    String::from_utf8_lossy(alpn),
                    endpoint_id
                );
                AcceptAlpnOutcome::Accept
            }
            Err(_) => {
                println!(
                    "✗ ALPN rate-limited: {} from endpoint {}",
                    String::from_utf8_lossy(alpn),
                    endpoint_id
                );
                AcceptAlpnOutcome::close(0u32, b"rate limited")
            }
        }
    }
}

// -- Main --

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting connection filter example with rate limiting\n");

    // Create the rate-limited filter
    let filter = Arc::new(RateLimitedFilter::new());

    // Create endpoint and router
    let endpoint = Endpoint::bind().await?;
    let endpoint_id = endpoint.id();

    // Wait for the endpoint to be online
    endpoint.online().await;
    let endpoint_addr = endpoint.addr();

    println!("Node ID: {}", endpoint_id);
    println!("Listening on:");
    for addr in endpoint_addr.ip_addrs() {
        println!("  {}", addr);
    }
    if let Some(relay) = endpoint_addr.relay_urls().next() {
        println!("Relay: {}", relay);
    }
    println!("\nRate limits:");
    println!("  - Unvalidated addresses: 5/sec (requires retry validation)");
    println!("  - Validated addresses: 10/sec");
    println!("  - Endpoint IDs: 20/sec");
    println!("  - ALPNs: 30/sec");
    println!("\nWaiting for connections...\n");

    let router = Router::builder(endpoint)
        .connection_filter(filter)
        .accept(ALPN, Echo)
        .spawn();

    // Keep running until interrupted
    tokio::signal::ctrl_c().await.anyerr()?;
    println!("\nShutting down...");

    router.shutdown().await.anyerr()?;
    Ok(())
}

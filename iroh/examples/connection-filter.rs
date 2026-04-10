//! Example demonstrating the [`ConnectionFilter`] hook with rate limiting.
//!
//! The framework's [`ConnectionFilter`] is just a boxed function:
//!
//! ```ignore
//! pub type ConnectionFilter =
//!     Arc<dyn Fn(&Incoming) -> AcceptAddrOutcome + Send + Sync + 'static>;
//! ```
//!
//! That gives you full control but doesn't structure the decision in any way.
//! For most use cases you want a friendlier API with named decision points.
//! This example shows one such structure: a `RateLimitedFilter` struct with
//! methods for each kind of pre-handshake check, plus a small `dispatch`
//! function that turns it into a [`ConnectionFilter`].
//!
//! ## What it filters
//!
//! 1. **By socket address** (direct connections) — uses QUIC retry tokens to
//!    require address validation before consuming further resources.
//! 2. **By endpoint id** (relay connections) — the relay frame carries the
//!    remote endpoint id before the TLS handshake.
//! 3. **By proposed ALPNs** (all connections) — peeks at the TLS ClientHello
//!    via [`Incoming::decrypt`] to see what protocols the client is offering,
//!    *before* the handshake completes.
//!
//! Each kind of check has its own rate limit using the `governor` crate.
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
    Endpoint, EndpointId,
    endpoint::{Connection, Incoming, IncomingAddr, presets},
    protocol::{AcceptAddrOutcome, AcceptError, ProtocolHandler, Router},
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

// -- Rate limited filter --

/// Rate-limited filter with named decision points.
///
/// This type doesn't implement any framework trait — it's just an ordinary
/// struct with methods for each check. The `dispatch` method below is what
/// turns it into a [`ConnectionFilter`].
#[derive(Debug)]
struct RateLimitedFilter {
    /// Rate limiter for initial (unvalidated) addresses.
    addr_limiter: Arc<RateLimiter<SocketAddr, DashMapStateStore<SocketAddr>, DefaultClock>>,
    /// Rate limiter for validated addresses.
    validated_limiter: Arc<RateLimiter<SocketAddr, DashMapStateStore<SocketAddr>, DefaultClock>>,
    /// Rate limiter for endpoint ids (relay connections).
    endpoint_limiter: Arc<RateLimiter<EndpointId, DashMapStateStore<EndpointId>, DefaultClock>>,
    /// Rate limiter for proposed ALPN strings.
    alpn_limiter: Arc<RateLimiter<Vec<u8>, DashMapStateStore<Vec<u8>>, DefaultClock>>,
}

impl RateLimitedFilter {
    fn new() -> Self {
        // Allow 5 connections per second for unvalidated addresses.
        let addr_quota = Quota::per_second(std::num::NonZeroU32::new(5).unwrap());
        let addr_limiter = Arc::new(RateLimiter::keyed(addr_quota));

        // Allow 10 connections per second for validated addresses.
        let validated_quota = Quota::per_second(std::num::NonZeroU32::new(10).unwrap());
        let validated_limiter = Arc::new(RateLimiter::keyed(validated_quota));

        // Allow 20 connections per second per endpoint id.
        let endpoint_quota = Quota::per_second(std::num::NonZeroU32::new(20).unwrap());
        let endpoint_limiter = Arc::new(RateLimiter::keyed(endpoint_quota));

        // Allow 30 connections per second per proposed ALPN.
        let alpn_quota = Quota::per_second(std::num::NonZeroU32::new(30).unwrap());
        let alpn_limiter = Arc::new(RateLimiter::keyed(alpn_quota));

        Self {
            addr_limiter,
            validated_limiter,
            endpoint_limiter,
            alpn_limiter,
        }
    }

    /// Decide whether to accept a direct connection by socket address.
    ///
    /// `validated` is `true` if the remote has already responded to a retry
    /// packet, proving it owns the address.
    fn accept_addr(&self, addr: SocketAddr, validated: bool) -> AcceptAddrOutcome {
        if validated {
            match self.validated_limiter.check_key(&addr) {
                Ok(_) => {
                    println!("✓ Validated address accepted: {addr}");
                    AcceptAddrOutcome::Accept
                }
                Err(_) => {
                    println!("✗ Validated address rate-limited: {addr}");
                    AcceptAddrOutcome::Reject
                }
            }
        } else {
            // Initial unvalidated connection — require validation.
            match self.addr_limiter.check_key(&addr) {
                Ok(_) => {
                    println!("⟳ Address requires validation: {addr}");
                    AcceptAddrOutcome::Retry
                }
                Err(_) => {
                    println!("✗ Unvalidated address rate-limited (ignored): {addr}");
                    AcceptAddrOutcome::Ignore
                }
            }
        }
    }

    /// Decide whether to accept a relay connection by endpoint id.
    fn accept_endpoint_id(&self, endpoint_id: EndpointId) -> AcceptAddrOutcome {
        match self.endpoint_limiter.check_key(&endpoint_id) {
            Ok(_) => {
                println!("✓ Endpoint id accepted: {endpoint_id}");
                AcceptAddrOutcome::Accept
            }
            Err(_) => {
                println!("✗ Endpoint id rate-limited: {endpoint_id}");
                AcceptAddrOutcome::Reject
            }
        }
    }

    /// Decide whether to accept a connection based on the ALPNs it proposes.
    ///
    /// This peeks at the TLS ClientHello, so it can filter on the protocols
    /// the client is offering *before* the handshake completes. The decrypt
    /// is relatively expensive (~1200 bytes copied + decrypted), so this is
    /// only worth it if you actually need to make a decision based on the
    /// proposed ALPNs.
    fn accept_handshake_alpns(&self, incoming: &Incoming) -> AcceptAddrOutcome {
        let Some(decrypted) = incoming.decrypt() else {
            // Decrypt failed — best to drop silently.
            println!("✗ Failed to decrypt initial");
            return AcceptAddrOutcome::Ignore;
        };
        let Some(alpns) = decrypted.alpns() else {
            // No ALPN extension in the ClientHello — accept by default.
            return AcceptAddrOutcome::Accept;
        };
        for alpn in alpns {
            let Ok(alpn) = alpn else {
                println!("✗ Failed to parse ALPN");
                return AcceptAddrOutcome::Reject;
            };
            let alpn_vec = alpn.to_vec();
            if self.alpn_limiter.check_key(&alpn_vec).is_err() {
                println!(
                    "✗ ALPN rate-limited: {}",
                    String::from_utf8_lossy(&alpn_vec)
                );
                return AcceptAddrOutcome::Reject;
            }
            println!("✓ ALPN accepted: {}", String::from_utf8_lossy(&alpn_vec));
        }
        AcceptAddrOutcome::Accept
    }
}

/// Dispatch an incoming connection through the rate-limited filter.
///
/// This is the bridge from the filter struct to the [`ConnectionFilter`]
/// hook signature. It handles the address/endpoint-id dispatch and chains
/// the cheaper checks first (address or endpoint id) before the expensive
/// `decrypt()`-based ALPN check.
fn dispatch(filter: &RateLimitedFilter, incoming: &Incoming) -> AcceptAddrOutcome {
    // First: cheap pre-decrypt checks.
    let outcome = match incoming.remote_addr() {
        IncomingAddr::Ip(addr) => {
            let validated = incoming.remote_addr_validated();
            filter.accept_addr(addr, validated)
        }
        IncomingAddr::Relay { endpoint_id, .. } => filter.accept_endpoint_id(endpoint_id),
        // Custom transports and any future variants: no pre-handshake info
        // to filter on.
        _ => AcceptAddrOutcome::Accept,
    };
    if !matches!(outcome, AcceptAddrOutcome::Accept) {
        return outcome;
    }
    // Then: expensive ALPN check.
    filter.accept_handshake_alpns(incoming)
}

// -- Main --

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting connection filter example with rate limiting\n");

    // Wrap the filter struct in a closure that the framework can call.
    let filter = Arc::new(RateLimitedFilter::new());
    let connection_filter: Arc<dyn Fn(&Incoming) -> AcceptAddrOutcome + Send + Sync + 'static> = {
        let filter = filter.clone();
        Arc::new(move |incoming| dispatch(&filter, incoming))
    };

    // Create endpoint and router
    let endpoint = Endpoint::bind(presets::N0).await?;
    let endpoint_id = endpoint.id();

    // Wait for the endpoint to be online
    endpoint.online().await;
    let endpoint_addr = endpoint.addr();

    println!("Node ID: {endpoint_id}");
    println!("Listening on:");
    for addr in endpoint_addr.ip_addrs() {
        println!("  {addr}");
    }
    if let Some(relay) = endpoint_addr.relay_urls().next() {
        println!("Relay: {relay}");
    }
    println!("\nRate limits:");
    println!("  - Unvalidated addresses: 5/sec (requires retry validation)");
    println!("  - Validated addresses: 10/sec");
    println!("  - Endpoint ids: 20/sec");
    println!("  - Proposed ALPNs: 30/sec");
    println!("\nWaiting for connections...\n");

    let router = Router::builder(endpoint)
        .connection_filter(connection_filter)
        .accept(ALPN, Echo)
        .spawn();

    // Keep running until interrupted
    tokio::signal::ctrl_c().await.anyerr()?;
    println!("\nShutting down...");

    router.shutdown().await.anyerr()?;
    Ok(())
}

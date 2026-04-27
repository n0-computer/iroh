//! Integration tests for [`iroh_dns::dns::DnsResolver`].
//!
//! These hit live DNS so they need network connectivity. They run
//! by default like every other integration test: `cargo test -p
//! iroh-dns` is enough.

use std::time::Duration;

use iroh_dns::dns::DnsResolver;

const TIMEOUT: Duration = Duration::from_secs(8);
const HOST: &str = "dns.iroh.link";

fn install_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("hickory_resolver=trace,hickory_proto=debug,hickory_net=debug,iroh_dns=trace")),
        )
        .with_test_writer()
        .try_init();
}

#[tokio::test]
async fn resolver_constructs_without_panic() {
    install_tracing();
    let _resolver = DnsResolver::new();
}

#[tokio::test]
async fn resolver_resolves_dns_iroh_link() {
    install_tracing();
    let resolver = DnsResolver::new();
    let mut hits: Vec<String> = Vec::new();

    match resolver.lookup_ipv4(HOST, TIMEOUT).await {
        Ok(addrs) => {
            for ip in addrs {
                hits.push(format!("A {ip}"));
            }
        }
        Err(err) => eprintln!("IPv4 lookup failed (continuing): {err:#} :: debug={err:?}"),
    }

    match resolver.lookup_ipv6(HOST, TIMEOUT).await {
        Ok(addrs) => {
            for ip in addrs {
                hits.push(format!("AAAA {ip}"));
            }
        }
        Err(err) => eprintln!("IPv6 lookup failed (continuing): {err:#} :: debug={err:?}"),
    }

    assert!(
        !hits.is_empty(),
        "neither IPv4 nor IPv6 lookup returned an answer for {HOST}",
    );
    eprintln!("{HOST} resolved to: {hits:?}");
}

//! Network-dependent smoke tests for [`iroh_dns::dns::DnsResolver`].
//!
//! Builds the default resolver and looks up `dns.iroh.link`. Marked
//! `#[ignore]` so the network dependency does not flake the regular
//! `cargo test` run; pass `--include-ignored` to opt in.
//!
//! CI runs these on a fresh Android emulator (no JNI context, no
//! configured system DNS) to gate the no-panic-on-fresh-Android-
//! process invariant added in this branch and to verify that the
//! public DNS fallback (Cloudflare and Google over UDP, TCP, and
//! DoH) reaches the wider internet through the emulator's NAT.

use std::time::Duration;

use iroh_dns::dns::DnsResolver;

const TIMEOUT: Duration = Duration::from_secs(8);
const HOST: &str = "dns.iroh.link";

#[tokio::test]
#[ignore = "network-dependent; run with --include-ignored or --ignored"]
async fn resolver_constructs_without_panic() {
    let _resolver = DnsResolver::new();
}

#[tokio::test]
#[ignore = "network-dependent; run with --include-ignored or --ignored"]
async fn resolver_resolves_dns_iroh_link() {
    let resolver = DnsResolver::new();
    let mut hits: Vec<String> = Vec::new();

    match resolver.lookup_ipv4(HOST, TIMEOUT).await {
        Ok(addrs) => {
            for ip in addrs {
                hits.push(format!("A {ip}"));
            }
        }
        Err(err) => eprintln!("IPv4 lookup failed (continuing): {err:#}"),
    }

    match resolver.lookup_ipv6(HOST, TIMEOUT).await {
        Ok(addrs) => {
            for ip in addrs {
                hits.push(format!("AAAA {ip}"));
            }
        }
        Err(err) => eprintln!("IPv6 lookup failed (continuing): {err:#}"),
    }

    assert!(
        !hits.is_empty(),
        "neither IPv4 nor IPv6 lookup returned an answer for {HOST}",
    );
    eprintln!("{HOST} resolved to: {hits:?}");
}

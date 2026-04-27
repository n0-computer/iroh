//! Integration tests for [`iroh_dns::dns::DnsResolver`].
//!
//! These hit live DNS so they need network connectivity. They run
//! by default like every other integration test: `cargo test -p
//! iroh-dns` is enough.

use std::time::Duration;

use iroh_dns::dns::DnsResolver;

const TIMEOUT: Duration = Duration::from_secs(8);
const HOST: &str = "dns.iroh.link";

#[tokio::test]
async fn resolver_constructs_without_panic() {
    let _resolver = DnsResolver::new();
}

// Ignored on Android: in the GitHub-hosted emulator the public DNS
// fallback's hickory connection pool repeatedly returns
// "no connections available" within ~30 ms, well before the 8s
// per-lookup timeout, so a resolution that works locally fails in
// CI. Tracking the actual fix separately; see Frando/android-dns-fix.
#[cfg_attr(target_os = "android", ignore = "flaky on emulator (no connections available)")]
#[tokio::test]
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

//! Integration tests for [`iroh_dns::dns::DnsResolver`].
//!
//! These hit live DNS so they need network connectivity. They run
//! by default like every other integration test: `cargo test -p
//! iroh-dns` is enough.

use std::time::Duration;

#[cfg(target_os = "android")]
use iroh_dns::dns::DnsProtocol;
use iroh_dns::dns::DnsResolver;

const TIMEOUT: Duration = Duration::from_secs(8);
const HOST: &str = "dns.iroh.link";

#[tokio::test]
async fn resolver_constructs_without_panic() {
    let _resolver = DnsResolver::new();
}

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

/// Resolves through the Android emulator's QEMU NAT DNS proxy.
///
/// 10.0.2.3 is the well-known emulator DNS gateway, documented at
/// <https://developer.android.com/studio/run/emulator-networking>.
/// Pointing the resolver at it explicitly sidesteps the missing
/// system-DNS reader (no JNI context here) so this test exercises
/// hickory's pool, sockets, and our `DnsResolver` plumbing against a
/// nameserver that is always reachable inside the emulator,
/// independent of whether public DNS is reachable on the runner.
#[cfg(target_os = "android")]
#[tokio::test]
async fn resolves_via_emulator_dns_proxy() {
    let nameserver = "10.0.2.3:53".parse().unwrap();
    let resolver = DnsResolver::builder()
        .with_nameserver(nameserver, DnsProtocol::Udp)
        .build();

    let addrs: Vec<_> = resolver
        .lookup_ipv4(HOST, TIMEOUT)
        .await
        .expect("IPv4 lookup via 10.0.2.3 should succeed in the emulator")
        .collect();

    assert!(
        !addrs.is_empty(),
        "expected at least one A record for {HOST} via 10.0.2.3",
    );
    eprintln!("{HOST} resolved via 10.0.2.3 to: {addrs:?}");
}

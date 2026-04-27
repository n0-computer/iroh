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

// Ignored on Android: the GitHub-hosted Android emulator's QEMU NAT
// has no route to public IPs, so every server in the public DNS
// fallback (Cloudflare and Google over UDP/TCP/DoH) fails the
// `connect` syscall with ENETUNREACH. Hickory's pool collapses every
// `Io` error into the loop's initial `NoConnections` placeholder via
// `most_specific()` (lib.rs:421), which is why the visible error is
// "no connections available" rather than "network is unreachable".
//
// On real Android devices a caller installs a JNI context up front
// (see `install_android_jni_context`) so the system DNS reader picks
// up the device's actual nameservers; on the CI emulator that path
// is also unavailable because we run the test as a plain binary, not
// as an app with a JavaVM. The Android-specific
// `resolves_via_emulator_dns_proxy` test below exercises the
// resolver against the emulator's QEMU DNS proxy at 10.0.2.3, which
// is the one DNS endpoint that *is* reachable in this environment.
#[cfg_attr(
    target_os = "android",
    ignore = "GH-runner emulator NAT cannot reach public DNS (ENETUNREACH)"
)]
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
/// Using it explicitly sidesteps both the missing system-DNS reader
/// (no JNI context here) and the absent route to public IPs on the
/// GitHub-hosted runner. The point of this test is to exercise
/// hickory's pool, sockets, and our `DnsResolver` plumbing on
/// Android in CI; the public-DNS test above covers the same ground
/// on every other platform.
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

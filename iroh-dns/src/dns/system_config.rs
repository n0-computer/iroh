//! System DNS configuration parsing.
//!
//! Reading the system DNS configuration is platform-specific: `/etc/resolv.conf`
//! on Unix, the network adapters on Windows, and a JNI call on Android. The
//! per-platform readers live in the `unix`, `windows`, and `android` submodules;
//! this module holds the shared [`SystemDnsConfig`] type, the dispatch, and the
//! Google DNS fallback.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::DnsProtocol;

#[cfg(target_os = "android")]
mod android;
#[cfg(not(any(windows, target_os = "android")))]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "android")]
pub use android::install_android_jni_context;
#[cfg(target_os = "android")]
use android::read_system_dns;
#[cfg(not(any(windows, target_os = "android")))]
use unix::read_system_dns;
#[cfg(windows)]
use windows::read_system_dns;

/// Standard DNS port.
const DNS_PORT: u16 = 53;

/// Google Public DNS IPv4 primary (8.8.8.8).
const GOOGLE_DNS_IPV4_PRIMARY: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
/// Google Public DNS IPv4 secondary (8.8.4.4).
const GOOGLE_DNS_IPV4_SECONDARY: Ipv4Addr = Ipv4Addr::new(8, 8, 4, 4);
/// Google Public DNS IPv6 primary (2001:4860:4860::8888).
const GOOGLE_DNS_IPV6_PRIMARY: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
/// Google Public DNS IPv6 secondary (2001:4860:4860::8844).
const GOOGLE_DNS_IPV6_SECONDARY: Ipv6Addr =
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844);

/// Parsed system DNS configuration.
#[derive(Debug, Clone, Default)]
pub(super) struct SystemDnsConfig {
    pub(super) nameservers: Vec<(SocketAddr, DnsProtocol)>,
    /// Search domains from resolv.conf `search` or `domain` directives.
    ///
    /// When resolving a short hostname (one with fewer dots than `ndots`,
    /// default 1), the resolver should try appending each search domain
    /// before querying the bare name.
    pub(super) search_domains: Vec<String>,
    /// The `ndots` option from resolv.conf.
    ///
    /// Names with at least this many dots are tried as absolute first.
    /// `None` means use the default (1).
    /// See <https://man7.org/linux/man-pages/man5/resolv.conf.5.html>.
    pub(super) ndots: Option<usize>,
}

/// Parse system DNS configuration.
///
/// Reads the nameservers using the platform-specific reader and falls back to
/// Google DNS if parsing fails or no servers are found.
pub(super) fn system_config() -> SystemDnsConfig {
    match read_system_dns() {
        Ok(config) if !config.nameservers.is_empty() => config,
        _ => SystemDnsConfig {
            nameservers: fallback_nameservers(),
            search_domains: Vec::new(),
            ndots: None,
        },
    }
}

/// Google DNS fallback nameservers.
pub(super) fn fallback_nameservers() -> Vec<(SocketAddr, DnsProtocol)> {
    vec![
        (
            SocketAddr::new(IpAddr::V4(GOOGLE_DNS_IPV4_PRIMARY), DNS_PORT),
            DnsProtocol::Udp,
        ),
        (
            SocketAddr::new(IpAddr::V4(GOOGLE_DNS_IPV4_SECONDARY), DNS_PORT),
            DnsProtocol::Udp,
        ),
        (
            SocketAddr::new(IpAddr::V6(GOOGLE_DNS_IPV6_PRIMARY), DNS_PORT),
            DnsProtocol::Udp,
        ),
        (
            SocketAddr::new(IpAddr::V6(GOOGLE_DNS_IPV6_SECONDARY), DNS_PORT),
            DnsProtocol::Udp,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_nameservers_are_google_dns() {
        let servers = fallback_nameservers();
        assert_eq!(servers.len(), 4);
        assert!(servers.iter().all(|(_, p)| *p == DnsProtocol::Udp));
        assert!(servers.iter().all(|(a, _)| a.port() == DNS_PORT));
        assert_eq!(servers.iter().filter(|(a, _)| a.ip().is_ipv4()).count(), 2);
        assert_eq!(servers.iter().filter(|(a, _)| a.ip().is_ipv6()).count(), 2);
    }
}

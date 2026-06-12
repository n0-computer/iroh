//! DNS configuration: nameservers and resolv.conf options.
//!
//! Reading the system DNS configuration is platform-specific: `/etc/resolv.conf`
//! on Unix, the network adapters on Windows, and a JNI call on Android. The
//! per-platform readers live in the `unix`, `windows`, and `android` submodules;
//! this module holds the shared [`DnsConfig`] type, the dispatch, and the
//! public-resolver fallback.

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

/// Standard DNS port (Do53). DoH fallbacks use the HTTPS port instead.
const DNS_PORT: u16 = 53;
/// HTTPS port, used for the DNS-over-HTTPS fallback nameservers.
#[cfg(with_crypto_provider)]
const HTTPS_PORT: u16 = 443;

// Public DNS providers used for the last-resort fallback. Each provider's
// certificate covers its anycast IPs, so the same IPs work for DNS-over-HTTPS
// addressed by IP (see transport::https_query).
const CLOUDFLARE_V4_PRIMARY: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const CLOUDFLARE_V4_SECONDARY: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 1);
const CLOUDFLARE_V6_PRIMARY: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
const CLOUDFLARE_V6_SECONDARY: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001);
const GOOGLE_V4_PRIMARY: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const GOOGLE_V4_SECONDARY: Ipv4Addr = Ipv4Addr::new(8, 8, 4, 4);
const GOOGLE_V6_PRIMARY: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
const GOOGLE_V6_SECONDARY: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844);
const QUAD9_V4_PRIMARY: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
const QUAD9_V4_SECONDARY: Ipv4Addr = Ipv4Addr::new(149, 112, 112, 112);
const QUAD9_V6_PRIMARY: Ipv6Addr = Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe);
const QUAD9_V6_SECONDARY: Ipv6Addr = Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009);

/// Parsed DNS configuration: the nameservers to query and resolv.conf options.
#[derive(Debug, Clone, Default)]
pub(super) struct DnsConfig {
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

impl DnsConfig {
    /// Reads the system DNS configuration using the platform-specific reader.
    pub(super) fn system() -> Result<Self, std::io::Error> {
        read_system_dns()
    }

    /// The public-resolver fallback configuration (Cloudflare, Google, Quad9).
    pub(super) fn fallback() -> Self {
        Self::from_nameservers(fallback_nameservers())
    }

    /// Builds a config from an explicit nameserver list, with no search domains
    /// and the default `ndots`.
    pub(super) fn from_nameservers(nameservers: Vec<(SocketAddr, DnsProtocol)>) -> Self {
        Self {
            nameservers,
            search_domains: Vec::new(),
            ndots: None,
        }
    }

    /// Reads the system configuration, falling back to public resolvers if it
    /// fails or yields no nameservers.
    pub(super) fn system_with_fallback() -> Self {
        match Self::system() {
            Ok(config) if !config.nameservers.is_empty() => config,
            _ => Self::fallback(),
        }
    }
}

/// Public resolvers used as a last resort when no nameservers are configured.
///
/// Spans multiple providers (Cloudflare, Google, Quad9) and transports so that
/// resolution still works when one provider is down or plain DNS is blocked.
/// The DNS-over-HTTPS entries (when a crypto provider is available) traverse
/// networks that filter port 53. The resolver tracks per-server RTT, so the
/// servers that actually work on the current network float to the front.
fn fallback_nameservers() -> Vec<(SocketAddr, DnsProtocol)> {
    let udp = |ip: IpAddr| (SocketAddr::new(ip, DNS_PORT), DnsProtocol::Udp);
    #[cfg_attr(not(with_crypto_provider), allow(unused_mut))]
    let mut servers = vec![
        udp(IpAddr::V4(CLOUDFLARE_V4_PRIMARY)),
        udp(IpAddr::V4(GOOGLE_V4_PRIMARY)),
        udp(IpAddr::V4(QUAD9_V4_PRIMARY)),
        udp(IpAddr::V6(CLOUDFLARE_V6_PRIMARY)),
        udp(IpAddr::V6(GOOGLE_V6_PRIMARY)),
        udp(IpAddr::V6(QUAD9_V6_PRIMARY)),
        udp(IpAddr::V4(CLOUDFLARE_V4_SECONDARY)),
        udp(IpAddr::V4(GOOGLE_V4_SECONDARY)),
        udp(IpAddr::V4(QUAD9_V4_SECONDARY)),
        udp(IpAddr::V6(CLOUDFLARE_V6_SECONDARY)),
        udp(IpAddr::V6(GOOGLE_V6_SECONDARY)),
        udp(IpAddr::V6(QUAD9_V6_SECONDARY)),
    ];
    #[cfg(with_crypto_provider)]
    {
        let doh = |ip: IpAddr| (SocketAddr::new(ip, HTTPS_PORT), DnsProtocol::Https);
        servers.extend([
            doh(IpAddr::V4(CLOUDFLARE_V4_PRIMARY)),
            doh(IpAddr::V4(GOOGLE_V4_PRIMARY)),
            doh(IpAddr::V4(QUAD9_V4_PRIMARY)),
        ]);
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_nameservers_span_providers_and_families() {
        let servers = fallback_nameservers();
        assert!(servers.len() >= 6);
        // Both address families are represented.
        assert!(servers.iter().any(|(a, _)| a.ip().is_ipv4()));
        assert!(servers.iter().any(|(a, _)| a.ip().is_ipv6()));
        // UDP entries use the standard DNS port.
        assert!(
            servers
                .iter()
                .filter(|(_, p)| *p == DnsProtocol::Udp)
                .all(|(a, _)| a.port() == DNS_PORT)
        );
        // Cloudflare, Google and Quad9 are all present.
        let ips: Vec<IpAddr> = servers.iter().map(|(a, _)| a.ip()).collect();
        assert!(ips.contains(&IpAddr::V4(CLOUDFLARE_V4_PRIMARY)));
        assert!(ips.contains(&IpAddr::V4(GOOGLE_V4_PRIMARY)));
        assert!(ips.contains(&IpAddr::V4(QUAD9_V4_PRIMARY)));
    }
}

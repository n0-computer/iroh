use std::net::{IpAddr, Ipv6Addr};

use anyhow::Result;
use hickory_resolver::{Resolver, TokioResolver};
use once_cell::sync::Lazy;

/// The DNS resolver type used throughout `iroh`.
pub(crate) type DnsResolver = TokioResolver;

static DNS_RESOLVER: Lazy<TokioResolver> =
    Lazy::new(|| create_default_resolver().expect("unable to create DNS resolver"));

/// Get a reference to the default DNS resolver.
///
/// The default resolver can be cheaply cloned and is shared throughout the running process.
/// It is configured to use the system's DNS configuration.
pub fn default_resolver() -> &'static DnsResolver {
    &DNS_RESOLVER
}

/// Deprecated IPv6 site-local anycast addresses still configured by windows.
///
/// Windows still configures these site-local addresses as soon even as an IPv6 loopback
/// interface is configured.  We do not want to use these DNS servers, the chances of them
/// being usable are almost always close to zero, while the chance of DNS configuration
/// **only** relying on these servers and not also being configured normally are also almost
/// zero.  The chance of the DNS resolver accidentally trying one of these and taking a
/// bunch of timeouts to figure out they're no good are on the other hand very high.
const WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS: [IpAddr; 3] = [
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3)),
];

/// Get resolver to query MX records.
///
/// We first try to read the system's resolver from `/etc/resolv.conf`.
/// This does not work at least on some Androids, therefore we fallback
/// to the default `ResolverConfig` which uses eg. to google's `8.8.8.8` or `8.8.4.4`.
fn create_default_resolver() -> Result<TokioResolver> {
    let (system_config, mut options) =
        hickory_resolver::system_conf::read_system_conf().unwrap_or_default();

    // Copy all of the system config, but strip the bad windows nameservers.  Unfortunately
    // there is no easy way to do this.
    let mut config = hickory_resolver::config::ResolverConfig::new();
    if let Some(name) = system_config.domain() {
        config.set_domain(name.clone());
    }
    for name in system_config.search() {
        config.add_search(name.clone());
    }
    for nameserver_cfg in system_config.name_servers() {
        if !WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS.contains(&nameserver_cfg.socket_addr.ip()) {
            config.add_name_server(nameserver_cfg.clone());
        }
    }

    // see [`ResolverExt::lookup_ipv4_ipv6`] for info on why we avoid `LookupIpStrategy::Ipv4AndIpv6`
    options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6;

    let resolver = Resolver::tokio(config, options);
    Ok(resolver)
}

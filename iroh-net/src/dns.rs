//! This module exports a DNS resolver, which is also the default resolver used in the
//! [`crate::Endpoint`] if no custom resolver is configured.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use anyhow::Result;
use futures_lite::Future;
use hickory_resolver::{AsyncResolver, IntoName, TokioAsyncResolver};
use once_cell::sync::Lazy;

pub mod node_info;

/// The DNS resolver type used throughout `iroh-net`.
pub type DnsResolver = TokioAsyncResolver;

static DNS_RESOLVER: Lazy<TokioAsyncResolver> =
    Lazy::new(|| create_default_resolver().expect("unable to create DNS resolver"));

/// Get a reference to the default DNS resolver.
///
/// The default resolver can be cheaply cloned and is shared throughout the running process.
/// It is configured to use the system's DNS configuration.
pub fn default_resolver() -> &'static DnsResolver {
    &DNS_RESOLVER
}

/// Get the DNS resolver used within iroh-net.
pub fn resolver() -> &'static TokioAsyncResolver {
    Lazy::force(&DNS_RESOLVER)
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
fn create_default_resolver() -> Result<TokioAsyncResolver> {
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

    let resolver = AsyncResolver::tokio(config, options);
    Ok(resolver)
}

/// Extension trait to [`DnsResolver`].
pub trait ResolverExt {
    /// Perform an ipv4 lookup with a timeout.
    fn lookup_ipv4<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Perform an ipv6 lookup with a timeout.
    fn lookup_ipv6<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Race an ipv4 and ipv6 lookup with a timeout.
    fn lookup_ipv4_ipv6<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;
}

impl ResolverExt for DnsResolver {
    async fn lookup_ipv4<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let addrs = tokio::time::timeout(timeout, self.ipv4_lookup(host)).await??;
        Ok(addrs.into_iter().map(|ip| IpAddr::V4(ip.0)))
    }

    async fn lookup_ipv6<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let addrs = tokio::time::timeout(timeout, self.ipv6_lookup(host)).await??;
        Ok(addrs.into_iter().map(|ip| IpAddr::V6(ip.0)))
    }

    /// Resolve IPv4 and IPv6 in parallel.
    ///
    /// `LookupIpStrategy::Ipv4AndIpv6` will wait for ipv6 resolution timeout, even if it is
    /// not usable on the stack, so we manually query both lookups concurrently and time them out
    /// individually.
    async fn lookup_ipv4_ipv6<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let res = tokio::join!(
            self.lookup_ipv4(host.clone(), timeout),
            self.lookup_ipv6(host, timeout)
        );

        match res {
            (Ok(ipv4), Ok(ipv6)) => Ok(LookupIter::Both(ipv4.chain(ipv6))),
            (Ok(ipv4), Err(_)) => Ok(LookupIter::Ipv4(ipv4)),
            (Err(_), Ok(ipv6)) => Ok(LookupIter::Ipv6(ipv6)),
            (Err(ipv4_err), Err(ipv6_err)) => {
                anyhow::bail!("Ipv4: {:?}, Ipv6: {:?}", ipv4_err, ipv6_err)
            }
        }
    }
}

/// Helper enum to give a unified type to the iterators of [`ResolverExt::lookup_ipv4_ipv6`]
enum LookupIter<A, B> {
    Ipv4(A),
    Ipv6(B),
    Both(std::iter::Chain<A, B>),
}

impl<A: Iterator<Item = IpAddr>, B: Iterator<Item = IpAddr>> Iterator for LookupIter<A, B> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            LookupIter::Ipv4(iter) => iter.next(),
            LookupIter::Ipv6(iter) => iter.next(),
            LookupIter::Both(iter) => iter.next(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::defaults::NA_RELAY_HOSTNAME;

    use super::*;

    #[tokio::test]
    #[cfg_attr(target_os = "windows", ignore = "flaky")]
    async fn test_dns_lookup_basic() {
        let _logging = iroh_test::logging::setup();
        let resolver = default_resolver();
        let res = resolver.lookup_ip(NA_RELAY_HOSTNAME).await.unwrap();
        let res: Vec<_> = res.iter().collect();
        assert!(!res.is_empty());
        dbg!(res);
    }

    #[tokio::test]
    #[cfg_attr(target_os = "windows", ignore = "flaky")]
    async fn test_dns_lookup_ipv4_ipv6() {
        let _logging = iroh_test::logging::setup();
        let resolver = default_resolver();
        let res: Vec<_> = resolver
            .lookup_ipv4_ipv6(NA_RELAY_HOSTNAME, Duration::from_secs(5))
            .await
            .unwrap()
            .collect();
        assert!(!res.is_empty());
        dbg!(res);
    }
}

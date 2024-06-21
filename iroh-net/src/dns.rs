//! This module exports a DNS resolver, which is also the default resolver used in the
//! [`crate::Endpoint`] if no custom resolver is configured.
//!
//! It also exports [`ResolverExt`]: A extension trait over [`DnsResolver`] to perform DNS queries
//! by ipv4, ipv6, name and node_id. See the [`node_info`] module documentation for details on how
//! iroh node records are structured.

use std::fmt::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use anyhow::Result;
use futures_lite::{Future, StreamExt};
use hickory_resolver::{AsyncResolver, IntoName, TokioAsyncResolver};
use iroh_base::key::NodeId;
use iroh_base::node_addr::NodeAddr;
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
    fn lookup_ipv4<N: IntoName>(
        &self,
        host: N,
        timeout: Duration,
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Perform an ipv6 lookup with a timeout.
    fn lookup_ipv6<N: IntoName>(
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

    /// Looks up node info by DNS name.
    fn lookup_by_name(&self, name: &str) -> impl Future<Output = Result<NodeAddr>>;

    /// Looks up node info by [`NodeId`] and origin domain name.
    fn lookup_by_id(
        &self,
        node_id: &NodeId,
        origin: &str,
    ) -> impl Future<Output = Result<NodeAddr>>;

    /// Perform an ipv4 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied to each call individually. The
    /// result of the first successful call is returned, or a summary of all errors otherwise.
    fn lookup_ipv4_staggered<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
        delays_ms: &[u64],
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Perform an ipv6 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied to each call individually. The
    /// result of the first successful call is returned, or a summary of all errors otherwise.
    fn lookup_ipv6_staggered<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
        delays_ms: &[u64],
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Race an ipv4 and ipv6 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied as stated in
    /// [`Self::lookup_ipv4_ipv6`]. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    fn lookup_ipv4_ipv6_staggered<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
        delays_ms: &[u64],
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Looks up node info by DNS name in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    fn lookup_by_name_staggered(
        &self,
        name: &str,
        delays_ms: &[u64],
    ) -> impl Future<Output = Result<NodeAddr>>;

    /// Looks up node info by [`NodeId`] and origin domain name.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    fn lookup_by_id_staggered(
        &self,
        node_id: &NodeId,
        origin: &str,
        delays_ms: &[u64],
    ) -> impl Future<Output = Result<NodeAddr>>;
}

impl ResolverExt for DnsResolver {
    async fn lookup_ipv4<N: IntoName>(
        &self,
        host: N,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let addrs = tokio::time::timeout(timeout, self.ipv4_lookup(host)).await??;
        Ok(addrs.into_iter().map(|ip| IpAddr::V4(ip.0)))
    }

    async fn lookup_ipv6<N: IntoName>(
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

    /// Looks up node info by DNS name.
    ///
    /// The resource records returned for `name` must either contain an [`node_info::IROH_TXT_NAME`] TXT
    /// record or be a CNAME record that leads to an [`node_info::IROH_TXT_NAME`] TXT record.
    async fn lookup_by_name(&self, name: &str) -> Result<NodeAddr> {
        let attrs = node_info::TxtAttrs::<node_info::IrohAttr>::lookup_by_name(self, name).await?;
        let info: node_info::NodeInfo = attrs.into();
        Ok(info.into())
    }

    /// Looks up node info by [`NodeId`] and origin domain name.
    async fn lookup_by_id(&self, node_id: &NodeId, origin: &str) -> Result<NodeAddr> {
        let attrs =
            node_info::TxtAttrs::<node_info::IrohAttr>::lookup_by_id(self, node_id, origin).await?;
        let info: node_info::NodeInfo = attrs.into();
        Ok(info.into())
    }

    /// Perform an ipv4 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied to each call individually. The
    /// result of the first successful call is returned, or a summary of all errors otherwise.
    async fn lookup_ipv4_staggered<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
        delays_ms: &[u64],
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let f = || self.lookup_ipv4(host.clone(), timeout);
        stagger_call(f, delays_ms).await
    }

    /// Perform an ipv6 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied to each call individually. The
    /// result of the first successful call is returned, or a summary of all errors otherwise.
    async fn lookup_ipv6_staggered<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
        delays_ms: &[u64],
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let f = || self.lookup_ipv6(host.clone(), timeout);
        stagger_call(f, delays_ms).await
    }

    /// Race an ipv4 and ipv6 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied as stated in
    /// [`Self::lookup_ipv4_ipv6`]. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    async fn lookup_ipv4_ipv6_staggered<N: IntoName + Clone>(
        &self,
        host: N,
        timeout: Duration,
        delays_ms: &[u64],
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let f = || self.lookup_ipv4_ipv6(host.clone(), timeout);
        stagger_call(f, delays_ms).await
    }

    /// Looks up node info by DNS name in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    async fn lookup_by_name_staggered(&self, name: &str, delays_ms: &[u64]) -> Result<NodeAddr> {
        let f = || self.lookup_by_name(name);
        stagger_call(f, delays_ms).await
    }

    /// Looks up node info by [`NodeId`] and origin domain name.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    async fn lookup_by_id_staggered(
        &self,
        node_id: &NodeId,
        origin: &str,
        delays_ms: &[u64],
    ) -> Result<NodeAddr> {
        let f = || self.lookup_by_id(node_id, origin);
        stagger_call(f, delays_ms).await
    }
}

/// Helper enum to give a unified type to the iterators of [`ResolverExt::lookup_ipv4_ipv6`].
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

/// Staggers calls to the future F with the given delays.
///
/// The first call is performed immediately. The first call to succeed generates an Ok result
/// ignoring any previous error. If all calls fail, an error sumarizing all errors is returned.
async fn stagger_call<T, F: Fn() -> Fut, Fut: Future<Output = Result<T>>>(
    f: F,
    delays_ms: &[u64],
) -> Result<T> {
    let mut calls = futures_buffered::FuturesUnorderedBounded::new(delays_ms.len() + 1);
    // NOTE: we add the 0 delay here to have a uniform set of futures. This is more performant than
    // using alternatives that allow futures of different types.
    for delay in std::iter::once(&0u64).chain(delays_ms) {
        let delay = std::time::Duration::from_millis(*delay);
        let fut = f();
        let staggered_fut = async move {
            tokio::time::sleep(delay).await;
            fut.await
        };
        calls.push(staggered_fut)
    }

    let mut errors = vec![];
    while let Some(call_result) = calls.next().await {
        match call_result {
            Ok(t) => return Ok(t),
            Err(e) => errors.push(e),
        }
    }

    anyhow::bail!(
        "no calls succeed: [ {}]",
        errors.into_iter().fold(String::new(), |mut summary, e| {
            write!(summary, "{e} ").expect("infallible");
            summary
        })
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::AtomicUsize;

    use crate::defaults::NA_RELAY_HOSTNAME;

    use super::*;
    const TIMEOUT: Duration = Duration::from_secs(5);
    const STAGGERING_DELAYS: &[u64] = &[200, 300];

    #[tokio::test]
    async fn test_dns_lookup_ipv4_ipv6() {
        let _logging = iroh_test::logging::setup();
        let resolver = default_resolver();
        let res: Vec<_> = resolver
            .lookup_ipv4_ipv6_staggered(NA_RELAY_HOSTNAME, TIMEOUT, STAGGERING_DELAYS)
            .await
            .unwrap()
            .collect();
        assert!(!res.is_empty());
        dbg!(res);
    }

    #[tokio::test]
    async fn stagger_basic() {
        let _logging = iroh_test::logging::setup();
        const CALL_RESULTS: &[Result<u8, u8>] = &[Err(2), Ok(3), Ok(5), Ok(7)];
        static DONE_CALL: AtomicUsize = AtomicUsize::new(0);
        let f = || {
            let r_pos = DONE_CALL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            async move {
                tracing::info!(r_pos, "call");
                CALL_RESULTS[r_pos].map_err(|e| anyhow::anyhow!("{e}"))
            }
        };

        let delays = [1000, 15];
        let result = stagger_call(f, &delays).await.unwrap();
        assert_eq!(result, 5)
    }
}

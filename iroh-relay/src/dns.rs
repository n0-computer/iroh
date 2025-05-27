//! DNS resolver

use std::{
    fmt::{self, Write},
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use hickory_resolver::{name_server::TokioConnectionProvider, TokioResolver};
use iroh_base::NodeId;
use n0_future::{
    boxed::BoxFuture,
    time::{self, Duration},
    StreamExt,
};
use url::Url;

use crate::{
    defaults::timeouts::DNS_TIMEOUT,
    node_info::{self, NodeInfo},
};

/// The n0 testing DNS node origin, for production.
pub const N0_DNS_NODE_ORIGIN_PROD: &str = "dns.iroh.link";
/// The n0 testing DNS node origin, for testing.
pub const N0_DNS_NODE_ORIGIN_STAGING: &str = "staging-dns.iroh.link";

/// Trait for DNS resolvers used in iroh.
pub trait Resolver: fmt::Debug + Send + Sync + 'static {
    /// Looks up an IPv4 address.
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>>>;

    /// Looks up an IPv6 address.
    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>>>;

    /// Looks up TXT records.
    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecord>>>;

    /// Clears the internal cache.
    fn clear_cache(&self);
}

/// Boxed iterator alias.
pub type BoxIter<T> = Box<dyn Iterator<Item = T> + Send + 'static>;

/// DNS resolver for use in iroh.
///
/// This internally contains a [`dyn Resolver`]. See the public methods for how to construct
/// a [`DnsResolver`] with sensible defaults or with a custom resolver.
#[derive(Debug, Clone)]
pub struct DnsResolver(Arc<dyn Resolver>);

impl std::ops::Deref for DnsResolver {
    type Target = dyn Resolver;
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new_with_system_defaults()
    }
}

impl DnsResolver {
    /// Creates a new [`DnsResolver`] from a struct that implements [`Resolver`].
    ///
    /// [`Resolver`] is implemented for [`hickory_resolver::TokioResolver`], so you can construct
    /// a [`TokioResolver`] and pass that to this function.
    ///
    /// To use a different DNS resolver, you need to implement [`Resolver`] for your custom resolver
    /// and then pass to this function.
    pub fn new(resolver: impl Resolver) -> Self {
        Self(Arc::new(resolver))
    }

    /// Creates a new DNS resolver with sensible cross-platform defaults.
    ///
    /// We first try to read the system's resolver from `/etc/resolv.conf`.
    /// This does not work at least on some Androids, therefore we fallback
    /// to the default `ResolverConfig` which uses Google's `8.8.8.8` or `8.8.4.4`.
    pub fn new_with_system_defaults() -> Self {
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

        // see [`DnsResolver::lookup_ipv4_ipv6`] for info on why we avoid `LookupIpStrategy::Ipv4AndIpv6`
        options.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6;

        let mut builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        *builder.options_mut() = options;
        Self::new(builder.build())
    }

    /// Creates a new DNS resolver configured with a single UDP DNS nameserver.
    pub fn with_nameserver(nameserver: SocketAddr) -> Self {
        let mut config = hickory_resolver::config::ResolverConfig::new();
        let nameserver_config = hickory_resolver::config::NameServerConfig::new(
            nameserver,
            hickory_resolver::proto::xfer::Protocol::Udp,
        );
        config.add_name_server(nameserver_config);

        let builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        Self::new(builder.build())
    }

    /// Performs a TXT lookup with a timeout.
    pub async fn lookup_txt(
        &self,
        host: impl ToString,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = TxtRecord>> {
        let res = time::timeout(timeout, self.0.lookup_txt(host.to_string())).await??;
        Ok(res)
    }

    /// Performs an IPv4 lookup with a timeout.
    pub async fn lookup_ipv4(
        &self,
        host: impl ToString,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let addrs = time::timeout(timeout, self.0.lookup_ipv4(host.to_string())).await??;
        Ok(addrs.map(IpAddr::V4))
    }

    /// Performs an IPv6 lookup with a timeout.
    pub async fn lookup_ipv6(
        &self,
        host: impl ToString,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let addrs = time::timeout(timeout, self.0.lookup_ipv6(host.to_string())).await??;
        Ok(addrs.map(IpAddr::V6))
    }

    /// Resolves IPv4 and IPv6 in parallel with a timeout.
    ///
    /// `LookupIpStrategy::Ipv4AndIpv6` will wait for ipv6 resolution timeout, even if it is
    /// not usable on the stack, so we manually query both lookups concurrently and time them out
    /// individually.
    pub async fn lookup_ipv4_ipv6(
        &self,
        host: impl ToString,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let host = host.to_string();
        let res = tokio::join!(
            self.lookup_ipv4(host.clone(), timeout),
            self.lookup_ipv6(host, timeout)
        );

        match res {
            (Ok(ipv4), Ok(ipv6)) => Ok(LookupIter::Both(ipv4.chain(ipv6))),
            (Ok(ipv4), Err(_)) => Ok(LookupIter::Ipv4(ipv4)),
            (Err(_), Ok(ipv6)) => Ok(LookupIter::Ipv6(ipv6)),
            (Err(ipv4_err), Err(ipv6_err)) => {
                bail!("Ipv4: {:?}, Ipv6: {:?}", ipv4_err, ipv6_err)
            }
        }
    }

    /// Resolves a hostname from a URL to an IP address.
    pub async fn resolve_host(
        &self,
        url: &Url,
        prefer_ipv6: bool,
        timeout: Duration,
    ) -> Result<IpAddr> {
        let host = url.host().context("Invalid URL")?;
        match host {
            url::Host::Domain(domain) => {
                // Need to do a DNS lookup
                let lookup = tokio::join!(
                    self.lookup_ipv4(domain, timeout),
                    self.lookup_ipv6(domain, timeout)
                );
                let (v4, v6) = match lookup {
                    (Err(ipv4_err), Err(ipv6_err)) => {
                        bail!("Ipv4: {ipv4_err:?}, Ipv6: {ipv6_err:?}");
                    }
                    (Err(_), Ok(mut v6)) => (None, v6.next()),
                    (Ok(mut v4), Err(_)) => (v4.next(), None),
                    (Ok(mut v4), Ok(mut v6)) => (v4.next(), v6.next()),
                };
                if prefer_ipv6 { v6.or(v4) } else { v4.or(v6) }.context("No response")
            }
            url::Host::Ipv4(ip) => Ok(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Ok(IpAddr::V6(ip)),
        }
    }

    /// Performs an IPv4 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied to each call individually. The
    /// result of the first successful call is returned, or a summary of all errors otherwise.
    pub async fn lookup_ipv4_staggered(
        &self,
        host: impl ToString,
        timeout: Duration,
        delays_ms: &[u64],
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let host = host.to_string();
        let f = || self.lookup_ipv4(host.clone(), timeout);
        stagger_call(f, delays_ms).await
    }

    /// Performs an IPv6 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied to each call individually. The
    /// result of the first successful call is returned, or a summary of all errors otherwise.
    pub async fn lookup_ipv6_staggered(
        &self,
        host: impl ToString,
        timeout: Duration,
        delays_ms: &[u64],
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let host = host.to_string();
        let f = || self.lookup_ipv6(host.clone(), timeout);
        stagger_call(f, delays_ms).await
    }

    /// Races an IPv4 and IPv6 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied as stated in
    /// [`Self::lookup_ipv4_ipv6`]. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    pub async fn lookup_ipv4_ipv6_staggered(
        &self,
        host: impl ToString,
        timeout: Duration,
        delays_ms: &[u64],
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let host = host.to_string();
        let f = || self.lookup_ipv4_ipv6(host.clone(), timeout);
        stagger_call(f, delays_ms).await
    }

    /// Looks up node info by [`NodeId`] and origin domain name.
    ///
    /// To lookup nodes that published their node info to the DNS servers run by n0,
    /// pass [`N0_DNS_NODE_ORIGIN_PROD`] as `origin`.
    pub async fn lookup_node_by_id(&self, node_id: &NodeId, origin: &str) -> Result<NodeInfo> {
        let name = node_info::node_domain(node_id, origin);
        let name = node_info::ensure_iroh_txt_label(name);
        let lookup = self.lookup_txt(name.clone(), DNS_TIMEOUT).await?;
        let attrs = node_info::TxtAttrs::from_txt_lookup(name, lookup)?;
        Ok(attrs.into())
    }

    /// Looks up node info by DNS name.
    pub async fn lookup_node_by_domain_name(&self, name: &str) -> Result<NodeInfo> {
        let name = node_info::ensure_iroh_txt_label(name.to_string());
        let lookup = self.lookup_txt(name.clone(), DNS_TIMEOUT).await?;
        let attrs = node_info::TxtAttrs::from_txt_lookup(name, lookup)?;
        Ok(attrs.into())
    }

    /// Looks up node info by DNS name in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    pub async fn lookup_node_by_domain_name_staggered(
        &self,
        name: &str,
        delays_ms: &[u64],
    ) -> Result<NodeInfo> {
        let f = || self.lookup_node_by_domain_name(name);
        stagger_call(f, delays_ms).await
    }

    /// Looks up node info by [`NodeId`] and origin domain name.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    pub async fn lookup_node_by_id_staggered(
        &self,
        node_id: &NodeId,
        origin: &str,
        delays_ms: &[u64],
    ) -> Result<NodeInfo> {
        let f = || self.lookup_node_by_id(node_id, origin);
        stagger_call(f, delays_ms).await
    }
}

/// Implementation of [`Resolver`] for [`hickory_resolver::TokioResolver`].
impl Resolver for TokioResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>>> {
        let this = self.clone();
        Box::pin(async move {
            let addrs = this.ipv4_lookup(host).await?;
            let iter: BoxIter<Ipv4Addr> = Box::new(addrs.into_iter().map(Ipv4Addr::from));
            Ok(iter)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>>> {
        let this = self.clone();
        Box::pin(async move {
            let addrs = this.ipv6_lookup(host).await?;
            let iter: BoxIter<Ipv6Addr> = Box::new(addrs.into_iter().map(Ipv6Addr::from));
            Ok(iter)
        })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecord>>> {
        let this = self.clone();
        Box::pin(async move {
            let lookup = this.txt_lookup(host).await?;
            let iter: BoxIter<TxtRecord> = Box::new(
                lookup
                    .into_iter()
                    .map(|txt| TxtRecord::from_iter(txt.iter().cloned())),
            );
            Ok(iter)
        })
    }

    fn clear_cache(&self) {
        self.clear_cache();
    }
}

/// Record data for a TXT record.
///
/// This contains a list of character strings, as defined in [RFC 1035 Section 3.3.14].
///
/// [`TxtRecord`] implements [`fmt::Display`], so you can call [`ToString::to_string`] to
/// convert the record data into a string. This will parse each character string with
/// [`String::from_utf8_lossy`] and then concatenate all strings without a seperator.
///
/// If you want to process each character string individually, use [`Self::iter`].
///
/// [RFC 1035 Section 3.3.14]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14
#[derive(Debug, Clone)]
pub struct TxtRecord(Box<[Box<[u8]>]>);

impl TxtRecord {
    /// Returns an iterator over the character strings contained in this TXT record.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(|x| x.as_ref())
    }
}

impl fmt::Display for TxtRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for s in self.iter() {
            write!(f, "{}", &String::from_utf8_lossy(s))?
        }
        Ok(())
    }
}

impl FromIterator<Box<[u8]>> for TxtRecord {
    fn from_iter<T: IntoIterator<Item = Box<[u8]>>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl From<Vec<Box<[u8]>>> for TxtRecord {
    fn from(value: Vec<Box<[u8]>>) -> Self {
        Self(value.into_boxed_slice())
    }
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

/// Helper enum to give a unified type to the iterators of [`DnsResolver::lookup_ipv4_ipv6`].
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
/// ignoring any previous error. If all calls fail, an error summarizing all errors is returned.
async fn stagger_call<T, F: Fn() -> Fut, Fut: Future<Output = Result<T>>>(
    f: F,
    delays_ms: &[u64],
) -> Result<T> {
    let mut calls = n0_future::FuturesUnorderedBounded::new(delays_ms.len() + 1);
    // NOTE: we add the 0 delay here to have a uniform set of futures. This is more performant than
    // using alternatives that allow futures of different types.
    for delay in std::iter::once(&0u64).chain(delays_ms) {
        let delay = Duration::from_millis(*delay);
        let fut = f();
        let staggered_fut = async move {
            time::sleep(delay).await;
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

    bail!(
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

    use tracing_test::traced_test;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn stagger_basic() {
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

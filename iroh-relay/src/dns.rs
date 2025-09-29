//! DNS resolver

use std::{
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use hickory_resolver::{TokioResolver, name_server::TokioConnectionProvider};
use iroh_base::NodeId;
use n0_future::{
    StreamExt,
    boxed::BoxFuture,
    time::{self, Duration},
};
use nested_enum_utils::common_fields;
use snafu::{Backtrace, GenerateImplicitData, OptionExt, ResultExt, Snafu};
use tokio::sync::RwLock;
use url::Url;

use crate::{
    defaults::timeouts::DNS_TIMEOUT,
    node_info::{self, NodeInfo, ParseError},
};

/// The n0 testing DNS node origin, for production.
pub const N0_DNS_NODE_ORIGIN_PROD: &str = "dns.iroh.link";
/// The n0 testing DNS node origin, for testing.
pub const N0_DNS_NODE_ORIGIN_STAGING: &str = "staging-dns.iroh.link";

/// Percent of total delay to jitter. 20 means +/- 20% of delay.
const MAX_JITTER_PERCENT: u64 = 20;

/// Trait for DNS resolvers used in iroh.
pub trait Resolver: fmt::Debug + Send + Sync + 'static {
    /// Looks up an IPv4 address.
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>>;

    /// Looks up an IPv6 address.
    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>>;

    /// Looks up TXT records.
    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>>;

    /// Clears the internal cache.
    fn clear_cache(&self);

    /// Completely resets the DNS resolver.
    ///
    /// This is called when the host's network changes majorly. Implementations should rebind all sockets
    /// and refresh the nameserver configuration if read from the host system.
    fn reset(&mut self);
}

/// Boxed iterator alias.
pub type BoxIter<T> = Box<dyn Iterator<Item = T> + Send + 'static>;

/// Potential errors related to dns.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(visibility(pub(crate)))]
pub enum DnsError {
    #[snafu(transparent)]
    Timeout { source: tokio::time::error::Elapsed },
    #[snafu(display("No response"))]
    NoResponse {},
    #[snafu(display("Resolve failed ipv4: {ipv4}, ipv6 {ipv6}"))]
    ResolveBoth {
        ipv4: Box<DnsError>,
        ipv6: Box<DnsError>,
    },
    #[snafu(display("missing host"))]
    MissingHost {},
    #[snafu(transparent)]
    Resolve {
        source: hickory_resolver::ResolveError,
    },
    #[snafu(display("invalid DNS response: not a query for _iroh.z32encodedpubkey"))]
    InvalidResponse {},
}

#[cfg(not(wasm_browser))]
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(visibility(pub(crate)))]
pub enum LookupError {
    #[snafu(display("Malformed txt from lookup"))]
    ParseError {
        #[snafu(source(from(ParseError, Box::new)))]
        source: Box<ParseError>,
    },
    #[snafu(display("Failed to resolve TXT record"))]
    LookupFailed {
        #[snafu(source(from(DnsError, Box::new)))]
        source: Box<DnsError>,
    },
}

/// Error returned when an input value is too long for [`crate::node_info::UserData`].
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[snafu(display("no calls succeeded: [{}]", errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("")))]
pub struct StaggeredError<E: std::fmt::Debug + std::fmt::Display> {
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
    errors: Vec<E>,
}

impl<E: std::fmt::Debug + std::fmt::Display> StaggeredError<E> {
    pub(crate) fn new(errors: Vec<E>) -> Self {
        Self {
            errors,
            backtrace: GenerateImplicitData::generate(),
            span_trace: n0_snafu::SpanTrace::generate(),
        }
    }
}

/// The DNS resolver used throughout `iroh`.
#[derive(Debug, Clone)]
pub struct DnsResolver(DnsResolverInner);

impl DnsResolver {
    /// Creates a new DNS resolver with sensible cross-platform defaults.
    ///
    /// We first try to read the system's resolver from `/etc/resolv.conf`.
    /// This does not work at least on some Androids, therefore we fallback
    /// to the default `ResolverConfig` which uses eg. to google's `8.8.8.8` or `8.8.4.4`.
    pub fn new() -> Self {
        let resolver = HickoryResolver::new(HickoryResolverOpts::SystemDefaults);
        Self(DnsResolverInner::Hickory(Arc::new(RwLock::new(resolver))))
    }

    /// Creates a new [`DnsResolver`] from a struct that implements [`Resolver`].
    ///
    /// [`Resolver`] is implemented for [`hickory_resolver::TokioResolver`], so you can construct
    /// a [`TokioResolver`] and pass that to this function.
    ///
    /// To use a different DNS resolver, you need to implement [`Resolver`] for your custom resolver
    /// and then pass to this function.
    pub fn custom(resolver: impl Resolver) -> Self {
        Self(DnsResolverInner::Custom(Arc::new(RwLock::new(resolver))))
    }

    /// Creates a new DNS resolver configured with a single UDP DNS nameserver.
    pub fn with_nameserver(nameserver: SocketAddr) -> Self {
        let resolver = HickoryResolver::new(HickoryResolverOpts::SingleUdpNameserver(nameserver));
        Self(DnsResolverInner::Hickory(Arc::new(RwLock::new(resolver))))
    }

    /// Removes all entries from the cache.
    pub async fn clear_cache(&self) {
        self.0.clear_cache().await
    }

    /// Recreates the inner resolver.
    pub async fn reset(&self) {
        self.0.reset().await
    }

    /// Looks up a TXT record.
    pub async fn lookup_txt<T: ToString>(
        &self,
        host: T,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = TxtRecordData>, DnsError> {
        let host = host.to_string();
        let res = time::timeout(timeout, self.0.lookup_txt(host)).await??;
        Ok(res)
    }

    /// Performs an IPv4 lookup with a timeout.
    pub async fn lookup_ipv4<T: ToString>(
        &self,
        host: T,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr> + use<T>, DnsError> {
        let host = host.to_string();
        let addrs = time::timeout(timeout, self.0.lookup_ipv4(host)).await??;
        Ok(addrs.into_iter().map(IpAddr::V4))
    }

    /// Performs an IPv6 lookup with a timeout.
    pub async fn lookup_ipv6<T: ToString>(
        &self,
        host: T,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr> + use<T>, DnsError> {
        let host = host.to_string();
        let addrs = time::timeout(timeout, self.0.lookup_ipv6(host)).await??;
        Ok(addrs.into_iter().map(IpAddr::V6))
    }

    /// Resolves IPv4 and IPv6 in parallel with a timeout.
    ///
    /// `LookupIpStrategy::Ipv4AndIpv6` will wait for ipv6 resolution timeout, even if it is
    /// not usable on the stack, so we manually query both lookups concurrently and time them out
    /// individually.
    pub async fn lookup_ipv4_ipv6<T: ToString>(
        &self,
        host: T,
        timeout: Duration,
    ) -> Result<impl Iterator<Item = IpAddr> + use<T>, DnsError> {
        let host = host.to_string();
        let res = tokio::join!(
            self.lookup_ipv4(host.clone(), timeout),
            self.lookup_ipv6(host, timeout)
        );

        match res {
            (Ok(ipv4), Ok(ipv6)) => Ok(LookupIter::Both(ipv4.chain(ipv6))),
            (Ok(ipv4), Err(_)) => Ok(LookupIter::Ipv4(ipv4)),
            (Err(_), Ok(ipv6)) => Ok(LookupIter::Ipv6(ipv6)),
            (Err(ipv4_err), Err(ipv6_err)) => Err(ResolveBothSnafu {
                ipv4: Box::new(ipv4_err),
                ipv6: Box::new(ipv6_err),
            }
            .build()),
        }
    }

    /// Resolves a hostname from a URL to an IP address.
    pub async fn resolve_host(
        &self,
        url: &Url,
        prefer_ipv6: bool,
        timeout: Duration,
    ) -> Result<IpAddr, DnsError> {
        let host = url.host().context(MissingHostSnafu)?;
        match host {
            url::Host::Domain(domain) => {
                // Need to do a DNS lookup
                let lookup = tokio::join!(
                    self.lookup_ipv4(domain, timeout),
                    self.lookup_ipv6(domain, timeout)
                );
                let (v4, v6) = match lookup {
                    (Err(ipv4_err), Err(ipv6_err)) => {
                        return Err(ResolveBothSnafu {
                            ipv4: Box::new(ipv4_err),
                            ipv6: Box::new(ipv6_err),
                        }
                        .build());
                    }
                    (Err(_), Ok(mut v6)) => (None, v6.next()),
                    (Ok(mut v4), Err(_)) => (v4.next(), None),
                    (Ok(mut v4), Ok(mut v6)) => (v4.next(), v6.next()),
                };
                if prefer_ipv6 {
                    v6.or(v4).context(NoResponseSnafu)
                } else {
                    v4.or(v6).context(NoResponseSnafu)
                }
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
    ) -> Result<impl Iterator<Item = IpAddr>, StaggeredError<DnsError>> {
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
    ) -> Result<impl Iterator<Item = IpAddr>, StaggeredError<DnsError>> {
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
    ) -> Result<impl Iterator<Item = IpAddr>, StaggeredError<DnsError>> {
        let host = host.to_string();
        let f = || self.lookup_ipv4_ipv6(host.clone(), timeout);
        stagger_call(f, delays_ms).await
    }

    /// Looks up node info by [`NodeId`] and origin domain name.
    ///
    /// To lookup nodes that published their node info to the DNS servers run by n0,
    /// pass [`N0_DNS_NODE_ORIGIN_PROD`] as `origin`.
    pub async fn lookup_node_by_id(
        &self,
        node_id: &NodeId,
        origin: &str,
    ) -> Result<NodeInfo, LookupError> {
        let name = node_info::node_domain(node_id, origin);
        let name = node_info::ensure_iroh_txt_label(name);
        let lookup = self
            .lookup_txt(name.clone(), DNS_TIMEOUT)
            .await
            .context(LookupFailedSnafu)?;
        let info = NodeInfo::from_txt_lookup(name, lookup).context(ParseSnafu)?;
        Ok(info)
    }

    /// Looks up node info by DNS name.
    pub async fn lookup_node_by_domain_name(&self, name: &str) -> Result<NodeInfo, LookupError> {
        let name = node_info::ensure_iroh_txt_label(name.to_string());
        let lookup = self
            .lookup_txt(name.clone(), DNS_TIMEOUT)
            .await
            .context(LookupFailedSnafu)?;
        let info = NodeInfo::from_txt_lookup(name, lookup).context(ParseSnafu)?;
        Ok(info)
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
    ) -> Result<NodeInfo, StaggeredError<LookupError>> {
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
    ) -> Result<NodeInfo, StaggeredError<LookupError>> {
        let f = || self.lookup_node_by_id(node_id, origin);
        stagger_call(f, delays_ms).await
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl reqwest::dns::Resolve for DnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let this = self.clone();
        let name = name.as_str().to_string();
        Box::pin(async move {
            let res = this.lookup_ipv4_ipv6(name, DNS_TIMEOUT).await;
            match res {
                Ok(addrs) => {
                    let addrs: reqwest::dns::Addrs =
                        Box::new(addrs.map(|addr| SocketAddr::new(addr, 0)));
                    Ok(addrs)
                }
                Err(err) => {
                    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(err);
                    Err(err)
                }
            }
        })
    }
}

/// Wrapper enum that contains either a hickory resolver or a custom resolver.
///
/// We do this to save the cost of boxing the futures and iterators when using
/// default hickory resolver.
#[derive(Debug, Clone)]
enum DnsResolverInner {
    Hickory(Arc<RwLock<HickoryResolver>>),
    Custom(Arc<RwLock<dyn Resolver>>),
}

impl DnsResolverInner {
    async fn lookup_ipv4(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv4Addr> + use<>, DnsError> {
        Ok(match self {
            Self::Hickory(resolver) => Either::Left(resolver.read().await.lookup_ipv4(host).await?),
            Self::Custom(resolver) => Either::Right(resolver.read().await.lookup_ipv4(host).await?),
        })
    }

    async fn lookup_ipv6(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv6Addr> + use<>, DnsError> {
        Ok(match self {
            Self::Hickory(resolver) => Either::Left(resolver.read().await.lookup_ipv6(host).await?),
            Self::Custom(resolver) => Either::Right(resolver.read().await.lookup_ipv6(host).await?),
        })
    }

    async fn lookup_txt(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = TxtRecordData> + use<>, DnsError> {
        Ok(match self {
            Self::Hickory(resolver) => Either::Left(resolver.read().await.lookup_txt(host).await?),
            Self::Custom(resolver) => Either::Right(resolver.read().await.lookup_txt(host).await?),
        })
    }

    async fn clear_cache(&self) {
        match self {
            Self::Hickory(resolver) => resolver.read().await.clear_cache(),
            Self::Custom(resolver) => resolver.read().await.clear_cache(),
        }
    }

    async fn reset(&self) {
        match self {
            Self::Hickory(resolver) => resolver.write().await.reset(),
            Self::Custom(resolver) => resolver.write().await.reset(),
        }
    }
}

#[derive(Debug, Clone)]
enum HickoryResolverOpts {
    SystemDefaults,
    SingleUdpNameserver(SocketAddr),
}

#[derive(Debug)]
struct HickoryResolver {
    resolver: TokioResolver,
    opts: HickoryResolverOpts,
}

impl HickoryResolver {
    fn new(opts: HickoryResolverOpts) -> Self {
        let resolver = match opts {
            HickoryResolverOpts::SystemDefaults => Self::with_system_defaults(),
            HickoryResolverOpts::SingleUdpNameserver(addr) => Self::with_single_nameserver(addr),
        };
        Self { resolver, opts }
    }

    fn with_single_nameserver(nameserver: SocketAddr) -> TokioResolver {
        let mut config = hickory_resolver::config::ResolverConfig::new();
        let nameserver_config = hickory_resolver::config::NameServerConfig::new(
            nameserver,
            hickory_resolver::proto::xfer::Protocol::Udp,
        );
        config.add_name_server(nameserver_config);

        let builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        builder.build()
    }

    fn with_system_defaults() -> TokioResolver {
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
        builder.build()
    }

    async fn lookup_ipv4(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv4Addr> + use<>, DnsError> {
        Ok(self
            .resolver
            .ipv4_lookup(host)
            .await?
            .into_iter()
            .map(Ipv4Addr::from))
    }

    /// Looks up an IPv6 address.
    async fn lookup_ipv6(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv6Addr> + use<>, DnsError> {
        Ok(self
            .resolver
            .ipv6_lookup(host)
            .await?
            .into_iter()
            .map(Ipv6Addr::from))
    }

    /// Looks up TXT records.
    async fn lookup_txt(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = TxtRecordData> + use<>, DnsError> {
        Ok(self
            .resolver
            .txt_lookup(host)
            .await?
            .into_iter()
            .map(|txt| TxtRecordData::from_iter(txt.iter().cloned())))
    }

    /// Clears the internal cache.
    fn clear_cache(&self) {
        self.resolver.clear_cache()
    }

    fn reset(&mut self) {
        *self = Self::new(self.opts.clone());
    }
}

/// Record data for a TXT record.
///
/// This contains a list of character strings, as defined in [RFC 1035 Section 3.3.14].
///
/// [`TxtRecordData`] implements [`fmt::Display`], so you can call [`ToString::to_string`] to
/// convert the record data into a string. This will parse each character string with
/// [`String::from_utf8_lossy`] and then concatenate all strings without a separator.
///
/// If you want to process each character string individually, use [`Self::iter`].
///
/// [RFC 1035 Section 3.3.14]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14
#[derive(Debug, Clone)]
pub struct TxtRecordData(Box<[Box<[u8]>]>);

impl TxtRecordData {
    /// Returns an iterator over the character strings contained in this TXT record.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(|x| x.as_ref())
    }
}

impl fmt::Display for TxtRecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for s in self.iter() {
            write!(f, "{}", &String::from_utf8_lossy(s))?
        }
        Ok(())
    }
}

impl FromIterator<Box<[u8]>> for TxtRecordData {
    fn from_iter<T: IntoIterator<Item = Box<[u8]>>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl From<Vec<Box<[u8]>>> for TxtRecordData {
    fn from(value: Vec<Box<[u8]>>) -> Self {
        Self(value.into_boxed_slice())
    }
}

/// Helper enum to give a unified type to either of two iterators
enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<T, A: Iterator<Item = T>, B: Iterator<Item = T>> Iterator for Either<A, B> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Either::Left(iter) => iter.next(),
            Either::Right(iter) => iter.next(),
        }
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
async fn stagger_call<
    T,
    E: std::fmt::Debug + std::fmt::Display,
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
>(
    f: F,
    delays_ms: &[u64],
) -> Result<T, StaggeredError<E>> {
    let mut calls = n0_future::FuturesUnorderedBounded::new(delays_ms.len() + 1);
    // NOTE: we add the 0 delay here to have a uniform set of futures. This is more performant than
    // using alternatives that allow futures of different types.
    for delay in std::iter::once(&0u64).chain(delays_ms) {
        let delay = add_jitter(delay);
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

    Err(StaggeredError::new(errors))
}

fn add_jitter(delay: &u64) -> Duration {
    // If delay is 0, return 0 immediately.
    if *delay == 0 {
        return Duration::ZERO;
    }

    // Calculate jitter as a random value in the range of +/- MAX_JITTER_PERCENT of the delay.
    let max_jitter = delay.saturating_mul(MAX_JITTER_PERCENT * 2) / 100;
    let jitter = rand::random::<u64>() % max_jitter;

    Duration::from_millis(delay.saturating_sub(max_jitter / 2).saturating_add(jitter))
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
                CALL_RESULTS[r_pos].map_err(|_| InvalidResponseSnafu.build())
            }
        };

        let delays = [1000, 15];
        let result = stagger_call(f, &delays).await.unwrap();
        assert_eq!(result, 5)
    }

    #[test]
    #[traced_test]
    fn jitter_test_zero() {
        let jittered_delay = add_jitter(&0);
        assert_eq!(jittered_delay, Duration::from_secs(0));
    }

    //Sanity checks that I did the math right
    #[test]
    #[traced_test]
    fn jitter_test_nonzero_lower_bound() {
        let delay: u64 = 300;
        for _ in 0..100 {
            assert!(add_jitter(&delay) >= Duration::from_millis(delay * 8 / 10));
        }
    }

    #[test]
    #[traced_test]
    fn jitter_test_nonzero_upper_bound() {
        let delay: u64 = 300;
        for _ in 0..100 {
            assert!(add_jitter(&delay) < Duration::from_millis(delay * 12 / 10));
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn custom_resolver() {
        #[derive(Debug)]
        struct MyResolver;
        impl Resolver for MyResolver {
            fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
                Box::pin(async move {
                    let addr = if host == "foo.example" {
                        Ipv4Addr::new(1, 1, 1, 1)
                    } else {
                        return Err(NoResponseSnafu.build());
                    };
                    let iter: BoxIter<Ipv4Addr> = Box::new(vec![addr].into_iter());
                    Ok(iter)
                })
            }

            fn lookup_ipv6(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
                todo!()
            }

            fn lookup_txt(
                &self,
                _host: String,
            ) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
                todo!()
            }

            fn clear_cache(&self) {
                todo!()
            }

            fn reset(&mut self) {
                todo!()
            }
        }

        let resolver = DnsResolver::custom(MyResolver);
        let mut iter = resolver
            .lookup_ipv4("foo.example", Duration::from_secs(1))
            .await
            .expect("not to fail");
        let addr = iter.next().expect("one result");
        assert_eq!(addr, "1.1.1.1".parse::<IpAddr>().unwrap());

        let res = resolver
            .lookup_ipv4("bar.example", Duration::from_secs(1))
            .await;
        assert!(matches!(res, Err(DnsError::NoResponse { .. })))
    }
}

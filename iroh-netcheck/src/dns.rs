use std::fmt::Write;
use std::net::IpAddr;

use anyhow::Result;
use futures_lite::{Future, StreamExt};
use hickory_resolver::{IntoName, TokioAsyncResolver};

use crate::defaults::timeouts::DNS_TIMEOUT;

/// Delay used to perform staggered dns queries.
const DNS_STAGGERING_MS: &[u64] = &[200, 300];

/// Extension trait to [`TokioAsyncResolver`].
pub trait ResolverExt {
    /// Perform an ipv4 lookup with a timeout.
    fn lookup_ipv4<N: IntoName>(
        &self,
        host: N,
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Perform an ipv6 lookup with a timeout.
    fn lookup_ipv6<N: IntoName>(
        &self,
        host: N,
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Race an ipv4 and ipv6 lookup with a timeout.
    fn lookup_ipv4_ipv6<N: IntoName + Clone>(
        &self,
        host: N,
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Perform an ipv4 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied to each call individually. The
    /// result of the first successful call is returned, or a summary of all errors otherwise.
    fn lookup_ipv4_staggered<N: IntoName + Clone>(
        &self,
        host: N,
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
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;

    /// Race an ipv4 and ipv6 lookup with a timeout in a staggered fashion.
    ///
    /// From the moment this function is called, each lookup is scheduled after the delays in
    /// `delays_ms` with the first call being done immediately. `[200ms, 300ms]` results in calls
    /// at T+0ms, T+200ms and T+300ms. The `timeout` is applied as stated in
    /// [`Self::lookup_ipv4_ipv6`]. The result of the first successful call is returned, or a
    /// summary of all errors otherwise.
    // TODO(@divma): adjust docs
    fn lookup_ipv4_ipv6_staggered<N: IntoName + Clone>(
        &self,
        host: N,
    ) -> impl Future<Output = Result<impl Iterator<Item = IpAddr>>>;
}

impl ResolverExt for TokioAsyncResolver {
    async fn lookup_ipv4<N: IntoName>(&self, host: N) -> Result<impl Iterator<Item = IpAddr>> {
        let addrs = tokio::time::timeout(DNS_TIMEOUT, self.ipv4_lookup(host)).await??;
        Ok(addrs.into_iter().map(|ip| IpAddr::V4(ip.0)))
    }

    async fn lookup_ipv6<N: IntoName>(&self, host: N) -> Result<impl Iterator<Item = IpAddr>> {
        let addrs = tokio::time::timeout(DNS_TIMEOUT, self.ipv6_lookup(host)).await??;
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
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let res = tokio::join!(self.lookup_ipv4(host.clone()), self.lookup_ipv6(host));

        match res {
            (Ok(ipv4), Ok(ipv6)) => Ok(LookupIter::Both(ipv4.chain(ipv6))),
            (Ok(ipv4), Err(_)) => Ok(LookupIter::Ipv4(ipv4)),
            (Err(_), Ok(ipv6)) => Ok(LookupIter::Ipv6(ipv6)),
            (Err(ipv4_err), Err(ipv6_err)) => {
                anyhow::bail!("Ipv4: {:?}, Ipv6: {:?}", ipv4_err, ipv6_err)
            }
        }
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
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let f = || self.lookup_ipv4(host.clone());
        stagger_call(f, DNS_STAGGERING_MS).await
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
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let f = || self.lookup_ipv6(host.clone());
        stagger_call(f, DNS_STAGGERING_MS).await
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
    ) -> Result<impl Iterator<Item = IpAddr>> {
        let f = || self.lookup_ipv4_ipv6(host.clone());
        stagger_call(f, DNS_STAGGERING_MS).await
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
/// ignoring any previous error. If all calls fail, an error summarizing all errors is returned.
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
    use std::time::Duration;

    use super::*;
    const TIMEOUT: Duration = Duration::from_secs(5);
    const STAGGERING_DELAYS: &[u64] = &[200, 300];

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

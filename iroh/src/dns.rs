//! This module exports a DNS resolver, which is also the default resolver used in the
//! [`crate::Endpoint`] if no custom resolver is configured.
//!
//! It also exports [`ResolverExt`]: A extension trait over [`DnsResolver`] to perform DNS queries
//! by ipv4, ipv6, name and node_id. See the [`node_info`] module documentation for details on how
//! iroh node records are structured.

use anyhow::Result;
use iroh_base::{NodeAddr, NodeId};
use iroh_relay::dns::stagger_call;
use n0_future::Future;

pub mod node_info;

pub use iroh_relay::dns::DnsResolver;

/// Extension trait to [`DnsResolver`].
pub trait ResolverExt {
    /// Looks up node info by DNS name.
    fn lookup_by_name(&self, name: &str) -> impl Future<Output = Result<NodeAddr>>;

    /// Looks up node info by [`NodeId`] and origin domain name.
    fn lookup_by_id(
        &self,
        node_id: &NodeId,
        origin: &str,
    ) -> impl Future<Output = Result<NodeAddr>>;

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
    async fn lookup_by_name(&self, name: &str) -> Result<NodeAddr> {
        let attrs = node_info::TxtAttrs::<node_info::IrohAttr>::lookup_by_name(self, name).await?;
        let info: node_info::NodeInfo = attrs.into();
        Ok(info.into())
    }

    async fn lookup_by_id(&self, node_id: &NodeId, origin: &str) -> Result<NodeAddr> {
        let attrs =
            node_info::TxtAttrs::<node_info::IrohAttr>::lookup_by_id(self, node_id, origin).await?;
        let info: node_info::NodeInfo = attrs.into();
        Ok(info.into())
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

#[cfg(test)]
pub(crate) mod tests {
    use std::{sync::atomic::AtomicUsize, time::Duration};

    use tracing_test::traced_test;

    use super::*;
    use crate::defaults::staging::NA_RELAY_HOSTNAME;
    const TIMEOUT: Duration = Duration::from_secs(5);
    const STAGGERING_DELAYS: &[u64] = &[200, 300];

    #[tokio::test]
    #[traced_test]
    async fn test_dns_lookup_ipv4_ipv6() {
        let resolver = DnsResolver::new_with_defaults();
        let res: Vec<_> = resolver
            .lookup_ipv4_ipv6_staggered(NA_RELAY_HOSTNAME, TIMEOUT, STAGGERING_DELAYS)
            .await
            .unwrap()
            .collect();
        assert!(!res.is_empty());
        dbg!(res);
    }

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

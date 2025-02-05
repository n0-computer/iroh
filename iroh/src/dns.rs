//! This module exports a DNS resolver, which is also the default resolver used in the
//! [`crate::Endpoint`] if no custom resolver is configured.
//!
//! The resolver provides methods to resolve domain names to ipv4 and ipv6 addresses,
//! and to resolve node ids to node addresses.
//!
//! See the [`node_info`] module documentation for details on how
//! iroh node records are structured.

pub use iroh_relay::dns::{node_info, DnsResolver};

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use tracing_test::traced_test;

    use super::DnsResolver;
    use crate::defaults::staging::NA_RELAY_HOSTNAME;

    const TIMEOUT: Duration = Duration::from_secs(5);
    const STAGGERING_DELAYS: &[u64] = &[200, 300];

    #[tokio::test]
    #[traced_test]
    async fn test_dns_lookup_ipv4_ipv6() {
        let resolver = DnsResolver::new();
        let res: Vec<_> = resolver
            .lookup_ipv4_ipv6_staggered(NA_RELAY_HOSTNAME, TIMEOUT, STAGGERING_DELAYS)
            .await
            .unwrap()
            .collect();
        assert!(!res.is_empty());
        dbg!(res);
    }
}

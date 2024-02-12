use anyhow::Result;
use once_cell::sync::Lazy;
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};

pub static DNS_RESOLVER: Lazy<TokioAsyncResolver> =
    Lazy::new(|| get_resolver().expect("unable to create DNS resolver"));

/// Get resolver to query MX records.
///
/// We first try to read the system's resolver from `/etc/resolv.conf`.
/// This does not work at least on some Androids, therefore we fallback
/// to the default `ResolverConfig` which uses eg. to google's `8.8.8.8` or `8.8.4.4`.
fn get_resolver() -> Result<TokioAsyncResolver> {
    let (config, mut options) =
        trust_dns_resolver::system_conf::read_system_conf().unwrap_or_default();
    // lookup IPv4 and IPv6 in parallel
    options.ip_strategy = trust_dns_resolver::config::LookupIpStrategy::Ipv4AndIpv6;

    let resolver = AsyncResolver::tokio(config, options);
    Ok(resolver)
}

#[cfg(test)]
mod tests {
    use crate::defaults::NA_DERP_HOSTNAME;

    use super::*;

    #[tokio::test]
    async fn test_dns_lookup() {
        let res = DNS_RESOLVER.lookup_ip(NA_DERP_HOSTNAME).await.unwrap();
        let res: Vec<_> = res.iter().collect();
        assert!(!res.is_empty());
        dbg!(res);
    }
}

//! Utilities used in [`iroh`](crate).

/// Creates a [`reqwest::ClientBuilder`] from a [`rustls::ClientConfig`] and our [`DnsResolver`].
///
/// In a browser context these options are not supported, so this function takes no arguments
/// if `wasm_browser` is enabled.
///
/// [`DnsResolver`]: crate::dns::DnsResolver
#[cfg(not(wasm_browser))]
pub(crate) fn reqwest_client_builder(
    tls_client_config: rustls::ClientConfig,
    dns_resolver: crate::dns::DnsResolver,
) -> reqwest::ClientBuilder {
    use self::reqwest_dns_resolver::ReqwestDnsResolver;

    reqwest::Client::builder()
        .tls_backend_preconfigured(tls_client_config)
        .dns_resolver(ReqwestDnsResolver(dns_resolver))
}

#[cfg(wasm_browser)]
pub(crate) fn reqwest_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
}

#[cfg(not(wasm_browser))]
mod reqwest_dns_resolver {
    use std::net::SocketAddr;

    use iroh_dns::dns::{DNS_TIMEOUT, DnsResolver};

    use crate::address_lookup::DNS_STAGGERING_MS;

    /// Implementation of [`reqwest::dns::Resolve`] for [`DnsResolver`].
    ///
    /// Wrapped in a newtype to not expose this in the public iroh API.
    pub(super) struct ReqwestDnsResolver(pub(super) DnsResolver);

    impl reqwest::dns::Resolve for ReqwestDnsResolver {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let this = self.0.clone();
            let name = name.as_str().to_string();
            Box::pin(async move {
                // Staggered so that a single unresponsive DNS server does not stall the
                // request for the full timeout.  Ideally this resolves **both** IPv4 and
                // IPv6 rather than racing them, but our resolver has no function for that
                // yet.
                let res = this
                    .lookup_ipv4_ipv6_staggered(name, DNS_TIMEOUT, DNS_STAGGERING_MS)
                    .await
                    // Collected eagerly: the returned iterator borrows the resolver, which
                    // does not outlive this future.
                    .map(|addrs| {
                        addrs
                            .map(|addr| SocketAddr::new(addr, 0))
                            .collect::<Vec<_>>()
                    });
                match res {
                    Ok(addrs) => {
                        let addrs: reqwest::dns::Addrs = Box::new(addrs.into_iter());
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
}

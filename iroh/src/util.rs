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

    /// Implementation of [`reqwest::dns::Resolve`] for [`DnsResolver`].
    ///
    /// Wrapped in a newtype to not expose this in the public iroh API.
    pub(super) struct ReqwestDnsResolver(pub(super) DnsResolver);

    impl reqwest::dns::Resolve for ReqwestDnsResolver {
        fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let this = self.0.clone();
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
}

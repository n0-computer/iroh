//! Utilities used in [`iroh`][`crate`]

#[cfg(wasm_browser)]
pub(crate) fn reqwest_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
}

/// Creates a reqwest client builder that always uses the rustls backend, unless we
/// are in a browser context, where that is not supported.
#[cfg(not(wasm_browser))]
pub(crate) fn reqwest_client_builder(
    tls_client_config: rustls::ClientConfig,
    dns_resolver: crate::dns::DnsResolver,
) -> reqwest::ClientBuilder {
    use std::sync::Arc;

    use self::reqwest_dns_resolver::ReqwestDnsResolver;

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_client_config)
        .dns_resolver(Arc::new(ReqwestDnsResolver(dns_resolver)))
}

#[cfg(not(wasm_browser))]
mod reqwest_dns_resolver {
    //! Implementation of [`reqwest::dns::Resolve`] for [`DnsResolver`].
    //!
    //! Wrapped in a newtype to not expose this in the public iroh API.

    use std::{net::SocketAddr, time::Duration};

    use iroh_dns::dns::DnsResolver;

    const DNS_TIMEOUT: Duration = Duration::from_secs(3);

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

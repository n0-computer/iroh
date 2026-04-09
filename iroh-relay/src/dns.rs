//! DNS resolver and endpoint lookup.
//!
//! Re-exports the DNS resolver from [`iroh_dns::dns`] and adds iroh-specific
//! endpoint lookup methods via [`DnsResolverExt`].

use std::future::Future;

use iroh_base::EndpointId;
pub use iroh_dns::dns::*;

use crate::endpoint_info::{EndpointIdExt, EndpointInfo};

/// Extension trait adding iroh endpoint lookup methods to [`DnsResolver`].
pub trait DnsResolverExt {
    /// Looks up endpoint info by [`EndpointId`] and origin domain name.
    ///
    /// To lookup endpoints that published their endpoint info to the DNS servers run by n0,
    /// pass [`N0_DNS_ENDPOINT_ORIGIN_PROD`] as `origin`.
    fn lookup_endpoint_by_id(
        &self,
        endpoint_id: &EndpointId,
        origin: &str,
    ) -> impl Future<Output = Result<EndpointInfo, LookupError>> + Send;

    /// Looks up endpoint info by DNS name.
    fn lookup_endpoint_by_domain_name(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<EndpointInfo, LookupError>> + Send;

    /// Looks up endpoint info by DNS name in a staggered fashion.
    fn lookup_endpoint_by_domain_name_staggered(
        &self,
        name: &str,
        delays_ms: &[u64],
    ) -> impl Future<Output = Result<EndpointInfo, StaggeredError<LookupError>>> + Send;

    /// Looks up endpoint info by [`EndpointId`] and origin domain name in a staggered fashion.
    fn lookup_endpoint_by_id_staggered(
        &self,
        endpoint_id: &EndpointId,
        origin: &str,
        delays_ms: &[u64],
    ) -> impl Future<Output = Result<EndpointInfo, StaggeredError<LookupError>>> + Send;
}

impl DnsResolverExt for DnsResolver {
    async fn lookup_endpoint_by_id(
        &self,
        endpoint_id: &EndpointId,
        origin: &str,
    ) -> Result<EndpointInfo, LookupError> {
        let name = format!("_iroh.{}.{}", endpoint_id.to_z32(), origin);
        let lookup = self.lookup_txt(name.clone(), DNS_TIMEOUT).await?;
        let info = EndpointInfo::from_txt_lookup(name, lookup)?;
        Ok(info)
    }

    async fn lookup_endpoint_by_domain_name(
        &self,
        name: &str,
    ) -> Result<EndpointInfo, LookupError> {
        let name = if name.starts_with("_iroh.") {
            name.to_string()
        } else {
            format!("_iroh.{name}")
        };
        let lookup = self.lookup_txt(name.clone(), DNS_TIMEOUT).await?;
        let info = EndpointInfo::from_txt_lookup(name, lookup)?;
        Ok(info)
    }

    async fn lookup_endpoint_by_domain_name_staggered(
        &self,
        name: &str,
        delays_ms: &[u64],
    ) -> Result<EndpointInfo, StaggeredError<LookupError>> {
        let f = || self.lookup_endpoint_by_domain_name(name);
        stagger_call(f, delays_ms).await
    }

    async fn lookup_endpoint_by_id_staggered(
        &self,
        endpoint_id: &EndpointId,
        origin: &str,
        delays_ms: &[u64],
    ) -> Result<EndpointInfo, StaggeredError<LookupError>> {
        let f = || self.lookup_endpoint_by_id(endpoint_id, origin);
        stagger_call(f, delays_ms).await
    }
}

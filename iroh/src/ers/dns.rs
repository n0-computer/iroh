//! DNS endpoint discovery for iroh

use iroh_base::EndpointId;
use iroh_relay::dns::DnsResolver;
pub use iroh_relay::dns::{N0_DNS_ENDPOINT_ORIGIN_PROD, N0_DNS_ENDPOINT_ORIGIN_STAGING};
use n0_future::boxed::BoxStream;

use crate::{
    Endpoint,
    endpoint::force_staging_infra,
    ers::{EndpointIdResolutionSystem, Error as ErsError, IntoErs, IntoErsError, Item as ErsItem},
};

pub(crate) const DNS_STAGGERING_MS: &[u64] = &[200, 300];

/// DNS endpoint discovery
///
/// When asked to resolve a [`EndpointId`], this service performs a lookup in the Domain Name System (DNS).
///
/// It uses the [`Endpoint`]'s DNS resolver to query for `TXT` records under the domain
/// `_iroh.<z32-endpoint-id>.<origin-domain>`:
///
/// * `_iroh`: is the record name
/// * `<z32-endpoint-id>` is the [`EndpointId`] encoded in [`z-base-32`] format
/// * `<origin-domain>` is the endpoint origin domain as set in [`Dns::builder`].
///
/// Each TXT record returned from the query is expected to contain a string in the format `<name>=<value>`.
/// If a TXT record contains multiple character strings, they are concatenated first.
/// The supported attributes are:
/// * `relay=<url>`: The URL of the home relay server of the endpoint
///
/// The DNS resolver defaults to using the nameservers configured on the host system, but can be changed
/// with [`crate::endpoint::Builder::dns_resolver`].
///
/// [`z-base-32`]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
/// [`Endpoint`]: crate::Endpoint
#[derive(Debug)]
pub struct Dns {
    origin_domain: String,
    dns_resolver: DnsResolver,
}

/// Builder for [`Dns`].
///
/// See [`Dns::builder`].
#[derive(Debug)]
pub struct DnsBuilder {
    origin_domain: String,
    dns_resolver: Option<DnsResolver>,
}

impl DnsBuilder {
    /// Sets the DNS resolver to use.
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Builds a [`Dns`] with the passed [`DnsResolver`].
    pub fn build(self) -> Dns {
        Dns {
            dns_resolver: self.dns_resolver.unwrap_or_default(),
            origin_domain: self.origin_domain,
        }
    }
}

impl Dns {
    /// Creates a [`DnsBuilder`] that implements [`IntoErs`].
    pub fn builder(origin_domain: String) -> DnsBuilder {
        DnsBuilder {
            origin_domain,
            dns_resolver: None,
        }
    }

    /// Creates a new DNS discovery using the `iroh.link` domain.
    ///
    /// This uses the [`N0_DNS_ENDPOINT_ORIGIN_PROD`] domain.
    ///
    /// # Usage during tests
    ///
    /// For testing it is possible to use the [`N0_DNS_ENDPOINT_ORIGIN_STAGING`] domain
    /// with [`Dns::builder`].  This would then use a hosted staging discovery
    /// service for testing purposes.
    pub fn n0_dns() -> DnsBuilder {
        if force_staging_infra() {
            Self::builder(N0_DNS_ENDPOINT_ORIGIN_STAGING.to_string())
        } else {
            Self::builder(N0_DNS_ENDPOINT_ORIGIN_PROD.to_string())
        }
    }
}

impl IntoErs for DnsBuilder {
    fn into_ers(
        mut self,
        endpoint: &Endpoint,
    ) -> Result<impl EndpointIdResolutionSystem, IntoErsError> {
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(endpoint.dns_resolver().clone());
        }
        Ok(self.build())
    }
}

impl EndpointIdResolutionSystem for Dns {
    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<ErsItem, ErsError>>> {
        let resolver = self.dns_resolver.clone();
        let origin_domain = self.origin_domain.clone();
        let fut = async move {
            let endpoint_info = resolver
                .lookup_endpoint_by_id_staggered(&endpoint_id, &origin_domain, DNS_STAGGERING_MS)
                .await
                .map_err(|e| ErsError::from_err_any("dns", e))?;
            Ok(ErsItem::new(endpoint_info, "dns", None))
        };
        let stream = n0_future::stream::once_future(fut);
        Some(Box::pin(stream))
    }
}

//! DNS endpoint discovery for iroh

use iroh_base::EndpointId;
use iroh_relay::dns::DnsResolver;
pub use iroh_relay::dns::{N0_DNS_ENDPOINT_ORIGIN_PROD, N0_DNS_ENDPOINT_ORIGIN_STAGING};
use n0_future::boxed::BoxStream;

use crate::{
    Endpoint,
    address_lookup::{
        AddressLookup, Error as AddressLookupError, IntoAddressLookup, IntoAddressLookupError,
        Item as AddressLookupItem,
    },
    endpoint::force_staging_infra,
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
/// * `<origin-domain>` is the endpoint origin domain as set in [`DnsAddressLookup::builder`].
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
pub struct DnsAddressLookup {
    origin_domain: String,
    dns_resolver: DnsResolver,
}

/// Builder for [`DnsAddressLookup`].
///
/// See [`DnsAddressLookup::builder`].
#[derive(Debug)]
pub struct DnsAddressLookupBuilder {
    origin_domain: String,
    dns_resolver: Option<DnsResolver>,
}

impl DnsAddressLookupBuilder {
    /// Sets the DNS resolver to use.
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Builds a [`DnsAddressLookup`] with the passed [`DnsResolver`].
    pub fn build(self) -> DnsAddressLookup {
        DnsAddressLookup {
            dns_resolver: self.dns_resolver.unwrap_or_default(),
            origin_domain: self.origin_domain,
        }
    }
}

impl DnsAddressLookup {
    /// Creates a [`DnsAddressLookupBuilder`] that implements [`IntoAddressLookup`].
    pub fn builder(origin_domain: String) -> DnsAddressLookupBuilder {
        DnsAddressLookupBuilder {
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
    /// with [`DnsAddressLookup::builder`].  This would then use a hosted staging discovery
    /// service for testing purposes.
    pub fn n0_dns() -> DnsAddressLookupBuilder {
        if force_staging_infra() {
            Self::builder(N0_DNS_ENDPOINT_ORIGIN_STAGING.to_string())
        } else {
            Self::builder(N0_DNS_ENDPOINT_ORIGIN_PROD.to_string())
        }
    }
}

impl IntoAddressLookup for DnsAddressLookupBuilder {
    fn into_address_lookup(
        mut self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, IntoAddressLookupError> {
        if self.dns_resolver.is_none() {
            self.dns_resolver = Some(endpoint.dns_resolver().clone());
        }
        Ok(self.build())
    }
}

impl AddressLookup for DnsAddressLookup {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        let resolver = self.dns_resolver.clone();
        let origin_domain = self.origin_domain.clone();
        let fut = async move {
            let endpoint_info = resolver
                .lookup_endpoint_by_id_staggered(&endpoint_id, &origin_domain, DNS_STAGGERING_MS)
                .await
                .map_err(|e| AddressLookupError::from_err_any("dns", e))?;
            Ok(AddressLookupItem::new(endpoint_info, "dns", None))
        };
        let stream = n0_future::stream::once_future(fut);
        Some(Box::pin(stream))
    }
}

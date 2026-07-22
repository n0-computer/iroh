//! Metrics for address lookup.

use iroh_metrics::{Counter, EncodeLabelSet, Family, MetricsGroup};
use serde::{Deserialize, Serialize};

/// Labels identifying an address lookup service by its provenance string,
/// see [`crate::address_lookup::Item::provenance`].
#[derive(
    Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, EncodeLabelSet,
)]
pub struct ServiceLabels {
    /// Provenance string of the service.
    pub service: String,
}

impl ServiceLabels {
    /// Creates labels for the given service provenance.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

/// Metrics collected by address lookup.
///
/// A lookup is one call to [`AddressLookupServices::resolve`] and queries all
/// configured services at once. Each service can yield several results and
/// errors per lookup; those are counted in the `service_*` counters, labeled
/// by the service's provenance (e.g. `dns`, `pkarr`).
///
/// [`AddressLookupServices::resolve`]: crate::address_lookup::AddressLookupServices::resolve
#[derive(Debug, Serialize, Deserialize, MetricsGroup)]
#[non_exhaustive]
#[metrics(name = "address_lookup", default)]
pub struct Metrics {
    /// Lookups started.
    pub lookups: Counter,
    /// Lookups that ended without a single result.
    ///
    /// Includes lookups with no services configured. Lookups abandoned early
    /// (e.g. once a connection is established) are not counted.
    pub lookups_failed: Counter,
    /// Results yielded per service.
    pub service_results: Family<ServiceLabels, Counter>,
    /// Errors yielded per service.
    pub service_errors: Family<ServiceLabels, Counter>,
}

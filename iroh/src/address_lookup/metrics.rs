//! Metrics for address lookup.

use iroh_metrics::{Counter, EncodeLabelSet, Family, MetricsGroup};
use serde::{Deserialize, Serialize};

/// Labels identifying an address lookup service.
///
/// The `service` label is the provenance string of the service that produced
/// the result, see [`crate::address_lookup::Item::provenance`].
#[derive(
    Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, EncodeLabelSet,
)]
pub struct ServiceLabels {
    /// The provenance string of the address lookup service.
    pub service: String,
}

impl ServiceLabels {
    /// Creates the label set for a service provenance string.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

/// Metrics collected by address lookup.
///
/// Tracks per-service resolution outcomes, labeled by the service's
/// provenance string (e.g. `dns`, `pkarr`, `memory_lookup`).
#[derive(Debug, Serialize, Deserialize, MetricsGroup)]
#[non_exhaustive]
#[metrics(name = "address_lookup", default)]
pub struct Metrics {
    /// Number of address lookups started.
    pub lookups: Counter,
    /// Number of address lookups that ended without producing any result.
    ///
    /// This counts lookups where all services failed or produced no items,
    /// including lookups started without any service configured. Lookups
    /// abandoned early (e.g. because a connection was established) are not
    /// counted.
    pub lookups_failed: Counter,
    /// Number of successful resolutions, labeled by the service that produced the result.
    pub resolve_success: Family<ServiceLabels, Counter>,
    /// Number of failed resolutions, labeled by the service that produced the error.
    pub resolve_error: Family<ServiceLabels, Counter>,
}

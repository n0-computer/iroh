//! Presets allow configuring an endpoint quickly with a chosen set of defaults.
//!
//! # Example
//!
//! ```no_run
//! # async fn main() -> n0_snafu::Result {
//! use iroh::{Endpoint, Watcher, endpoint::presets};
//!
//! let endpoint = Endpoint::bind_preset(presets::N0).await?;
//! # let _ = endpoint;
//! # Ok(())
//! # }
//! ```
use super::Builder;
use crate::discovery::pkarr::PkarrPublisher;

/// Defines a preset
pub trait Preset {
    /// Applies the configuration to the passed in [`Builder`].
    fn apply(self, builder: Builder) -> Builder;
}

/// Configures the endpoint to use the n0 defaults
///
/// Currently this consists of the DNS discovery service.
///
/// The default discovery service publishes to and resolves from the
/// n0.computer dns server `iroh.link`.
///
/// This is equivalent to adding both a [`crate::discovery::pkarr::PkarrPublisher`]
/// and a [`crate::discovery::dns::DnsDiscovery`], both configured to use the
/// n0.computer dns server.
///
/// This will by default use [`N0_DNS_PKARR_RELAY_PROD`].
/// When in tests, or when the `test-utils` feature is enabled, this will use the
/// [`N0_DNS_PKARR_RELAY_STAGING`].
///
/// [`N0_DNS_PKARR_RELAY_PROD`]: crate::discovery::pkarr::N0_DNS_PKARR_RELAY_PROD
/// [`N0_DNS_PKARR_RELAY_STAGING`]: crate::discovery::pkarr::N0_DNS_PKARR_RELAY_STAGING
#[derive(Debug, Copy, Clone, Default)]
pub struct N0;

impl Preset for N0 {
    fn apply(self, mut builder: Builder) -> Builder {
        builder = builder.add_discovery(PkarrPublisher::n0_dns());
        // Resolve using HTTPS requests to our DNS server's /pkarr path in browsers
        #[cfg(wasm_browser)]
        {
            use crate::discovery::pkarr::PkarrResolver;

            builder = builder.add_discovery(PkarrResolver::n0_dns());
        }
        // Resolve using DNS queries outside browsers.
        #[cfg(not(wasm_browser))]
        {
            use crate::discovery::dns::DnsDiscovery;

            builder = builder.add_discovery(DnsDiscovery::n0_dns());
        }
        builder
    }
}

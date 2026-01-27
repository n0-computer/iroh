//! Presets allow configuring an endpoint quickly with a chosen set of defaults.
//!
//! # Example
//!
//! ```no_run
//! # async fn wrapper() -> n0_error::Result {
//! use iroh::{Endpoint, RelayMode, Watcher, endpoint::presets};
//!
//! let endpoint = Endpoint::empty_builder(RelayMode::Disabled)
//!     .preset(presets::N0)
//!     .bind()
//!     .await?;
//! # let _ = endpoint;
//! # Ok(())
//! # }
//! ```

use crate::{
    address_lookup::PkarrPublisher,
    endpoint::{Builder, default_relay_mode},
};

/// Defines a preset
pub trait Preset {
    /// Applies the configuration to the passed in [`Builder`].
    fn apply(self, builder: Builder) -> Builder;
}

/// Configures the endpoint to use the n0 defaults
///
/// Currently this consists of
/// - the DNS Address Lookup service.
/// - the default relay servers provided by Number 0.
///
/// The default address lookup service publishes to and resolves from the
/// n0.computer dns server `iroh.link`.
///
/// This is equivalent to adding both a [`crate::address_lookup::PkarrPublisher`]
/// and a [`crate::address_lookup::DnsAddressLookup`], both configured to use the
/// n0.computer dns server.
///
/// This will by default use [`N0_DNS_PKARR_RELAY_PROD`].
/// When in tests, or when the `test-utils` feature is enabled, this will use the
/// [`N0_DNS_PKARR_RELAY_STAGING`].
///
/// [`N0_DNS_PKARR_RELAY_PROD`]: crate::address_lookup::N0_DNS_PKARR_RELAY_PROD
/// [`N0_DNS_PKARR_RELAY_STAGING`]: crate::address_lookup::N0_DNS_PKARR_RELAY_STAGING
#[derive(Debug, Copy, Clone, Default)]
pub struct N0;

impl Preset for N0 {
    fn apply(self, mut builder: Builder) -> Builder {
        builder = builder.address_lookup(PkarrPublisher::n0_dns());
        // Resolve using HTTPS requests to our DNS server's /pkarr path in browsers
        #[cfg(wasm_browser)]
        {
            use crate::address_lookup::PkarrResolver;

            builder = builder.address_lookup(PkarrResolver::n0_dns());
        }
        // Resolve using DNS queries outside browsers.
        #[cfg(not(wasm_browser))]
        {
            builder = builder.address_lookup(crate::address_lookup::DnsAddressLookup::n0_dns());
        }

        builder = builder.relay_mode(default_relay_mode());

        builder
    }
}

//! Presets allow configuring an endpoint quickly with a chosen set of defaults.
//!
//! # Example
//!
//! ```no_run
//! # async fn wrapper() -> n0_error::Result {
//! use iroh::{Endpoint, RelayMode, Watcher, endpoint::presets};
//!
//! let endpoint = Endpoint::builder(presets::N0).bind().await?;
//! # let _ = endpoint;
//! # Ok(())
//! # }
//! ```

use crate::endpoint::Builder;

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
/// - setting the [`rustls::crypto::CryptoProvider`] to [ring] or [aws-lc-rs], depending
///   on which feature is enabled in iroh (preferring ring if both are enabled).
///
/// Due to the last point, this preset is only available with the `ring` or
/// `aws-lc-rs` preset installed.
/// If you want to set your own crypto provider, we recommend copying the
/// implementation of this preset into your own and setting the appropriate crypto
/// provider there.
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
/// [ring]: rustls::crypto::ring::default_provider
/// [aws-lc-rs]: rustls::crypto::aws_lc_rs::default_provider
/// [`N0_DNS_PKARR_RELAY_PROD`]: crate::address_lookup::N0_DNS_PKARR_RELAY_PROD
/// [`N0_DNS_PKARR_RELAY_STAGING`]: crate::address_lookup::N0_DNS_PKARR_RELAY_STAGING
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
#[derive(Debug, Copy, Clone, Default)]
pub struct N0;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
impl Preset for N0 {
    fn apply(self, mut builder: Builder) -> Builder {
        use std::sync::Arc;

        use crate::{address_lookup::PkarrPublisher, endpoint::default_relay_mode};

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

        #[cfg(feature = "ring")]
        {
            builder = builder.crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));
        }

        #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
        {
            builder =
                builder.crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        }

        builder = builder.relay_mode(default_relay_mode());

        builder
    }
}

/// Configures the endpoint to use the n0 defaults, but with relay mode disabled.
///
/// Currently this consists of
/// - setting `RelayMode::Disabled`
/// - the DNS Address Lookup service, that publishes IP addresses rather than
///   relay urls.
/// - setting the [`rustls::crypto::CryptoProvider`] to [ring] or [aws-lc-rs], depending
///   on which feature is enabled in iroh (preferring ring if both are enabled).
///
/// Due to the last point, this preset is only available with the `ring` or
/// `aws-lc-rs` preset installed.
/// If you want to set your own crypto provider, we recommend copying the
/// implementation of this preset into your own and setting the appropriate crypto
/// provider there.
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
/// [ring]: rustls::crypto::ring::default_provider
/// [aws-lc-rs]: rustls::crypto::aws_lc_rs::default_provider
/// [`N0_DNS_PKARR_RELAY_PROD`]: crate::address_lookup::N0_DNS_PKARR_RELAY_PROD
/// [`N0_DNS_PKARR_RELAY_STAGING`]: crate::address_lookup::N0_DNS_PKARR_RELAY_STAGING
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
#[derive(Debug, Copy, Clone, Default)]
pub struct N0DisableRelay;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
impl Preset for N0DisableRelay {
    fn apply(self, builder: Builder) -> Builder {
        use crate::RelayMode;

        N0.apply(builder).relay_mode(RelayMode::Disabled)
    }
}

use std::{sync::Arc, time::Duration};

use governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use serde::{Deserialize, Serialize};
use tower_governor::{
    GovernorLayer,
    governor::GovernorConfigBuilder,
    key_extractor::{PeerIpKeyExtractor, SmartIpKeyExtractor},
};

/// Rate limiting strategy for the HTTP server.
#[derive(Debug, Deserialize, Default, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitConfig {
    /// Disables rate limiting entirely.
    Disabled,
    /// Rate limits by the connection's peer IP address.
    ///
    /// See [`PeerIpKeyExtractor`].
    ///
    /// [`PeerIpKeyExtractor`]: https://docs.rs/tower_governor/latest/tower_governor/key_extractor/struct.PeerIpKeyExtractor.html
    #[default]
    Simple,
    /// Rate limits by the client IP, extracted from reverse-proxy headers.
    ///
    /// Uses the headers commonly set by reverse proxies (for example
    /// `X-Forwarded-For`) to extract the original client IP, falling back to the
    /// connection's peer IP address. See [`SmartIpKeyExtractor`].
    ///
    /// [`SmartIpKeyExtractor`]: https://docs.rs/tower_governor/latest/tower_governor/key_extractor/struct.SmartIpKeyExtractor.html
    Smart,
}

impl Default for &RateLimitConfig {
    fn default() -> Self {
        &RateLimitConfig::Simple
    }
}

/// Create the default rate-limiting layer.
///
/// This spawns a background thread to clean up the rate limiting cache.
pub fn create<RespBody>(
    rate_limit_config: &RateLimitConfig,
) -> Option<GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware<QuantaInstant>, RespBody>> {
    let use_smart_extractor = match rate_limit_config {
        RateLimitConfig::Disabled => {
            tracing::info!("Rate limiting disabled");
            return None;
        }
        RateLimitConfig::Simple => false,
        RateLimitConfig::Smart => true,
    };

    tracing::info!("Rate limiting enabled ({rate_limit_config:?})");

    // Configure rate limiting:
    // * allow bursts with up to five requests per IP address
    // * replenish one element every two seconds
    let mut governor_conf_builder = GovernorConfigBuilder::default();
    // governor_conf_builder.use_headers()
    governor_conf_builder.per_second(4);
    governor_conf_builder.burst_size(2);

    if use_smart_extractor {
        governor_conf_builder.key_extractor(SmartIpKeyExtractor);
    }

    let governor_conf = governor_conf_builder
        .finish()
        .expect("failed to build rate-limiting governor");

    let governor_conf = Arc::new(governor_conf);

    // The governor needs a background task for garbage collection (to clear expired records)
    let gc_interval = Duration::from_secs(60);
    let governor_limiter = governor_conf.limiter().clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(gc_interval);
            tracing::debug!("rate limiting storage size: {}", governor_limiter.len());
            governor_limiter.retain_recent();
        }
    });

    Some(GovernorLayer::new(governor_conf))
}

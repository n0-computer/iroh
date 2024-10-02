use std::time::Duration;

use governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::{PeerIpKeyExtractor, SmartIpKeyExtractor},
    GovernorLayer,
};

use super::RateLimitConfig;

/// Create the default rate-limiting layer.
///
/// This spawns a background thread to clean up the rate limiting cache.
pub fn create(
    rate_limit_config: Option<RateLimitConfig>,
) -> Option<GovernorLayer<'static, PeerIpKeyExtractor, NoOpMiddleware<QuantaInstant>>> {
    let use_smart_extractor = match rate_limit_config {
        Some(RateLimitConfig::Boolean(false)) => {
            tracing::info!("Rate limiting disabled");
            return None;
        }
        // By default apply rate limit
        None | Some(RateLimitConfig::Boolean(true)) => false,
        Some(RateLimitConfig::Smart) => true,
    };

    tracing::info!("Rate limiting enabled");

    // Configure rate limiting:
    // * allow bursts with up to five requests per IP address
    // * replenish one element every two seconds
    let mut governor_conf_builder = GovernorConfigBuilder::default();
    // governor_conf_builder.use_headers()
    governor_conf_builder.per_second(4);
    governor_conf_builder.burst_size(2);

    if use_smart_extractor {
        tracing::info!("Rate limiting using smart extractor");
        governor_conf_builder.key_extractor(SmartIpKeyExtractor);
    }

    let governor_conf = governor_conf_builder
        .finish()
        .expect("failed to build rate-limiting governor");

    // The governor layer needs a reference that outlives the layer.
    // The tower_governor crate recommends in its examples to use Box::leak here.
    // In the unreleased v0.4 of tower_governor this was changed to use an Arc instead.
    // https://github.com/benwis/tower-governor/pull/27
    let governor_conf = Box::leak(Box::new(governor_conf));

    // The governor needs a background task for garbage collection (to clear expired records)
    let gc_interval = Duration::from_secs(60);
    let governor_limiter = governor_conf.limiter().clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(gc_interval);
        tracing::debug!("rate limiting storage size: {}", governor_limiter.len());
        governor_limiter.retain_recent();
    });

    Some(GovernorLayer {
        config: &*governor_conf,
    })
}

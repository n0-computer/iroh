use std::time::Duration;

use governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::PeerIpKeyExtractor, GovernorLayer,
};

/// Create the default rate-limiting layer.
///
/// This spawns a background thread to clean up the rate limiting cache.
pub fn create() -> GovernorLayer<'static, PeerIpKeyExtractor, NoOpMiddleware<QuantaInstant>> {
    // Configure rate limiting:
    // * allow bursts with up to five requests per IP address
    // * replenish one element every two seconds
    let governor_conf = GovernorConfigBuilder::default()
        // .use_headers()
        .per_second(4)
        .burst_size(2)
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

    GovernorLayer {
        config: &*governor_conf,
    }
}

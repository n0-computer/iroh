//! Host-provided QUIC timing services.
//!
//! Public items are re-exported from [`crate::endpoint`] when the
//! `unstable-custom-runtime` feature is enabled.
#![cfg_attr(not(feature = "unstable-custom-runtime"), allow(unreachable_pub))]

use std::{fmt::Debug, future::Future, pin::Pin};

#[cfg(wasm_browser)]
pub use n0_future::time::Instant as QuicInstant;
#[cfg(not(wasm_browser))]
pub use std::time::Instant as QuicInstant;

/// Supplies the monotonic clock and sleeps used by an endpoint's QUIC runtime.
///
/// Iroh continues to own task spawning, tracing, and endpoint shutdown. A custom
/// time source only replaces the clock and timer implementation used by noq.
///
/// [`Self::now`] and the deadlines passed to [`Self::sleep_until`] must use the
/// same clock and time origin. Time returned by [`Self::now`] must never move
/// backwards. A sleep may complete late, but must not complete before its
/// deadline.
pub trait QuicTimeSource: Send + Sync + Debug + 'static {
    /// Returns the current monotonic time.
    fn now(&self) -> QuicInstant;

    /// Returns a future that completes once `deadline` has been reached.
    ///
    /// Iroh may drop this future before it completes when noq resets its timer.
    /// Dropping the future must cancel any obsolete wakeup associated with it.
    fn sleep_until(&self, deadline: QuicInstant) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

//! Timeouts and pacing of the net report.

use n0_future::time::Duration;

/// Seconds a cycle waits for a second relay before it picks the home relay.
///
/// It is public for use in documentation and in the timeout calculations of
/// callers.
pub const FIRST_REPORT_TIMEOUT_SECS: u64 = 3;

/// Timeout for the captive portal HTTP request itself.
pub(super) const CAPTIVE_PORTAL_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeouts and pacing of the net report.
///
/// A probe cycle starts on a trigger: startup, a network change, a change of
/// the relay map, or the periodic refresh. It ends when every probe has
/// finished or [`Self::cycle_timeout`] has passed. These values are not
/// configurable by users yet. Tests shorten them.
#[derive(Debug, Clone)]
pub(crate) struct Timing {
    /// Minimum time between the starts of two probe cycles.
    ///
    /// A trigger within this window after a cycle started waits until the
    /// window ends, and further triggers merge into it, so a burst of network
    /// changes runs a single cycle. A network change also waits this long
    /// before its cycle starts, so that the socket has rebound when the probes
    /// go out.
    pub(crate) request_debounce: Duration,
    /// Maximum wait for a second relay before a cycle picks the home relay.
    pub(crate) first_report_timeout: Duration,
    /// Timeout of a single QAD or HTTPS probe.
    ///
    /// Longer than the first-report deadline, so that a probe on a degraded
    /// link still completes and refines what the cycle knows.
    pub(crate) probe_timeout: Duration,
    /// Maximum duration of a probe cycle.
    ///
    /// Bounds the network activity of a cycle, including probes delayed by
    /// the QAD stagger.
    pub(crate) cycle_timeout: Duration,
    /// Age of the last full cycle after which the next cycle is full.
    pub(crate) full_cycle_interval: Duration,
    /// Delay before the captive portal check starts.
    ///
    /// Gives fast QAD probes time to succeed first: if UDP works, a QAD answer
    /// cancels the captive portal check before it starts.
    pub(crate) captive_portal_delay: Duration,
    /// Time between two refresh cycles, before a random jitter of up to 30%.
    ///
    /// The default gives 20 to 26 seconds, just under the common UDP NAT
    /// timeout of 30 seconds.
    pub(crate) refresh_interval: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            request_debounce: Duration::from_millis(100),
            first_report_timeout: Duration::from_secs(FIRST_REPORT_TIMEOUT_SECS),
            probe_timeout: Duration::from_secs(15),
            cycle_timeout: Duration::from_secs(30),
            full_cycle_interval: Duration::from_secs(5 * 60),
            captive_portal_delay: Duration::from_millis(200),
            refresh_interval: Duration::from_secs(20),
        }
    }
}

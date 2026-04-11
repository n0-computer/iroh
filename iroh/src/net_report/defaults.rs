//! Default values used in net_report.

/// Contains all timeouts that we use in `iroh-net-report`.
pub(crate) mod timeouts {
    use n0_future::time::Duration;

    /// Maximum number of seconds before a net report is guaranteed to be
    /// emitted. Exposed as a public constant for use in documentation and
    /// caller timeout calculations.
    pub const TIMEOUT: u64 = 3;

    /// Deadline after which the actor emits a report even if probes are
    /// still running. Guarantees consumers see results within a bounded
    /// time. HTTPS and captive portal probes continue past this point.
    pub(crate) const REPORT_TIMEOUT: Duration = Duration::from_secs(TIMEOUT);

    /// Deadline after which remaining HTTPS probes are cancelled.
    ///
    /// QAD probes are not affected and keep running until
    /// [`QAD_PROBE_TIMEOUT`]. This bounds total network activity per
    /// cycle while giving degraded-link QAD probes time to finish.
    pub(crate) const ABORT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Per-probe timeout for individual HTTPS latency measurements.
    pub(crate) const PROBES_TIMEOUT: Duration = Duration::from_secs(3);

    /// Per-probe timeout for individual QAD (QUIC Address Discovery) probes.
    ///
    /// Longer than [`PROBES_TIMEOUT`] because QAD probes on degraded links
    /// should have extra time to complete after the initial report deadline.
    pub(crate) const QAD_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

    /// Delay before starting the captive portal check.
    ///
    /// Gives fast QAD probes time to succeed first: if UDP works, the
    /// captive portal check is cancelled before it starts. Short enough
    /// that the check still runs promptly when UDP is blocked.
    pub(crate) const CAPTIVE_PORTAL_DELAY: Duration = Duration::from_millis(200);

    /// Timeout for the captive portal HTTP request itself.
    ///
    /// Must be shorter than `ABORT_TIMEOUT - CAPTIVE_PORTAL_DELAY` so the
    /// check finishes before the cycle's abort deadline.
    pub(crate) const CAPTIVE_PORTAL_TIMEOUT: Duration = Duration::from_secs(2);

    /// Timeout for DNS resolution used by probe helpers.
    pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(3);
}

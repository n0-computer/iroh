//! Default values used in net_report.

/// Contains all timeouts that we use in `iroh-net-report`.
pub(crate) mod timeouts {
    use n0_future::time::Duration;

    // Timeouts for net_report

    /// The maximum amount of time, in seconds, before a net report is
    /// guaranteed to be emitted. Exposed for use in documentation.
    pub const TIMEOUT: u64 = 3;

    /// Time after which the actor emits a report even if probes are
    /// still running. This guarantees consumers see results quickly.
    /// HTTPS and captive portal probes continue running beyond this.
    pub(crate) const REPORT_TIMEOUT: Duration = Duration::from_secs(TIMEOUT);

    /// Time after which remaining HTTPS probes are cancelled.
    ///
    /// QAD probes are not affected by this timeout and keep running
    /// until [`QAD_PROBE_TIMEOUT`]. This bounds the total network
    /// activity per cycle while allowing degraded-link QAD probes to
    /// complete.
    pub(crate) const ABORT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Per-probe timeout for HTTPS latency measurements.
    pub(crate) const PROBES_TIMEOUT: Duration = Duration::from_secs(3);

    /// Max time for an individual QAD probe to complete.
    ///
    /// Longer than [`PROBES_TIMEOUT`] so that probes on degraded links can
    /// complete after the initial report deadline and still be picked up.
    pub(crate) const QAD_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

    /// How long to await for a captive-portal result.
    ///
    /// This delay is chosen so it starts after good-working QAD probes
    /// would have finished, but not too long so the delay is bearable if
    /// UDP/QAD is blocked.
    pub(crate) const CAPTIVE_PORTAL_DELAY: Duration = Duration::from_millis(200);

    /// Timeout for captive portal checks
    ///
    /// Must be lower than [`OVERALL_REPORT_TIMEOUT`] minus
    /// [`CAPTIVE_PORTAL_DELAY`].
    pub(crate) const CAPTIVE_PORTAL_TIMEOUT: Duration = Duration::from_secs(2);

    pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(3);
}

//! Default values used in net_report.

/// Contains all timeouts that we use in `iroh-net-report`.
pub(crate) mod timeouts {
    use n0_future::time::Duration;

    // Timeouts for net_report

    /// The maximum amount of time, in seconds, the net_report will spend gathering a single report.
    // This is separated from `OVERALL_REPORT_TIMEOUT` to use as a reference
    // in documentation outside of this crate. `OVERALL_REPORT_TIMEOUT` is a
    // duration and rustdoc cannot calculate it at runtime, and so cannot be
    // used directly for documentation purposes.
    pub const TIMEOUT: u64 = 5;

    /// The maximum amount of time net_report will spend gathering a single report.
    pub(crate) const OVERALL_REPORT_TIMEOUT: Duration = Duration::from_secs(TIMEOUT);

    /// The total time we wait for all the probes.
    ///
    /// This includes the QAD and HTTPS probes, which will all
    /// start at different times based on the ProbePlan.
    pub(crate) const PROBES_TIMEOUT: Duration = Duration::from_secs(3);

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

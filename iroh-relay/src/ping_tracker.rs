use n0_future::time::{self, Duration, Instant};
use tracing::debug;

/// Maximum time for a ping response in the relay protocol.
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum timeout for an RTT-based health check ping.
const MIN_HEALTH_CHECK_TIMEOUT: Duration = Duration::from_millis(500);

/// Tracks pings on a single relay connection.
///
/// Only the last ping needs is useful, any previously sent ping is forgotten and ignored.
#[derive(Debug)]
pub struct PingTracker {
    inner: Option<PingInner>,
    default_timeout: Duration,
    /// Last measured round-trip time to the relay server.
    last_rtt: Option<Duration>,
}

#[derive(Debug)]
struct PingInner {
    data: [u8; 8],
    deadline: Instant,
    sent_at: Instant,
}

impl Default for PingTracker {
    fn default() -> Self {
        Self::new(PING_TIMEOUT)
    }
}

impl PingTracker {
    /// Creates a new ping tracker, setting the ping timeout for pings.
    pub fn new(default_timeout: Duration) -> Self {
        Self {
            inner: None,
            default_timeout,
            last_rtt: None,
        }
    }

    /// Returns the current timeout set for pings.
    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Starts a new ping with an RTT-based timeout.
    pub fn new_ping(&mut self) -> [u8; 8] {
        let timeout = self.ping_timeout();
        self.new_ping_with_timeout(timeout)
    }

    /// Starts a new ping with a custom timeout.
    pub fn new_ping_with_timeout(&mut self, timeout: Duration) -> [u8; 8] {
        let ping_data = rand::random();
        let now = Instant::now();
        debug!(data = ?ping_data, "Sending ping to relay server.");
        self.inner = Some(PingInner {
            data: ping_data,
            deadline: now + timeout,
            sent_at: now,
        });
        ping_data
    }

    /// Updates the ping tracker with a received pong.
    ///
    /// Only the pong of the most recent ping will do anything.  There is no harm feeding
    /// any pong however.
    pub fn pong_received(&mut self, data: [u8; 8]) {
        if let Some(inner) = &self.inner
            && inner.data == data
        {
            let rtt = inner.sent_at.elapsed();
            debug!(?data, ?rtt, "Pong received from relay server");
            self.last_rtt = Some(rtt);
            self.inner = None;
        }
    }

    /// Returns the timeout for the next ping.
    ///
    /// Uses 3x the last measured RTT (to account for jitter), falling back to
    /// the default timeout if no RTT has been measured yet.
    pub fn ping_timeout(&self) -> Duration {
        self.last_rtt
            .map(|rtt| {
                (rtt * 3)
                    .max(MIN_HEALTH_CHECK_TIMEOUT)
                    .min(self.default_timeout)
            })
            .unwrap_or(self.default_timeout)
    }

    /// Cancel-safe waiting for a ping timeout.
    ///
    /// Unless the most recent sent ping times out, this will never return.
    pub async fn timeout(&mut self) {
        match self.inner {
            Some(PingInner { deadline, data, .. }) => {
                time::sleep_until(deadline).await;
                debug!(?data, "Ping timeout.");
                self.inner = None;
            }
            None => std::future::pending().await,
        }
    }
}

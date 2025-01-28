use n0_future::time::{self, Duration, Instant};
use tracing::debug;

/// Maximum time for a ping response in the relay protocol.
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Tracks pings on a single relay connection.
///
/// Only the last ping needs is useful, any previously sent ping is forgotten and ignored.
#[derive(Debug)]
pub struct PingTracker {
    inner: Option<PingInner>,
    default_timeout: Duration,
}

#[derive(Debug)]
struct PingInner {
    data: [u8; 8],
    deadline: Instant,
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
        }
    }

    /// Returns the current timeout set for pings.
    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Starts a new ping.
    pub fn new_ping(&mut self) -> [u8; 8] {
        let ping_data = rand::random();
        debug!(data = ?ping_data, "Sending ping to relay server.");
        self.inner = Some(PingInner {
            data: ping_data,
            deadline: Instant::now() + self.default_timeout,
        });
        ping_data
    }

    /// Updates the ping tracker with a received pong.
    ///
    /// Only the pong of the most recent ping will do anything.  There is no harm feeding
    /// any pong however.
    pub fn pong_received(&mut self, data: [u8; 8]) {
        if self.inner.as_ref().map(|inner| inner.data) == Some(data) {
            debug!(?data, "Pong received from relay server");
            self.inner = None;
        }
    }

    /// Cancel-safe waiting for a ping timeout.
    ///
    /// Unless the most recent sent ping times out, this will never return.
    pub async fn timeout(&mut self) {
        match self.inner {
            Some(PingInner { deadline, data }) => {
                time::sleep_until(deadline).await;
                debug!(?data, "Ping timeout.");
                self.inner = None;
            }
            None => std::future::pending().await,
        }
    }
}

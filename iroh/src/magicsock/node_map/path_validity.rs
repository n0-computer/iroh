use n0_future::time::{Duration, Instant};

use crate::magicsock::Metrics as MagicsockMetrics;

/// How long we trust a UDP address as the exclusive path (i.e. without also sending via the relay).
///
/// Trust for a UDP address begins when we receive a DISCO UDP pong on that address.
/// It is then further extended by this duration every time we receive QUIC payload data while it's
/// currently trusted.
///
/// If trust goes away, it can be brought back with another valid DISCO UDP pong.
const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);

/// Tracks a path's validity.
///
/// A path is valid:
/// - For [`Source::trust_duration`] after a successful [`PongReply`].
/// - For [`Source::trust_duration`] longer starting at the most recent
///   received application payload *while the path was valid*.
///
/// [`PongReply`]: super::node_state::PongReply
#[derive(Debug, Clone, Default)]
pub(super) struct PathValidity(Option<Inner>);

#[derive(Debug, Clone)]
struct Inner {
    latest_pong: Instant,
    latency: Duration,
    trust_until: Instant,
    congestion_metrics: CongestionMetrics,
}

/// Congestion tracking for a UDP path.
#[derive(Debug, Default, Clone)]
struct CongestionMetrics {
    /// Rolling window of recent latency measurements (stores up to 8 samples).
    latency_samples: [Option<Duration>; 8],
    /// Index for next sample insertion (circular buffer).
    sample_index: usize,
    /// Total pings sent on this path.
    pings_sent: u32,
    /// Total pongs received on this path.
    pongs_received: u32,
}

impl CongestionMetrics {
    fn add_latency_sample(&mut self, latency: Duration) {
        self.latency_samples[self.sample_index] = Some(latency);
        self.sample_index = (self.sample_index + 1) % self.latency_samples.len();
        self.pongs_received = self.pongs_received.saturating_add(1);
    }

    fn record_ping_sent(&mut self) {
        self.pings_sent = self.pings_sent.saturating_add(1);
    }

    /// Calculate packet loss rate (0.0 to 1.0).
    fn packet_loss_rate(&self) -> f64 {
        if self.pings_sent == 0 {
            return 0.0;
        }
        let lost = self.pings_sent.saturating_sub(self.pongs_received);
        lost as f64 / self.pings_sent as f64
    }

    /// Calculate RTT variance as a congestion indicator.
    /// Higher variance suggests congestion or unstable path.
    fn rtt_variance(&self) -> Option<Duration> {
        let samples: Vec<Duration> = self.latency_samples.iter().filter_map(|&s| s).collect();

        if samples.len() < 2 {
            return None;
        }

        let mean = samples.iter().sum::<Duration>() / samples.len() as u32;
        let variance: f64 = samples
            .iter()
            .map(|&s| {
                let diff = s.as_secs_f64() - mean.as_secs_f64();
                diff * diff
            })
            .sum::<f64>()
            / samples.len() as f64;

        Some(Duration::from_secs_f64(variance.sqrt()))
    }

    /// Calculate average latency from recent samples.
    #[cfg(test)]
    fn avg_latency(&self) -> Option<Duration> {
        let samples: Vec<Duration> = self.latency_samples.iter().filter_map(|&s| s).collect();

        if samples.is_empty() {
            return None;
        }

        Some(samples.iter().sum::<Duration>() / samples.len() as u32)
    }

    /// Path quality score (0.0 = worst, 1.0 = best).
    /// Factors in packet loss and RTT variance.
    fn quality_score(&self) -> f64 {
        let packet_loss = self.packet_loss_rate();

        // Defensive: packet_loss should never exceed 1.0, but clamp just in case
        if packet_loss > 1.0 {
            tracing::warn!(
                packet_loss,
                pings_sent = self.pings_sent,
                pongs_received = self.pongs_received,
                "packet loss rate exceeded 1.0 - possible bug in tracking"
            );
        }
        let loss_penalty = (1.0 - packet_loss).clamp(0.0, 1.0);

        // Penalize high RTT variance
        let variance_penalty = match self.rtt_variance() {
            Some(var) if var.as_millis() > 50 => 0.7,
            Some(var) if var.as_millis() > 20 => 0.85,
            Some(_) => 1.0,
            None => 1.0,
        };

        loss_penalty * variance_penalty
    }
}

#[derive(Debug)]
pub(super) enum Source {
    ReceivedPong,
    QuicPayload,
}

impl Source {
    fn trust_duration(&self) -> Duration {
        match self {
            Source::ReceivedPong => TRUST_UDP_ADDR_DURATION,
            Source::QuicPayload => TRUST_UDP_ADDR_DURATION,
        }
    }
}

impl PathValidity {
    pub(super) fn new(pong_at: Instant, latency: Duration) -> Self {
        let mut metrics = CongestionMetrics::default();
        // Account for the ping that must have been sent to receive this pong
        metrics.record_ping_sent();
        metrics.add_latency_sample(latency);
        Self(Some(Inner {
            trust_until: pong_at + Source::ReceivedPong.trust_duration(),
            latest_pong: pong_at,
            latency,
            congestion_metrics: metrics,
        }))
    }

    /// Update with a new pong, preserving congestion history.
    pub(super) fn update_pong(&mut self, pong_at: Instant, latency: Duration) {
        match &mut self.0 {
            Some(inner) => {
                inner.trust_until = pong_at + Source::ReceivedPong.trust_duration();
                inner.latest_pong = pong_at;
                inner.latency = latency;
                inner.congestion_metrics.add_latency_sample(latency);
            }
            None => {
                *self = Self::new(pong_at, latency);
            }
        }
    }

    pub(super) fn empty() -> Self {
        Self(None)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub(super) fn is_valid(&self, now: Instant) -> bool {
        let Some(state) = self.0.as_ref() else {
            return false;
        };

        state.is_valid(now)
    }

    pub(super) fn latency_if_valid(&self, now: Instant) -> Option<Duration> {
        let state = self.0.as_ref()?;
        state.is_valid(now).then_some(state.latency)
    }

    pub(super) fn is_outdated(&self, now: Instant) -> bool {
        let Some(state) = self.0.as_ref() else {
            return false;
        };

        // We *used* to be valid, but are now outdated.
        // This happens when we had a DISCO pong but didn't receive
        // any payload data or further pongs for at least TRUST_UDP_ADDR_DURATION
        state.is_outdated(now)
    }

    pub(super) fn latency_if_outdated(&self, now: Instant) -> Option<Duration> {
        let state = self.0.as_ref()?;
        state.is_outdated(now).then_some(state.latency)
    }

    /// Reconfirms path validity, if a payload was received while the
    /// path was valid.
    pub(super) fn receive_payload(&mut self, now: Instant, source: Source) {
        let Some(state) = self.0.as_mut() else {
            return;
        };

        if state.is_valid(now) {
            state.trust_until = now + source.trust_duration();
        }
    }

    pub(super) fn latency(&self) -> Option<Duration> {
        Some(self.0.as_ref()?.latency)
    }

    pub(super) fn latest_pong(&self) -> Option<Instant> {
        Some(self.0.as_ref()?.latest_pong)
    }

    /// Record that a ping was sent on this path.
    pub(super) fn record_ping_sent(&mut self) {
        if let Some(state) = self.0.as_mut() {
            state.congestion_metrics.record_ping_sent();
        }
    }

    /// Get the path quality score (0.0 = worst, 1.0 = best).
    #[cfg(test)]
    pub(super) fn quality_score(&self) -> f64 {
        self.0
            .as_ref()
            .map(|state| state.congestion_metrics.quality_score())
            .unwrap_or(0.0)
    }

    /// Get packet loss rate for this path.
    #[cfg(test)]
    pub(super) fn packet_loss_rate(&self) -> f64 {
        self.0
            .as_ref()
            .map(|state| state.congestion_metrics.packet_loss_rate())
            .unwrap_or(0.0)
    }

    /// Get RTT variance as congestion indicator.
    #[cfg(test)]
    pub(super) fn rtt_variance(&self) -> Option<Duration> {
        self.0
            .as_ref()
            .and_then(|state| state.congestion_metrics.rtt_variance())
    }

    /// Get average latency from recent samples.
    #[cfg(test)]
    pub(super) fn avg_latency(&self) -> Option<Duration> {
        self.0
            .as_ref()
            .and_then(|state| state.congestion_metrics.avg_latency())
    }

    /// Record congestion metrics to the metrics system.
    /// Should be called periodically or on significant events.
    pub(super) fn record_metrics(&self, metrics: &MagicsockMetrics) {
        let Some(state) = self.0.as_ref() else {
            return;
        };

        let loss_rate = state.congestion_metrics.packet_loss_rate();
        metrics.path_packet_loss_rate.observe(loss_rate);

        if let Some(variance) = state.congestion_metrics.rtt_variance() {
            metrics
                .path_rtt_variance_ms
                .observe(variance.as_millis() as f64);
        }

        let quality = state.congestion_metrics.quality_score();
        metrics.path_quality_score.observe(quality);
    }
}

impl Inner {
    fn is_valid(&self, now: Instant) -> bool {
        self.latest_pong <= now && now < self.trust_until
    }

    fn is_outdated(&self, now: Instant) -> bool {
        self.latest_pong <= now && self.trust_until <= now
    }
}

#[cfg(test)]
mod tests {
    use n0_future::time::{Duration, Instant};

    use super::{PathValidity, Source, TRUST_UDP_ADDR_DURATION};

    #[tokio::test(start_paused = true)]
    async fn test_basic_path_validity_lifetime() {
        let mut validity = PathValidity(None);
        assert!(!validity.is_valid(Instant::now()));
        assert!(!validity.is_outdated(Instant::now()));

        validity = PathValidity::new(Instant::now(), Duration::from_millis(20));
        assert!(validity.is_valid(Instant::now()));
        assert!(!validity.is_outdated(Instant::now()));

        tokio::time::advance(TRUST_UDP_ADDR_DURATION / 2).await;
        assert!(validity.is_valid(Instant::now()));
        assert!(!validity.is_outdated(Instant::now()));

        validity.receive_payload(Instant::now(), Source::QuicPayload);
        assert!(validity.is_valid(Instant::now()));
        assert!(!validity.is_outdated(Instant::now()));

        tokio::time::advance(TRUST_UDP_ADDR_DURATION / 2).await;
        assert!(validity.is_valid(Instant::now()));
        assert!(!validity.is_outdated(Instant::now()));

        tokio::time::advance(TRUST_UDP_ADDR_DURATION / 2).await;
        assert!(!validity.is_valid(Instant::now()));
        assert!(validity.is_outdated(Instant::now()));
    }
    #[tokio::test]
    async fn test_congestion_metrics() {
        let mut validity = PathValidity::new(Instant::now(), Duration::from_millis(10));
        // new() initializes with pings_sent=1, pongs_received=1

        // Record some additional ping sends
        validity.record_ping_sent();
        validity.record_ping_sent();
        validity.record_ping_sent();
        // Now: pings_sent=4, pongs_received=1

        validity.update_pong(Instant::now(), Duration::from_millis(15));
        // Now: pings_sent=4, pongs_received=2

        // Packet loss should be (4-2)/4 = 0.5
        let loss_rate = validity.packet_loss_rate();
        assert!((loss_rate - 0.5).abs() < 0.01);

        // Quality score should be reduced due to packet loss
        let quality = validity.quality_score();
        assert!(quality < 1.0);
        assert!(quality > 0.45); // Should still be relatively good (1.0 - 0.5 = 0.5)
    }

    #[tokio::test]
    async fn test_congestion_rtt_variance() {
        let mut validity = PathValidity::new(Instant::now(), Duration::from_millis(10));

        // Add varying latencies
        validity.update_pong(Instant::now(), Duration::from_millis(10));
        validity.update_pong(Instant::now(), Duration::from_millis(50));
        validity.update_pong(Instant::now(), Duration::from_millis(20));
        validity.update_pong(Instant::now(), Duration::from_millis(40));

        // Should have variance
        let variance = validity.rtt_variance();
        assert!(variance.is_some());
        assert!(variance.unwrap().as_millis() > 0);

        // Average latency should be around 30ms
        let avg = validity.avg_latency();
        assert!(avg.is_some());
        let avg_ms = avg.unwrap().as_millis();
        assert!((25..=35).contains(&avg_ms));
    }

    #[tokio::test]
    async fn test_quality_score_with_high_variance() {
        let mut validity = PathValidity::new(Instant::now(), Duration::from_millis(10));

        // Add highly varying latencies (simulating congestion)
        for i in 0..8 {
            let latency = if i % 2 == 0 {
                Duration::from_millis(10)
            } else {
                Duration::from_millis(100)
            };
            validity.update_pong(Instant::now(), latency);
            validity.record_ping_sent();
        }

        // Quality should be penalized due to high variance
        let quality = validity.quality_score();
        assert!(quality < 0.9); // Should be penalized
    }
}

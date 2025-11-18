//! Tracker for stateful metrics for connections and paths.

use std::time::Duration;

use quinn_proto::PathId;
use rustc_hash::FxHashMap;

use crate::{magicsock::transports, metrics::MagicsockMetrics};

#[derive(Debug, Default)]
pub(super) struct MetricsTracker {
    transport_summary: TransportSummary,
    path_rtt_variance: FxHashMap<PathId, RttVariance>,
}

impl MetricsTracker {
    pub(super) fn add_path(&mut self, path_id: PathId, remote: &transports::Addr) {
        self.transport_summary.add_path(remote);
        self.path_rtt_variance.insert(path_id, Default::default());
    }

    pub(super) fn remove_path(&mut self, path_id: &PathId) {
        self.path_rtt_variance.remove(path_id);
    }

    pub(super) fn record_periodic(
        &mut self,
        metrics: &MagicsockMetrics,
        conn: &quinn::Connection,
        path_remotes: &FxHashMap<PathId, transports::Addr>,
        selected_path: Option<transports::Addr>,
    ) {
        for (path_id, remote) in path_remotes.iter() {
            let Some(stats) = conn.path_stats(*path_id) else {
                continue;
            };

            let loss_rate = if stats.sent_packets == 0 {
                0.0
            } else {
                stats.lost_packets as f64 / stats.sent_packets as f64
            };
            metrics.path_packet_loss_rate.observe(loss_rate);

            if Some(remote) == selected_path.as_ref() {
                metrics
                    .connection_latency_ms
                    .observe(stats.rtt.as_millis() as f64);
            }

            if let Some(rtt_variance) = self.path_rtt_variance.get_mut(path_id) {
                rtt_variance.add_rtt_sample(stats.rtt);
                if let Some(variance) = rtt_variance.rtt_variance() {
                    metrics
                        .path_rtt_variance_ms
                        .observe(variance.as_millis() as f64);
                }

                let quality = rtt_variance.quality_score(loss_rate);
                metrics.path_quality_score.observe(quality);
            };
        }
    }

    pub(super) fn record_closed(&self, metrics: &MagicsockMetrics) {
        metrics.num_conns_closed.inc();
        match self.transport_summary {
            TransportSummary::IpOnly => {
                metrics.num_conns_transport_ip_only.inc();
            }
            TransportSummary::RelayOnly => {
                metrics.num_conns_transport_relay_only.inc();
            }
            TransportSummary::IpAndRelay => {
                metrics.num_conns_transport_ip_and_relay.inc();
            }
            TransportSummary::None => {}
        }
    }
}

/// Tracks RTT variance over time, as a congestion marker.
#[derive(Debug, Default)]
struct RttVariance {
    /// Rolling window of recent latency measurements (stores up to 8 samples).
    samples: [Option<Duration>; 8],
    /// Index for next sample insertion (circular buffer).
    index: usize,
}

impl RttVariance {
    fn add_rtt_sample(&mut self, rtt: Duration) {
        self.samples[self.index] = Some(rtt);
        self.index = (self.index + 1) % self.samples.len();
    }

    /// Calculate RTT variance as a congestion indicator.
    /// Higher variance suggests congestion or unstable path.
    fn rtt_variance(&self) -> Option<Duration> {
        let samples: Vec<Duration> = self.samples.iter().filter_map(|&s| s).collect();

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

    /// Path quality score (0.0 = worst, 1.0 = best).
    /// Factors in packet loss and RTT variance.
    fn quality_score(&self, packet_loss: f64) -> f64 {
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

/// Used for metrics tracking.
#[derive(Debug, Clone, Copy, Default)]
enum TransportSummary {
    #[default]
    None,
    IpOnly,
    RelayOnly,
    IpAndRelay,
}

impl TransportSummary {
    fn add_path(&mut self, addr: &transports::Addr) {
        use transports::Addr;
        *self = match (*self, addr) {
            (TransportSummary::None | TransportSummary::IpOnly, Addr::Ip(_)) => Self::IpOnly,
            (TransportSummary::None | TransportSummary::RelayOnly, Addr::Relay(_, _)) => {
                Self::RelayOnly
            }
            _ => Self::IpAndRelay,
        }
    }
}

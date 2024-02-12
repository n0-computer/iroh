//! The [`BestAddr`] is the currently active best address for UDP sends.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use iroh_metrics::inc;
use tracing::{debug, info};

use crate::magicsock::metrics::Metrics as MagicsockMetrics;

/// How long we trust a UDP address as the exclusive path (without using DERP) without having heard a Pong reply.
const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);

#[derive(Debug, Default)]
pub(super) struct BestAddr(Option<BestAddrInner>);

#[derive(Debug)]
struct BestAddrInner {
    addr: AddrLatency,
    trust_until: Option<Instant>,
    confirmed_at: Instant,
}

impl BestAddrInner {
    fn is_trusted(&self, now: Instant) -> bool {
        self.trust_until
            .map(|trust_until| trust_until >= now)
            .unwrap_or(false)
    }
}

#[derive(Debug)]
pub(super) enum Source {
    ReceivedPong,
    BestCandidate,
}

impl Source {
    fn trust_until(&self, from: Instant) -> Instant {
        match self {
            Source::ReceivedPong => from + TRUST_UDP_ADDR_DURATION,
            // TODO: Fix time.  no really, fix this time
            Source::BestCandidate => from + Duration::from_secs(60 * 60),
        }
    }
}

#[derive(Debug)]
pub(super) enum State<'a> {
    Valid(&'a AddrLatency),
    Outdated(&'a AddrLatency),
    Empty,
}

#[derive(Debug)]
pub enum ClearReason {
    Reset,
    Inactive,
    PongTimeout,
}

impl BestAddr {
    #[cfg(test)]
    pub fn from_parts(
        addr: SocketAddr,
        latency: Duration,
        confirmed_at: Instant,
        trust_until: Instant,
    ) -> Self {
        let inner = BestAddrInner {
            addr: AddrLatency { addr, latency },
            confirmed_at,
            trust_until: Some(trust_until),
        };
        Self(Some(inner))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn clear(&mut self, reason: ClearReason, has_derp: bool) -> bool {
        if let Some(addr) = self.addr() {
            self.0 = None;
            info!(?reason, ?has_derp, old_addr = %addr, "clearing best_addr");
            // no longer relying on the direct connection
            inc!(MagicsockMetrics, num_direct_conns_removed);
            if has_derp {
                // we are now relying on the relay connection, add a relay conn
                inc!(MagicsockMetrics, num_relay_conns_added);
            }
            true
        } else {
            false
        }
    }

    pub fn clear_if_equals(
        &mut self,
        addr: SocketAddr,
        reason: ClearReason,
        has_derp: bool,
    ) -> bool {
        match &self.addr() {
            Some(best_addr) if *best_addr == addr => self.clear(reason, has_derp),
            _ => false,
        }
    }

    /// Clears best_addr if it equals `addr` and was confirmed before `confirmed_before`.
    ///
    /// If the given addr is currently the best address, **and** the best address was
    /// confirmed longer ago than the provided time, then this clears the best address.
    pub fn clear_if_addr_older(
        &mut self,
        addr: SocketAddr,
        confirmed_before: Instant,
        reason: ClearReason,
        has_derp: bool,
    ) {
        if let Some(ref inner) = self.0 {
            if inner.addr.addr == addr && inner.confirmed_at < confirmed_before {
                self.clear(reason, has_derp);
            }
        }
    }

    pub fn clear_trust(&mut self) {
        if let Some(state) = self.0.as_mut() {
            state.trust_until = None;
        }
    }

    pub fn insert_if_better_or_reconfirm(
        &mut self,
        addr: SocketAddr,
        latency: Duration,
        source: Source,
        confirmed_at: Instant,
        has_derp: bool,
    ) {
        match self.0.as_mut() {
            None => {
                self.insert(addr, latency, source, confirmed_at, has_derp);
            }
            Some(state) => {
                let candidate = AddrLatency { addr, latency };
                if !state.is_trusted(confirmed_at) || candidate.is_better_than(&state.addr) {
                    self.insert(addr, latency, source, confirmed_at, has_derp);
                } else if state.addr.addr == addr {
                    state.confirmed_at = confirmed_at;
                    state.trust_until = Some(source.trust_until(confirmed_at));
                }
            }
        }
    }

    fn insert(
        &mut self,
        addr: SocketAddr,
        latency: Duration,
        source: Source,
        confirmed_at: Instant,
        has_derp: bool,
    ) {
        let trust_until = source.trust_until(confirmed_at);

        if self
            .0
            .as_ref()
            .map(|prev| prev.addr.addr == addr)
            .unwrap_or_default()
        {
            debug!(
                %addr,
                latency = ?latency,
                trust_for = ?trust_until.duration_since(Instant::now()),
               "re-selecting direct path for endpoint"
            );
        } else {
            info!(
               %addr,
               latency = ?latency,
               trust_for = ?trust_until.duration_since(Instant::now()),
               "selecting new direct path for endpoint"
            );
        }
        let was_empty = self.is_empty();
        let inner = BestAddrInner {
            addr: AddrLatency { addr, latency },
            trust_until: Some(trust_until),
            confirmed_at,
        };
        self.0 = Some(inner);
        if was_empty && has_derp {
            // we now have a direct connection, adjust direct connection count
            inc!(MagicsockMetrics, num_direct_conns_added);
            if has_derp {
                // we no longer rely on the relay connection, decrease the relay connection
                // count
                inc!(MagicsockMetrics, num_relay_conns_removed);
            }
        }
    }

    pub fn state(&self, now: Instant) -> State {
        match &self.0 {
            None => State::Empty,
            Some(state) => match state.trust_until {
                Some(expiry) if now < expiry => State::Valid(&state.addr),
                Some(_) | None => State::Outdated(&state.addr),
            },
        }
    }

    pub fn addr(&self) -> Option<SocketAddr> {
        self.0.as_ref().map(|a| a.addr.addr)
    }
}

/// A `SocketAddr` with an associated latency.
#[derive(Debug, Clone)]
pub struct AddrLatency {
    pub addr: SocketAddr,
    pub latency: Duration,
}

impl AddrLatency {
    /// Reports whether `self` is a better addr to use than `other`.
    fn is_better_than(&self, other: &Self) -> bool {
        if self.addr == other.addr {
            return false;
        }
        if self.addr.is_ipv6() && other.addr.is_ipv4() {
            // Prefer IPv6 for being a bit more robust, as long as
            // the latencies are roughly equivalent.
            if self.latency / 10 * 9 < other.latency {
                return true;
            }
        } else if self.addr.is_ipv4() && other.addr.is_ipv6() && other.is_better_than(self) {
            return false;
        }
        self.latency < other.latency
    }
}

//! The [`BestAddr`] is the currently active best address for UDP sends.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use iroh_metrics::inc;
use tracing::{debug, info, trace};

use super::{AddrLatency, TRUST_UDP_ADDR_DURATION};
use crate::magicsock::metrics::Metrics as MagicsockMetrics;

#[derive(Debug, Default)]
pub(super) struct BestAddr(Option<BestAddrInner>);

#[derive(Debug)]
struct BestAddrInner {
    addr: AddrLatency,
    trust_until: Option<Instant>,
    confirmed_at: Instant,
}

#[derive(Debug)]
pub(super) enum BestAddrSource {
    ReceivedPong,
    BestCandidate,
}

impl BestAddrSource {
    fn trust_until(&self, from: Instant) -> Instant {
        match self {
            BestAddrSource::ReceivedPong => from + TRUST_UDP_ADDR_DURATION,
            // TODO: Fix time
            BestAddrSource::BestCandidate => from + Duration::from_secs(60 * 60),
        }
    }
}

#[derive(Debug)]
pub(super) enum BestAddrState<'a> {
    Valid(&'a AddrLatency),
    Outdated(&'a AddrLatency),
    Empty,
}

#[derive(Debug)]
pub enum BestAddrClearReason {
    Reset,
    Inactive,
    PruneCallMeMaybe,
    PongTimeout,
}

impl BestAddr {
    #[cfg(test)]
    pub fn from_parts(
        addr: SocketAddr,
        latency: Option<Duration>,
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

    pub fn is_valid(&self, now: Instant) -> bool {
        matches!(self.state(now), BestAddrState::Valid(_))
    }

    pub fn clear(&mut self, reason: BestAddrClearReason, has_derp: bool) -> bool {
        if let Some(addr) = self.addr() {
            self.0 = None;
            debug!(?reason, ?has_derp, old_addr = %addr, "remove best_addr");
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
        reason: BestAddrClearReason,
        has_derp: bool,
    ) -> bool {
        match &self.addr() {
            Some(best_addr) if *best_addr == addr => self.clear(reason, has_derp),
            _ => false,
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
        latency: Option<Duration>,
        source: BestAddrSource,
        confirmed_at: Instant,
        has_derp: bool,
    ) {
        match self.0.as_mut() {
            None => self.insert(addr, latency, source, confirmed_at, has_derp),
            Some(state) => {
                let candidate = AddrLatency { addr, latency };
                if candidate.is_better_than(&state.addr) {
                    self.insert(addr, latency, source, confirmed_at, has_derp)
                } else if state.addr.addr == addr {
                    state.confirmed_at = confirmed_at;
                    state.trust_until = Some(source.trust_until(confirmed_at));
                }
            }
        }
    }

    pub fn insert(
        &mut self,
        addr: SocketAddr,
        latency: Option<Duration>,
        source: BestAddrSource,
        confirmed_at: Instant,
        has_derp: bool,
    ) {
        let trust_until = source.trust_until(confirmed_at);

        info!(
           %addr,
           latency = ?latency,
           trust_for = ?trust_until.duration_since(Instant::now()),
           "new best_addr (candidate address with most recent pong)"
        );
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

    pub fn state(&self, now: Instant) -> BestAddrState {
        match &self.0 {
            None => {
                trace!("best_addr invalid: not set");
                BestAddrState::Empty
            }
            Some(state) => match state.trust_until {
                Some(expiry) if now < expiry => {
                    trace!(addr = %state.addr.addr, remaining=?expiry.duration_since(now), "best_addr valid");
                    BestAddrState::Valid(&state.addr)
                }
                Some(expiry) => {
                    trace!(addr = %state.addr.addr, since=?expiry.duration_since(now), "best_addr invalid: expired");
                    BestAddrState::Outdated(&state.addr)
                }
                None => {
                    trace!(addr = %state.addr.addr, "best_addr invalid: trust_best_addr_until not set");
                    BestAddrState::Outdated(&state.addr)
                }
            },
        }
    }

    pub fn addr(&self) -> Option<SocketAddr> {
        self.0.as_ref().map(|a| a.addr.addr)
    }

    pub fn addr_info(&self) -> Option<&AddrLatency> {
        self.0.as_ref().map(|a| &a.addr)
    }

    pub fn latency(&self) -> Option<Duration> {
        self.addr_info().and_then(|a| a.latency)
    }
}

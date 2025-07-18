//! The [`BestAddr`] is the currently active best address for UDP sends.

use std::net::SocketAddr;

use n0_future::time::{Duration, Instant};
use tracing::{debug, info};

/// How long we trust a UDP address as the exclusive path (without using relay) without having heard a Pong reply.
pub(super) const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);

/// The grace period at which we consider switching away from our best addr
/// to another address that we've received data on.
///
/// The trusted address lifecycle goes as follows:
/// - A UDP DICSO pong is received, this validates that the path is for sure valid.
/// - The disco path that seems to have the lowest latency is the path we use to send on.
/// - We trust this path as a path to send on for at least TRUST_UDP_ADDR_DURATION.
/// - This time is extended every time we receive a UDP DISCO pong on the address.
/// - This time is *also* extended every time we receive *application* payloads on this
///   address (i.e. QUIC datagrams).
/// - If our best address becomes outdated (TRUST_UDP_ADDR_DURATION expires) without
///   another pong or payload data, then we'll start sending over the relay, too!
///   (we switch to ConnectionType::Mixed)
///
/// However, we might not get any UDP DISCO pongs because they're UDP packets and get
/// lost under e.g. high load.
///
/// This is usually fine, because we also receive on the best addr, and that extends its
/// "trust period" just as well.
///
/// However, if *additionally* we send on a different address than the one we receive on,
/// then this extension doesn't happen.
///
/// To fix this, we also apply the same path validation logic to non-best addresses.
/// I.e. we keep track of when they last received a pong, at which point we consider them
/// validated, and then extend this validation period when we receive application data
/// while they're valid (or when we receive another pong).
///
/// Now, when our best address becomes outdated, we need to switch to another valid path.
///
/// We could switch to another path once the best address becomes outdated, but then we'd
/// already start sending on the relay for a couple of iterations!
///
/// So instead, we switch to another path when it looks like the best address becomes
/// outdated.
/// Not just any path, but the path that we're currently receiving from for this node.
///
/// Since we might not be receiving constantly from the remote side (e.g. if it's a
/// one-sided transfer), we need to take care to do consider switching early enough.
///
/// So this duration is chosen as at least 1 keep alive interval (1s default in iroh atm)
/// + at maximum 400ms of latency spike.
const TRUST_UDP_ADDR_SOON_OUTDATED: Duration = Duration::from_millis(1400);

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

    fn addr(&self) -> SocketAddr {
        self.addr.addr
    }
}

#[derive(Debug)]
pub(super) enum Source {
    ReceivedPong,
    BestCandidate,
    Udp,
}

impl Source {
    fn trust_duration(&self) -> Duration {
        match self {
            Source::ReceivedPong => TRUST_UDP_ADDR_DURATION,
            // TODO: Fix time
            Source::BestCandidate => Duration::from_secs(60 * 60),
            Source::Udp => TRUST_UDP_ADDR_DURATION,
        }
    }
}

#[derive(Debug)]
pub(super) enum State<'a> {
    Valid(&'a AddrLatency),
    Outdated(&'a AddrLatency),
    Empty,
}

#[derive(Debug, Clone, Copy)]
pub enum ClearReason {
    Reset,
    Inactive,
    PongTimeout,
    MatchesOurLocalAddr,
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

    /// Unconditionally clears the best address.
    pub fn clear(&mut self, reason: ClearReason, has_relay: bool) {
        let old = self.0.take();
        if let Some(old_addr) = old.as_ref().map(BestAddrInner::addr) {
            info!(?reason, ?has_relay, %old_addr, "clearing best_addr");
        }
    }

    /// Clears the best address if equal to `addr`.
    pub fn clear_if_equals(&mut self, addr: SocketAddr, reason: ClearReason, has_relay: bool) {
        if self.addr() == Some(addr) {
            self.clear(reason, has_relay)
        }
    }

    pub fn clear_trust(&mut self, why: &'static str) {
        if let Some(state) = self.0.as_mut() {
            info!(
                %why,
                prev_trust_until = ?state.trust_until,
                "clearing best_addr trust",
            );
            state.trust_until = None;
        }
    }

    pub fn insert_if_better_or_reconfirm(
        &mut self,
        addr: SocketAddr,
        latency: Duration,
        source: Source,
        confirmed_at: Instant,
        now: Instant,
    ) {
        match self.0.as_mut() {
            None => {
                self.insert(addr, latency, source, confirmed_at);
            }
            Some(state) => {
                let candidate = AddrLatency { addr, latency };
                if !state.is_trusted(now) || candidate.is_better_than(&state.addr) {
                    self.insert(addr, latency, source, confirmed_at);
                } else if state.addr.addr == addr {
                    state.confirmed_at = confirmed_at;
                    state.trust_until = Some(confirmed_at + source.trust_duration());
                }
            }
        }
    }

    pub fn insert_if_soon_outdated_or_reconfirm(
        &mut self,
        addr: SocketAddr,
        latency: Duration,
        source: Source,
        confirmed_at: Instant,
        now: Instant,
    ) {
        match self.0.as_mut() {
            None => {
                self.insert(addr, latency, source, confirmed_at);
            }
            Some(state) => {
                // If the current best addr will soon be outdated
                // and the given candidate will be trusted for longer
                if !state.is_trusted(now + TRUST_UDP_ADDR_SOON_OUTDATED)
                    && state.confirmed_at < confirmed_at
                {
                    println!("best addr will soon not be trusted, let's switch");
                    self.insert(addr, latency, source, confirmed_at);
                } else if state.addr.addr == addr {
                    state.confirmed_at = confirmed_at;
                    state.trust_until = Some(confirmed_at + source.trust_duration());
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
    ) {
        let trust_until = confirmed_at + source.trust_duration();

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
               "re-selecting direct path for node"
            );
        } else {
            info!(
               %addr,
               latency = ?latency,
               trust_for = ?trust_until.duration_since(Instant::now()),
               "selecting new direct path for node"
            );
        }
        let inner = BestAddrInner {
            addr: AddrLatency { addr, latency },
            trust_until: Some(trust_until),
            confirmed_at,
        };
        self.0 = Some(inner);
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
        self.0.as_ref().map(BestAddrInner::addr)
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

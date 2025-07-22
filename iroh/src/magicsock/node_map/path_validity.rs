use n0_future::time::{Duration, Instant};

use crate::magicsock::node_map::node_state::PongReply;

/// How long we trust a UDP address as the exclusive path (without using relay) without having heard a Pong reply.
const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);

/// Tracks a path's validity.
///
/// A path is valid:
/// - For [`Source::trust_duration`] after a successful [`PongReply`].
/// - For [`Source::trust_duration`] longer starting at the most recent
///   received application payload *while the path was valid*.
#[derive(Debug, Clone, Default)]
pub(super) struct PathValidity(Option<Inner>);

#[derive(Debug, Clone)]
struct Inner {
    recent_pong: PongReply,
    confirmed_at: Instant,
    trust_until: Instant,
}

#[derive(Debug)]
pub(super) enum Source {
    ReceivedPong,
    // BestCandidate,
    Udp,
}

impl Source {
    fn trust_duration(&self) -> Duration {
        match self {
            Source::ReceivedPong => TRUST_UDP_ADDR_DURATION,
            // // TODO: Fix time
            // Source::BestCandidate => Duration::from_secs(60 * 60),
            Source::Udp => TRUST_UDP_ADDR_DURATION,
        }
    }
}

impl PathValidity {
    pub(super) fn new(recent_pong: PongReply) -> Self {
        Self(Some(Inner {
            confirmed_at: recent_pong.pong_at,
            trust_until: recent_pong.pong_at + Source::ReceivedPong.trust_duration(),
            recent_pong,
        }))
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
        let Some(state) = self.0.as_ref() else {
            return None;
        };

        state.is_valid(now).then_some(state.recent_pong.latency)
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
        let Some(state) = self.0.as_ref() else {
            return None;
        };

        state.is_outdated(now).then_some(state.recent_pong.latency)
    }

    /// Reconfirms path validity, if a payload was received while the
    /// path was valid.
    pub(super) fn receive_payload(&mut self, now: Instant, source: Source) {
        let Some(state) = self.0.as_mut() else {
            return;
        };

        if state.is_valid(now) {
            state.confirmed_at = now;
            state.trust_until = now + source.trust_duration();
        }
    }

    pub(super) fn get_pong(&self) -> Option<&PongReply> {
        self.0.as_ref().map(|inner| &inner.recent_pong)
    }

    // TODO(matheus23): Use this to bias the choice of best outdated addr maybe?
    pub(super) fn confirmed_at(&self) -> Option<Instant> {
        self.0.as_ref().map(|inner| inner.confirmed_at)
    }
}

impl Inner {
    fn is_valid(&self, now: Instant) -> bool {
        self.confirmed_at <= now && now < self.trust_until
    }

    fn is_outdated(&self, now: Instant) -> bool {
        self.confirmed_at <= now && self.trust_until <= now
    }
}

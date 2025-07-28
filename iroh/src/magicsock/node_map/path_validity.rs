use n0_future::time::{Duration, Instant};

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
        Self(Some(Inner {
            trust_until: pong_at + Source::ReceivedPong.trust_duration(),
            latest_pong: pong_at,
            latency,
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
}

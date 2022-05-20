use ahash::AHashMap;
use libp2p::PeerId;
use tracing::trace;

#[derive(Default, Debug)]
pub struct SessionManager {
    sessions: AHashMap<PeerId, Session>,
}

#[derive(Debug)]
pub struct Session {
    pub state: SessionState,
}

impl SessionManager {
    pub fn unconfirmed_connection(&mut self, peer_id: &PeerId) {
        let session = self.sessions.entry(*peer_id).or_insert(Session {
            state: SessionState::Available,
        });
        match session.state {
            SessionState::Dialing(count) | SessionState::New(count) => {
                session.state = SessionState::Connected(count);
            }
            _ => {}
        }
    }

    pub fn disconnected(&mut self, peer_id: &PeerId) {
        self.sessions.remove(peer_id);
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&PeerId, &mut Session)> {
        self.sessions.iter_mut()
    }

    pub fn create_session(&mut self, peer_id: &PeerId) {
        let session = self.sessions.entry(*peer_id).or_insert(Session {
            state: SessionState::New(1),
        });
        match session.state {
            SessionState::Available => {
                // already connected
                trace!("already connected to {}", peer_id);
                session.state = SessionState::Connected(1);
            }
            SessionState::Connected(ref mut count) => {
                *count += 1;
            }
            _ => {}
        }
    }

    pub fn current_dials(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| matches!(s.state, SessionState::Dialing(_)))
            .count()
    }

    pub fn destroy_session(&mut self, peer_id: &PeerId) {
        if let Some(session) = self.sessions.get_mut(peer_id) {
            match session.state {
                SessionState::Connected(ref mut count)
                | SessionState::New(ref mut count)
                | SessionState::Dialing(ref mut count) => {
                    *count -= 1;
                    if *count == 0 {
                        session.state = SessionState::Available;
                    }
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug)]
pub enum SessionState {
    /// Connected, but not used in a query.
    Available,
    /// Requested in a query, but not connected.
    New(usize),
    Dialing(usize),
    Connected(usize),
    // Disconnected will be removed from the list
}

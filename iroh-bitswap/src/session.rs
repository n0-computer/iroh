use std::num::NonZeroU8;

use ahash::AHashMap;
use libp2p::{
    swarm::{
        dial_opts::{DialOpts, PeerCondition},
        NetworkBehaviourAction, NotifyHandler,
    },
    PeerId,
};
use tracing::trace;

use crate::{behaviour::BitswapHandler, query::QueryManager, BitswapEvent};

#[derive(Default, Debug)]
pub struct SessionManager {
    sessions: AHashMap<PeerId, Session>,
    config: Config,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Limit of how many providers are concurrently dialed.
    pub dial_concurrency_factor_providers: NonZeroU8,
    /// Limit of how many dials are done per provider peer.
    pub dial_concurrency_factor_peer: NonZeroU8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dial_concurrency_factor_providers: 32.try_into().unwrap(),
            dial_concurrency_factor_peer: 32.try_into().unwrap(),
        }
    }
}

#[derive(Debug)]
pub struct Session {
    state: State,
    query_count: usize,
}

impl SessionManager {
    pub fn new(config: Config) -> Self {
        Self {
            sessions: Default::default(),
            config,
        }
    }

    pub fn new_connection(&mut self, peer_id: &PeerId) {
        let session = self.sessions.entry(*peer_id).or_insert(Session {
            state: State::Connected,
            query_count: 0,
        });

        match session.state {
            State::Dialing | State::New => {
                session.state = State::Connected;
            }
            _ => {}
        }
    }

    pub fn disconnected(&mut self, peer_id: &PeerId) {
        self.sessions.remove(peer_id);
    }

    pub fn create_session(&mut self, peer_id: &PeerId) {
        let session = self.sessions.entry(*peer_id).or_insert(Session {
            state: State::New,
            query_count: 0,
        });
        session.query_count += 1;
    }

    pub fn current_dials(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| matches!(s.state, State::Dialing))
            .count()
    }

    pub fn destroy_session(&mut self, peer_id: &PeerId) {
        if let Some(session) = self.sessions.get_mut(peer_id) {
            match session.state {
                State::Connected | State::New | State::Dialing => {
                    session.query_count -= 1;
                }
            }
        }
    }

    pub fn poll(
        &mut self,
        queries: &mut QueryManager,
    ) -> Option<NetworkBehaviourAction<BitswapEvent, BitswapHandler>> {
        // limit parallel dials
        let skip_dialing =
            self.current_dials() >= self.config.dial_concurrency_factor_providers.get() as _;

        for (peer_id, session) in self.sessions.iter_mut() {
            match session.state {
                State::New => {
                    if skip_dialing {
                        // no dialing this round
                        continue;
                    }
                    trace!("Dialing {}", peer_id);
                    let handler = Default::default();
                    session.state = State::Dialing;
                    return Some(NetworkBehaviourAction::Dial {
                        opts: DialOpts::peer_id(*peer_id)
                            .condition(PeerCondition::Always)
                            .override_dial_concurrency_factor(
                                self.config.dial_concurrency_factor_peer,
                            )
                            .build(),
                        handler,
                    });
                }
                State::Dialing => {
                    // Nothing to do yet
                }
                State::Connected => {
                    if let Some(event) = queries.poll(peer_id) {
                        return Some(NetworkBehaviourAction::NotifyHandler {
                            peer_id: *peer_id,
                            handler: NotifyHandler::Any,
                            event,
                        });
                    }
                }
            }
        }

        None
    }
}

#[derive(Debug)]
enum State {
    /// Requested in a query, but not connected.
    New,
    /// Currently Dialing
    Dialing,
    /// Connected
    Connected,
    // Disconnected will be removed from the list
}

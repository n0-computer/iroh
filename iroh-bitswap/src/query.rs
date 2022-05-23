use ahash::AHashSet;
use bytes::Bytes;
use cid::Cid;
use libp2p::PeerId;
use tracing::{error, trace};

use crate::{BitswapMessage, Block, Priority};

#[derive(Default, Debug)]
pub struct QueryManager {
    queries: Vec<Query>,
}

impl QueryManager {
    fn new_query(&mut self, query: Query) {
        self.queries.push(query);
    }

    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queries.len()
    }

    pub fn get(&mut self, cid: Cid, priority: Priority, providers: AHashSet<PeerId>) {
        self.new_query(Query::Get {
            providers,
            cid,
            priority,
            state: State::New,
        });
    }

    pub fn send(&mut self, receiver: PeerId, cid: Cid, data: Bytes) {
        self.new_query(Query::Send {
            receiver,
            block: Block { cid, data },
            state: State::New,
        });
    }

    pub fn cancel(&mut self, cid: &Cid) {
        let mut cancels = Vec::new();
        self.queries.retain(|query| match query {
            Query::Get {
                providers: _,
                cid: c,
                priority: _,
                state,
            } => {
                let to_remove = cid == c;
                if to_remove {
                    if let State::Sent(providers) = state {
                        // send out cancels to the providers
                        cancels.push((providers.clone(), *cid));
                    }
                }
                !to_remove
            }
            Query::Cancel { .. } => true,
            Query::Send { .. } => true,
        });

        for (providers, cid) in cancels.into_iter() {
            self.new_query(Query::Cancel {
                providers,
                cid,
                state: State::New,
            });
        }
    }

    pub fn process_block(&mut self, sender: &PeerId, block: &Block) -> (Vec<PeerId>, bool) {
        let mut cancels = Vec::new();
        let mut unused_providers = Vec::new();
        let mut wanted_block = false;

        self.queries.retain(|query| {
            match query {
                Query::Get {
                    providers,
                    cid,
                    priority: _,
                    state,
                } => {
                    if &block.cid == cid {
                        wanted_block = true;
                        for provider in providers {
                            unused_providers.push(*provider);
                        }

                        if let State::Sent(providers) = state {
                            // send out cancels to the providers
                            let mut providers = providers.clone();
                            providers.remove(sender);
                            if !providers.is_empty() {
                                cancels.push((providers, block.cid));
                            }
                        }
                        false
                    } else {
                        true
                    }
                }
                Query::Cancel { .. } => true,
                Query::Send { .. } => true,
            }
        });

        for (providers, cid) in cancels.into_iter() {
            self.new_query(Query::Cancel {
                providers,
                cid,
                state: State::New,
            });
        }

        (unused_providers, wanted_block)
    }

    pub fn poll(&mut self, peer_id: &PeerId) -> Option<BitswapMessage> {
        if self.is_empty() {
            return None;
        }

        // Aggregate all queries for this peer
        let mut msg = BitswapMessage::default();

        trace!("connected {}, looking for queries: {}", peer_id, self.len());
        let mut num_queries = 0;
        for query in self.queries.iter_mut().filter(|query| match query {
            Query::Get { providers, .. } | Query::Cancel { providers, .. } => {
                providers.contains(peer_id)
            }
            Query::Send { receiver, .. } => receiver == peer_id,
        }) {
            num_queries += 1;
            match query {
                Query::Get {
                    providers,
                    cid,
                    priority,
                    state,
                } => {
                    msg.wantlist_mut().want_block(cid, *priority);

                    providers.remove(peer_id);

                    // update state
                    match state {
                        State::New => {
                            *state = State::Sent([*peer_id].into_iter().collect());
                        }
                        State::Sent(sent_providers) => {
                            sent_providers.insert(*peer_id);
                        }
                    }
                }
                Query::Cancel {
                    providers,
                    cid,
                    state,
                } => {
                    msg.wantlist_mut().cancel_block(cid);

                    providers.remove(peer_id);

                    // update state
                    match state {
                        State::New => {
                            *state = State::Sent([*peer_id].into_iter().collect());
                        }
                        State::Sent(sent_providers) => {
                            sent_providers.insert(*peer_id);
                        }
                    }
                }
                Query::Send {
                    block,
                    state,
                    receiver,
                } => match state {
                    State::New => {
                        msg.add_block(block.clone());
                        *state = State::Sent([*receiver].into_iter().collect());
                    }
                    State::Sent(_) => {
                        // nothing to do anymore
                        num_queries -= 1;
                    }
                },
            }
        }

        if num_queries > 0 {
            if msg.is_empty() {
                error!("{} queries, but message is empty: {:?}", num_queries, msg);
            } else {
                trace!("sending message to {} {:?}", peer_id, msg);
                return Some(msg);
            }
        }

        None
    }
}

#[derive(Debug)]
enum Query {
    /// Fetch a single CID.
    Get {
        providers: AHashSet<PeerId>,
        cid: Cid,
        priority: Priority,
        state: State,
    },
    /// Cancel a single CID.
    Cancel {
        providers: AHashSet<PeerId>,
        cid: Cid,
        state: State,
    },
    /// Sends a single Block.
    Send {
        receiver: PeerId,
        block: Block,
        state: State,
    },
}

#[derive(Debug)]
enum State {
    New,
    Sent(AHashSet<PeerId>),
}

use ahash::{AHashMap, AHashSet};
use bytes::Bytes;
use cid::Cid;
use libp2p::PeerId;
use tracing::{error, trace};

use crate::{BitswapMessage, Block, Priority};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryId(usize);

#[derive(Default, Debug)]
pub struct QueryManager {
    queries: AHashMap<QueryId, Query>,
    next_id: usize,
}

impl QueryManager {
    fn new_query(&mut self, query: Query) -> QueryId {
        let id = QueryId(self.next_id);
        self.next_id += 1;
        self.queries.insert(id, query);
        id
    }

    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queries.len()
    }

    pub fn get(&mut self, cid: Cid, priority: Priority, providers: AHashSet<PeerId>) -> QueryId {
        self.new_query(Query::Get {
            providers,
            cid,
            priority,
            state: State::New,
        })
    }

    pub fn send(&mut self, receiver: PeerId, cid: Cid, data: Bytes) -> QueryId {
        self.new_query(Query::Send {
            receiver,
            block: Block { cid, data },
            state: State::New,
        })
    }

    pub fn cancel(&mut self, cid: &Cid) -> Option<QueryId> {
        let mut cancel = None;
        self.queries.retain(|_, query| match query {
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
                        cancel = Some((providers.clone(), *cid));
                    }
                }
                !to_remove
            }
            Query::Cancel { .. } => true,
            Query::Send { .. } => true,
        });

        cancel.map(|(providers, cid)| {
            self.new_query(Query::Cancel {
                providers,
                cid,
                state: State::New,
            })
        })
    }

    pub fn process_block(
        &mut self,
        sender: &PeerId,
        block: &Block,
    ) -> (Vec<PeerId>, Option<QueryId>) {
        let mut cancels = Vec::new();
        let mut unused_providers = Vec::new();
        let mut query_id = None;

        self.queries.retain(|id, query| {
            match query {
                Query::Get {
                    providers,
                    cid,
                    priority: _,
                    state,
                } => {
                    if &block.cid == cid {
                        query_id = Some(*id);
                        for provider in providers.iter() {
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

        (unused_providers, query_id)
    }

    pub fn poll(&mut self, peer_id: &PeerId) -> Option<BitswapMessage> {
        if self.is_empty() {
            return None;
        }

        // Aggregate all queries for this peer
        let mut msg = BitswapMessage::default();

        trace!("connected {}, looking for queries: {}", peer_id, self.len());
        let mut num_queries = 0;
        let mut finished_queries = Vec::new();

        for (query_id, query) in self.queries.iter_mut().filter(|(_, query)| match query {
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
                            if providers.is_empty() {
                                finished_queries.push(*query_id);
                            }
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
                        finished_queries.push(*query_id);
                    }
                },
            }
        }

        // remove finished queries
        for id in finished_queries {
            self.queries.remove(&id);
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

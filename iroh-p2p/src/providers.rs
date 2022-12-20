use std::collections::{HashSet, VecDeque};

use ahash::AHashMap;
use libp2p::{
    kad::{record::Key, store::MemoryStore, GetProvidersError, Kademlia, QueryId},
    PeerId,
};
use tokio::sync::mpsc;

type ResponseChannel = mpsc::Sender<Result<HashSet<PeerId>, String>>;

const OUTSTANDING_LIMIT: usize = 2048;

/// Manages provider queries to the DHT.
#[derive(Debug)]
pub struct Providers {
    outstanding_queries: VecDeque<Query>,
    current_queries: AHashMap<Key, RunningQuery>,
    max_running_queries: usize,
}

#[derive(Debug)]
struct Query {
    key: Key,
    queries: Vec<QueryDetails>,
}

#[derive(Debug)]
struct RunningQuery {
    query_id: QueryId,
    found_providers: HashSet<PeerId>,
    queries: Vec<QueryDetails>,
}

#[derive(Debug, Clone)]
struct QueryDetails {
    limit: usize,
    response_channel: ResponseChannel,
}

impl Providers {
    pub fn new(max_running_queries: usize) -> Self {
        Self {
            outstanding_queries: Default::default(),
            current_queries: Default::default(),
            max_running_queries,
        }
    }

    /// Drops queries if the queue is full.
    pub fn push(&mut self, key: Key, limit: usize, response_channel: ResponseChannel) -> bool {
        // Check if we already have a query running
        if let Some(running_query) = self.current_queries.get_mut(&key) {
            // send all found providers
            let providers = running_query
                .found_providers
                .iter()
                .copied()
                .take(limit)
                .collect::<HashSet<_>>();
            if !providers.is_empty() {
                let channel = response_channel.clone();
                tokio::task::spawn(async move {
                    let _ = channel.send(Ok(providers)).await;
                });
            }

            if running_query.found_providers.len() < limit && !response_channel.is_closed() {
                running_query.queries.push(QueryDetails {
                    limit,
                    response_channel,
                });
            }
            true
        } else if let Some(entry) = self.outstanding_queries.iter_mut().find(|q| q.key == key) {
            entry.queries.push(QueryDetails {
                limit,
                response_channel,
            });
            true
        } else if self.outstanding_queries.len() < OUTSTANDING_LIMIT {
            self.outstanding_queries.push_back(Query {
                key,
                queries: vec![QueryDetails {
                    limit,
                    response_channel,
                }],
            });
            true
        } else {
            false
        }
    }

    pub fn handle_get_providers_ok(
        &mut self,
        id: QueryId,
        is_last: bool,
        key: Key,
        providers: HashSet<PeerId>,
        kad: &mut Kademlia<MemoryStore>,
    ) {
        if let Some(query) = self.current_queries.get_mut(&key) {
            // Ignore queries we didn't start.
            if query.query_id != id {
                return;
            }

            // Remove all canceled requests
            query
                .queries
                .retain(|query| !query.response_channel.is_closed());

            // If no queries are left we are done.
            if query.queries.is_empty() {
                self.current_queries.remove(&key);
                if let Some(mut query) = kad.query_mut(&id) {
                    query.finish();
                }
                return;
            }

            // Determine new providers.
            let new_providers: HashSet<PeerId> = providers
                .difference(&query.found_providers)
                .copied()
                .collect();

            // Send out providers
            if !new_providers.is_empty() {
                let queries = query.queries.clone();
                let np = new_providers.clone();
                tokio::task::spawn(async move {
                    for query in queries {
                        let _ = query.response_channel.send(Ok(np.clone())).await;
                    }
                });

                query.found_providers.extend(new_providers);
            }

            if is_last {
                self.current_queries.remove(&key);
                // we freed a spot, poll for advancing queries
                self.poll(kad);
            } else {
                // Cleanup all that are finished.
                query
                    .queries
                    .retain(|q| q.limit >= query.found_providers.len());

                // Check if ther are any queries left.
                if query.queries.is_empty() {
                    self.current_queries.remove(&key);
                    if let Some(mut query) = kad.query_mut(&id) {
                        query.finish();
                    }

                    // we freed a spot, poll for advancing queries
                    self.poll(kad);
                }
            }
        }
    }

    pub fn handle_no_additional_records(&mut self, id: QueryId, kad: &mut Kademlia<MemoryStore>) {
        let mut key = None;
        for (k, q) in self.current_queries.iter() {
            if q.query_id == id {
                key = Some(k.clone());
                break;
            }
        }
        if let Some(key) = key {
            self.current_queries.remove(&key);
            // we freed a spot, poll for advancing queries
            self.poll(kad);
        }
    }

    pub fn handle_get_providers_error(
        &mut self,
        id: QueryId,
        error: GetProvidersError,
        kad: &mut Kademlia<MemoryStore>,
    ) {
        let key = match error {
            GetProvidersError::Timeout { key, .. } => key,
        };

        if let Some(query) = self.current_queries.remove(&key) {
            // Ignore queries not from us.
            if query.query_id != id {
                // Put back, this should rarely happen.
                self.current_queries.insert(key, query);
                return;
            }

            tokio::task::spawn(async move {
                for q in query.queries {
                    let _ = q.response_channel.send(Err("timeout".to_string())).await;
                }
            });

            // we freed a spot, poll for advancing queries
            self.poll(kad);
        }
    }

    pub fn poll(&mut self, kad: &mut Kademlia<MemoryStore>) {
        // Start a new query if not enough and have an outstanding one.
        if self.current_queries.len() < self.max_running_queries {
            if let Some(Query { key, queries }) = self.outstanding_queries.pop_front() {
                let query_id = kad.get_providers(key.clone());
                self.current_queries.insert(
                    key,
                    RunningQuery {
                        query_id,
                        found_providers: Default::default(),
                        queries,
                    },
                );
            }
        }

        // Cleanup
        for query in self.current_queries.values_mut() {
            query
                .queries
                .retain(|query| !query.response_channel.is_closed());
        }
        self.current_queries.retain(|_, query| {
            if query.queries.is_empty() {
                if let Some(mut query) = kad.query_mut(&query.query_id) {
                    query.finish();
                }
                false
            } else {
                true
            }
        });
    }
}

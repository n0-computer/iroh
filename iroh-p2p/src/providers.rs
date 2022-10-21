use std::collections::HashSet;

use ahash::AHashMap;
use libp2p::{
    kad::{record::Key, store::MemoryStore, GetProvidersError, Kademlia, QueryId},
    PeerId,
};
use tokio::sync::mpsc;

type ResponseChannel = mpsc::Sender<Result<HashSet<PeerId>, String>>;

/// Manages provider queries to the DHT.
#[derive(Debug)]
pub struct Providers {
    outstanding_queries: (mpsc::Sender<Query>, mpsc::Receiver<Query>),
    current_queries: AHashMap<Key, RunningQuery>,
    max_running_queries: usize,
}

#[derive(Debug)]
struct Query {
    key: Key,
    limit: usize,
    response_channel: ResponseChannel,
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
        let outstanding_queries = mpsc::channel(2048);

        Self {
            outstanding_queries,
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
        } else {
            self.outstanding_queries
                .0
                .try_send(Query {
                    key,
                    limit,
                    response_channel,
                })
                .is_ok()
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
                kad.query_mut(&id).map(|mut query| query.finish());
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
                    .retain(|q| dbg!(q.limit) >= dbg!(query.found_providers.len()));

                // Check if ther are any queries left.
                if query.queries.is_empty() {
                    self.current_queries.remove(&key);
                    kad.query_mut(&id).map(|mut query| query.finish());

                    // we freed a spot, poll for advancing queries
                    self.poll(kad);
                }
            }
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
            if let Ok(Query {
                key,
                limit,
                response_channel,
            }) = self.outstanding_queries.1.try_recv()
            {
                let query_id = kad.get_providers(key.clone());
                self.current_queries.insert(
                    key,
                    RunningQuery {
                        query_id,
                        found_providers: Default::default(),
                        queries: vec![QueryDetails {
                            limit,
                            response_channel,
                        }],
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
                kad.query_mut(&query.query_id)
                    .map(|mut query| query.finish());
                false
            } else {
                true
            }
        });
    }
}

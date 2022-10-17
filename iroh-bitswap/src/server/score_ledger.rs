use std::{
    fmt::Debug,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashMap;
use anyhow::{anyhow, Result};
use iroh_metrics::core::MRecorder;
use iroh_metrics::{bitswap::BitswapMetrics, inc};
use libp2p::PeerId;
use tokio::{
    sync::{oneshot, RwLock},
    task::JoinHandle,
};
use tracing::error;

use crate::server::ewma::ewma;

use super::decision::ScorePeerFunc;

/// The alpha for the EWMA used to track short term usefulness.
const SHORT_TERM_ALPHA: f64 = 0.5;
/// The alpha for the EWMA used to track long term usefulness.
const LONG_TERM_ALPHA: f64 = 0.05;
/// How frequently the engine should sample usefulness. Peers that
/// interact every shortTerm time period are considered "active".
const SHORT_TERM: Duration = Duration::from_secs(10);
/// Defines what "long term" means in terms of the
/// shortTerm duration. Peers that interact once every longTermRatio are
/// considered useful over the long term.
const LONG_TERM_RATIO: usize = 10;

// long/short term scores for tagging peers

/// This is a high tag but it grows _very_ slowly.
const LONG_TERM_SCORE: f64 = 10.;
/// This is a high tag but it'll go away quickly if we aren't using the peer.
const SHORT_TERM_SCORE: f64 = 10.;

/// Sotres the data exchange relationship between two peers.
#[derive(Debug)]
struct IndividualScoreLedger {
    /// The remote peer.
    partner: PeerId,
    /// Tracks bytes sent.
    bytes_sent: u64,
    /// Tracks bytes received.
    bytes_recv: u64,
    /// Last data exchange.
    last_exchange: Instant,
    /// Short term usefulnes.
    short_score: f64,
    /// Long term usefulnes.
    long_score: f64,
    /// Peer tagger score.
    score: usize,
    /// Number of exchanges we had with this peer.
    exchange_count: u64,
}

/// A summary of the ledger for the given peer.
#[derive(Debug)]
pub struct Receipt {
    pub peer: PeerId,
    pub value: f64,
    pub sent: u64,
    pub recv: u64,
    pub exchanged: u64,
}

impl IndividualScoreLedger {
    pub fn new(partner: PeerId) -> Self {
        IndividualScoreLedger {
            partner,
            bytes_sent: 0,
            bytes_recv: 0,
            last_exchange: Instant::now(),
            short_score: 0.,
            long_score: 0.,
            score: 0,
            exchange_count: 0,
        }
    }

    /// Increments the sent counter.
    pub fn add_to_sent_bytes(&mut self, n: usize) {
        self.exchange_count += 1;
        self.last_exchange = Instant::now();
        self.bytes_sent += n as u64;
    }

    /// Increments the received counters.
    pub fn add_to_recv_bytes(&mut self, n: usize) {
        self.exchange_count += 1;
        self.last_exchange = Instant::now();
        self.bytes_recv += n as u64;
    }

    /// Returns the receipt for this ledger
    pub fn receipt(&self) -> Receipt {
        Receipt {
            peer: self.partner,
            value: self.bytes_sent as f64 / (self.bytes_recv as f64 + 1.),
            sent: self.bytes_sent,
            recv: self.bytes_recv,
            exchanged: self.exchange_count,
        }
    }
}

#[derive(Debug)]
pub struct DefaultScoreLedger {
    state: Arc<State>,
    closer: oneshot::Sender<()>,
    worker: JoinHandle<()>,
}

struct State {
    /// The scoring function.
    score_peer: Box<dyn ScorePeerFunc>,
    ledger_map: RwLock<AHashMap<PeerId, IndividualScoreLedger>>,
    /// How frequently the engine should sample peer usefulness.
    peer_sample_interval: Duration,
}

impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("score_peer", &"Box<dyn ScorePeerFunc>")
            .field("ledger_map", &self.ledger_map)
            .field("peer_sample_interval", &self.peer_sample_interval)
            .finish()
    }
}

impl DefaultScoreLedger {
    pub async fn new(score_peer: Box<dyn ScorePeerFunc>) -> Self {
        let state = Arc::new(State {
            score_peer,
            ledger_map: Default::default(),
            peer_sample_interval: SHORT_TERM,
        });
        let (closer_s, mut closer_r) = oneshot::channel();
        let state_worker = state.clone();

        let rt = tokio::runtime::Handle::current();
        let worker = rt.spawn(async move {
            let state = state_worker;
            let mut ticker = tokio::time::interval(state.peer_sample_interval);

            let mut updates = Vec::new();
            let mut last_short_update = Instant::now();
            let mut last_long_update = Instant::now();
            let mut i = 0;

            loop {
                inc!(BitswapMetrics::ScoreLedgerLoopTick);
                tokio::select! {
                    biased;
                    _ = &mut closer_r => {
                        // shutdown
                        break;
                    }
                    _ = ticker.tick() => {
                        i = (i + 1) % LONG_TERM_RATIO;

                        let is_update_long = i == 0;
                        let mut ledger_map = state.ledger_map.write().await;
                        for ledger in ledger_map.values_mut() {
                            // update the short term score
                            ledger.short_score = if ledger.last_exchange > last_short_update {
                                ewma(ledger.short_score, SHORT_TERM_SCORE, SHORT_TERM_ALPHA)
                            } else {
                                ewma(ledger.short_score, 0., SHORT_TERM_ALPHA)
                            };

                            if is_update_long {
                                ledger.long_score = if ledger.last_exchange > last_long_update {
                                    ewma(ledger.long_score, LONG_TERM_SCORE, LONG_TERM_ALPHA)
                                } else {
                                    ewma(ledger.long_score, 0., LONG_TERM_ALPHA)
                                };
                            }

                            // calculate the new score

                            let lscore = if ledger.bytes_recv == 0 {
                                0.
                            } else {
                                ledger.bytes_recv as f64 / (ledger.bytes_recv + ledger.bytes_sent) as f64
                            };
                            let score =
                                ((ledger.short_score + ledger.long_score) * (lscore * 0.5 + 0.75)) as usize;

                            // store global updates if need, to be sent out outside of the lock
                            if ledger.score != score {
                                updates.push((ledger.partner, score));
                                ledger.score = score;
                            }
                        }

                        // record times
                        last_short_update = Instant::now();
                        if is_update_long {
                            last_long_update = Instant::now();
                        }

                        // apply updates
                        while let Some((peer, score)) = updates.pop() {
                            (state.score_peer)(&peer, score);
                        }
                    }
                }
            }
        });

        DefaultScoreLedger {
            state,
            closer: closer_s,
            worker,
        }
    }

    pub async fn stop(self) -> Result<()> {
        match self.closer.send(()) {
            Ok(_) => {
                self.worker.await.map_err(|e| anyhow!("{:?}", e))?;
            }
            Err(err) => {
                error!("failed to stop score ledger: {:?}", err);
            }
        }
        Ok(())
    }

    /// Increments the sent counter.
    pub async fn add_to_sent_bytes(&self, peer: &PeerId, n: usize) {
        let mut ledger = self.state.ledger_map.write().await;
        let entry = ledger
            .entry(*peer)
            .or_insert_with(|| IndividualScoreLedger::new(*peer));
        entry.add_to_sent_bytes(n);
    }

    /// Increments the received counters.
    pub async fn add_to_recv_bytes(&self, peer: &PeerId, n: usize) {
        let mut ledger = self.state.ledger_map.write().await;
        let entry = ledger
            .entry(*peer)
            .or_insert_with(|| IndividualScoreLedger::new(*peer));
        entry.add_to_recv_bytes(n);
    }

    /// Start accounting when a peer connects.
    pub async fn peer_connected(&self, peer: &PeerId) {
        self.state
            .ledger_map
            .write()
            .await
            .entry(*peer)
            .or_insert_with(|| IndividualScoreLedger::new(*peer));
    }

    /// Clean up accounting when a peer disconnects.
    pub async fn peer_disconnected(&self, peer: &PeerId) {
        self.state.ledger_map.write().await.remove(peer);
    }

    pub async fn receipt(&self, peer: &PeerId) -> Option<Receipt> {
        if let Some(ledger) = self.state.ledger_map.read().await.get(peer) {
            return Some(ledger.receipt());
        }

        None
    }
}

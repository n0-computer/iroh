use std::{sync::Arc, thread::JoinHandle, time::Duration};

use ahash::AHashSet;
use anyhow::{ensure, Result};
use cid::Cid;
use crossbeam::channel::{Receiver, Sender};
use derivative::Derivative;
use libp2p::PeerId;
use tracing::warn;

use crate::Block;

use self::session_wants::SessionWants;

use super::{
    block_presence_manager::BlockPresenceManager, peer_manager::PeerManager,
    provider_query_manager::ProviderQueryManager, session_interest_manager::SessionInterestManager,
    session_manager::SessionManager, session_peer_manager::SessionPeerManager,
};

mod cid_queue;
mod peer_response_tracker;
mod sent_want_blocks_tracker;
mod session_want_sender;
mod session_wants;

pub use self::session_want_sender::SessionWantSender;

const BROADCAST_LIVE_WANTS_LIMIT: usize = 64;

/// The kind of operation being executed in the event loop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Receive(Vec<Cid>),
    Want(Vec<Cid>),
    Cancel(Vec<Cid>),
    Broadcast(Vec<Cid>),
    WantsSent(Vec<Cid>),
}

impl Op {
    fn keys(&self) -> &[Cid] {
        match self {
            Op::Receive(ref keys) => keys,
            Op::Want(ref keys) => keys,
            Op::Cancel(ref keys) => keys,
            Op::Broadcast(ref keys) => keys,
            Op::WantsSent(ref keys) => keys,
        }
    }
}

/// Holds state for an individual bitswap transfer operation.
/// Allows bitswap to make smarter decisions about who to send what.
#[derive(Debug, Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

#[derive(Derivative)]
#[derivative(Debug)]
struct Inner {
    self_id: PeerId,
    id: u64,
    session_manager: SessionManager,
    peer_manager: PeerManager,
    session_peer_manager: SessionPeerManager,
    provider_finder: ProviderQueryManager,
    session_interest_manager: SessionInterestManager,
    session_wants: SessionWants,
    session_want_sender: SessionWantSender,
    latency_tracker: LatencyTracker,
    incoming: Sender<Op>,
    closer: Sender<()>,
    worker: Option<JoinHandle<()>>,
    #[derivative(Debug = "ignore")]
    notify: bus::BusReadHandle<Block>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.closer.send(()).ok();
        self.worker
            .take()
            .expect("missing worker")
            .join()
            .expect("worker error");
        //  Signal to the SessionManager that the session has been shutdown
        self.session_manager.remove_session(self.id);
    }
}

impl Session {
    pub fn new(
        self_id: PeerId,
        id: u64,
        session_manager: SessionManager,
        peer_manager: PeerManager,
        session_peer_manager: SessionPeerManager,
        provider_finder: ProviderQueryManager,
        session_interest_manager: SessionInterestManager,
        block_presence_manager: BlockPresenceManager,
        notify: bus::BusReadHandle<Block>,
        initial_search_delay: Duration,
        periodic_search_delay: Duration,
    ) -> Self {
        let base_tick_delay = Duration::from_millis(500);
        let session_want_sender = SessionWantSender::new(
            id,
            peer_manager.clone(),
            session_peer_manager.clone(),
            session_manager.clone(),
            block_presence_manager,
        );

        let (closer_s, closer_r) = crossbeam::channel::bounded(1);
        let (incoming_s, incoming_r) = crossbeam::channel::bounded(128);

        let worker = std::thread::spawn(move || {
            // Session run loop

            let idle_tick = crossbeam::channel::tick(initial_search_delay);
            let periodic_search_timer = crossbeam::channel::tick(periodic_search_delay);
            let mut loop_state = LoopState::new();

            loop {
                crossbeam::channel::select! {
                    recv(incoming_r) -> oper => {
                        match oper {
                            Ok(Op::Receive(keys)) => {}/*loop_state.handle_receive(keys)*/,
                            Ok(Op::Want(keys)) => {}/*loop_state.want_blocks(keys)*/,
                            Ok(Op::Cancel(keys)) => {
                                /*
                                loop_state.cancel_pending(&keys);
                                loop_state.cancel(&keys)*/
                            }
                            Ok(Op::WantsSent(keys)) => {/*loop_state.wants_sent(keys)*/},
                            Ok(Op::Broadcast(keys)) => {/*loop_state.broadcast(keys)*/},
                            Err(err) => {
                                // incoming channel gone, shutdown/panic
                                warn!("incoming channel error: {:?}", err);
                                break;
                            }
                        }
                    }
                    recv(idle_tick) -> _ => {
                        // The session hasn't received blocks for a while, broadcast
                        //loop_state.broadacast();
                    }
                    recv(periodic_search_timer) -> _ => {
                        // Periodically search for a random live want
                        // loop_state.handle_periodic_search();
                    }
                    recv(closer_r) -> _ => {
                        // Shutdown
                        break;
                    }
                }
            }
        });

        let inner = Arc::new(Inner {
            self_id,
            id,
            session_manager,
            peer_manager,
            session_peer_manager,
            provider_finder,
            session_interest_manager,
            session_wants: SessionWants::new(BROADCAST_LIVE_WANTS_LIMIT),
            session_want_sender,
            latency_tracker: Default::default(),
            incoming: incoming_s,
            notify,
            closer: closer_s,
            worker: Some(worker),
        });

        Session { inner }
    }

    pub fn id(&self) -> u64 {
        self.inner.id
    }

    /// Receives incoming blocks from the given peer.
    pub fn receive_from(&self, from: &PeerId, keys: &[Cid], haves: &[Cid], dont_haves: &[Cid]) {
        // The SessionManager tells each Session about all keys that it may be
        // interested in. Here the Session filters the keys to the ones that this
        // particular Session is interested in.
        let mut interested_res = self
            .inner
            .session_interest_manager
            .filter_session_interested(self.inner.id, &[keys, haves, dont_haves][..]);
        let dont_haves = interested_res.pop().unwrap();
        let haves = interested_res.pop().unwrap();
        let keys = interested_res.pop().unwrap();

        // Inform the session want sender that a message has been received
        self.inner
            .session_want_sender
            .update(*from, keys.clone(), haves, dont_haves);

        if keys.is_empty() {
            return;
        }

        // Inform the session that blocks have been received.
        self.inner.incoming.send(Op::Receive(keys)).ok();
    }

    // Fetches a single block.
    pub fn get_block(&self, key: Cid) -> Result<Block> {
        let r = self.get_blocks(vec![key])?;
        let block = r.recv()?;
        Ok(block)
    }

    // Fetches a set of blocks within the context of this session and
    // returns a channel that found blocks will be returned on. No order is
    // guaranteed on the returned blocks.
    pub fn get_blocks(&self, keys: Vec<Cid>) -> Result<Receiver<Block>> {
        ensure!(!keys.is_empty(), "missing keys");

        let (s, r) = crossbeam::channel::bounded(8);
        let mut remaining: AHashSet<Cid> = keys.iter().copied().collect();
        let mut blocks = self.inner.notify.add_rx();
        let incoming = self.inner.incoming.clone();
        std::thread::spawn(move || {
            for block in blocks.iter() {
                let cid = *block.cid();
                if remaining.contains(&cid) {
                    match s.send(block) {
                        Ok(_) => {
                            remaining.remove(&cid);
                        }
                        Err(_) => {
                            // receiver dropped, shutdown
                            break;
                        }
                    }
                }
            }

            // cancel all remaining
            incoming
                .send(Op::Cancel(remaining.into_iter().collect()))
                .ok();
        });

        self.inner.incoming.send(Op::Want(keys))?;

        Ok(r)
    }

    // TODO: pass these to sessionwantsender

    // // onWantsSent is called when wants are sent to a peer by the session wants sender
    // fn onWantsSent(p peer.ID, wantBlocks []cid.Cid, wantHaves []cid.Cid) {
    // 	allBlks := append(wantBlocks[:len(wantBlocks):len(wantBlocks)], wantHaves...)
    // 	s.nonBlockingEnqueue(op{op: opWantsSent, keys: allBlks})
    // }

    // // onPeersExhausted is called when all available peers have sent DONT_HAVE for
    // // a set of cids (or all peers become unavailable)
    // fn onPeersExhausted(ks []cid.Cid) {
    // 	s.nonBlockingEnqueue(op{op: opBroadcast, keys: ks})
    // }

    // // We don't want to block the sessionWantSender if the incoming channel
    // // is full. So if we can't immediately send on the incoming channel spin
    // // it off into a go-routine.
    // fn nonBlockingEnqueue(o op) {
    // 	select {
    // 	case s.incoming <- o:
    // 	default:
    // 		go func() {
    // 			select {
    // 			case s.incoming <- o:
    // 			case <-s.ctx.Done():
    // 			}
    // 		}()
    // 	}
    // }
}

#[derive(Debug)]
struct LoopState {}

impl LoopState {
    fn new() -> Self {
        LoopState {}
    }

    //     // Called when the session hasn't received any blocks for some time, or when
    //     // all peers in the session have sent DONT_HAVE for a particular set of CIDs.
    //     // Send want-haves to all connected peers, and search for new peers with the CID.
    //     fn broadcast(ctx context.Context, wants []cid.Cid) {
    // 	// If this broadcast is because of an idle timeout (we haven't received
    // 	// any blocks for a while) then broadcast all pending wants
    // 	if wants == nil {
    // 	    wants = s.sw.PrepareBroadcast()
    // 	}

    // 	// Broadcast a want-have for the live wants to everyone we're connected to
    // 	s.broadcastWantHaves(ctx, wants)

    // 	// do not find providers on consecutive ticks
    // 	// -- just rely on periodic search widening
    // 	 if len(wants) > 0 && (s.consecutiveTicks == 0) {
    // 	     // Search for providers who have the first want in the list.
    // 	     // Typically if the provider has the first block they will have
    // 	     // the rest of the blocks also.
    // 	     log.Debugw("FindMorePeers", "session", s.id, "cid", wants[0], "pending", len(wants))
    // 		 s.findMorePeers(ctx, wants[0])
    // 	 }
    // 	s.resetIdleTick()

    // 	// If we have live wants record a consecutive tick
    // 	 if s.sw.HasLiveWants() {
    // 	     s.consecutiveTicks++
    // 	 }
    //     }

    //     // handlePeriodicSearch is called periodically to search for providers of a
    //     // randomly chosen CID in the sesssion.
    //     fn handlePeriodicSearch(ctx context.Context) {
    // 	randomWant := s.sw.RandomLiveWant()
    // 	                  if !randomWant.Defined() {
    // 		              return
    // 	                  }

    // 	// TODO: come up with a better strategy for determining when to search
    // 	// for new providers for blocks.
    // 	s.findMorePeers(ctx, randomWant)

    // 	    s.broadcastWantHaves(ctx, []cid.Cid{randomWant})

    // 	    s.periodicSearchTimer.Reset(s.periodicSearchDelay.NextWaitTime())
    //     }

    //     // findMorePeers attempts to find more peers for a session by searching for
    //     // providers for the given Cid
    //     fn findMorePeers(ctx context.Context, c cid.Cid) {
    // 	go func(k cid.Cid) {
    // 	    for p := range s.providerFinder.FindProvidersAsync(ctx, k) {
    // 		// When a provider indicates that it has a cid, it's equivalent to
    // 		// the providing peer sending a HAVE
    // 		s.sws.Update(p, nil, []cid.Cid{c}, nil)
    // 	    }
    // 	}(c)
    //     }

    // // handleReceive is called when the session receives blocks from a peer
    // fn handleReceive(ks []cid.Cid) {
    // 	// Record which blocks have been received and figure out the total latency
    // 	// for fetching the blocks
    // 	wanted, totalLatency := s.sw.BlocksReceived(ks)
    // 	if len(wanted) == 0 {
    // 		return
    // 	}

    // 	// Record latency
    // 	s.latencyTrkr.receiveUpdate(len(wanted), totalLatency)

    // 	// Inform the SessionInterestManager that this session is no longer
    // 	// expecting to receive the wanted keys
    // 	s.sim.RemoveSessionWants(s.id, wanted)

    // 	s.idleTick.Stop()

    // 	// We've received new wanted blocks, so reset the number of ticks
    // 	// that have occurred since the last new block
    // 	s.consecutiveTicks = 0

    // 	s.resetIdleTick()
    // }

    // // wantBlocks is called when blocks are requested by the client
    // fn wantBlocks(ctx context.Context, newks []cid.Cid) {
    // 	if len(newks) > 0 {
    // 		// Inform the SessionInterestManager that this session is interested in the keys
    // 		s.sim.RecordSessionInterest(s.id, newks)
    // 		// Tell the sessionWants tracker that that the wants have been requested
    // 		s.sw.BlocksRequested(newks)
    // 		// Tell the sessionWantSender that the blocks have been requested
    // 		s.sws.Add(newks)
    // 	}

    // 	// If we have discovered peers already, the sessionWantSender will
    // 	// send wants to them
    // 	if s.sprm.PeersDiscovered() {
    // 		return
    // 	}

    // 	// No peers discovered yet, broadcast some want-haves
    // 	ks := s.sw.GetNextWants()
    // 	if len(ks) > 0 {
    // 		log.Infow("No peers - broadcasting", "session", s.id, "want-count", len(ks))
    // 		s.broadcastWantHaves(ctx, ks)
    // 	}
    // }

    // // Send want-haves to all connected peers
    // fn broadcastWantHaves(ctx context.Context, wants []cid.Cid) {
    // 	log.Debugw("broadcastWantHaves", "session", s.id, "cids", wants)
    // 	s.pm.BroadcastWantHaves(ctx, wants)
    // }

    // // The session will broadcast if it has outstanding wants and doesn't receive
    // // any blocks for some time.
    // // The length of time is calculated
    // //   - initially
    // //     as a fixed delay
    // //   - once some blocks are received
    // //     from a base delay and average latency, with a backoff
    // fn resetIdleTick() {
    // 	var tickDelay time.Duration
    // 	if !s.latencyTrkr.hasLatency() {
    // 		tickDelay = s.initialSearchDelay
    // 	} else {
    // 		avLat := s.latencyTrkr.averageLatency()
    // 		tickDelay = s.baseTickDelay + (3 * avLat)
    // 	}
    // 	tickDelay = tickDelay * time.Duration(1+s.consecutiveTicks)
    // 	s.idleTick.Reset(tickDelay)
    // }
}

#[derive(Debug, Default)]
struct LatencyTracker {
    total_latency: Duration,
    count: usize,
}

impl LatencyTracker {
    fn has_latency(&self) -> bool {
        !self.total_latency.is_zero() && self.count > 0
    }

    fn average_latency(&self) -> Duration {
        Duration::from_secs_f64(self.total_latency.as_secs_f64() / self.count as f64)
    }

    fn receive_update(&mut self, count: usize, latency: Duration) {
        self.count += count;
        self.total_latency += latency;
    }
}

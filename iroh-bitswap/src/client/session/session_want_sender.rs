use std::thread::JoinHandle;

use ahash::{AHashMap, AHashSet};
use cid::Cid;
use crossbeam::channel::Sender;
use libp2p::PeerId;

use crate::client::{
    block_presence_manager::BlockPresenceManager, peer_manager::PeerManager,
    session_manager::SessionManager, session_peer_manager::SessionPeerManager,
};

use super::{
    peer_response_tracker::PeerResponseTracker, sent_want_blocks_tracker::SentWantBlocksTracker,
};

/// Maximum number of changes to accept before blocking
const CHANGES_BUFFER_SIZE: usize = 128;

/// If the session receives this many DONT_HAVEs in a row from a peer,
/// it prunes the peer from the session
const PEER_DONT_HAVE_LIMIT: usize = 16;

/// Indicates whether a peer has a block.
///
/// Note that the order is important, we decide which peer to send a want to
/// based on knowing whether peer has the block. eg we're more likely to send
/// a want to a peer that has the block than a peer that doesnt have the block
/// so BPHave > BPDontHave
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum BlockPresence {
    DontHave = 0,
    Unknown = 1,
    Have = 2,
}

/// Encapsulates a message received by the session.
struct Update {
    /// Which peer sent the update
    from: PeerId,
    /// cids of blocks received
    keys: Vec<Cid>,
    /// HAVE message
    haves: Vec<Cid>,
    /// DONT_HAVE message
    dont_haves: Vec<Cid>,
}

/// Indicates a peer's connection state
struct PeerAvailability {
    target: PeerId,
    available: bool,
}

/// Can be new wants, a new message received by the session, or a change in the
/// connect status of a peer.
struct Change {
    /// New wants requested.
    add: Vec<Cid>,
    /// Wants cancelled.
    cancel: Vec<Cid>,
    /// New message received by session (blocks / HAVEs / DONT_HAVEs).
    update: Update,
    /// Peer has connected / disconnected.
    availability: PeerAvailability,
}

/// Convenience structs for passing around want-blocks and want-haves for a peer.
#[derive(Default, Debug, PartialEq, Eq)]
struct WantSets {
    want_blocks: AHashSet<Cid>,
    want_haves: AHashSet<Cid>,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct AllWants(AHashMap<PeerId, WantSets>);

impl AllWants {
    fn for_peer(&mut self, peer: &PeerId) -> &WantSets {
        &*self.0.entry(*peer).or_default()
    }
}

// type onSendFn func(to peer.ID, wantBlocks []cid.Cid, wantHaves []cid.Cid)
// type onPeersExhaustedFn func([]cid.Cid)

/// Responsible for sending want-have and want-block to
/// peers. For each want, it sends a single optimistic want-block request to
/// one peer and want-have requests to all other peers in the session.
/// To choose the best peer for the optimistic want-block it maintains a list
/// of how peers have responded to each want (HAVE / DONT_HAVE / Unknown) and
/// consults the peer response tracker (records which peers sent us blocks).
#[derive(Debug)]
struct SessionWantSender {
    /// The session ID
    session_id: u64,
    /// A channel that collects incoming changes (events)
    changes: Sender<Change>,
    /// Information about each want indexed by CID.
    wants: AHashMap<Cid, WantInfo>,
    /// Keeps track of how many consecutive DONT_HAVEs a peer has sent.
    peer_consecutive_dont_haves: AHashMap<PeerId, usize>,
    /// Tracks which peers we have send want-block to.
    sent_want_blocks_tracker: SentWantBlocksTracker,
    /// Tracks the number of blocks each peer sent us
    peer_response_tracker: PeerResponseTracker,
    /// Sends wants to peers
    peer_manager: PeerManager,
    /// Keeps track of peers in the session
    session_peer_manager: SessionPeerManager,
    /// Cancels wants.
    session_manager: SessionManager,
    /// Keeps track of which peer has / doesn't have a block.
    block_presence_manager: BlockPresenceManager,
    // /// Called when wants are sent
    // onSend onSendFn,
    // /// Called when all peers explicitly don't have a block
    // onPeersExhausted onPeersExhaustedFn,
    closer: Sender<()>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for SessionWantSender {
    fn drop(&mut self) {
        self.closer.send(()).ok();
        self.worker
            .take()
            .expect("missing worker")
            .join()
            .expect("worker paniced");

        // Unregister the session with the PeerManager
        self.peer_manager.unregister_session(self.session_id);
    }
}

impl SessionWantSender {
    pub fn new(
        session_id: u64,
        peer_manager: PeerManager,
        session_peer_manager: SessionPeerManager,
        session_manager: SessionManager,
        block_presence_manager: BlockPresenceManager,
    ) -> Self {
        let (changes_s, changes_r) = crossbeam::channel::bounded(64);
        let (closer_s, closer_r) = crossbeam::channel::bounded(1);

        let worker = std::thread::spawn(move || {
            // The main loop for processing incoming changes
            loop {
                crossbeam::channel::select! {
                    recv(closer_r) -> _ => {
                        break;
                    }
                    recv(changes_r) -> change => {
                        match change {
                            Ok(change) => {/*on_change(change)*/},
                            Err(err) => {
                                // sender gone
                                break;
                            }
                        }
                    }
                }
            }
        });

        SessionWantSender {
            session_id,
            changes: changes_s,
            wants: Default::default(),
            peer_consecutive_dont_haves: Default::default(),
            sent_want_blocks_tracker: SentWantBlocksTracker::default(),
            peer_response_tracker: PeerResponseTracker::default(),
            peer_manager,
            session_peer_manager,
            session_manager,
            block_presence_manager,
            worker: Some(worker),
            closer: closer_s,
        }
    }

    pub fn id(&self) -> u64 {
        self.session_id
    }

    // /// Called when new wants are added to the session
    // pub fn add(&self, ks []cid.Cid) {
    //     if len(ks) == 0 {
    //         return
    //     }
    //     sws.addChange(change{add: ks})
    // }

    // /// Called when a request is cancelled
    // pub fn cancel(&self, ks []cid.Cid) {
    //     if len(ks) == 0 {
    //         return
    //     }
    //     sws.addChange(change{cancel: ks})
    // }

    // // Called when the session receives a message with incoming blocks or HAVE / DONT_HAVE.
    // pub fn update(&self, from peer.ID, ks []cid.Cid, haves []cid.Cid, dontHaves []cid.Cid) {
    //     hasUpdate := len(ks) > 0 || len(haves) > 0 || len(dontHaves) > 0
    //         if !hasUpdate {
    //     	return
    //         }

    //     sws.addChange(change{
    //         update: update{from, ks, haves, dontHaves},
    //     })
    // }

    // // SignalAvailability is called by the PeerManager to signal that a peer has
    // // connected / disconnected
    // pub fn signal_availability(&self, p peer.ID, isAvailable bool) {
    //     availability := peerAvailability{p, isAvailable}
    //     // Add the change in a non-blocking manner to avoid the possibility of a
    //     // deadlock
    //     sws.addChangeNonBlocking(change{availability: availability})
    // }

    // // Shutdown the sessionWantSender
    // pub fn shutdown(&self) {
    //     // Signal to the run loop to stop processing
    //     sws.shutdown()
    //     // Wait for run loop to complete
    //         <-sws.closed
    // }

    // // addChange adds a new change to the queue
    // fn add_change(&self, c change) {
    //     select {
    //         case sws.changes <- c;
    //         case <-sws.ctx.Done();
    //     }
    // }

    // // addChangeNonBlocking adds a new change to the queue, using a go-routine
    // // if the change blocks, so as to avoid potential deadlocks
    // fn addChangeNonBlocking(&self, c change) {
    //     select {
    //         case sws.changes <- c:;
    //         default:
    //         // changes channel is full, so add change in a go routine instead
    //         go func() {
    //     	select {
    //     	    case sws.changes <- c:;
    //     	    case <-sws.ctx.Done():;
    //     	}
    //         }()
    //     }
    // }

    // // collectChanges collects all the changes that have occurred since the last
    // // invocation of onChange
    // fn collectChanges(&self, changes []change) []change {
    //     for len(changes) < changesBufferSize {
    //         select {
    //     	case next := <-sws.changes:;
    //     		      changes = append(changes, next)
    //     	              default:;
    //     		      return changes
    //     	}
    //         }
    //         return changes
    //     }
    // }

    // /// Processes the next set of changes
    // fn onChange(&self, changes []change) {
    //     // Several changes may have been recorded since the last time we checked,
    //     // so pop all outstanding changes from the channel
    //     changes = sws.collectChanges(changes)

    //     // Apply each change
    //                  availability := make(map[peer.ID]bool, len(changes))
    //         cancels := make([]cid.Cid, 0)
    //         var updates []update
    //         for _, chng := range changes {
    //     	// Initialize info for new wants
    //     	for _, c := range chng.add {
    //     	    sws.trackWant(c)
    //     	}

    //     	// Remove cancelled wants
    //     	for _, c := range chng.cancel {
    //     	    sws.untrackWant(c)
    //     	       cancels = append(cancels, c)
    //     	}

    //     	// Consolidate updates and changes to availability
    //     	if chng.update.from != "" {
    //     	    // If the update includes blocks or haves, treat it as signaling that
    //     	    // the peer is available
    //     	    if len(chng.update.ks) > 0 || len(chng.update.haves) > 0 {
    //     		p := chng.update.from
    //     			        availability[p] = true

    //     		// Register with the PeerManager
    //     		    sws.pm.RegisterSession(p, sws)
    //     	    }

    //     	    updates = append(updates, chng.update)
    //     	}
    //     	if chng.availability.target != "" {
    //     	    availability[chng.availability.target] = chng.availability.available
    //     	}
    //         }

    //     // Update peer availability
    //     newlyAvailable, newlyUnavailable := sws.processAvailability(availability)

    //     // Update wants
    //                                            dontHaves := sws.processUpdates(updates)

    //     // Check if there are any wants for which all peers have indicated they
    //     // don't have the want
    //                                                            sws.checkForExhaustedWants(dontHaves, newlyUnavailable)

    //     // If there are any cancels, send them
    //                                                               if len(cancels) > 0 {
    //     	                                                      sws.canceller.CancelSessionWants(sws.sessionID, cancels)
    //                                                               }

    //     // If there are some connected peers, send any pending wants
    //     if sws.spm.HasPeers() {
    //         sws.sendNextWants(newlyAvailable)
    //     }
    // }

    // // processAvailability updates the want queue with any changes in
    // // peer availability
    // // It returns the peers that have become
    // // - newly available
    // // - newly unavailable
    // fn  processAvailability(&self, availability map[peer.ID]bool) (avail []peer.ID, unavail []peer.ID) {
    //     var newlyAvailable []peer.ID;
    //     var newlyUnavailable []peer.ID;
    //     for p, isNowAvailable := range availability {
    //         stateChange := false
    //     	if isNowAvailable {
    //     	    isNewPeer := sws.spm.AddPeer(p)
    //     		                if isNewPeer {
    //     			            stateChange = true
    //     			                newlyAvailable = append(newlyAvailable, p)
    //     		                }
    //     	} else {
    //     	    wasAvailable := sws.spm.RemovePeer(p)
    //     		                   if wasAvailable {
    //     			               stateChange = true
    //     			                   newlyUnavailable = append(newlyUnavailable, p)
    //     		                   }
    //     	}

    //         // If the state has changed
    //         if stateChange {
    //     	sws.updateWantsPeerAvailability(p, isNowAvailable)
    //     	// Reset the count of consecutive DONT_HAVEs received from the
    //     	// peer
    //     	   delete(sws.peerConsecutiveDontHaves, p)
    //         }
    //     }

    //     return newlyAvailable, newlyUnavailable
    // }

    // // trackWant creates a new entry in the map of CID -> want info
    // fn  trackWant(&self, c cid.Cid) {
    //     if _, ok := sws.wants[c]; ok {
    //         return
    //     }

    //     // Create the want info
    //     wi := newWantInfo(sws.peerRspTrkr)
    //         sws.wants[c] = wi

    //     // For each available peer, register any information we know about
    //     // whether the peer has the block
    //         for _, p := range sws.spm.Peers() {
    //     	sws.updateWantBlockPresence(c, p)
    //         }
    // }

    // // untrackWant removes an entry from the map of CID -> want info
    // fn  untrackWant(&self, c cid.Cid) {
    //     delete(sws.wants, c)
    // }

    // // processUpdates processes incoming blocks and HAVE / DONT_HAVEs.
    // // It returns all DONT_HAVEs.
    // fn  processUpdates(&self, updates []update) []cid.Cid {
    //     // Process received blocks keys
    //     blkCids := cid.NewSet()
    //                   for _, upd := range updates {
    //     	          for _, c := range upd.ks {
    //     		      blkCids.Add(c)

    //     		      // Remove the want
    //     		             removed := sws.removeWant(c)
    //     		                           if removed != nil {
    //     			                       // Inform the peer tracker that this peer was the first to send
    //     			                       // us the block
    //     			                       sws.peerRspTrkr.receivedBlockFrom(upd.from)

    //     			                       // Protect the connection to this peer so that we can ensure
    //     			                       // that the connection doesn't get pruned by the connection
    //     			                       // manager
    //     			                                      sws.spm.ProtectConnection(upd.from)
    //     		                           }
    //     		      delete(sws.peerConsecutiveDontHaves, upd.from)
    //     	          }
    //                   }

    //     // Process received DONT_HAVEs
    //     dontHaves := cid.NewSet()
    //                     prunePeers := make(map[peer.ID]struct{})
    //         for _, upd := range updates {
    //     	for _, c := range upd.dontHaves {
    //     	    // Track the number of consecutive DONT_HAVEs each peer receives
    //     	    if sws.peerConsecutiveDontHaves[upd.from] == peerDontHaveLimit {
    //     		prunePeers[upd.from] = struct{}{}
    //     	    } else {
    //     		sws.peerConsecutiveDontHaves[upd.from]++
    //     	    }

    //     	    // If we already received a block for the want, there's no need to
    //     	    // update block presence etc
    //     	    if blkCids.Has(c) {
    //     		continue
    //     	    }

    //     	    dontHaves.Add(c)

    //     	    // Update the block presence for the peer
    //     		     sws.updateWantBlockPresence(c, upd.from)

    //     	    // Check if the DONT_HAVE is in response to a want-block
    //     	    // (could also be in response to want-have)
    //     		        if sws.swbt.haveSentWantBlockTo(upd.from, c) {
    //     			    // If we were waiting for a response from this peer, clear
    //     			    // sentTo so that we can send the want to another peer
    //     			    if sentTo, ok := sws.getWantSentTo(c); ok && sentTo == upd.from {
    //     				sws.setWantSentTo(c, "")
    //     			    }
    //     		        }
    //     	}
    //         }

    //     // Process received HAVEs
    //     for _, upd := range updates {
    //         for _, c := range upd.haves {
    //     	// If we haven't already received a block for the want
    //     	if !blkCids.Has(c) {
    //     	    // Update the block presence for the peer
    //     	    sws.updateWantBlockPresence(c, upd.from)
    //     	}

    //     	// Clear the consecutive DONT_HAVE count for the peer
    //     	delete(sws.peerConsecutiveDontHaves, upd.from)
    //     	    delete(prunePeers, upd.from)
    //         }
    //     }

    //     // If any peers have sent us too many consecutive DONT_HAVEs, remove them
    //     // from the session
    //     for p := range prunePeers {
    //         // Before removing the peer from the session, check if the peer
    //         // sent us a HAVE for a block that we want
    //         for c := range sws.wants {
    //     	if sws.bpm.PeerHasBlock(p, c) {
    //     	    delete(prunePeers, p)
    //     		break
    //     	}
    //         }
    //     }
    //     if len(prunePeers) > 0 {
    //         go func() {
    //     	for p := range prunePeers {
    //     	    // Peer doesn't have anything we want, so remove it
    //     	    log.Infof("peer %s sent too many dont haves, removing from session %d", p, sws.ID())
    //     	       sws.SignalAvailability(p, false)
    //     	}
    //         }()
    //     }

    //     return dontHaves.Keys()
    // }

    // // checkForExhaustedWants checks if there are any wants for which all peers
    // // have sent a DONT_HAVE. We call these "exhausted" wants.
    // fn  checkForExhaustedWants(&self, dontHaves []cid.Cid, newlyUnavailable []peer.ID) {
    //     // If there are no new DONT_HAVEs, and no peers became unavailable, then
    //     // we don't need to check for exhausted wants
    //     if len(dontHaves) == 0 && len(newlyUnavailable) == 0 {
    //         return
    //     }

    //     // We need to check each want for which we just received a DONT_HAVE
    //     wants := dontHaves

    //     // If a peer just became unavailable, then we need to check all wants
    //     // (because it may be the last peer who hadn't sent a DONT_HAVE for a CID)
    //         if len(newlyUnavailable) > 0 {
    //     	// Collect all pending wants
    //     	wants = make([]cid.Cid, len(sws.wants))
    //     	    for c := range sws.wants {
    //     		wants = append(wants, c)
    //     	    }

    //     	// If the last available peer in the session has become unavailable
    //     	// then we need to broadcast all pending wants
    //     	if !sws.spm.HasPeers() {
    //     	    sws.processExhaustedWants(wants)
    //     	       return
    //     	}
    //         }

    //     // If all available peers for a cid sent a DONT_HAVE, signal to the session
    //     // that we've exhausted available peers
    //     if len(wants) > 0 {
    //         exhausted := sws.bpm.AllPeersDoNotHaveBlock(sws.spm.Peers(), wants)
    //     	                sws.processExhaustedWants(exhausted)
    //     }
    // }

    // // processExhaustedWants filters the list so that only those wants that haven't
    // // already been marked as exhausted are passed to onPeersExhausted()
    // fn processExhaustedWants(&self, exhausted []cid.Cid) {
    //     newlyExhausted := sws.newlyExhausted(exhausted);
    //     if len(newlyExhausted) > 0 {
    //         sws.onPeersExhausted(newlyExhausted);
    //     }
    // }

    // // sendNextWants sends wants to peers according to the latest information
    // // about which peers have / dont have blocks
    // fn sendNextWants(&self, newlyAvailable []peer.ID) {
    //     toSend := make(allWants);

    //     for c, wi := range sws.wants {
    //         // Ensure we send want-haves to any newly available peers
    //         for _, p := range newlyAvailable {
    //     	toSend.forPeer(p).wantHaves.Add(c)
    //         }

    //         // We already sent a want-block to a peer and haven't yet received a
    //         // response yet
    //         if wi.sentTo != "" {
    //     	continue
    //         }

    //         // All the peers have indicated that they don't have the block
    //         // corresponding to this want, so we must wait to discover more peers
    //         if wi.bestPeer == "" {
    //     	// TODO: work this out in real time instead of using bestP?
    //     	continue
    //         }

    //         // Record that we are sending a want-block for this want to the peer
    //         sws.setWantSentTo(c, wi.bestPeer)

    //         // Send a want-block to the chosen peer
    //            toSend.forPeer(wi.bestPeer).wantBlocks.Add(c)

    //         // Send a want-have to each other peer
    //     	                                     for _, op := range sws.spm.Peers() {
    //     		                                 if op != wi.bestPeer {
    //     			                             toSend.forPeer(op).wantHaves.Add(c)
    //     		                                 }
    //     	                                     }
    //     }

    //     // Send any wants we've collected
    //     sws.sendWants(toSend)
    // }

    // // sendWants sends want-have and want-blocks to the appropriate peers
    // fn sendWants(&self, sends allWants) {
    //     // For each peer we're sending a request to
    //     for p, snd := range sends {
    //         // Piggyback some other want-haves onto the request to the peer
    //         for _, c := range sws.getPiggybackWantHaves(p, snd.wantBlocks) {
    //     	snd.wantHaves.Add(c)
    //         }

    //         // Send the wants to the peer.
    //         // Note that the PeerManager ensures that we don't sent duplicate
    //         // want-haves / want-blocks to a peer, and that want-blocks take
    //         // precedence over want-haves.
    //         wblks := snd.wantBlocks.Keys()
    //     	                   whaves := snd.wantHaves.Keys()
    //     	                                          sws.pm.SendWants(sws.ctx, p, wblks, whaves)

    //         // Inform the session that we've sent the wants
    //     	                                                sws.onSend(p, wblks, whaves)

    //         // Record which peers we send want-block to
    //     	                                                   sws.swbt.addSentWantBlocksTo(p, wblks)
    //     }
    // }

    // // getPiggybackWantHaves gets the want-haves that should be piggybacked onto
    // // a request that we are making to send want-blocks to a peer
    // fn  getPiggybackWantHaves(&self, p peer.ID, wantBlocks *cid.Set) []cid.Cid {
    //     var whs []cid.Cid
    //                  for c := range sws.wants {
    //     	         // Don't send want-have if we're already sending a want-block
    //     	         // (or have previously)
    //     	         if !wantBlocks.Has(c) && !sws.swbt.haveSentWantBlockTo(p, c) {
    //     		     whs = append(whs, c)
    //     	         }
    //                  }
    //     return whs
    // }

    // // newlyExhausted filters the list of keys for wants that have not already
    // // been marked as exhausted (all peers indicated they don't have the block)
    // fn  newlyExhausted(&self, ks []cid.Cid) []cid.Cid {
    //     var res []cid.Cid
    //                  for _, c := range ks {
    //     	         if wi, ok := sws.wants[c]; ok {
    //     		     if !wi.exhausted {
    //     			 res = append(res, c)
    //     			     wi.exhausted = true
    //     		     }
    //     	         }
    //                  }
    //     return res
    // }

    // // removeWant is called when the corresponding block is received
    // fn  removeWant(&self, c cid.Cid) *wantInfo {
    //     if wi, ok := sws.wants[c]; ok {
    //         delete(sws.wants, c)
    //     	return wi
    //     }
    //     return nil
    // }

    // // updateWantsPeerAvailability is called when the availability changes for a
    // // peer. It updates all the wants accordingly.
    // fn  updateWantsPeerAvailability(&self, p peer.ID, isNowAvailable bool) {
    //     for c, wi := range sws.wants {
    //         if isNowAvailable {
    //     	sws.updateWantBlockPresence(c, p)
    //         } else {
    //     	wi.removePeer(p)
    //         }
    //     }
    // }

    // // updateWantBlockPresence is called when a HAVE / DONT_HAVE is received for the given
    // // want / peer
    // fn  updateWantBlockPresence(&self, c cid.Cid, p peer.ID) {
    //     wi, ok := sws.wants[c]
    //         if !ok {
    //     	return
    //         }

    //     // If the peer sent us a HAVE or DONT_HAVE for the cid, adjust the
    //     // block presence for the peer / cid combination
    //     if sws.bpm.PeerHasBlock(p, c) {
    //         wi.setPeerBlockPresence(p, BPHave)
    //     } else if sws.bpm.PeerDoesNotHaveBlock(p, c) {
    //         wi.setPeerBlockPresence(p, BPDontHave)
    //     } else {
    //         wi.setPeerBlockPresence(p, BPUnknown)
    //     }
    // }

    // // Which peer was the want sent to
    // fn getWantSentTo(&self, c cid.Cid) (peer.ID, bool) {
    //     if wi, ok := sws.wants[c]; ok {
    //         return wi.sentTo, true
    //     }
    //     return "", false
    // }

    // // Record which peer the want was sent to
    // fn setWantSentTo(&self, c cid.Cid, p peer.ID) {
    //     if wi, ok := sws.wants[c]; ok {
    //         wi.sentTo = p
    //     }
    // }
}

/// Keeps track of the information for a want
#[derive(Debug)]
struct WantInfo {
    /// Tracks HAVE / DONT_HAVE sent to us for the want by each peer
    block_presence: AHashMap<PeerId, BlockPresence>,
    /// The peer that we've sent a want-block to (cleared when we get a response)
    sent_to: Option<PeerId>,
    /// The "best" peer to send the want to next
    best_peer: Option<PeerId>,
    /// Keeps track of how many hits / misses each peer has sent us for wants in the session.
    peer_response_tracker: PeerResponseTracker,
    /// True if all known peers have sent a DONT_HAVE for this want
    exhausted: bool,
}

impl WantInfo {
    fn new(peer_response_tracker: PeerResponseTracker) -> Self {
        WantInfo {
            block_presence: Default::default(),
            sent_to: None,
            best_peer: None,
            peer_response_tracker,
            exhausted: false,
        }
    }

    /// Sets the block presence for the given peer
    fn set_peer_block_presence(&mut self, peer: PeerId, bp: BlockPresence) {
        self.block_presence.insert(peer, bp);
        self.calculate_best_peer();

        // If a peer informed us that it has a block then make sure the want is no
        // longer flagged as exhausted (exhausted means no peers have the block)
        if bp == BlockPresence::Have {
            self.exhausted = false;
        }
    }

    /// Deletes the given peer from the want info
    fn remove_peer(&mut self, peer: &PeerId) {
        // If we were waiting to hear back from the peer that is being removed,
        // clear the sent_to field so we no longer wait
        if Some(peer) == self.sent_to.as_ref() {
            self.sent_to = None;
        }

        self.block_presence.remove(peer);
        self.calculate_best_peer();
    }

    /// Finds the best peer to send the want to next
    fn calculate_best_peer(&mut self) {
        // Recalculate the best peer
        let mut best_bp = BlockPresence::DontHave;
        let mut best_peer = None;

        // Find the peer with the best block presence, recording how many peers
        // share the block presence
        let mut count_with_best = 0;
        for (peer, bp) in &self.block_presence {
            if bp > &best_bp {
                best_bp = *bp;
                best_peer = Some(*peer);
                count_with_best = 1;
            } else if bp == &best_bp {
                count_with_best += 1;
            }
        }

        self.best_peer = best_peer;

        // If no peer has a block presence better than DONT_HAVE, bail out
        if best_peer.is_none() {
            return;
        }

        // If there was only one peer with the best block presence, we're done
        if count_with_best <= 1 {
            return;
        }

        // There were multiple peers with the best block presence, so choose one of
        // them to be the best
        let mut peers_with_best = Vec::new();
        for (peer, bp) in &self.block_presence {
            if bp == &best_bp {
                peers_with_best.push(*peer);
            }
        }
        self.best_peer = self.peer_response_tracker.choose(&peers_with_best);
    }
}

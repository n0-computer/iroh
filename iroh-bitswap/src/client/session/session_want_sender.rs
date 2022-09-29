use cid::Cid;
use libp2p::PeerId;

/// Maximum number of changes to accept before blocking
const CHANGES_BUFFER_SIZE: usize = 128;

/// If the session receives this many DONT_HAVEs in a row from a peer,
/// it prunes the peer from the session
const PEER_DONT_HAVE_LIMIT: usize = 16;

/// Iindicates whether a peer has a block.
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

// type onSendFn func(to peer.ID, wantBlocks []cid.Cid, wantHaves []cid.Cid)
// type onPeersExhaustedFn func([]cid.Cid)

// // sessionWantSender is responsible for sending want-have and want-block to
// // peers. For each want, it sends a single optimistic want-block request to
// // one peer and want-have requests to all other peers in the session.
// // To choose the best peer for the optimistic want-block it maintains a list
// // of how peers have responded to each want (HAVE / DONT_HAVE / Unknown) and
// // consults the peer response tracker (records which peers sent us blocks).
// type sessionWantSender struct {
// 	// The context is used when sending wants
// 	ctx context.Context
// 	// Called to shutdown the sessionWantSender
// 	shutdown func()
// 	// The sessionWantSender uses the closed channel to signal when it's
// 	// finished shutting down
// 	closed chan struct{}
// 	// The session ID
// 	sessionID uint64
// 	// A channel that collects incoming changes (events)
// 	changes chan change
// 	// Information about each want indexed by CID
// 	wants map[cid.Cid]*wantInfo
// 	// Keeps track of how many consecutive DONT_HAVEs a peer has sent
// 	peerConsecutiveDontHaves map[peer.ID]int
// 	// Tracks which peers we have send want-block to
// 	swbt *sentWantBlocksTracker
// 	// Tracks the number of blocks each peer sent us
// 	peerRspTrkr *peerResponseTracker
// 	// Sends wants to peers
// 	pm PeerManager
// 	// Keeps track of peers in the session
// 	spm SessionPeerManager
// 	// Cancels wants
// 	canceller SessionWantsCanceller
// 	// Keeps track of which peer has / doesn't have a block
// 	bpm *bsbpm.BlockPresenceManager
// 	// Called when wants are sent
// 	onSend onSendFn
// 	// Called when all peers explicitly don't have a block
// 	onPeersExhausted onPeersExhaustedFn
// }

// func newSessionWantSender(sid uint64, pm PeerManager, spm SessionPeerManager, canceller SessionWantsCanceller,
// 	bpm *bsbpm.BlockPresenceManager, onSend onSendFn, onPeersExhausted onPeersExhaustedFn) sessionWantSender {

// 	ctx, cancel := context.WithCancel(context.Background())
// 	sws := sessionWantSender{
// 		ctx:                      ctx,
// 		shutdown:                 cancel,
// 		closed:                   make(chan struct{}),
// 		sessionID:                sid,
// 		changes:                  make(chan change, changesBufferSize),
// 		wants:                    make(map[cid.Cid]*wantInfo),
// 		peerConsecutiveDontHaves: make(map[peer.ID]int),
// 		swbt:                     newSentWantBlocksTracker(),
// 		peerRspTrkr:              newPeerResponseTracker(),

// 		pm:               pm,
// 		spm:              spm,
// 		canceller:        canceller,
// 		bpm:              bpm,
// 		onSend:           onSend,
// 		onPeersExhausted: onPeersExhausted,
// 	}

// 	return sws
// }

// func (sws *sessionWantSender) ID() uint64 {
// 	return sws.sessionID
// }

// // Add is called when new wants are added to the session
// func (sws *sessionWantSender) Add(ks []cid.Cid) {
// 	if len(ks) == 0 {
// 		return
// 	}
// 	sws.addChange(change{add: ks})
// }

// // Cancel is called when a request is cancelled
// func (sws *sessionWantSender) Cancel(ks []cid.Cid) {
// 	if len(ks) == 0 {
// 		return
// 	}
// 	sws.addChange(change{cancel: ks})
// }

// // Update is called when the session receives a message with incoming blocks
// // or HAVE / DONT_HAVE
// func (sws *sessionWantSender) Update(from peer.ID, ks []cid.Cid, haves []cid.Cid, dontHaves []cid.Cid) {
// 	hasUpdate := len(ks) > 0 || len(haves) > 0 || len(dontHaves) > 0
// 	if !hasUpdate {
// 		return
// 	}

// 	sws.addChange(change{
// 		update: update{from, ks, haves, dontHaves},
// 	})
// }

// // SignalAvailability is called by the PeerManager to signal that a peer has
// // connected / disconnected
// func (sws *sessionWantSender) SignalAvailability(p peer.ID, isAvailable bool) {
// 	availability := peerAvailability{p, isAvailable}
// 	// Add the change in a non-blocking manner to avoid the possibility of a
// 	// deadlock
// 	sws.addChangeNonBlocking(change{availability: availability})
// }

// // Run is the main loop for processing incoming changes
// func (sws *sessionWantSender) Run() {
// 	for {
// 		select {
// 		case ch := <-sws.changes:
// 			sws.onChange([]change{ch})
// 		case <-sws.ctx.Done():
// 			// Unregister the session with the PeerManager
// 			sws.pm.UnregisterSession(sws.sessionID)

// 			// Close the 'closed' channel to signal to Shutdown() that the run
// 			// loop has exited
// 			close(sws.closed)
// 			return
// 		}
// 	}
// }

// // Shutdown the sessionWantSender
// func (sws *sessionWantSender) Shutdown() {
// 	// Signal to the run loop to stop processing
// 	sws.shutdown()
// 	// Wait for run loop to complete
// 	<-sws.closed
// }

// // addChange adds a new change to the queue
// func (sws *sessionWantSender) addChange(c change) {
// 	select {
// 	case sws.changes <- c:
// 	case <-sws.ctx.Done():
// 	}
// }

// // addChangeNonBlocking adds a new change to the queue, using a go-routine
// // if the change blocks, so as to avoid potential deadlocks
// func (sws *sessionWantSender) addChangeNonBlocking(c change) {
// 	select {
// 	case sws.changes <- c:
// 	default:
// 		// changes channel is full, so add change in a go routine instead
// 		go func() {
// 			select {
// 			case sws.changes <- c:
// 			case <-sws.ctx.Done():
// 			}
// 		}()
// 	}
// }

// // collectChanges collects all the changes that have occurred since the last
// // invocation of onChange
// func (sws *sessionWantSender) collectChanges(changes []change) []change {
// 	for len(changes) < changesBufferSize {
// 		select {
// 		case next := <-sws.changes:
// 			changes = append(changes, next)
// 		default:
// 			return changes
// 		}
// 	}
// 	return changes
// }

// // onChange processes the next set of changes
// func (sws *sessionWantSender) onChange(changes []change) {
// 	// Several changes may have been recorded since the last time we checked,
// 	// so pop all outstanding changes from the channel
// 	changes = sws.collectChanges(changes)

// 	// Apply each change
// 	availability := make(map[peer.ID]bool, len(changes))
// 	cancels := make([]cid.Cid, 0)
// 	var updates []update
// 	for _, chng := range changes {
// 		// Initialize info for new wants
// 		for _, c := range chng.add {
// 			sws.trackWant(c)
// 		}

// 		// Remove cancelled wants
// 		for _, c := range chng.cancel {
// 			sws.untrackWant(c)
// 			cancels = append(cancels, c)
// 		}

// 		// Consolidate updates and changes to availability
// 		if chng.update.from != "" {
// 			// If the update includes blocks or haves, treat it as signaling that
// 			// the peer is available
// 			if len(chng.update.ks) > 0 || len(chng.update.haves) > 0 {
// 				p := chng.update.from
// 				availability[p] = true

// 				// Register with the PeerManager
// 				sws.pm.RegisterSession(p, sws)
// 			}

// 			updates = append(updates, chng.update)
// 		}
// 		if chng.availability.target != "" {
// 			availability[chng.availability.target] = chng.availability.available
// 		}
// 	}

// 	// Update peer availability
// 	newlyAvailable, newlyUnavailable := sws.processAvailability(availability)

// 	// Update wants
// 	dontHaves := sws.processUpdates(updates)

// 	// Check if there are any wants for which all peers have indicated they
// 	// don't have the want
// 	sws.checkForExhaustedWants(dontHaves, newlyUnavailable)

// 	// If there are any cancels, send them
// 	if len(cancels) > 0 {
// 		sws.canceller.CancelSessionWants(sws.sessionID, cancels)
// 	}

// 	// If there are some connected peers, send any pending wants
// 	if sws.spm.HasPeers() {
// 		sws.sendNextWants(newlyAvailable)
// 	}
// }

// // processAvailability updates the want queue with any changes in
// // peer availability
// // It returns the peers that have become
// // - newly available
// // - newly unavailable
// func (sws *sessionWantSender) processAvailability(availability map[peer.ID]bool) (avail []peer.ID, unavail []peer.ID) {
// 	var newlyAvailable []peer.ID
// 	var newlyUnavailable []peer.ID
// 	for p, isNowAvailable := range availability {
// 		stateChange := false
// 		if isNowAvailable {
// 			isNewPeer := sws.spm.AddPeer(p)
// 			if isNewPeer {
// 				stateChange = true
// 				newlyAvailable = append(newlyAvailable, p)
// 			}
// 		} else {
// 			wasAvailable := sws.spm.RemovePeer(p)
// 			if wasAvailable {
// 				stateChange = true
// 				newlyUnavailable = append(newlyUnavailable, p)
// 			}
// 		}

// 		// If the state has changed
// 		if stateChange {
// 			sws.updateWantsPeerAvailability(p, isNowAvailable)
// 			// Reset the count of consecutive DONT_HAVEs received from the
// 			// peer
// 			delete(sws.peerConsecutiveDontHaves, p)
// 		}
// 	}

// 	return newlyAvailable, newlyUnavailable
// }

// // trackWant creates a new entry in the map of CID -> want info
// func (sws *sessionWantSender) trackWant(c cid.Cid) {
// 	if _, ok := sws.wants[c]; ok {
// 		return
// 	}

// 	// Create the want info
// 	wi := newWantInfo(sws.peerRspTrkr)
// 	sws.wants[c] = wi

// 	// For each available peer, register any information we know about
// 	// whether the peer has the block
// 	for _, p := range sws.spm.Peers() {
// 		sws.updateWantBlockPresence(c, p)
// 	}
// }

// // untrackWant removes an entry from the map of CID -> want info
// func (sws *sessionWantSender) untrackWant(c cid.Cid) {
// 	delete(sws.wants, c)
// }

// // processUpdates processes incoming blocks and HAVE / DONT_HAVEs.
// // It returns all DONT_HAVEs.
// func (sws *sessionWantSender) processUpdates(updates []update) []cid.Cid {
// 	// Process received blocks keys
// 	blkCids := cid.NewSet()
// 	for _, upd := range updates {
// 		for _, c := range upd.ks {
// 			blkCids.Add(c)

// 			// Remove the want
// 			removed := sws.removeWant(c)
// 			if removed != nil {
// 				// Inform the peer tracker that this peer was the first to send
// 				// us the block
// 				sws.peerRspTrkr.receivedBlockFrom(upd.from)

// 				// Protect the connection to this peer so that we can ensure
// 				// that the connection doesn't get pruned by the connection
// 				// manager
// 				sws.spm.ProtectConnection(upd.from)
// 			}
// 			delete(sws.peerConsecutiveDontHaves, upd.from)
// 		}
// 	}

// 	// Process received DONT_HAVEs
// 	dontHaves := cid.NewSet()
// 	prunePeers := make(map[peer.ID]struct{})
// 	for _, upd := range updates {
// 		for _, c := range upd.dontHaves {
// 			// Track the number of consecutive DONT_HAVEs each peer receives
// 			if sws.peerConsecutiveDontHaves[upd.from] == peerDontHaveLimit {
// 				prunePeers[upd.from] = struct{}{}
// 			} else {
// 				sws.peerConsecutiveDontHaves[upd.from]++
// 			}

// 			// If we already received a block for the want, there's no need to
// 			// update block presence etc
// 			if blkCids.Has(c) {
// 				continue
// 			}

// 			dontHaves.Add(c)

// 			// Update the block presence for the peer
// 			sws.updateWantBlockPresence(c, upd.from)

// 			// Check if the DONT_HAVE is in response to a want-block
// 			// (could also be in response to want-have)
// 			if sws.swbt.haveSentWantBlockTo(upd.from, c) {
// 				// If we were waiting for a response from this peer, clear
// 				// sentTo so that we can send the want to another peer
// 				if sentTo, ok := sws.getWantSentTo(c); ok && sentTo == upd.from {
// 					sws.setWantSentTo(c, "")
// 				}
// 			}
// 		}
// 	}

// 	// Process received HAVEs
// 	for _, upd := range updates {
// 		for _, c := range upd.haves {
// 			// If we haven't already received a block for the want
// 			if !blkCids.Has(c) {
// 				// Update the block presence for the peer
// 				sws.updateWantBlockPresence(c, upd.from)
// 			}

// 			// Clear the consecutive DONT_HAVE count for the peer
// 			delete(sws.peerConsecutiveDontHaves, upd.from)
// 			delete(prunePeers, upd.from)
// 		}
// 	}

// 	// If any peers have sent us too many consecutive DONT_HAVEs, remove them
// 	// from the session
// 	for p := range prunePeers {
// 		// Before removing the peer from the session, check if the peer
// 		// sent us a HAVE for a block that we want
// 		for c := range sws.wants {
// 			if sws.bpm.PeerHasBlock(p, c) {
// 				delete(prunePeers, p)
// 				break
// 			}
// 		}
// 	}
// 	if len(prunePeers) > 0 {
// 		go func() {
// 			for p := range prunePeers {
// 				// Peer doesn't have anything we want, so remove it
// 				log.Infof("peer %s sent too many dont haves, removing from session %d", p, sws.ID())
// 				sws.SignalAvailability(p, false)
// 			}
// 		}()
// 	}

// 	return dontHaves.Keys()
// }

// // checkForExhaustedWants checks if there are any wants for which all peers
// // have sent a DONT_HAVE. We call these "exhausted" wants.
// func (sws *sessionWantSender) checkForExhaustedWants(dontHaves []cid.Cid, newlyUnavailable []peer.ID) {
// 	// If there are no new DONT_HAVEs, and no peers became unavailable, then
// 	// we don't need to check for exhausted wants
// 	if len(dontHaves) == 0 && len(newlyUnavailable) == 0 {
// 		return
// 	}

// 	// We need to check each want for which we just received a DONT_HAVE
// 	wants := dontHaves

// 	// If a peer just became unavailable, then we need to check all wants
// 	// (because it may be the last peer who hadn't sent a DONT_HAVE for a CID)
// 	if len(newlyUnavailable) > 0 {
// 		// Collect all pending wants
// 		wants = make([]cid.Cid, len(sws.wants))
// 		for c := range sws.wants {
// 			wants = append(wants, c)
// 		}

// 		// If the last available peer in the session has become unavailable
// 		// then we need to broadcast all pending wants
// 		if !sws.spm.HasPeers() {
// 			sws.processExhaustedWants(wants)
// 			return
// 		}
// 	}

// 	// If all available peers for a cid sent a DONT_HAVE, signal to the session
// 	// that we've exhausted available peers
// 	if len(wants) > 0 {
// 		exhausted := sws.bpm.AllPeersDoNotHaveBlock(sws.spm.Peers(), wants)
// 		sws.processExhaustedWants(exhausted)
// 	}
// }

// // processExhaustedWants filters the list so that only those wants that haven't
// // already been marked as exhausted are passed to onPeersExhausted()
// func (sws *sessionWantSender) processExhaustedWants(exhausted []cid.Cid) {
// 	newlyExhausted := sws.newlyExhausted(exhausted)
// 	if len(newlyExhausted) > 0 {
// 		sws.onPeersExhausted(newlyExhausted)
// 	}
// }

// // convenience structs for passing around want-blocks and want-haves for a peer
// type wantSets struct {
// 	wantBlocks *cid.Set
// 	wantHaves  *cid.Set
// }

// type allWants map[peer.ID]*wantSets

// func (aw allWants) forPeer(p peer.ID) *wantSets {
// 	if _, ok := aw[p]; !ok {
// 		aw[p] = &wantSets{
// 			wantBlocks: cid.NewSet(),
// 			wantHaves:  cid.NewSet(),
// 		}
// 	}
// 	return aw[p]
// }

// // sendNextWants sends wants to peers according to the latest information
// // about which peers have / dont have blocks
// func (sws *sessionWantSender) sendNextWants(newlyAvailable []peer.ID) {
// 	toSend := make(allWants)

// 	for c, wi := range sws.wants {
// 		// Ensure we send want-haves to any newly available peers
// 		for _, p := range newlyAvailable {
// 			toSend.forPeer(p).wantHaves.Add(c)
// 		}

// 		// We already sent a want-block to a peer and haven't yet received a
// 		// response yet
// 		if wi.sentTo != "" {
// 			continue
// 		}

// 		// All the peers have indicated that they don't have the block
// 		// corresponding to this want, so we must wait to discover more peers
// 		if wi.bestPeer == "" {
// 			// TODO: work this out in real time instead of using bestP?
// 			continue
// 		}

// 		// Record that we are sending a want-block for this want to the peer
// 		sws.setWantSentTo(c, wi.bestPeer)

// 		// Send a want-block to the chosen peer
// 		toSend.forPeer(wi.bestPeer).wantBlocks.Add(c)

// 		// Send a want-have to each other peer
// 		for _, op := range sws.spm.Peers() {
// 			if op != wi.bestPeer {
// 				toSend.forPeer(op).wantHaves.Add(c)
// 			}
// 		}
// 	}

// 	// Send any wants we've collected
// 	sws.sendWants(toSend)
// }

// // sendWants sends want-have and want-blocks to the appropriate peers
// func (sws *sessionWantSender) sendWants(sends allWants) {
// 	// For each peer we're sending a request to
// 	for p, snd := range sends {
// 		// Piggyback some other want-haves onto the request to the peer
// 		for _, c := range sws.getPiggybackWantHaves(p, snd.wantBlocks) {
// 			snd.wantHaves.Add(c)
// 		}

// 		// Send the wants to the peer.
// 		// Note that the PeerManager ensures that we don't sent duplicate
// 		// want-haves / want-blocks to a peer, and that want-blocks take
// 		// precedence over want-haves.
// 		wblks := snd.wantBlocks.Keys()
// 		whaves := snd.wantHaves.Keys()
// 		sws.pm.SendWants(sws.ctx, p, wblks, whaves)

// 		// Inform the session that we've sent the wants
// 		sws.onSend(p, wblks, whaves)

// 		// Record which peers we send want-block to
// 		sws.swbt.addSentWantBlocksTo(p, wblks)
// 	}
// }

// // getPiggybackWantHaves gets the want-haves that should be piggybacked onto
// // a request that we are making to send want-blocks to a peer
// func (sws *sessionWantSender) getPiggybackWantHaves(p peer.ID, wantBlocks *cid.Set) []cid.Cid {
// 	var whs []cid.Cid
// 	for c := range sws.wants {
// 		// Don't send want-have if we're already sending a want-block
// 		// (or have previously)
// 		if !wantBlocks.Has(c) && !sws.swbt.haveSentWantBlockTo(p, c) {
// 			whs = append(whs, c)
// 		}
// 	}
// 	return whs
// }

// // newlyExhausted filters the list of keys for wants that have not already
// // been marked as exhausted (all peers indicated they don't have the block)
// func (sws *sessionWantSender) newlyExhausted(ks []cid.Cid) []cid.Cid {
// 	var res []cid.Cid
// 	for _, c := range ks {
// 		if wi, ok := sws.wants[c]; ok {
// 			if !wi.exhausted {
// 				res = append(res, c)
// 				wi.exhausted = true
// 			}
// 		}
// 	}
// 	return res
// }

// // removeWant is called when the corresponding block is received
// func (sws *sessionWantSender) removeWant(c cid.Cid) *wantInfo {
// 	if wi, ok := sws.wants[c]; ok {
// 		delete(sws.wants, c)
// 		return wi
// 	}
// 	return nil
// }

// // updateWantsPeerAvailability is called when the availability changes for a
// // peer. It updates all the wants accordingly.
// func (sws *sessionWantSender) updateWantsPeerAvailability(p peer.ID, isNowAvailable bool) {
// 	for c, wi := range sws.wants {
// 		if isNowAvailable {
// 			sws.updateWantBlockPresence(c, p)
// 		} else {
// 			wi.removePeer(p)
// 		}
// 	}
// }

// // updateWantBlockPresence is called when a HAVE / DONT_HAVE is received for the given
// // want / peer
// func (sws *sessionWantSender) updateWantBlockPresence(c cid.Cid, p peer.ID) {
// 	wi, ok := sws.wants[c]
// 	if !ok {
// 		return
// 	}

// 	// If the peer sent us a HAVE or DONT_HAVE for the cid, adjust the
// 	// block presence for the peer / cid combination
// 	if sws.bpm.PeerHasBlock(p, c) {
// 		wi.setPeerBlockPresence(p, BPHave)
// 	} else if sws.bpm.PeerDoesNotHaveBlock(p, c) {
// 		wi.setPeerBlockPresence(p, BPDontHave)
// 	} else {
// 		wi.setPeerBlockPresence(p, BPUnknown)
// 	}
// }

// // Which peer was the want sent to
// func (sws *sessionWantSender) getWantSentTo(c cid.Cid) (peer.ID, bool) {
// 	if wi, ok := sws.wants[c]; ok {
// 		return wi.sentTo, true
// 	}
// 	return "", false
// }

// // Record which peer the want was sent to
// func (sws *sessionWantSender) setWantSentTo(c cid.Cid, p peer.ID) {
// 	if wi, ok := sws.wants[c]; ok {
// 		wi.sentTo = p
// 	}
// }

// // wantInfo keeps track of the information for a want
// type wantInfo struct {
// 	// Tracks HAVE / DONT_HAVE sent to us for the want by each peer
// 	blockPresence map[peer.ID]BlockPresence
// 	// The peer that we've sent a want-block to (cleared when we get a response)
// 	sentTo peer.ID
// 	// The "best" peer to send the want to next
// 	bestPeer peer.ID
// 	// Keeps track of how many hits / misses each peer has sent us for wants
// 	// in the session
// 	peerRspTrkr *peerResponseTracker
// 	// true if all known peers have sent a DONT_HAVE for this want
// 	exhausted bool
// }

// // func newWantInfo(prt *peerResponseTracker, c cid.Cid, startIndex int) *wantInfo {
// func newWantInfo(prt *peerResponseTracker) *wantInfo {
// 	return &wantInfo{
// 		blockPresence: make(map[peer.ID]BlockPresence),
// 		peerRspTrkr:   prt,
// 		exhausted:     false,
// 	}
// }

// // setPeerBlockPresence sets the block presence for the given peer
// func (wi *wantInfo) setPeerBlockPresence(p peer.ID, bp BlockPresence) {
// 	wi.blockPresence[p] = bp
// 	wi.calculateBestPeer()

// 	// If a peer informed us that it has a block then make sure the want is no
// 	// longer flagged as exhausted (exhausted means no peers have the block)
// 	if bp == BPHave {
// 		wi.exhausted = false
// 	}
// }

// // removePeer deletes the given peer from the want info
// func (wi *wantInfo) removePeer(p peer.ID) {
// 	// If we were waiting to hear back from the peer that is being removed,
// 	// clear the sentTo field so we no longer wait
// 	if p == wi.sentTo {
// 		wi.sentTo = ""
// 	}
// 	delete(wi.blockPresence, p)
// 	wi.calculateBestPeer()
// }

// // calculateBestPeer finds the best peer to send the want to next
// func (wi *wantInfo) calculateBestPeer() {
// 	// Recalculate the best peer
// 	bestBP := BPDontHave
// 	bestPeer := peer.ID("")

// 	// Find the peer with the best block presence, recording how many peers
// 	// share the block presence
// 	countWithBest := 0
// 	for p, bp := range wi.blockPresence {
// 		if bp > bestBP {
// 			bestBP = bp
// 			bestPeer = p
// 			countWithBest = 1
// 		} else if bp == bestBP {
// 			countWithBest++
// 		}
// 	}
// 	wi.bestPeer = bestPeer

// 	// If no peer has a block presence better than DONT_HAVE, bail out
// 	if bestPeer == "" {
// 		return
// 	}

// 	// If there was only one peer with the best block presence, we're done
// 	if countWithBest <= 1 {
// 		return
// 	}

// 	// There were multiple peers with the best block presence, so choose one of
// 	// them to be the best
// 	var peersWithBest []peer.ID
// 	for p, bp := range wi.blockPresence {
// 		if bp == bestBP {
// 			peersWithBest = append(peersWithBest, p)
// 		}
// 	}
// 	wi.bestPeer = wi.peerRspTrkr.choose(peersWithBest)
// }

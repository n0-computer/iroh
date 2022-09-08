use std::task::{Context, Poll};

use caches::{Cache, PutResult};
use iroh_metrics::{core::MRecorder, inc, p2p::P2PMetrics};
use libp2p::{
    core::{connection::ConnectionId, transport::ListenerId, ConnectedPoint},
    swarm::{
        handler::DummyConnectionHandler, ConnectionHandler, DialError, IntoConnectionHandler,
        NetworkBehaviour, NetworkBehaviourAction, PollParameters,
    },
    Multiaddr, PeerId,
};

pub struct PeerManager {
    bad_peers: caches::RawLRU<PeerId, ()>,
}

const DEFAULT_BAD_PEER_CAP: usize = 10 * 4096;

impl Default for PeerManager {
    fn default() -> Self {
        PeerManager {
            bad_peers: caches::RawLRU::new(DEFAULT_BAD_PEER_CAP).unwrap(),
        }
    }
}

#[derive(Debug)]
pub enum PeerManagerEvent {}

impl PeerManager {
    pub fn is_bad_peer(&self, peer_id: &PeerId) -> bool {
        self.bad_peers.contains(peer_id)
    }
}

impl NetworkBehaviour for PeerManager {
    type ConnectionHandler = DummyConnectionHandler;
    type OutEvent = PeerManagerEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        DummyConnectionHandler::default()
    }

    fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
        vec![]
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        _connection_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        other_established: usize,
    ) {
        if other_established == 0 {
            let p = self.bad_peers.remove(peer_id);
            if p.is_some() {
                inc!(P2PMetrics::BadPeerRemoved);
            }
        }
    }

    fn inject_connection_closed(
        &mut self,
        _: &PeerId,
        _: &ConnectionId,
        _: &ConnectedPoint,
        _: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        _remaining_established: usize,
    ) {
    }

    fn inject_address_change(
        &mut self,
        _: &PeerId,
        _: &ConnectionId,
        _old: &ConnectedPoint,
        _new: &ConnectedPoint,
    ) {
    }

    fn inject_event(
        &mut self,
        _peer_id: PeerId,
        _connection: ConnectionId,
        _event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    ) {
    }

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        error: &DialError,
    ) {
        if let Some(peer_id) = peer_id {
            match error {
                DialError::ConnectionLimit(_) | DialError::DialPeerConditionFalse(_) => {}
                _ => {
                    if PutResult::Put == self.bad_peers.put(peer_id, ()) {
                        inc!(P2PMetrics::BadPeer);
                    }
                }
            }
        }
    }

    fn inject_listen_failure(
        &mut self,
        _local_addr: &Multiaddr,
        _send_back_addr: &Multiaddr,
        _handler: Self::ConnectionHandler,
    ) {
    }

    fn inject_new_listener(&mut self, _id: ListenerId) {}

    fn inject_new_listen_addr(&mut self, _id: ListenerId, _addr: &Multiaddr) {}

    fn inject_expired_listen_addr(&mut self, _id: ListenerId, _addr: &Multiaddr) {}

    fn inject_listener_error(&mut self, _id: ListenerId, _err: &(dyn std::error::Error + 'static)) {
    }

    fn inject_listener_closed(&mut self, _id: ListenerId, _reason: Result<(), &std::io::Error>) {}

    fn inject_new_external_addr(&mut self, _addr: &Multiaddr) {}

    fn inject_expired_external_addr(&mut self, _addr: &Multiaddr) {}

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        Poll::Pending
    }
}

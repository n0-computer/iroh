use std::{
    num::NonZeroUsize,
    task::{Context, Poll},
    time::Duration,
};

use ahash::AHashMap;
use iroh_metrics::{core::MRecorder, inc, p2p::P2PMetrics};
use libp2p::{
    core::{connection::ConnectionId, transport::ListenerId, ConnectedPoint},
    identify::Info as IdentifyInfo,
    ping::Success as PingSuccess,
    swarm::{
        dummy, ConnectionHandler, DialError, IntoConnectionHandler, NetworkBehaviour,
        NetworkBehaviourAction, PollParameters,
    },
    Multiaddr, PeerId,
};
use lru::LruCache;

pub struct PeerManager {
    info: AHashMap<PeerId, Info>,
    bad_peers: LruCache<PeerId, ()>,
}

#[derive(Default, Debug, Clone)]
pub struct Info {
    pub last_rtt: Option<Duration>,
    pub last_info: Option<IdentifyInfo>,
}

impl Info {
    pub fn latency(&self) -> Option<Duration> {
        // only approximation, this is wrong but the best we have for now
        self.last_rtt.map(|rtt| rtt / 2)
    }
}

const DEFAULT_BAD_PEER_CAP: Option<NonZeroUsize> = NonZeroUsize::new(10 * 4096);

impl Default for PeerManager {
    fn default() -> Self {
        PeerManager {
            info: Default::default(),
            bad_peers: LruCache::new(DEFAULT_BAD_PEER_CAP.unwrap()),
        }
    }
}

#[derive(Debug)]
pub enum PeerManagerEvent {}

impl PeerManager {
    pub fn is_bad_peer(&self, peer_id: &PeerId) -> bool {
        self.bad_peers.contains(peer_id)
    }

    pub fn inject_identify_info(&mut self, peer_id: PeerId, new_info: IdentifyInfo) {
        self.info.entry(peer_id).or_default().last_info = Some(new_info);
    }

    pub fn inject_ping(&mut self, peer_id: PeerId, new_ping: PingSuccess) {
        if let PingSuccess::Ping { rtt } = new_ping {
            self.info.entry(peer_id).or_default().last_rtt = Some(rtt);
        }
    }

    pub fn info_for_peer(&self, peer_id: &PeerId) -> Option<&Info> {
        self.info.get(peer_id)
    }
}

impl NetworkBehaviour for PeerManager {
    type ConnectionHandler = dummy::ConnectionHandler;
    type OutEvent = PeerManagerEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        dummy::ConnectionHandler
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        self.info
            .get(peer_id)
            .and_then(|i| i.last_info.as_ref())
            .map(|i| i.listen_addrs.clone())
            .unwrap_or_default()
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        _connection_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        failed_addresses: Option<&Vec<Multiaddr>>,
        other_established: usize,
    ) {
        if other_established == 0 {
            let p = self.bad_peers.pop(peer_id);
            if p.is_some() {
                inc!(P2PMetrics::BadPeerRemoved);
            }
        }

        if let Some(failed_addresses) = failed_addresses {
            if let Some(info) = self.info.get_mut(peer_id) {
                if let Some(ref mut info) = info.last_info {
                    for addr in failed_addresses {
                        if let Some(i) = info.listen_addrs.iter().position(|a| a == addr) {
                            info.listen_addrs.remove(i);
                        }
                    }
                }
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
                    if self.bad_peers.put(peer_id, ()).is_none() {
                        inc!(P2PMetrics::BadPeer);
                    }
                    self.info.remove(&peer_id);
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

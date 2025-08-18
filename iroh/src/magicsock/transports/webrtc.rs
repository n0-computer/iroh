use iroh_base::NodeId;
use n0_watcher::Watchable;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct SessionDescription(pub String);

#[derive(Debug, Clone)]
pub struct IceCandidate(pub String);

#[derive(Debug)]
pub struct WebRtcTransport {
    local_description: Watchable<Option<SessionDescription>>,

    remote_description: Watchable<Option<SessionDescription>>,

    local_candidates: Watchable<Vec<IceCandidate>>,

    remote_candidates: Watchable<Vec<IceCandidate>>,

    signaling_tx: mpsc::Sender<SignalingMessage>,

    signaling_rx: mpsc::Receiver<SignalingMessage>,

    state: Watchable<ConnectionState>,

    my_node_id: NodeId,
}

#[derive(Debug, Clone)]
pub enum ConnectionState {
    New,
    Gathering,
    Connecting,
    Connected,
    Failed,
    Closed,
}

#[derive(Debug, Clone)]
pub enum SignalingMessage {
    Offer(SessionDescription),
    Answer(SessionDescription),
    Candidate(IceCandidate),
}

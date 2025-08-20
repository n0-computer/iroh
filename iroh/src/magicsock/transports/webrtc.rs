mod actor;

pub use self::actor::Config as WebRtcActorConfig;
use crate::magicsock::transports::webrtc::actor::Config;
use bytes::Bytes;
use iroh_base::NodeId;
use n0_watcher::{Watchable, Watcher};
use snafu::Snafu;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use tokio::sync::mpsc;

#[cfg(wasm_browser)]
use web_sys::{
    RtcConfiguration, RtcDataChannel, RtcIceCandidate, RtcIceServer, RtcPeerConnection,
    RtcSessionDescription,
};

#[cfg(not(wasm_browser))]
use webrtc::{
    Error as WebRtcNativeError,
    data_channel::RTCDataChannel,
    ice_transport::ice_server::RTCIceServer,
    peer_connection::sdp::session_description::RTCSessionDescription,
    peer_connection::{RTCPeerConnection, configuration::RTCConfiguration},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionDescription(pub String);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IceCandidate(pub String);

pub(crate) struct WebRtcTransport {
    local_description: Watchable<Option<SessionDescription>>,
    remote_description: Watchable<Option<SessionDescription>>,
    local_candidates: Watchable<Vec<IceCandidate>>,
    remote_candidates: Watchable<Vec<IceCandidate>>,
    signaling_tx: mpsc::Sender<SignalingMessage>,
    signaling_rx: mpsc::Receiver<SignalingMessage>,
    state: Watchable<ConnectionState>,
    my_node_id: NodeId,

    #[cfg(not(wasm_browser))]
    peer_connection: Option<Arc<RTCPeerConnection>>,

    #[cfg(not(wasm_browser))]
    data_channel: Option<Arc<RTCDataChannel>>,

    #[cfg(wasm_browser)]
    peer_connection: Option<RtcPeerConnection>,

    #[cfg(wasm_browser)]
    data_channel: Option<RtcDataChannel>,
}

impl Debug for WebRtcTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebRtcTransport")
            .field("local_description", &self.local_description)
            .field("remote_description", &self.remote_description)
            .field("local_candidates", &self.local_candidates)
            .field("remote_candidates", &self.remote_candidates)
            .field("state", &self.state)
            .field("my_node_id", &self.my_node_id)
            .field("peer_connection", &"<hidden>")
            .field("data_channel", &"<hidden>")
            .finish()
    }
}

impl WebRtcTransport {
    #[cfg(not(wasm_browser))]
    pub async fn new(config: Config) -> Result<Self, WebRtcError> {
        let (signaling_tx, signaling_rx) = mpsc::channel(100);

        // Create native peer connection
        let configuration = RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        };

        let api_builder = webrtc::api::APIBuilder::new();
        let api = api_builder.build();

        let peer_connection = Arc::new(
            api.new_peer_connection(configuration)
                .await
                .map_err(|e| WebRtcError::Native { source: e })?,
        );
        Ok(Self {
            local_description: Watchable::new(None),
            remote_description: Watchable::new(None),
            local_candidates: Watchable::new(Vec::new()),
            remote_candidates: Watchable::new(Vec::new()),
            signaling_tx,
            signaling_rx,
            state: Watchable::new(ConnectionState::New),
            my_node_id: config.node_id,
            peer_connection: Some(peer_connection),
            data_channel: None,
        })
    }

    #[cfg(not(wasm_browser))]
    pub async fn create_offer(&mut self) -> Result<SessionDescription, WebRtcError> {
        let pc = self
            .peer_connection
            .as_ref()
            .ok_or(WebRtcError::NoPeerConnection)?;

        let data_channel = pc
            .create_data_channel("data", None)
            .await
            .map_err(|e| WebRtcError::Native { source: e })?;

        // Store the Arc directly, no need to dereference
        self.data_channel = Some(data_channel);

        let offer = pc
            .create_offer(None)
            .await
            .map_err(|e| WebRtcError::Native { source: e })?;

        pc.set_local_description(offer.clone())
            .await
            .map_err(|e| WebRtcError::Native { source: e })?;

        let desc = SessionDescription(offer.sdp);
        self.local_description
            .set(Some(desc.clone()))
            .map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        self.state
            .set(ConnectionState::Gathering)
            .map_err(|_| WebRtcError::SetStateFailed)?;

        Ok(desc)
    }

    #[cfg(not(wasm_browser))]
    pub async fn set_remote_description(
        &mut self,
        sdp: SessionDescription,
    ) -> Result<(), WebRtcError> {
        let pc = self
            .peer_connection
            .as_ref()
            .ok_or(WebRtcError::NoPeerConnection)?;

        let remote_desc = RTCSessionDescription::offer(sdp.0.clone())
            .map_err(|e| WebRtcError::Native { source: e })?;

        pc.set_remote_description(remote_desc)
            .await
            .map_err(|e| WebRtcError::Native { source: e })?;

        self.remote_description
            .set(Some(sdp))
            .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        Ok(())
    }

    pub async fn send_data(&self, data: &[u8]) -> Result<(), WebRtcError> {
        #[cfg(not(wasm_browser))]
        {
            let channel = self
                .data_channel
                .as_ref()
                .ok_or(WebRtcError::NoDataChannel)?;
            // let message = DataChannelMessage::Binary(data.to_vec());
            let message = Bytes::from(data.to_vec());
            channel
                .send(&message)
                .await
                .map_err(|e| WebRtcError::Native { source: e })?;
        }

        #[cfg(wasm_browser)]
        {
            let channel = self
                .data_channel
                .as_ref()
                .ok_or(WebRtcError::NoDataChannel)?;
            channel
                .send_with_u8_array(data)
                .map_err(|_| WebRtcError::SendFailed)?;
        }

        Ok(())
    }

    /// Get connection state
    pub fn connection_state(&self) -> ConnectionState {
        self.state.get()
    }

    /// Watch connection state changes
    pub fn watch_state(&self) -> impl Watcher<Value = ConnectionState> + '_ {
        self.state.watch()
    }

    #[cfg(wasm_browser)]
    pub fn new(config: Config) -> Result<Self, WebRtcError> {
        use wasm_bindgen::JsValue;

        let (signaling_tx, signaling_rx) = mpsc::channel(100);

        let mut rtc_config = RtcConfiguration::new();
        let ice_servers = js_sys::Array::new();

        let stun_server = RtcIceServer::new();
        stun_server.set_urls(&JsValue::from("stun:stun.l.google.com:19302"));
        ice_servers.push(&stun_server);

        rtc_config.set_ice_servers(&ice_servers);

        let peer_connection = RtcPeerConnection::new_with_configuration(&rtc_config)
            .map_err(|_| WebRtcError::PeerConnectionCreationFailed)?;

        Ok(Self {
            local_description: Watchable::new(None),
            remote_description: Watchable::new(None),
            local_candidates: Watchable::new(Vec::new()),
            remote_candidates: Watchable::new(Vec::new()),
            signaling_tx,
            signaling_rx,
            state: Watchable::new(ConnectionState::New),
            my_node_id: config.node_id,
            peer_connection: Some(peer_connection),
            data_channel: None,
        })
    }

    /// Create offer - WASM implementation
    #[cfg(wasm_browser)]
    pub async fn create_offer(&mut self) -> Result<SessionDescription, WebRtcError> {
        use wasm_bindgen_futures::JsFuture;

        let pc = self
            .peer_connection
            .as_ref()
            .ok_or(WebRtcError::NoPeerConnection)?;

        let data_channel = pc.create_data_channel("data");
        self.data_channel = Some(data_channel);

        let offer_promise = pc.create_offer();
        let offer = JsFuture::from(offer_promise)
            .await
            .map_err(|_| WebRtcError::OfferCreationFailed)?;

        let offer_desc = RtcSessionDescription::from(offer);
        let sdp = offer_desc.sdp();

        let set_local_promise = pc.set_local_description(&offer_desc);
        JsFuture::from(set_local_promise)
            .await
            .map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        let desc = SessionDescription(sdp);
        self.local_description
            .set(Some(desc.clone()))
            .map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        self.state
            .set(ConnectionState::Gathering)
            .map_err(|_| WebRtcError::SetStateFailed)?;

        Ok(desc)
    }

    #[cfg(wasm_browser)]
    pub async fn set_remote_description(
        &mut self,
        sdp: SessionDescription,
    ) -> Result<(), WebRtcError> {
        use wasm_bindgen_futures::JsFuture;

        let pc = self
            .peer_connection
            .as_ref()
            .ok_or(WebRtcError::NoPeerConnection)?;

        let mut remote_desc = RtcSessionDescription::new(web_sys::RtcSdpType::Offer);
        remote_desc.set_sdp(&sdp.0);

        let promise = pc.set_remote_description(&remote_desc);
        JsFuture::from(promise)
            .await
            .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        self.remote_description
            .set(Some(sdp))
            .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConnectionState {
    New,
    Gathering,
    Connecting,
    Connected,
    Failed,
    Closed,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SignalingMessage {
    Offer(SessionDescription),
    Answer(SessionDescription),
    Candidate(IceCandidate),
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum WebRtcError {
    #[snafu(display("No peer connection available"))]
    NoPeerConnection,

    #[snafu(display("No data channel available"))]
    NoDataChannel,

    #[snafu(display("Failed to create peer connection"))]
    PeerConnectionCreationFailed,

    #[snafu(display("Failed to create offer"))]
    OfferCreationFailed,

    #[snafu(display("Failed to set local description"))]
    SetLocalDescriptionFailed,

    #[snafu(display("Failed to set remote description"))]
    SetRemoteDescriptionFailed,

    #[snafu(display("Failed to send data"))]
    SendFailed,

    #[snafu(display("Failed to set connection state"))]
    SetStateFailed,

    #[snafu(transparent)]
    #[cfg(not(wasm_browser))]
    Native {
        #[snafu(source)]
        source: WebRtcNativeError,
    },
}

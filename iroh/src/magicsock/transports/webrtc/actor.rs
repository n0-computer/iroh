use std::collections::HashMap;
use std::fmt::{Debug};
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, trace, warn};

use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::RTCPeerConnection;
use iroh_base::{ChannelId, NodeId, SecretKey};
use crate::magicsock::transports::webrtc::{WebRtcError};
use webrtc::api::APIBuilder;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;

#[cfg(wasm_browser)]
use web_sys::{RtcPeerConnection, RtcConfiguration};
#[cfg(wasm_browser)]
use web_sys::RtcIceCandidateInit;
#[cfg(wasm_browser)]
use wasm_bindgen_futures::JsFuture;
#[cfg(wasm_browser)]
use web_sys::{RtcSessionDescription, RtcSdpType};

use webrtc::data_channel::data_channel_message::DataChannelMessage;
use iroh_relay::protos::relay::Datagrams;

#[cfg(not(wasm_browser))]
pub type PlatformRtcConfig = RTCConfiguration;

#[cfg(wasm_browser)]
pub type PlatformRtcConfig = RtcConfiguration;

#[cfg(not(wasm_browser))]
pub type PlatformCandidateIceType = RTCIceCandidateInit;

#[cfg(wasm_browser)]
pub type PlatformCandidateIceType = RtcIceCandidateInit;

// Application data - these go through the data channel after connection
#[derive(Debug, Clone)]
pub struct ApplicationData {
    pub payload: Bytes,
    pub message_type: ApplicationMessageType,
}

#[derive(Debug, Clone)]
pub enum ApplicationMessageType {
    Chat,
    File,
    Command,
    // Your app-specific types
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalingMessage {
    Offer { sdp: String },
    Answer { sdp: String },
    IceCandidate { candidate: String, sdp_mid: Option<String>, sdp_mline_index: Option<u16> },
    Error { message: String },
}

#[derive(Debug, Clone)]
pub struct WebRtcRecvDatagrams {
    pub src: NodeId,
    pub channel_id: ChannelId,
    pub datagrams: Datagrams,
}

#[derive(Debug, Clone)]
pub struct WebRtcData {
    /// The data channel identifier (optional - could use default channel)
    pub channel_id: ChannelId,
    /// Reliability mode for this message
    pub delivery_mode: WebRtcDeliveryMode,
    /// The actual data payload
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebRtcDeliveryMode {
    /// Reliable, ordered delivery (like TCP)
    Reliable,
    /// Unreliable, unordered delivery (like UDP)
    Unreliable,
    /// Reliable but unordered delivery
    ReliableUnordered,
}

#[derive(Debug, Clone)]
pub(crate) struct WebRtcSendItem {
    /// The destination for the WebRTC data
    pub(crate) dest_node: NodeId,
    /// WebRTC-specific data to send
    pub(crate) data: WebRtcData,
}

pub(crate) enum WebRtcActorMessage {
    CreateOffer {
        peer_node: NodeId,
        config: PlatformRtcConfig,
        response: tokio::sync::oneshot::Sender<Result<String, WebRtcError>>
    },
    SetRemoteDescription {
        peer_node: NodeId,
        sdp: String,
        response: tokio::sync::oneshot::Sender<Result<(), WebRtcError>>
    },
    AddIceCandidate {
        peer_node: NodeId,
        candidate: PlatformCandidateIceType,
    },
    CreateAnswer {
        peer_node: NodeId,
        offer_sdp: String,
        config: PlatformRtcConfig,
        response: tokio::sync::oneshot::Sender<Result<String, WebRtcError>>,
    },
    CloseConnection {
        peer_node: NodeId,
    }
}

impl Debug for WebRtcActorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebRtcActorMessage::CreateOffer { peer_node, .. } => {
                f.write_fmt(format_args!("CreateOffer(peer_node: {:?})", peer_node))
            }
            WebRtcActorMessage::SetRemoteDescription { peer_node, .. } => {
                f.write_fmt(format_args!("SetRemoteDescription(peer_node: {:?})", peer_node))
            }
            WebRtcActorMessage::AddIceCandidate { peer_node, .. } => {
                f.write_fmt(format_args!("AddIceCandidate(peer_node: {:?})", peer_node))
            }
            WebRtcActorMessage::CreateAnswer { peer_node, .. } => {
                f.write_fmt(format_args!("CreateAnswer(peer_node: {:?})", peer_node))
            }
            WebRtcActorMessage::CloseConnection { peer_node } => {
                f.write_fmt(format_args!("CloseConnection(peer_node: {:?})", peer_node))
            }
        }
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

pub struct PeerConnectionState {
    #[cfg(not(wasm_browser))]
    peer_connection: Arc<RTCPeerConnection>,
    #[cfg(not(wasm_browser))]
    data_channel: Option<Arc<RTCDataChannel>>,

    #[cfg(wasm_browser)]
    peer_connection: RtcPeerConnection,
    #[cfg(wasm_browser)]
    data_channel: Option<web_sys::RtcDataChannel>,

    connection_state: ConnectionState,
    is_initiator: bool,
    peer_node: NodeId,
    send_recv_datagram: mpsc::Sender<WebRtcRecvDatagrams>,
}

impl PeerConnectionState {
    #[cfg(not(wasm_browser))]
    pub async fn new(
        config: PlatformRtcConfig,
        is_initiator: bool,
        peer_node: NodeId,
        send_recv_datagram: mpsc::Sender<WebRtcRecvDatagrams>
    ) -> Result<Self, WebRtcError> {
        let api = APIBuilder::new().build();

        let peer_connection = Arc::new(
            api
                .new_peer_connection(config)
                .await
                .map_err(|_| WebRtcError::PeerConnectionCreationFailed)?
        );

        Ok(Self {
            peer_connection,
            data_channel: None,
            connection_state: ConnectionState::New,
            is_initiator,
            peer_node,
            send_recv_datagram,
        })
    }

    #[cfg(wasm_browser)]
    pub async fn new(
        config: PlatformRtcConfig,
        is_initiator: bool,
        peer_node: NodeId,
        send_recv_datagram: mpsc::Sender<WebRtcRecvDatagrams>
    ) -> Result<Self, WebRtcError> {
        use wasm_bindgen::JsValue;

        let peer_connection = RtcPeerConnection::new_with_configuration(&config)
            .map_err(|_| WebRtcError::PeerConnectionCreationFailed)?;

        Ok(Self {
            peer_connection,
            data_channel: None,
            connection_state: ConnectionState::New,
            is_initiator,
            peer_node,
            send_recv_datagram,
        })
    }

    #[cfg(not(wasm_browser))]
    pub async fn create_offer(&mut self) -> Result<String, WebRtcError> {
        let data_channel = self.peer_connection
            .create_data_channel("data", None)
            .await
            .map_err(|_| WebRtcError::DataChannelCreationFailed)?;

        self.data_channel = Some(data_channel);
        self.setup_data_channel_handler().await?;

        let offer = self.peer_connection
            .create_offer(None)
            .await
            .map_err(|_| WebRtcError::OfferCreationFailed)?;

        self.peer_connection
            .set_local_description(offer.clone())
            .await
            .map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        self.connection_state = ConnectionState::Gathering;
        Ok(offer.sdp)
    }

    #[cfg(wasm_browser)]
    pub async fn create_offer(&mut self) -> Result<String, WebRtcError> {
        use wasm_bindgen_futures::JsFuture;

        let data_channel = self.peer_connection.create_data_channel("data");
        self.data_channel = Some(data_channel);

        let offer_promise = self.peer_connection.create_offer();
        let offer = JsFuture::from(offer_promise).await
            .map_err(|_| WebRtcError::OfferCreationFailed)?;

        let offer_desc = RtcSessionDescription::from(offer);
        let sdp = offer_desc.sdp();

        let set_local_promise = self.peer_connection.set_local_description(&offer_desc);
        JsFuture::from(set_local_promise).await
            .map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        self.connection_state = ConnectionState::Gathering;
        Ok(sdp)
    }

    #[cfg(not(wasm_browser))]
    pub async fn handle_offer(&mut self, offer_sdp: String) -> Result<String, WebRtcError> {
        if self.is_initiator {
            return Err(WebRtcError::UnexpectedOffer);
        }

        let remote_desc = RTCSessionDescription::offer(offer_sdp)
            .map_err(|_| WebRtcError::OfferCreationFailed)?;

        // Set remote description first
        self.peer_connection
            .set_remote_description(remote_desc)
            .await
            .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        // Create answer
        let answer = self.peer_connection
            .create_answer(None)
            .await
            .map_err(|_| WebRtcError::AnswerCreationFailed)?;

        // Set local description
        self.peer_connection
            .set_local_description(answer.clone())
            .await
            .map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        // Setup data channel handler for incoming connections
        self.peer_connection.on_data_channel(Box::new(move |d| {
            Box::pin(async move {
                info!("Data channel received: {}", d.label());
                // Store the data channel and set up handlers
            })
        }));

        self.connection_state = ConnectionState::Gathering;
        Ok(answer.sdp)
    }

    #[cfg(not(wasm_browser))]
    pub async fn handle_answer(&mut self, answer_sdp: String) -> Result<(), WebRtcError> {
        if !self.is_initiator {
            return Err(WebRtcError::UnexpectedAnswer);
        }

        let remote_desc = RTCSessionDescription::answer(answer_sdp)
            .map_err(|_| WebRtcError::AnswerCreationFailed)?;

        self.peer_connection
            .set_remote_description(remote_desc)
            .await
            .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        self.connection_state = ConnectionState::Connecting;
        Ok(())
    }

    #[cfg(not(wasm_browser))]
    pub async fn setup_ice_candidate_handler(&mut self) -> Result<(), WebRtcError> {
        self.peer_connection.on_ice_candidate(Box::new(move |candidate| {
            Box::pin(async move {
                if let Some(candidate) = candidate {
                    info!("ICE candidate discovered: {:?}", candidate);
                    // Send this candidate via signaling mechanism

                }
            })
        }));
        Ok(())
    }

    #[cfg(not(wasm_browser))]
    async fn setup_data_channel_handler(&mut self) -> Result<(), WebRtcError> {
        let data_channel = self
            .data_channel
            .as_ref()
            .ok_or(WebRtcError::NoDataChannel)?
            .clone();

        let peer_node = self.peer_node;
        let sender = self.send_recv_datagram.clone();

        data_channel.on_open(Box::new(move || {
            Box::pin(async move {
                info!("Data channel opened for peer {}", peer_node);
            })
        }));

        data_channel.on_message(Box::new(move |msg| {
            let sender = sender.clone();
            let peer_node = peer_node;

            Box::pin(async move {
                if let Err(e) = Self::handle_application_message(msg, peer_node, sender).await {
                    error!("Failed to handle application message: {:?}", e);
                }
            })
        }));

        data_channel.on_error(Box::new(move |err| {
            Box::pin(async move {
                error!("Data channel error for peer {}: {:?}", peer_node, err);
            })
        }));

        data_channel.on_close(Box::new(move || {
            Box::pin(async move {
                info!("Data channel closed for peer {}", peer_node);
            })
        }));

        Ok(())
    }

    async fn handle_application_message(
        msg: DataChannelMessage,
        src: NodeId,
        sender: mpsc::Sender<WebRtcRecvDatagrams>
    ) -> Result<(), WebRtcError> {
        let datagrams = Datagrams::from(msg.data);
        let recv_data = WebRtcRecvDatagrams {
            src,
            channel_id: 0.into(), // Default channel
            datagrams,
        };

        sender.send(recv_data).await?;

        // if msg.is_string {
        //     match String::from_utf8(msg.data.to_vec()) {
        //         Ok(text) => {
        //             info!("Received text message from {}: {}", src, text);
        //         }
        //         Err(e) => {
        //             error!("Failed to parse text message from {}: {}", src, e);
        //         }
        //     }
        // } else {
        //     info!("Received binary data from {}: {} bytes", src, msg.data.len());
        // }

        Ok(())
    }

    #[cfg(not(wasm_browser))]
    pub async fn set_remote_description(&mut self, sdp: String) -> Result<(), WebRtcError> {
        let remote_desc = RTCSessionDescription::offer(sdp)
            .map_err(|e| WebRtcError::Native { source: Box::new(e) })?;

        self.peer_connection
            .set_remote_description(remote_desc)
            .await
            .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        Ok(())
    }

    #[cfg(wasm_browser)]
    pub async fn set_remote_description(&mut self, sdp: String) -> Result<(), WebRtcError> {
        let mut remote_desc = RtcSessionDescription::new(RtcSdpType::Offer);
        remote_desc.set_sdp(&sdp);

        let promise = self.peer_connection.set_remote_description(&remote_desc);
        JsFuture::from(promise)
            .await
            .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        Ok(())
    }

    #[cfg(not(wasm_browser))]
    pub async fn create_answer(&mut self, offer_sdp: String) -> Result<String, WebRtcError> {
        // First set the remote description
        let remote_desc = RTCSessionDescription::offer(offer_sdp)
            .map_err(|_| WebRtcError::OfferCreationFailed)?;

        self.peer_connection
            .set_remote_description(remote_desc)
            .await
            .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        // Then create the answer
        let answer = self.peer_connection
            .create_answer(None)
            .await
            .map_err(|_| WebRtcError::AnswerCreationFailed)?;

        self.peer_connection
            .set_local_description(answer.clone())
            .await
            .map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        Ok(answer.sdp)
    }

    #[cfg(wasm_browser)]
    pub async fn create_answer(&mut self) -> Result<String, WebRtcError> {
        let answer_promise = self.peer_connection.create_answer();
        let answer = JsFuture::from(answer_promise).await
            .map_err(|_| WebRtcError::AnswerCreationFailed)?;

        let answer_desc = RtcSessionDescription::from(answer);
        let sdp = answer_desc.sdp();

        let set_local_promise = self.peer_connection.set_local_description(&answer_desc);
        JsFuture::from(set_local_promise)
            .await
            .map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        Ok(sdp)
    }

    pub async fn send_data(&self, data: &WebRtcData) -> Result<(), WebRtcError> {
        #[cfg(not(wasm_browser))]
        {
            let channel = self.data_channel.as_ref().ok_or(WebRtcError::NoDataChannel)?;
            channel.send(&data.payload)
                .await
                .map_err(|_| WebRtcError::SendFailed)?;
        }

        #[cfg(wasm_browser)]
        {
            let channel = self.data_channel.as_ref().ok_or(WebRtcError::NoDataChannel)?;
            channel.send_with_u8_array(&data.payload)
                .map_err(|_| WebRtcError::SendFailed)?;
        }

        Ok(())
    }

    pub async fn add_ice_candidate_for_peer(&mut self, candidate: PlatformCandidateIceType) -> Result<(), WebRtcError> {
        #[cfg(not(wasm_browser))]
        self.peer_connection.add_ice_candidate(candidate).await
            .map_err(|_| WebRtcError::AddIceCandidatesFailed)?;

        #[cfg(wasm_browser)]
        {
            let promise = self.peer_connection.add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&candidate));
            JsFuture::from(promise).await
                .map_err(|_| WebRtcError::AddIceCandidatesFailed)?;
        }

        Ok(())
    }
}

pub(crate) struct WebRtcActor {
    config: WebRtcActorConfig,
    recv_datagram_sender: mpsc::Sender<WebRtcRecvDatagrams>, // this will send data from any peer
    peer_connections: HashMap<NodeId, PeerConnectionState>,
}

impl WebRtcActor {
    pub(crate) fn new(config: WebRtcActorConfig, recv_datagram_sender: mpsc::Sender<WebRtcRecvDatagrams>) -> Self {
        WebRtcActor {
            config,
            recv_datagram_sender,
            peer_connections: HashMap::new(),
        }
    }

    pub(crate) async fn run(
        &mut self,
        mut control_receiver: mpsc::Receiver<WebRtcActorMessage>,
        mut sender: mpsc::Receiver<WebRtcSendItem>
    ) {
        loop {
            select! {
                control_msg = control_receiver.recv() => {
                    match control_msg {
                        Some(msg) => {
                            if let Err(err) = self.handle_control_message(msg).await {
                                error!("Error handling control message: {}", err);
                            }
                        }
                        None => {
                            info!("Control channel closed, shutting down WebRTC actor");
                            break;
                        }
                    }
                }
                send_item = sender.recv() => {
                    match send_item {
                        Some(item) => {
                            if let Err(err) = self.handle_send_item(item).await {
                                error!("Error sending item: {}", err);
                            }
                        }
                        None => {
                            info!("Send channel closed");
                        }
                    }
                }
            }
        }
    }

    async fn handle_control_message(&mut self, msg: WebRtcActorMessage) -> Result<(), WebRtcError> {
        match msg {
            WebRtcActorMessage::CreateOffer { peer_node, config, response } => {
                let result = self.create_offer_for_peer(peer_node, config).await;
                let _ = response.send(result);
            }
            WebRtcActorMessage::SetRemoteDescription { peer_node, sdp, response } => {
                let result = self.set_remote_description_for_peer(peer_node, sdp).await;
                let _ = response.send(result);
            }
            WebRtcActorMessage::AddIceCandidate { peer_node, candidate } => {
                self.add_ice_candidate_for_peer(peer_node, candidate).await?;
            }
            WebRtcActorMessage::CreateAnswer { peer_node, offer_sdp, config, response } => {
                let result = self.create_answer_for_peer(peer_node, offer_sdp, config).await;
                let _ = response.send(result);
            }
            WebRtcActorMessage::CloseConnection { peer_node } => {
                self.close_peer_connection(peer_node).await?;
            }
        }
        Ok(())
    }

    async fn handle_send_item(&mut self, item: WebRtcSendItem) -> Result<(), WebRtcError> {
        info!("Sending data to peer {}: {:?}", item.dest_node, item.data);

        match self.peer_connections.get(&item.dest_node) {
            Some(peer_state) => {
                peer_state.send_data(&item.data).await?;
                trace!("Successfully sent data to peer {}", item.dest_node);
            }
            None => {
                warn!("No connection found for peer {}; dropping message", item.dest_node);
                return Err(WebRtcError::NoPeerConnection);
            }
        }
        Ok(())
    }

    async fn create_offer_for_peer(&mut self, dest_node: NodeId, config: PlatformRtcConfig) -> Result<String, WebRtcError> {
        info!("Creating offer for peer {}", dest_node);

        let mut peer_state = PeerConnectionState::new(
            config,
            true,
            dest_node,
            self.recv_datagram_sender.clone()
        ).await?;

        let offer_sdp = peer_state.create_offer().await?;
        self.peer_connections.insert(dest_node, peer_state);

        Ok(offer_sdp)
    }

    async fn set_remote_description_for_peer(&mut self, peer_node: NodeId, sdp: String) -> Result<(), WebRtcError> {
        info!("Setting remote description for peer {}", peer_node);

        match self.peer_connections.get_mut(&peer_node) {
            Some(peer_state) => {
                peer_state.set_remote_description(sdp).await
            }
            None => {
                error!("No peer connection found for node: {}", peer_node);
                Err(WebRtcError::NoPeerConnection)
            }
        }
    }

    async fn create_answer_for_peer(
        &mut self,
        peer_node: NodeId,
        offer_sdp: String,
        config: PlatformRtcConfig
    ) -> Result<String, WebRtcError> {
        info!("Creating answer for peer: {}", peer_node);

        match self.peer_connections.get_mut(&peer_node) {
            Some(peer_state) => {
                peer_state.create_answer(offer_sdp).await
            }
            None => {
                // Create new peer connection for answering
                let mut peer_state = PeerConnectionState::new(
                    config,
                    false,
                    peer_node,
                    self.recv_datagram_sender.clone()
                ).await?;

                let answer_sdp = peer_state.create_answer(offer_sdp).await?;
                self.peer_connections.insert(peer_node, peer_state);

                Ok(answer_sdp)
            }
        }
    }

    async fn add_ice_candidate_for_peer(
        &mut self,
        peer_node: NodeId,
        candidate: PlatformCandidateIceType
    ) -> Result<(), WebRtcError> {
        info!("Adding ICE candidate for peer {}", peer_node);

        match self.peer_connections.get_mut(&peer_node) {
            Some(peer_state) => {
                peer_state.add_ice_candidate_for_peer(candidate).await
            }
            None => {
                error!("No connection found for peer {}", peer_node);
                Err(WebRtcError::NoPeerConnection)
            }
        }
    }

    async fn close_peer_connection(&mut self, peer_node: NodeId) -> Result<(), WebRtcError> {
        info!("Closing connection for peer {}", peer_node);

        match self.peer_connections.remove(&peer_node) {
            Some(mut peer_state) => {
                peer_state.connection_state = ConnectionState::Closed;
                info!("Connection closed for peer {}", peer_node);
            }
            None => {
                warn!("Attempted to close non-existent connection for peer: {}", peer_node);
            }
        }
        Ok(())
    }

    fn get_default_config(&self) -> PlatformRtcConfig {
        #[cfg(not(wasm_browser))]
        {
            RTCConfiguration::default()
        }

        #[cfg(wasm_browser)]
        {
            RtcConfiguration::new()
        }
    }
}

pub struct WebRtcActorConfig {
    pub secret_key: SecretKey,
    pub rtc_config: PlatformRtcConfig,
    #[cfg(not(wasm_browser))]
    pub bind_addr: SocketAddr

}

impl WebRtcActorConfig {

    pub(crate) fn new(secret_key: SecretKey, #[cfg(not(wasm_browser))] bind_addr: SocketAddr) -> Self {
        Self {
            secret_key,
            rtc_config: Self::default_rtc_config(),
            #[cfg(not(wasm_browser))]
            bind_addr
        }
    }

    pub fn with_rtc_config(secret_key: SecretKey, rtc_config: PlatformRtcConfig, #[cfg(not(wasm_browser))] bind_addr: SocketAddr) -> Self {
        Self {
            secret_key,
            rtc_config,
            #[cfg(not(wasm_browser))]
            bind_addr
        }
    }

    fn default_rtc_config() -> PlatformRtcConfig {
        #[cfg(not(wasm_browser))]
        {
            use webrtc::ice_transport::ice_server::RTCIceServer;

            RTCConfiguration {
                ice_servers: vec![
                    RTCIceServer {
                        urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                        ..Default::default()
                    },
                    RTCIceServer {
                        urls: vec!["stun:stun1.l.google.com:19302".to_owned()],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }
        }

        #[cfg(wasm_browser)]
        {
            use wasm_bindgen::JsValue;

            let mut config = RtcConfiguration::new();

            // Create ICE servers array
            let ice_servers = js_sys::Array::new();

            // Add Google STUN servers
            let mut stun1 = web_sys::RtcIceServer::new();
            stun1.set_urls(&JsValue::from_str("stun:stun.l.google.com:19302"));
            ice_servers.push(&stun1.into());

            let mut stun2 = web_sys::RtcIceServer::new();
            stun2.set_urls(&JsValue::from_str("stun:stun1.l.google.com:19302"));
            ice_servers.push(&stun2.into());

            config.set_ice_servers(&ice_servers.into());
            config
        }
    }


}





impl<T> From<mpsc::error::SendError<T>> for WebRtcError {
    fn from(err: mpsc::error::SendError<T>) -> WebRtcError {
        WebRtcError::SendError {
            message: err.to_string(),
        }
    }
}

impl From<oneshot::error::RecvError> for WebRtcError {
    fn from(source: oneshot::error::RecvError) -> WebRtcError {
        WebRtcError::RecvError { source }
    }
}
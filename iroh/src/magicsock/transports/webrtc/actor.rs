use std::collections::HashMap;
use std::fmt::{Debug};
use std::sync::Arc;
use bytes::Bytes;
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, trace, warn};

use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::RTCPeerConnection;
use iroh_base::{NodeId, SecretKey};
use crate::magicsock::transports::webrtc::{WebRtcError};
use webrtc::api::APIBuilder;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;

#[cfg(wasm_browser)]
use web_sys::{RtcPeerConnection, RtcConfiguration};
#[cfg(wasm_browser)]
use web_sys::RtcCandidateInit;
use crate::magicsock::transports::ChannelId;

#[cfg(not(wasm_browser))]
pub type PlatformRtcConfig = RTCConfiguration;

#[cfg(wasm_browser)]
pub type PlatformRtcConfig = RtcConfiguration;

#[cfg(not(wasm_browser))]
pub type PlatformCandidateIceType =   RTCIceCandidateInit;

#[cfg(wasm_browser)]
pub type PlatformCandidateIceType = RtcCandidateInit;

#[derive(Debug, Clone)]
pub struct WebRtcRecvDatagrams {

    pub src: NodeId,
    pub channel_id: Option<u16>,
    pub data: Bytes

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
            WebRtcActorMessage::SetRemoteDescription { peer_node, sdp , ..} => {
                f.write_fmt(format_args!("SetRemoteDescription(peer_node: {:?})", peer_node))
            }
            WebRtcActorMessage::AddIceCandidate { candidate, .. } => {
                f.write_fmt(format_args!("AddIceCandidate(candidate: {:?})", candidate))
            }
            WebRtcActorMessage::CreateAnswer { peer_node, offer_sdp, .. } => {
                f.write_fmt(format_args!("CreateAnswer(peer_node: {:?}, offer_sdp: {:?})", peer_node, offer_sdp))
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
    data_channel: Option<Arc<WebRtcDataChannel>>,

    connection_state: ConnectionState
}

impl PeerConnectionState {

    #[cfg(not(wasm_browser))]
    pub async fn new(config: PlatformRtcConfig) -> Result<Self, WebRtcError>{
        let api = APIBuilder::new().build();

        let peer_connection = Arc::new(
                api
                    .new_peer_connection(config)
                    .await
                    .map_err(|_| WebRtcError::PeerConnectionCreationFailed)?
                );

        Ok(
            Self{
                peer_connection,
                data_channel: None,
                connection_state: ConnectionState::New
            }
        )
    }

    #[cfg(wasm_browser)]
    pub async fn new(config: PlatformRtcConfig) -> Result<Self, WebRtcError>{

        use wasm_bindgen::JsValue;

        let peer_connection = Arc::new(
            RtcPeerConnection::new_with_configuration(config)
                .map_err(|_| WebRtcError::PeerConnectionCreationFailed)?
        );

        Ok(Self {

            peer_connection,
            data_channel: None,
            connection_state: ConnectionState::New
        })

    }

    #[cfg(not(wasm_browser))]
    pub async fn create_offer(&mut self) -> Result<String, WebRtcError> {

        let data_channel = self.peer_connection
            .create_data_channel("data", None)
            .await
            .map_err(|_| WebRtcError::DataChannelCreationFailed)?;

        self.data_channel = Some(data_channel);

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

        use wasm_bindgen_futures::JsValue;
        use web_sys::RtcDataChannelInit;


        let data_channel = self.peer_connection.create_data_channel("data");
        self.data_channel = Some(data_channel);

        let offer_promise = self.peer_connection
        .create_offer(None);

        let offer = JsFuture::from(offer_promise).await.map_err(|_| WebRtcError::OfferCreationFailed)?;

        let offer_desc = RtcSessionDescription::from(offer);

        let sdp = offer_desc.sdp();
        let set_local_promise = self.peer_connection.set_local_description(&offer_desc);
        JsFuture::from(set_local_promise).await.map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        self.connection_state = ConnectionState::Gathering;

        Ok(sdp)

    }

    #[cfg(not(wasm_browser))]
    pub async fn set_remote_description(&mut self, sdp: String) -> Result<(), WebRtcError>{

        let remote_desc = RTCSessionDescription::offer(sdp)
            .map_err(|e| WebRtcError::Native {source: e})?;
        self.peer_connection
            .set_remote_description(remote_desc)
        .await
            .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        Ok(())

    }

    #[cfg(wasm_browser)]
    pub async fn set_remote_description(&mut self, sdp: String) -> Result<(), WebRtcError>{

        use wasm_bindgen_futures::JsFuture;

        let mut remote_desc = RtcSessionDescription::new(RTCSdpType::Offer);

        remote_desc.set_sdp(&sdp);

        let promise = self.peer_connection.set_remote_description(&remote_desc);

        JsFuture::from(promise)
            .await
        .map_err(|_| WebRtcError::SetRemoteDescriptionFailed)?;

        Ok(())

    }

    #[cfg(not(wasm_browser))]
    pub async fn create_answer(&mut self, _offer_sdp: String) -> Result<String, WebRtcError>{

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
    pub async fn create_answer(&mut self) -> Result<String, WebRtcError>{

        use wasm_bindgen_futures::JsFuture;

        let answer_promise = self.peer_connection.create_answer();

        let answer = JsFuture::from(answer_promise).await.map_err(|_| WebRtcError::AnswerCreationFailed)?;

        let answer_desc = RtcSessionDescription::from(answer);

        let sdp = answer_desc.sdp();

        let set_local_promise = self.peer_connection.set_local_description(&answer_desc);

        JsFuture::from(set_local_promise)
        .await
        .map_err(|_| WebRtcError::SetLocalDescriptionFailed)?;

        Ok(sdp)

    }


    pub async fn send_data(&self, data: &WebRtcData) -> Result<(), WebRtcError>{

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


    pub async fn add_ice_candidate_for_peer(&mut self, candidate: PlatformCandidateIceType) -> Result<(), WebRtcError>{

        #[cfg(not(wasm_browser))]
        self.peer_connection.add_ice_candidate(candidate).await.map_err(|_| WebRtcError::AddIceCandidatesFailed)?;

        #[cfg(wasm_browser)]
        self.peer_connection.add_ice_candidate(candidate);

        Ok(())


    }

}


pub(crate) struct WebRtcActor {
    
    config: WebRtcActorConfig,
    recv_datagram_sender: mpsc::Sender<WebRtcRecvDatagrams>,
    peer_connections: HashMap<NodeId, PeerConnectionState>
    
}

impl WebRtcActor {
    pub(crate) fn new(config: WebRtcActorConfig, recv_datagram_sender: mpsc::Sender<WebRtcRecvDatagrams>) -> Self {

        WebRtcActor {
            config,
            recv_datagram_sender,
            peer_connections: HashMap::new()
        }
    }

    /// control_receiver for shutting down of the actor (create offer, set descriptions, etc.)
    /// send_receiver for sending messages to internet
    pub(crate) async fn run(&mut self,
           mut control_receiver: mpsc::Receiver<WebRtcActorMessage>,
           mut sender: mpsc::Receiver<WebRtcSendItem>
    ){
        loop {
            select! {
                // Handle control message (create offers , set descriptions, etc)
                control_msg = control_receiver.recv() => {
                    match control_msg {
                        Some(msg) => {
                            if let Err(err) = self.handle_control_message(msg).await {
                                error!("Error handling control message: {}", err);
                            }
                        }
                        None => {
                            println!("Control channel closed, shutting down webrtc actor");
                            break;
                        }
                    }
                }
                // Handle outgoing data to be sent to peers
                send_item = sender.recv() => {
                    match send_item {
                        Some(item) => {
                            if let Err(err) = self.handle_send_item(item).await {
                                error!("Error sending item: {}", err);
                            }
                        }
                        None => {
                            println!("Send channel closed");
                        }
                    }
                }
            }
        }
    }


    /// Handle control message like creating offer, setting remote descriptions, etc
    async fn handle_control_message(
        &mut self,
        msg: WebRtcActorMessage
    ) -> Result<(),WebRtcError>{

        match msg {
            WebRtcActorMessage::CreateOffer { peer_node,config,  response } => {

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

                self.close_peer_connection(peer_node).await?

            }
        }

        Ok(())

    }

    async fn handle_send_item(

        &mut self,
        item: WebRtcSendItem

    ) -> Result<(),WebRtcError>{

        info!("Sending data to peer {}: {:?}", item.dest_node, item.data);

        match self.peer_connections.get(&item.dest_node){

            Some(peer_state) => {

                peer_state.send_data(&item.data).await?;
                trace!("Successfully sent data to peer {}", item.dest_node);

            }
            None =>  {
                warn!("No connection found for peer {}; dropping message", item.dest_node);
                return Err(WebRtcError::NoPeerConnection)
            }

        }

        Ok(())


    }

    async fn create_offer_for_peer(&mut self, dest_node: NodeId, config: PlatformRtcConfig) -> Result<String,WebRtcError> {
        info!("Creating offer for peer {}", dest_node);


        let mut peer_state = PeerConnectionState::new(config).await?;


        let offer_sdp = peer_state.create_offer().await?;

        self.peer_connections.insert(dest_node, peer_state);

        Ok(offer_sdp)

    }

    async fn set_remote_description_for_peer(&mut self, peer_node: NodeId, sdp: String ) -> Result<(),WebRtcError>{

        info!("Setting remote description for peer {}", peer_node);

        match self.peer_connections.get_mut(&peer_node){

            Some(peer_state) => {
                peer_state.set_remote_description(sdp).await
            }
            None => {
                error!("Noe peer connection found for node : {}", peer_node);

                Err(WebRtcError::NoPeerConnection)

            }

        }

    }

    async fn create_answer_for_peer(&mut self, peer_node: NodeId, offer_sdp: String, config: PlatformRtcConfig) -> Result<String,WebRtcError>{

        info!("Creating answer for peer: {}", peer_node);

        self.set_remote_description_for_peer(peer_node, offer_sdp.clone()).await?;

        match self.peer_connections.get_mut(&peer_node){

            Some(peer_state) => {
                peer_state.create_answer(offer_sdp).await
            }
            None => {

                let mut peer_state = PeerConnectionState::new(config).await?;

                let answer_sdp = peer_state.create_answer(offer_sdp).await?;

                self.peer_connections.insert(peer_node, peer_state);

                Ok(answer_sdp)
            }
        }
    }


    async fn add_ice_candidate_for_peer(&mut self, peer_node: NodeId, candidate: PlatformCandidateIceType ) -> Result<(), WebRtcError>{

        info!("Adding ice candidate for peer {}", peer_node);

        match self.peer_connections.get_mut(&peer_node){
            None => {

                error!("No connection found for peer {}", peer_node);
                Err(WebRtcError::NoPeerConnection)
            }
            Some(peer_state) => {

                peer_state.add_ice_candidate_for_peer(candidate).await

            }
        }


    }

    async fn close_peer_connection(&mut self, peer_node: NodeId) -> Result<(), WebRtcError>{

        info!("Closing connection for peer {}", peer_node);

        match self.peer_connections.remove(&peer_node) {
            None => {
                warn!("Attempted to close non-existent connection for peer:  {}", peer_node);
            }
            Some(mut peer_state) => {
                peer_state.connection_state = ConnectionState::Closed;
                info!("Connection closed for peer {}", peer_node);

            }
        }
        Ok(())
    }

    fn get_default_config(&self) -> PlatformRtcConfig{

        #[cfg(not(wasm_browser))]
        {
            use webrtc::peer_connection::configuration::RTCConfiguration;
            RTCConfiguration::default()
        }

        #[cfg(wasm_browser)]
        {
            use web_sys::RtcConfiguration;
            RtcConfiguration::new()
        }
    }


}

pub struct WebRtcActorConfig{
    pub secret_key: SecretKey,
    pub rtc_config : PlatformRtcConfig
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

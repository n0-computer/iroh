mod actor;

use crate::magicsock::transports::webrtc::actor::{PlatformRtcConfig, WebRtcActor, WebRtcActorConfig, WebRtcActorMessage, WebRtcData, WebRtcDeliveryMode, WebRtcRecvDatagrams, WebRtcSendItem};
use bytes::Bytes;
use iroh_base::{NodeId, PublicKey};
use n0_watcher::{Watcher};
use snafu::Snafu;
use std::fmt::{Debug};
use std::io;
use std::task::{Context, Poll};
use n0_future::ready;
use tokio::sync::{mpsc, oneshot};
use tokio::task;
use tokio_util::sync::{PollSender};
use tokio_util::task::AbortOnDropHandle;
use tracing::{error,info_span, trace, warn, Instrument};
#[cfg(wasm_browser)]
use web_sys::{
    RtcConfiguration, RtcDataChannel, RtcIceCandidate, RtcIceServer, RtcPeerConnection,
    RtcSessionDescription,
};

use crate::magicsock::transports::{ChannelId, Transmit};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionDescription(pub String);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IceCandidate(pub String);

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

    #[snafu(display("Failed to create answer"))]
    AnswerCreationFailed,

    #[snafu(display("Failed to add ice candidate"))]
    AddIceCandidatesFailed,

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

    #[snafu(display("Failed to get sender"))]
    ChannelClosed,

    #[snafu(display("Failed to create data channel"))]
    DataChannelCreationFailed,

    #[snafu(display("Failed to send data across mpsc channel: {message}"))]
    SendError { message: String },

    #[snafu(display("Failed to receive from oneshot channel"))]
    RecvError {
        #[snafu(source)]
        source: oneshot::error::RecvError,
    },
}
/// Sender to send data to the webrtc actor
/// Channel id taken from function parameter for flexibility
#[derive(Debug, Clone)]
pub(crate) struct WebRtcSender {
    sender: PollSender<WebRtcSendItem>,
}


impl WebRtcSender {

    pub fn poll_send(

        &mut self,
        cx: &mut Context,
        dest_node: NodeId,
        transmit: &Transmit,
        channel_id: &ChannelId

    ) -> Poll<io::Result<()>> {

        match ready!(self.sender.poll_reserve(cx)){
            Ok(()) => {
                trace!(node = %dest_node, "send webrtc: message queued");

                let payload = Bytes::copy_from_slice(transmit.contents);

                let data = WebRtcData {
                    channel_id: channel_id.clone(),
                    delivery_mode: WebRtcDeliveryMode::Reliable,
                    payload
                };

                let item = WebRtcSendItem {
                    dest_node,
                    data
                };

                match self.sender.send_item(item) {
                    Ok(()) => {

                        Poll::Ready(Ok(()))

                    }
                    Err(_err) => {

                        error!(node = %dest_node, "error sending webrtc: message queued");

                        Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "channel to actor is closed")))

                    }
                }

            }
            Err(_) => {

                error!(node = %dest_node, "error sending webrtc: channel to actor is closed");

                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "channel to actor is closed")))

            }
        }


    }

    pub async fn send(
        &self,
        dest_node: NodeId,
        transmit: &Transmit<'_>,
        channel_id: &ChannelId,
    ) -> io::Result<()> {

        let Some(sender) = self.sender.get_ref() else {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "channel to actor is closed"));
        };

        trace!(node = %dest_node, "send webrtc: message queued");

        let payload = Bytes::copy_from_slice(transmit.contents);

        let data = WebRtcData {
            channel_id: channel_id.clone(),
            delivery_mode: WebRtcDeliveryMode::Reliable,
            payload
        };

        let item = WebRtcSendItem {
            dest_node,
            data
        };


        match sender.send(item).await {
            Ok(_) => {

                trace!(node = %dest_node, "sent webrtc: message queued");
                Ok(())

            }
            Err(mpsc::error::SendError(_)) => {
                error!(node = %dest_node, "error sending webrtc: message queued");
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "channel to actor is closed"))
            }
        }
    }


    pub fn try_send(
        &self,
        dest_node: NodeId,
        transmit: &Transmit,
        channel_id: &ChannelId
    ) -> io::Result<()> {
        let payload = Bytes::copy_from_slice(transmit.contents);

        let data = WebRtcData {
            channel_id: channel_id.clone(),
            delivery_mode: WebRtcDeliveryMode::Reliable,
            payload
        };

        let item = WebRtcSendItem {
            dest_node,
            data
        };

        let Some(sender) = self.sender.get_ref() else {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "channel to actor is closed"));
        };

        match sender.try_send(item) {
            Ok(_) => {
                trace!(node = %dest_node, "send webrtc: message queued");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!(node = %dest_node, "send webrtc: message dropped, channel to actor is closed");
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "channel to actor is closed",
                ))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(node = %dest_node, "send webrtc: message dropped, channel to actor is full");
                Err(io::Error::new(io::ErrorKind::WouldBlock, "channel full"))
            }
        }
    }




}


#[derive(Debug)]
pub(crate) struct WebRtcTransport {

    /// Channel to receive datagrams from the webrtc actor
    webrtc_datagram_recv_queue: mpsc::Receiver<WebRtcRecvDatagrams>,
    /// Channel sender for sending datagrams to the webrtc actor
    webrtc_datagram_send_channel: mpsc::Sender<WebRtcSendItem>,
    /// Control channel for actor management
    actor_sender: mpsc::Sender<WebRtcActorMessage>,
    /// Handle to the running actor task
    _actor_handle: AbortOnDropHandle<()>,
    ///Our node ID
    my_node_id: PublicKey

}




impl WebRtcTransport {

    pub fn new(config: WebRtcActorConfig) -> Self {

        //Create the SENDS channel (WebRtcSender -> WebRtcActor)
        let (webrtc_datagram_send_tx, webrtc_datagram_send_rx) = mpsc::channel(256);

        //Create the RECEIVE channel (WebRtcActor -> consumers)
        let (webrtc_datagram_recv_tx, webrtc_datagram_recv_rx) = mpsc::channel(512);

        //Create the control channel (for actor control messages)
        let (actor_sender, actor_receiver) = mpsc::channel(256);

        let my_node_id = config.secret_key.public();

        //Create the webrtc actor with the tx half of the receive channel
        let mut webrtc_actor = WebRtcActor::new(config, webrtc_datagram_recv_tx);



        // Spawn the actor task with both rx halves
        let actor_handle = AbortOnDropHandle::new(task::spawn(
            async move {
                webrtc_actor
                    .run(actor_receiver, webrtc_datagram_send_rx)
                    .await;
            }
                .instrument(info_span!("webrtc-actor"))
        ));

        Self {
            webrtc_datagram_recv_queue: webrtc_datagram_recv_rx,
            webrtc_datagram_send_channel: webrtc_datagram_send_tx,
            actor_sender,
            _actor_handle: actor_handle,
            my_node_id
        }


    }

    pub(crate) fn create_sender(&self) -> WebRtcSender{

        WebRtcSender {
            sender: PollSender::new(self.webrtc_datagram_send_channel.clone())
        }

    }


    ///Poll for incoming datagrams from peers
    pub fn poll_recv_datagrams(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Option<WebRtcRecvDatagrams>> {

        self.webrtc_datagram_recv_queue.poll_recv(cx)

    }

    /// Get our node ID
    pub fn local_node_id(&self) -> &PublicKey {
        &self.my_node_id
    }

    /// Create an offer for peer(high level API)
    pub async fn create_offer(&self, peer_node: NodeId, config: PlatformRtcConfig) -> Result<String, WebRtcError> {

        let (tx, rx) = oneshot::channel();

        let msg = WebRtcActorMessage::CreateOffer {
            peer_node,
            response: tx,
            config
        };


        self.actor_sender.send(msg).await?;

        rx.await?



    }

    /// Create remote description for a peer (high-level API)
    pub async fn set_remote_description(&self, peer_node: NodeId, sdp: String) -> Result<(), WebRtcError> {

        let (tx, rx) = oneshot::channel();

        let msg = WebRtcActorMessage::SetRemoteDescription {
            peer_node,
            sdp,
            response: tx
        };

        self.actor_sender.send(msg).await?;
        rx.await?


    }

    /// Create an answer for a peer (high-level API)
    pub async fn create_answer(&self, peer_node: NodeId, offer_sdp: String, config: PlatformRtcConfig) -> Result<String, WebRtcError> {

        let (tx, rx) = oneshot::channel();

        let msg = WebRtcActorMessage::CreateAnswer {
            peer_node,
            offer_sdp,
            response: tx,
            config
        };

        self.actor_sender.send(msg).await?;

        rx.await?

    }

    /// Close connection to a peer (high level API)
    pub async fn close_connection(&self, peer_node: NodeId) -> Result<(), WebRtcError> {

        let msg = WebRtcActorMessage::CloseConnection {
            peer_node,
        };

        self.actor_sender.send(msg).await.map_err(Into::into)

    }

}


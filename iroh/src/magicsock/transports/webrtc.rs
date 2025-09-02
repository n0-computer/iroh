pub mod actor;

use crate::magicsock::transports::webrtc::actor::{
    PlatformRtcConfig, WebRtcActor, WebRtcActorConfig, WebRtcActorMessage,
    WebRtcData, WebRtcDeliveryMode, WebRtcRecvDatagrams, WebRtcSendItem
};
use bytes::Bytes;
use iroh_base::{ChannelId, NodeId, PublicKey, WebRtcPort};
use snafu::Snafu;
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use n0_future::ready;
use tokio::sync::{mpsc, oneshot};
use tokio::task;
use tokio_util::sync::PollSender;
use tokio_util::task::AbortOnDropHandle;
use tracing::{error, info_span, trace, warn, Instrument};

#[cfg(wasm_browser)]
use web_sys::{
    RtcConfiguration, RtcDataChannel, RtcIceCandidate, RtcIceServer, RtcPeerConnection,
    RtcSessionDescription,
};

use crate::magicsock::transports::{Addr, Transmit};

/// Wrapper around SDP (Session Description Protocol) strings for type safety
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionDescription(pub String);

/// Wrapper around ICE candidate strings for type safety
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IceCandidate(pub String);

/// Messages exchanged during WebRTC signaling process
/// These are typically sent through a separate signaling server (not part of WebRTC itself)
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SignalingMessage {
    /// Initial connection offer from the initiating peer
    Offer(SessionDescription),
    /// Response to an offer from the receiving peer
    Answer(SessionDescription),
    /// ICE candidate discovered during connection establishment
    Candidate(IceCandidate),
}

/// Comprehensive error types for WebRTC operations
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum WebRtcError {
    #[snafu(display("No peer connection available for the specified node"))]
    NoPeerConnection,

    #[snafu(display("No data channel available - connection may not be established"))]
    NoDataChannel,

    #[snafu(display("Failed to create RTCPeerConnection"))]
    PeerConnectionCreationFailed,

    #[snafu(display("Failed to create WebRTC offer"))]
    OfferCreationFailed,

    #[snafu(display("Failed to create WebRTC answer"))]
    AnswerCreationFailed,

    #[snafu(display("Failed to add ICE candidate to peer connection"))]
    AddIceCandidatesFailed,

    #[snafu(display("Failed to set local SDP description"))]
    SetLocalDescriptionFailed,

    #[snafu(display("Failed to set remote SDP description"))]
    SetRemoteDescriptionFailed,

    #[snafu(display("Failed to send data through data channel"))]
    SendFailed,

    #[snafu(display("Failed to update connection state"))]
    SetStateFailed,

    #[snafu(display("Communication channel with WebRTC actor is closed"))]
    ChannelClosed,

    #[snafu(display("Failed to create WebRTC data channel"))]
    DataChannelCreationFailed,

    #[snafu(display("Failed to send data across mpsc channel: {message}"))]
    SendError { message: String },

    #[snafu(display("Failed to receive response from WebRTC actor"))]
    RecvError {
        #[snafu(source)]
        source: oneshot::error::RecvError,
    },

    #[snafu(display("Initiator peer cannot handle incoming offers"))]
    UnexpectedOffer,

    #[snafu(display("Receiving peer cannot handle incoming answers"))]
    UnexpectedAnswer,

    #[snafu(display("Native WebRTC error"))]
    Native {
        #[snafu(source)]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// High-level sender interface for WebRTC data transmission
///
/// This struct provides both polling and async interfaces for sending data to peers.
/// It wraps the underlying channel communication with the WebRTC actor.
#[derive(Debug, Clone)]
pub(crate) struct WebRtcSender {
    /// Polling-capable sender to the WebRTC actor's send queue
    sender: PollSender<WebRtcSendItem>,
}

impl WebRtcSender {
    /// Poll-based send operation for use in async contexts that need fine-grained control
    ///
    /// This method integrates with Tokio's polling system and is used by transport layers
    /// that need to implement custom polling logic.
    ///
    /// # Arguments
    /// * `cx` - Async context for waker registration
    /// * `dest_node` - Target peer's node ID
    /// * `transmit` - Data packet to send
    /// * `channel_id` - WebRTC data channel identifier
    ///
    /// # Returns
    /// * `Poll::Ready(Ok(()))` - Message was successfully queued
    /// * `Poll::Ready(Err(_))` - Send failed (channel closed)
    /// * `Poll::Pending` - Channel is full, task will be woken when space is available
    pub fn poll_send(
        &mut self,
        cx: &mut Context,
        dest_node: NodeId,
        transmit: &Transmit,
        channel_id: &ChannelId,
    ) -> Poll<io::Result<()>> {
        // Reserve space in the send queue
        match ready!(self.sender.poll_reserve(cx)) {
            Ok(()) => {
                trace!(node = %dest_node, "WebRTC send: reserving channel space");

                let payload = Bytes::copy_from_slice(transmit.contents);

                let data = WebRtcData {
                    channel_id: channel_id.clone(),
                    delivery_mode: WebRtcDeliveryMode::Reliable, // TODO: Make configurable
                    payload,
                };

                let item = WebRtcSendItem { dest_node, data };

                match self.sender.send_item(item) {
                    Ok(()) => {
                        trace!(node = %dest_node, "WebRTC send: message queued successfully");
                        Poll::Ready(Ok(()))
                    }
                    Err(_err) => {
                        error!(node = %dest_node, "WebRTC send: failed to queue message");
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "WebRTC actor channel closed",
                        )))
                    }
                }
            }
            Err(_) => {
                error!(node = %dest_node, "WebRTC send: actor channel is closed");
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "WebRTC actor channel closed",
                )))
            }
        }
    }

    /// Async send operation that waits for channel availability
    ///
    /// This is the preferred method for most use cases as it handles backpressure
    /// automatically by waiting when the channel is full.
    ///
    /// # Arguments
    /// * `dest_node` - Target peer's node ID
    /// * `transmit` - Data packet to send
    /// * `channel_id` - WebRTC data channel identifier
    pub async fn send(
        &self,
        dest_node: NodeId,
        transmit: &Transmit<'_>,
        channel_id: &ChannelId,
    ) -> io::Result<()> {
        let Some(sender) = self.sender.get_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "WebRTC actor channel closed",
            ));
        };

        trace!(node = %dest_node, "WebRTC send: preparing async send");

        let payload = Bytes::copy_from_slice(transmit.contents);

        let data = WebRtcData {
            channel_id: channel_id.clone(),
            delivery_mode: WebRtcDeliveryMode::Reliable,
            payload,
        };

        let item = WebRtcSendItem { dest_node, data };

        match sender.send(item).await {
            Ok(_) => {
                trace!(node = %dest_node, "WebRTC send: message sent successfully");
                Ok(())
            }
            Err(mpsc::error::SendError(_)) => {
                error!(node = %dest_node, "WebRTC send: actor channel closed during send");
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "WebRTC actor channel closed",
                ))
            }
        }
    }

    /// Non-blocking send that fails immediately if the channel is full
    ///
    /// Use this when you need to avoid blocking but can handle dropped messages.
    /// Returns `WouldBlock` error if the channel is full.
    ///
    /// # Arguments
    /// * `dest_node` - Target peer's node ID
    /// * `transmit` - Data packet to send
    /// * `channel_id` - WebRTC data channel identifier
    pub fn try_send(
        &self,
        dest_node: NodeId,
        transmit: &Transmit,
        channel_id: &ChannelId,
    ) -> io::Result<()> {
        let payload = Bytes::copy_from_slice(transmit.contents);

        let data = WebRtcData {
            channel_id: channel_id.clone(),
            delivery_mode: WebRtcDeliveryMode::Reliable,
            payload,
        };

        let item = WebRtcSendItem { dest_node, data };

        let Some(sender) = self.sender.get_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "WebRTC actor channel closed",
            ));
        };

        match sender.try_send(item) {
            Ok(_) => {
                trace!(node = %dest_node, "WebRTC try_send: message queued");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!(node = %dest_node, "WebRTC try_send: actor channel closed");
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "WebRTC actor channel closed",
                ))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(node = %dest_node, "WebRTC try_send: channel full, message dropped");
                Err(io::Error::new(io::ErrorKind::WouldBlock, "WebRTC send channel full"))
            }
        }
    }

}

/// Main WebRTC transport interface
///
/// This is the primary interface between the application layer and the WebRTC subsystem.
/// It manages:
/// - A background WebRTC actor that handles all WebRTC operations
/// - Bidirectional communication channels for data exchange
/// - High-level APIs for WebRTC connection management
///
/// # Architecture Overview
///
/// ```text
/// Application Layer
///        │
///        │ (calls methods)
///        ▼
/// WebRtcTransport ◄──── WebRtcSender
///        │                    │
///        │ (channels)         │ (poll_send/send)
///        ▼                    ▼
/// WebRtcActor ◄────────── Send Queue
///        │
///        │ (WebRTC operations)
///        ▼
/// Network (Internet)
/// ```
#[derive(Debug)]
pub(crate) struct WebRtcTransport {
    /// Incoming data from remote peers (WebRtcActor -> Application)
    /// This is where you receive `WebRtcRecvDatagrams` containing data from remote peers
    webrtc_datagram_recv_queue: mpsc::Receiver<WebRtcRecvDatagrams>,

    /// Outgoing data channel to WebRtcActor (Application -> WebRtcActor)
    /// Used internally by WebRtcSender instances
    webrtc_datagram_send_channel: mpsc::Sender<WebRtcSendItem>,

    /// Control channel for WebRTC operations (offer/answer/ICE candidates)
    /// Used for connection establishment and management
    actor_sender: mpsc::Sender<WebRtcActorMessage>,

    /// Handle to the background WebRTC actor task
    /// Automatically stops the actor when WebRtcTransport is dropped
    _actor_handle: AbortOnDropHandle<()>,

    /// Our local node identifier (derived from secret key)
    my_node_id: PublicKey,

    /// Bind addr
    #[cfg(not(wasm_browser))]
    bind_addr: SocketAddr,
}

impl WebRtcTransport {
    /// Create a new WebRTC transport instance
    ///
    /// This sets up the entire WebRTC subsystem:
    /// 1. Creates communication channels between transport and actor
    /// 2. Spawns the background WebRTC actor task
    /// 3. Returns the transport interface for application use
    ///
    /// # Channel Architecture
    ///
    /// ```text
    /// WebRtcTransport                    WebRtcActor
    ///       │                                 │
    ///       │ webrtc_datagram_send_tx         │ webrtc_datagram_send_rx
    ///       ├────────────────────────────────>┤ (for outgoing data)
    ///       │                                 │
    ///       │ webrtc_datagram_recv_rx         │ webrtc_datagram_recv_tx
    ///       ├<────────────────────────────────┤ (for incoming data)
    ///       │                                 │
    ///       │ actor_sender                    │ actor_receiver
    ///       └────────────────────────────────>┘ (for control messages)
    /// ```
    ///
    /// # Arguments
    /// * `config` - WebRTC configuration including secret key and RTC settings
    pub fn new(config: WebRtcActorConfig) -> Self {
        // Create the SEND channel (WebRtcTransport -> WebRtcActor)
        // This carries WebRtcSendItem messages when the application wants to send data
        let (webrtc_datagram_send_tx, webrtc_datagram_send_rx) = mpsc::channel(256);

        // Create the RECEIVE channel (WebRtcActor -> WebRtcTransport)
        // This carries WebRtcRecvDatagrams when data arrives from remote peers
        let (webrtc_datagram_recv_tx, webrtc_datagram_recv_rx) = mpsc::channel(512);

        // Create the CONTROL channel (WebRtcTransport -> WebRtcActor)
        // This carries WebRtcActorMessage for connection management (offers, answers, ICE)
        let (actor_sender, actor_receiver) = mpsc::channel(256);

        // Derive our public node ID from the secret key
        let my_node_id = config.secret_key.public();

        // Bind address
        #[cfg(not(wasm_browser))]
        let bind_addr = config.bind_addr;

        // Create the WebRTC actor with the transmit side of the receive channel
        // The actor will use webrtc_datagram_recv_tx to send incoming data back to us
        let mut webrtc_actor = WebRtcActor::new(config, webrtc_datagram_recv_tx);

        // Spawn the actor in the background with proper instrumentation
        // The actor runs the main event loop handling:
        // - Control messages (connection setup)
        // - Outgoing data (from send channel)
        // - Incoming data (forwarded via receive channel)
        let actor_handle = AbortOnDropHandle::new(task::spawn(
            async move {
                webrtc_actor
                    .run(actor_receiver, webrtc_datagram_send_rx)
                    .await;
            }
                .instrument(info_span!("webrtc-actor")),
        ));

        Self {
            webrtc_datagram_recv_queue: webrtc_datagram_recv_rx,
            webrtc_datagram_send_channel: webrtc_datagram_send_tx,
            actor_sender,
            _actor_handle: actor_handle,
            my_node_id,
            #[cfg(not(wasm_browser))]
            bind_addr
        }
    }

    /// Create a new sender instance for outgoing data
    ///
    /// Multiple senders can be created and used concurrently. Each sender
    /// provides different sending modes (polling, async, try_send) but all
    /// route through the same underlying channel to the WebRTC actor.
    ///
    /// # Usage
    /// ```rust
    /// let sender = transport.create_sender();
    /// sender.send(peer_id, &transmit_data, &channel_id).await?;
    /// ```
    pub(crate) fn create_sender(&self) -> WebRtcSender {
        WebRtcSender {
            sender: PollSender::new(self.webrtc_datagram_send_channel.clone()),
        }
    }

    /// Poll for incoming datagrams from remote peers
    ///
    /// This is the main method for receiving data in the WebRTC transport.
    /// It integrates with Tokio's polling system and will wake the current
    /// task when new data arrives.
    ///
    /// # Returns
    /// * `Poll::Ready(Some(datagram))` - New data received from a peer
    /// * `Poll::Ready(None)` - Channel closed (actor stopped)
    /// * `Poll::Pending` - No data available, task will be woken when data arrives
    ///
    /// # Usage
    /// ```rust
    /// while let Some(datagram) = transport.poll_recv(cx).await {
    ///     println!("Received {} bytes from {}", datagram.data.len(), datagram.src);
    /// }
    /// ```


    pub fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr]
    ) -> Poll<io::Result<usize>> {
        let mut num_msgs = 0;

        for ((buf_out, meta_out), addr) in bufs
            .iter_mut()
            .zip(metas.iter_mut())
            .zip(source_addrs.iter_mut())
        {
            let dm = match self.webrtc_datagram_recv_queue.poll_recv(cx) {
                Poll::Ready(Some(recv)) => recv,
                Poll::Ready(None) => {
                    error!("WebRTC channel closed");
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "connection closed",
                    )));
                }
                Poll::Pending => {
                    break;
                }
            };

            if buf_out.len() < dm.datagrams.contents.len() {
                // Our receive buffer isn't big enough to process this datagram.
                // Continuing would cause a panic.
                warn!(
                    quinn_buf_len = buf_out.len(),
                    datagram_len = dm.datagrams.contents.len(),
                    segment_size = ?dm.datagrams.segment_size,
                    "dropping received datagram: quinn buffer too small"
                );
                break;
            }

            buf_out[..dm.datagrams.contents.len()].copy_from_slice(&dm.datagrams.contents);
            meta_out.len = dm.datagrams.contents.len();
            meta_out.stride = dm
                .datagrams
                .segment_size
                .map_or(dm.datagrams.contents.len(), |s| u16::from(s) as usize);
            meta_out.ecn = None;
            meta_out.dst_ip = None;

            *addr = Addr::from(WebRtcPort::new(dm.src, dm.channel_id));

            num_msgs += 1;
        }

        // If we have any msgs to report, they are in the first `num_msgs` slots
        if num_msgs > 0 {
            debug_assert!(num_msgs <= metas.len());
            Poll::Ready(Ok(num_msgs))
        } else {
            Poll::Pending
        }
    }

    /// Get our local node identifier
    ///
    /// This is the public key corresponding to our secret key and identifies
    /// this node in the network.
    pub fn local_node_id(&self) -> &PublicKey {
        &self.my_node_id
    }

    // === WebRTC Connection Management API ===
    // These methods provide high-level interfaces for the WebRTC connection establishment process

    /// Create a WebRTC offer to initiate connection with a peer
    ///
    /// This is step 1 of the WebRTC connection process. The resulting SDP offer
    /// should be sent to the remote peer through your signaling mechanism.
    ///
    /// # WebRTC Flow
    /// 1. **create_offer()** ← You are here
    /// 2. Send offer to peer via signaling
    /// 3. Peer calls create_answer()
    /// 4. Receive answer via signaling
    /// 5. Exchange ICE candidates
    /// 6. Connection established
    ///
    /// # Arguments
    /// * `peer_node` - Node ID of the peer to connect to
    /// * `config` - WebRTC configuration for this connection
    ///
    /// # Returns
    /// SDP offer string to be sent to the peer
    pub async fn create_offer(
        &self,
        peer_node: NodeId,
        config: PlatformRtcConfig,
    ) -> Result<String, WebRtcError> {
        let (tx, rx) = oneshot::channel();

        let msg = WebRtcActorMessage::CreateOffer {
            peer_node,
            response: tx,
            config,
        };

        self.actor_sender.send(msg).await?;
        rx.await?
    }

    /// Set remote SDP description (offer or answer) from a peer
    ///
    /// This method is used to process SDP descriptions received from remote peers.
    /// It can handle both offers (when you're the answering peer) and answers
    /// (when you're the offering peer).
    ///
    /// # Arguments
    /// * `peer_node` - Node ID of the peer that sent this description
    /// * `sdp` - SDP string received from the peer
    pub async fn set_remote_description(
        &self,
        peer_node: NodeId,
        sdp: String,
    ) -> Result<(), WebRtcError> {
        let (tx, rx) = oneshot::channel();

        let msg = WebRtcActorMessage::SetRemoteDescription {
            peer_node,
            sdp,
            response: tx,
        };

        self.actor_sender.send(msg).await?;
        rx.await?
    }

    /// Create a WebRTC answer in response to a received offer
    ///
    /// This is step 3 of the WebRTC connection process (from the answering peer's perspective).
    /// The resulting SDP answer should be sent back to the offering peer.
    ///
    /// # WebRTC Flow (Answering Peer)
    /// 1. Receive offer via signaling
    /// 2. **create_answer()** ← You are here
    /// 3. Send answer to peer via signaling
    /// 4. Exchange ICE candidates
    /// 5. Connection established
    ///
    /// # Arguments
    /// * `peer_node` - Node ID of the peer that sent the offer
    /// * `offer_sdp` - SDP offer string received from the peer
    /// * `config` - WebRTC configuration for this connection
    ///
    /// # Returns
    /// SDP answer string to be sent back to the peer
    pub async fn create_answer(
        &self,
        peer_node: NodeId,
        offer_sdp: String,
        config: PlatformRtcConfig,
    ) -> Result<String, WebRtcError> {
        let (tx, rx) = oneshot::channel();

        let msg = WebRtcActorMessage::CreateAnswer {
            peer_node,
            offer_sdp,
            response: tx,
            config,
        };

        self.actor_sender.send(msg).await?;
        rx.await?
    }

    /// Add an ICE candidate received from a peer
    ///
    /// ICE candidates are discovered during the connection process and exchanged
    /// between peers to establish the optimal network path. This method should
    /// be called whenever you receive an ICE candidate from a peer via signaling.
    ///
    /// # Arguments
    /// * `peer_node` - Node ID of the peer that sent this candidate
    /// * `candidate` - ICE candidate information
    pub async fn add_ice_candidate(
        &self,
        peer_node: NodeId,
        candidate: crate::magicsock::transports::webrtc::actor::PlatformCandidateIceType,
    ) -> Result<(), WebRtcError> {
        let msg = WebRtcActorMessage::AddIceCandidate { peer_node, candidate };

        self.actor_sender.send(msg).await.map_err(Into::into)
    }

    /// Close connection to a specific peer
    ///
    /// This cleanly shuts down the WebRTC connection to the specified peer,
    /// cleaning up resources and closing data channels.
    ///
    /// # Arguments
    /// * `peer_node` - Node ID of the peer to disconnect from
    pub async fn close_connection(&self, peer_node: NodeId) -> Result<(), WebRtcError> {
        let msg = WebRtcActorMessage::CloseConnection { peer_node };

        self.actor_sender.send(msg).await.map_err(Into::into)
    }

    pub fn bind_addrs(&self) -> SocketAddr {
        self.bind_addr
    }
}

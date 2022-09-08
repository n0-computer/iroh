use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use asynchronous_codec::Framed;
use futures::prelude::*;
use futures::StreamExt;
use iroh_metrics::{bitswap::BitswapMetrics, core::MRecorder, inc};
use libp2p::core::upgrade::{
    InboundUpgrade, NegotiationError, OutboundUpgrade, ProtocolError, UpgradeError,
};
use libp2p::swarm::{
    ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, KeepAlive,
    NegotiatedSubstream, SubstreamProtocol,
};
use smallvec::SmallVec;
use tracing::{error, trace, warn};

use crate::{
    protocol::{BitswapCodec, ProtocolConfig},
    BitswapError, BitswapMessage, ProtocolId,
};

/// The initial time (in seconds) we set the keep alive for protocol negotiations to occur.
// TODO: configurable
const INITIAL_KEEP_ALIVE: u64 = 30;

#[derive(thiserror::Error, Debug)]
pub enum BitswapHandlerError {
    /// The maximum number of inbound substreams created has been exceeded.
    #[error("max inbound substreams")]
    MaxInboundSubstreams,
    /// The maximum number of outbound substreams created has been exceeded.
    #[error("max outbound substreams")]
    MaxOutboundSubstreams,
    /// The message exceeds the maximum transmission size.
    #[error("max transmission size")]
    MaxTransmissionSize,
    /// Protocol negotiation timeout.
    #[error("negotiation timeout")]
    NegotiationTimeout,
    /// Protocol negotiation failed.
    #[error("negotatiation protocol error {0}")]
    NegotiationProtocolError(#[from] ProtocolError),
    /// IO error.
    #[error("io {0}")]
    Io(#[from] std::io::Error),
    #[error("bitswap {0}")]
    Bitswap(#[from] BitswapError),
}

/// The event emitted by the Handler. This informs the behaviour of various events created
/// by the handler.
#[derive(Debug)]
pub enum HandlerEvent {
    /// A Bitswap message has been received.
    Message {
        /// The Bitswap message.
        message: BitswapMessage,
    },
    Connected {
        protocol: ProtocolId,
    },
    ProtocolNotSuppported,
}

/// A message sent from the behaviour to the handler.
#[derive(Debug, Clone)]
pub enum BitswapHandlerIn {
    /// A bitswap message to send.
    Message(BitswapMessage),
    // TODO: do we need a close?
}

/// The maximum number of substreams we accept or create before disconnecting from the peer.
///
/// Bitswap is supposed to have a single long-lived inbound and outbound substream. On failure we
/// attempt to recreate these. This imposes an upper bound of new substreams before we consider the
/// connection faulty and disconnect. This also prevents against potential substream creation loops.
const MAX_SUBSTREAM_CREATION: usize = 5;

/// Protocol Handler that manages a single long-lived substream with a peer.
pub struct BitswapHandler {
    /// Upgrade configuration for the bitswap protocol.
    listen_protocol: SubstreamProtocol<ProtocolConfig, ()>,

    /// The single long-lived outbound substream.
    outbound_substream: Option<OutboundSubstreamState>,

    /// The single long-lived inbound substream.
    inbound_substream: Option<InboundSubstreamState>,

    /// Pending events to yield.
    events: SmallVec<
        [ConnectionHandlerEvent<ProtocolConfig, BitswapMessage, HandlerEvent, BitswapHandlerError>;
            4],
    >,

    /// Queue of values that we want to send to the remote.
    send_queue: SmallVec<[BitswapMessage; 16]>,

    /// Flag indicating that an outbound substream is being established to prevent duplicate
    /// requests.
    outbound_substream_establishing: bool,

    /// The number of outbound substreams we have created.
    outbound_substreams_created: usize,

    /// The number of inbound substreams that have been created by the peer.
    inbound_substreams_created: usize,

    /// If the peer doesn't support the bitswap protocol we do not immediately disconnect.
    /// Rather, we disable the handler and prevent any incoming or outgoing substreams from being
    /// established.
    ///
    /// This value is set to true to indicate the peer doesn't support bitswap.
    protocol_unsupported: bool,

    /// Keeps track on whether we have sent the protocol version to the behaviour.
    //
    // NOTE: Use this flag rather than checking the substream count each poll.
    protocol_sent: bool,
    protocol: Option<ProtocolId>,

    /// The amount of time we allow idle connections before disconnecting.
    idle_timeout: Duration,

    /// Collection of errors from attempting an upgrade.
    upgrade_errors: VecDeque<ConnectionHandlerUpgrErr<BitswapHandlerError>>,

    /// Flag determining whether to maintain the connection to the peer.
    keep_alive: KeepAlive,
}

/// State of the inbound substream, opened either by us or by the remote.
enum InboundSubstreamState {
    /// Waiting for a message from the remote. The idle state for an inbound substream.
    WaitingInput(Framed<NegotiatedSubstream, BitswapCodec>),
    /// The substream is being closed.
    Closing(Framed<NegotiatedSubstream, BitswapCodec>),
    /// An error occurred during processing.
    Poisoned,
}

/// State of the outbound substream, opened either by us or by the remote.
enum OutboundSubstreamState {
    /// Waiting for the user to send a message. The idle state for an outbound substream.
    WaitingOutput(Framed<NegotiatedSubstream, BitswapCodec>),
    /// Waiting to send a message to the remote.
    PendingSend(Framed<NegotiatedSubstream, BitswapCodec>, BitswapMessage),
    /// Waiting to flush the substream so that the data arrives to the remote.
    PendingFlush(Framed<NegotiatedSubstream, BitswapCodec>),
    /// The substream is being closed. Used by either substream.
    _Closing(Framed<NegotiatedSubstream, BitswapCodec>),
    /// An error occurred during processing.
    Poisoned,
}

impl BitswapHandler {
    /// Builds a new [`BitswapHandler`].
    pub fn new(protocol_config: ProtocolConfig, idle_timeout: Duration) -> Self {
        Self {
            listen_protocol: SubstreamProtocol::new(protocol_config, ()),
            inbound_substream: None,
            outbound_substream: None,
            outbound_substream_establishing: false,
            outbound_substreams_created: 0,
            inbound_substreams_created: 0,
            send_queue: SmallVec::new(),
            protocol_unsupported: false,
            protocol: None,
            protocol_sent: false,
            idle_timeout,
            upgrade_errors: VecDeque::new(),
            keep_alive: KeepAlive::Until(Instant::now() + Duration::from_secs(INITIAL_KEEP_ALIVE)),
            events: Default::default(),
        }
    }
}

impl ConnectionHandler for BitswapHandler {
    type InEvent = BitswapHandlerIn;
    type OutEvent = HandlerEvent;
    type Error = BitswapHandlerError;
    type InboundOpenInfo = ();
    type InboundProtocol = ProtocolConfig;
    type OutboundOpenInfo = BitswapMessage;
    type OutboundProtocol = ProtocolConfig;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        self.listen_protocol.clone()
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        protocol: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
        _info: Self::InboundOpenInfo,
    ) {
        let substream = protocol;

        // If the peer doesn't support the protocol, reject all substreams
        if self.protocol_unsupported {
            return;
        }
        let protocol_id = substream.codec().protocol;
        if self.protocol.is_none() {
            self.protocol = Some(protocol_id);
        }

        self.inbound_substreams_created += 1;

        // new inbound substream. Replace the current one, if it exists.
        trace!("New inbound substream request: {:?}", protocol_id);
        self.inbound_substream = Some(InboundSubstreamState::WaitingInput(substream));
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        message: Self::OutboundOpenInfo,
    ) {
        let substream = protocol;

        // If the peer doesn't support the protocol, reject all substreams
        if self.protocol_unsupported {
            return;
        }

        let protocol_id = substream.codec().protocol;
        if self.protocol.is_none() {
            self.protocol = Some(protocol_id);
        }

        self.outbound_substream_establishing = false;
        self.outbound_substreams_created += 1;

        // Should never establish a new outbound substream if one already exists.
        // If this happens, an outbound message is not sent.
        if self.outbound_substream.is_some() {
            warn!("Established an outbound substream with one already available");
            // Add the message back to the send queue
            self.send_queue.push(message);
        } else {
            trace!("New outbound substream: {:?}", protocol_id);
            self.outbound_substream = Some(OutboundSubstreamState::PendingSend(substream, message));
        }
    }

    fn inject_event(&mut self, message: BitswapHandlerIn) {
        if !self.protocol_unsupported {
            match message {
                BitswapHandlerIn::Message(m) => {
                    self.send_queue.push(m);
                    // received a message, reset keepalive
                    // TODO: should we permanently keep this open instead, until we remove from all sessions?
                    self.keep_alive = KeepAlive::Until(Instant::now() + self.idle_timeout);
                }
            }
        } else {
            inc!(BitswapMetrics::ProtocolUnsupported);
        }
    }

    fn inject_dial_upgrade_error(
        &mut self,
        _: Self::OutboundOpenInfo,
        e: ConnectionHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Error,
        >,
    ) {
        self.outbound_substream_establishing = false;
        warn!("Dial upgrade error {:?}", e);
        self.upgrade_errors.push_back(e);
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        self.keep_alive
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            Self::Error,
        >,
    > {
        inc!(BitswapMetrics::HandlerPollCount);
        if !self.events.is_empty() {
            return Poll::Ready(self.events.remove(0));
        }

        inc!(BitswapMetrics::HandlerPollEventCount);
        // Handle any upgrade errors
        if let Some(error) = self.upgrade_errors.pop_front() {
            inc!(BitswapMetrics::HandlerConnUpgradeErrors);
            let reported_error = match error {
                // Timeout errors get mapped to NegotiationTimeout and we close the connection.
                ConnectionHandlerUpgrErr::Timeout | ConnectionHandlerUpgrErr::Timer => {
                    Some(BitswapHandlerError::NegotiationTimeout)
                }
                // There was an error post negotiation, close the connection.
                ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Apply(e)) => Some(e),
                ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Select(negotiation_error)) => {
                    match negotiation_error {
                        NegotiationError::Failed => {
                            // The protocol is not supported
                            self.protocol_unsupported = true;
                            if !self.protocol_sent {
                                self.protocol_sent = true;
                                // clear all substreams so the keep alive returns false
                                self.inbound_substream = None;
                                self.outbound_substream = None;
                                self.keep_alive = KeepAlive::No;
                                return Poll::Ready(ConnectionHandlerEvent::Custom(
                                    HandlerEvent::ProtocolNotSuppported,
                                ));
                            } else {
                                None
                            }
                        }
                        NegotiationError::ProtocolError(e) => {
                            Some(BitswapHandlerError::NegotiationProtocolError(e))
                        }
                    }
                }
            };

            // If there was a fatal error, close the connection.
            if let Some(error) = reported_error {
                return Poll::Ready(ConnectionHandlerEvent::Close(error));
            }
        }

        if !self.protocol_sent {
            if let Some(protocol) = self.protocol.as_ref() {
                self.protocol_sent = true;
                return Poll::Ready(ConnectionHandlerEvent::Custom(HandlerEvent::Connected {
                    protocol: *protocol,
                }));
            }
        }

        if self.inbound_substreams_created > MAX_SUBSTREAM_CREATION {
            inc!(BitswapMetrics::InboundSubstreamsCreatedLimit);
            // Too many inbound substreams have been created, end the connection.
            return Poll::Ready(ConnectionHandlerEvent::Close(
                BitswapHandlerError::MaxInboundSubstreams,
            ));
        }

        // determine if we need to create the stream
        if !self.send_queue.is_empty()
            && self.outbound_substream.is_none()
            && !self.outbound_substream_establishing
        {
            inc!(BitswapMetrics::OutboundSubstreamsEvent);
            if self.outbound_substreams_created >= MAX_SUBSTREAM_CREATION {
                inc!(BitswapMetrics::OutboundSubstreamsCreatedLimit);
                return Poll::Ready(ConnectionHandlerEvent::Close(
                    BitswapHandlerError::MaxOutboundSubstreams,
                ));
            }
            let message = self.send_queue.remove(0);
            self.send_queue.shrink_to_fit();
            self.outbound_substream_establishing = true;
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: self.listen_protocol.clone().map_info(|()| message),
            });
        }

        loop {
            inc!(BitswapMetrics::HandlerInboundLoopCount);
            match std::mem::replace(
                &mut self.inbound_substream,
                Some(InboundSubstreamState::Poisoned),
            ) {
                // inbound idle state
                Some(InboundSubstreamState::WaitingInput(mut substream)) => {
                    match substream.poll_next_unpin(cx) {
                        Poll::Ready(Some(Ok(message))) => {
                            // reset keep alive idle timeout
                            self.keep_alive = KeepAlive::Until(Instant::now() + self.idle_timeout);

                            self.inbound_substream =
                                Some(InboundSubstreamState::WaitingInput(substream));
                            return Poll::Ready(ConnectionHandlerEvent::Custom(message));
                        }
                        Poll::Ready(Some(Err(error))) => {
                            match error {
                                BitswapHandlerError::MaxTransmissionSize => {
                                    warn!("Message exceeded the maximum transmission size");
                                    self.inbound_substream =
                                        Some(InboundSubstreamState::WaitingInput(substream));
                                }
                                _ => {
                                    warn!("Inbound stream error: {}", error);
                                    // More serious errors, close this side of the stream. If the
                                    // peer is still around, they will re-establish their connection
                                    self.inbound_substream =
                                        Some(InboundSubstreamState::Closing(substream));
                                }
                            }
                        }
                        // peer closed the stream
                        Poll::Ready(None) => {
                            warn!("Peer closed their outbound stream");
                            self.inbound_substream =
                                Some(InboundSubstreamState::Closing(substream));
                        }
                        Poll::Pending => {
                            self.inbound_substream =
                                Some(InboundSubstreamState::WaitingInput(substream));
                            break;
                        }
                    }
                }
                Some(InboundSubstreamState::Closing(mut substream)) => {
                    match Sink::poll_close(Pin::new(&mut substream), cx) {
                        Poll::Ready(res) => {
                            if let Err(e) = res {
                                // Don't close the connection but just drop the inbound substream.
                                // In case the remote has more to send, they will open up a new
                                // substream.
                                warn!("Inbound substream error while closing: {:?}", e);
                            }
                            self.inbound_substream = None;
                            if self.outbound_substream.is_none() {
                                self.keep_alive = KeepAlive::No;
                            }
                            break;
                        }
                        Poll::Pending => {
                            self.inbound_substream =
                                Some(InboundSubstreamState::Closing(substream));
                            break;
                        }
                    }
                }
                None => {
                    self.inbound_substream = None;
                    break;
                }
                Some(InboundSubstreamState::Poisoned) => {
                    unreachable!("Error occurred during inbound stream processing")
                }
            }
        }

        // process outbound stream
        loop {
            inc!(BitswapMetrics::HandlerOutboundLoopCount);
            match std::mem::replace(
                &mut self.outbound_substream,
                Some(OutboundSubstreamState::Poisoned),
            ) {
                // outbound idle state
                Some(OutboundSubstreamState::WaitingOutput(substream)) => {
                    if !self.send_queue.is_empty() {
                        let message = self.send_queue.remove(0);
                        self.send_queue.shrink_to_fit();
                        self.outbound_substream =
                            Some(OutboundSubstreamState::PendingSend(substream, message));
                    } else {
                        self.outbound_substream =
                            Some(OutboundSubstreamState::WaitingOutput(substream));
                        break;
                    }
                }
                Some(OutboundSubstreamState::PendingSend(mut substream, message)) => {
                    match Sink::poll_ready(Pin::new(&mut substream), cx) {
                        Poll::Ready(Ok(())) => {
                            match Sink::start_send(Pin::new(&mut substream), message) {
                                Ok(()) => {
                                    self.outbound_substream =
                                        Some(OutboundSubstreamState::PendingFlush(substream))
                                }
                                Err(BitswapHandlerError::MaxTransmissionSize) => {
                                    error!("Message exceeded the maximum transmission size and was not sent.");
                                    self.outbound_substream =
                                        Some(OutboundSubstreamState::WaitingOutput(substream));
                                }
                                Err(e) => {
                                    error!("Error sending message: {}", e);
                                    return Poll::Ready(ConnectionHandlerEvent::Close(e));
                                }
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            error!("Outbound substream error while sending output: {:?}", e);
                            return Poll::Ready(ConnectionHandlerEvent::Close(e));
                        }
                        Poll::Pending => {
                            self.keep_alive = KeepAlive::Yes;
                            self.outbound_substream =
                                Some(OutboundSubstreamState::PendingSend(substream, message));
                            break;
                        }
                    }
                }
                Some(OutboundSubstreamState::PendingFlush(mut substream)) => {
                    match Sink::poll_flush(Pin::new(&mut substream), cx) {
                        Poll::Ready(Ok(())) => {
                            // reset the idle timeout
                            self.keep_alive = KeepAlive::Until(Instant::now() + self.idle_timeout);

                            self.outbound_substream =
                                Some(OutboundSubstreamState::WaitingOutput(substream))
                        }
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(ConnectionHandlerEvent::Close(e))
                        }
                        Poll::Pending => {
                            self.keep_alive = KeepAlive::Yes;
                            self.outbound_substream =
                                Some(OutboundSubstreamState::PendingFlush(substream));
                            break;
                        }
                    }
                }
                // Currently never used - manual shutdown may implement this in the future
                Some(OutboundSubstreamState::_Closing(mut substream)) => {
                    match Sink::poll_close(Pin::new(&mut substream), cx) {
                        Poll::Ready(Ok(())) => {
                            self.outbound_substream = None;
                            if self.inbound_substream.is_none() {
                                self.keep_alive = KeepAlive::No;
                            }
                            break;
                        }
                        Poll::Ready(Err(e)) => {
                            warn!("Outbound substream error while closing: {:?}", e);
                            return Poll::Ready(ConnectionHandlerEvent::Close(
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "Failed to close outbound substream",
                                )
                                .into(),
                            ));
                        }
                        Poll::Pending => {
                            self.keep_alive = KeepAlive::No;
                            self.outbound_substream =
                                Some(OutboundSubstreamState::_Closing(substream));
                            break;
                        }
                    }
                }
                None => {
                    self.outbound_substream = None;
                    break;
                }
                Some(OutboundSubstreamState::Poisoned) => {
                    unreachable!("Error occurred during outbound stream processing")
                }
            }
        }

        Poll::Pending
    }
}

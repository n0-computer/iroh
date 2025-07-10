//! Manages client-side connections to the relay server.
//!
//! based on tailscale/derp/derp_client.go

use std::{
    io,
    pin::Pin,
    str::Utf8Error,
    task::{ready, Context, Poll},
};

use bytes::Bytes;
#[cfg(not(wasm_browser))]
use bytes::BytesMut;
use iroh_base::{NodeId, SecretKey};
use n0_future::{time::Duration, Sink, Stream};
use nested_enum_utils::common_fields;
use snafu::{Backtrace, ResultExt, Snafu};
use tracing::{debug, warn};

use super::KeyCache;
#[cfg(not(wasm_browser))]
use crate::client::streams::{MaybeTlsStream, ProxyStream};
use crate::{
    protos::relay::{
        ClientInfo, Frame, RecvError as RecvRelayError, SendError as SendRelayError,
        PROTOCOL_VERSION,
    },
    MAX_PACKET_SIZE,
};

/// Error for sending messages to the relay server.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SendError {
    #[cfg(not(wasm_browser))]
    #[snafu(transparent)]
    RelayIo { source: io::Error },
    #[snafu(transparent)]
    WebsocketIo {
        #[cfg(not(wasm_browser))]
        source: tokio_websockets::Error,
        #[cfg(wasm_browser)]
        source: ws_stream_wasm::WsErr,
    },
    #[snafu(display("Exceeds max packet size ({MAX_PACKET_SIZE}): {size}"))]
    ExceedsMaxPacketSize { size: usize },
}

/// Errors when receiving messages from the relay server.
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RecvError {
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    ProtocolSend { source: SendRelayError },
    #[snafu(transparent)]
    ProtocolRecv { source: RecvRelayError },
    #[snafu(transparent)]
    Websocket {
        #[cfg(not(wasm_browser))]
        source: tokio_websockets::Error,
        #[cfg(wasm_browser)]
        source: ws_stream_wasm::WsErr,
    },
    #[snafu(display("invalid protocol message encoding"))]
    InvalidProtocolMessageEncoding { source: Utf8Error },
    #[snafu(display("Unexpected frame received: {frame_type}"))]
    UnexpectedFrame {
        frame_type: crate::protos::relay::FrameType,
    },
}

/// A connection to a relay server.
///
/// This holds a connection to a relay server.  It is:
///
/// - A [`Stream`] for [`ReceivedMessage`] to receive from the server.
/// - A [`Sink`] for [`SendMessage`] to send to the server.
/// - A [`Sink`] for [`Frame`] to send to the server.
///
/// The [`Frame`] sink is a more internal interface, it allows performing the handshake.
/// The [`SendMessage`] and [`ReceivedMessage`] are safer wrappers enforcing some protocol
/// invariants.
#[derive(derive_more::Debug)]
pub(crate) struct Conn {
    #[cfg(not(wasm_browser))]
    #[debug("tokio_websockets::WebSocketStream")]
    pub(crate) conn: tokio_websockets::WebSocketStream<MaybeTlsStream<ProxyStream>>,
    #[cfg(wasm_browser)]
    #[debug("WsStream")]
    pub(crate) conn: ws_stream_wasm::WsStream,
    pub(crate) key_cache: KeyCache,
}

impl Conn {
    /// Constructs a new websocket connection, including the initial server handshake.
    pub(crate) async fn new(
        #[cfg(not(wasm_browser))] conn: tokio_websockets::WebSocketStream<
            MaybeTlsStream<ProxyStream>,
        >,
        #[cfg(wasm_browser)] conn: ws_stream_wasm::WsStream,
        key_cache: KeyCache,
        secret_key: &SecretKey,
    ) -> Result<Self, SendRelayError> {
        let mut conn = Self { conn, key_cache };

        // exchange information with the server
        server_handshake(&mut conn, secret_key).await?;

        Ok(conn)
    }
}

/// Sends the server handshake message.
async fn server_handshake(writer: &mut Conn, secret_key: &SecretKey) -> Result<(), SendRelayError> {
    debug!("server_handshake: started");
    let client_info = ClientInfo {
        version: PROTOCOL_VERSION,
    };
    debug!("server_handshake: sending client_key: {:?}", &client_info);
    crate::protos::relay::send_client_key(&mut *writer, secret_key, &client_info).await?;

    debug!("server_handshake: done");
    Ok(())
}

impl Stream for Conn {
    type Item = Result<ReceivedMessage, RecvError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.conn).poll_next(cx)) {
            #[cfg(not(wasm_browser))]
            Some(Ok(msg)) => {
                if msg.is_close() {
                    // Indicate the stream is done when we receive a close message.
                    // Note: We don't have to poll the stream to completion for it to close gracefully.
                    return Poll::Ready(None);
                }
                if !msg.is_binary() {
                    warn!(?msg, "Got websocket message of unsupported type, skipping.");
                    return Poll::Pending;
                }
                let frame = Frame::from_bytes(msg.into_payload().into(), &self.key_cache)?;
                let message = ReceivedMessage::try_from(frame);
                Poll::Ready(Some(message))
            }
            #[cfg(not(wasm_browser))]
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            #[cfg(wasm_browser)]
            Some(ws_stream_wasm::WsMessage::Binary(vec)) => {
                let frame = Frame::from_bytes(Bytes::from(vec), &self.key_cache)?;
                Poll::Ready(Some(ReceivedMessage::try_from(frame)))
            }
            #[cfg(wasm_browser)]
            Some(msg) => {
                warn!(?msg, "Got websocket message of unsupported type, skipping.");
                Poll::Pending
            }
            None => Poll::Ready(None),
        }
    }
}

impl Sink<Frame> for Conn {
    type Error = SendError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, frame: Frame) -> Result<(), Self::Error> {
        if let Frame::SendPacket { dst_key: _, packet } = &frame {
            if packet.len() > MAX_PACKET_SIZE {
                return Err(ExceedsMaxPacketSizeSnafu { size: packet.len() }.build());
            }
        }

        #[cfg(not(wasm_browser))]
        let msg = tokio_websockets::Message::binary(tokio_websockets::Payload::from(
            frame.write_to(BytesMut::new()).freeze(),
        ));
        #[cfg(wasm_browser)]
        let msg = ws_stream_wasm::WsMessage::Binary(frame.write_to(Vec::new()));

        Pin::new(&mut self.conn).start_send(msg).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_close(cx).map_err(Into::into)
    }
}

impl Sink<SendMessage> for Conn {
    type Error = SendError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_ready(cx).map_err(Into::into)
    }

    fn start_send(mut self: Pin<&mut Self>, item: SendMessage) -> Result<(), Self::Error> {
        if let SendMessage::SendPacket(_, bytes) = &item {
            let size = bytes.len();
            snafu::ensure!(size <= MAX_PACKET_SIZE, ExceedsMaxPacketSizeSnafu { size });
        }

        let frame = Frame::from(item);
        #[cfg(not(wasm_browser))]
        let msg = tokio_websockets::Message::binary(tokio_websockets::Payload::from(
            frame.write_to(BytesMut::new()).freeze(),
        ));
        #[cfg(wasm_browser)]
        let msg = ws_stream_wasm::WsMessage::Binary(frame.write_to(Vec::new()));

        Pin::new(&mut self.conn).start_send(msg).map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.conn).poll_close(cx).map_err(Into::into)
    }
}

/// The messages received from a framed relay stream.
///
/// This is a type-validated version of the `Frame`s on the `RelayCodec`.
#[derive(derive_more::Debug, Clone)]
pub enum ReceivedMessage {
    /// Represents an incoming packet.
    ReceivedPacket {
        /// The [`NodeId`] of the packet sender.
        remote_node_id: NodeId,
        /// The received packet bytes.
        #[debug(skip)]
        data: Bytes, // TODO: ref
    },
    /// Indicates that the client identified by the underlying public key had previously sent you a
    /// packet but has now disconnected from the server.
    NodeGone(NodeId),
    /// Request from a client or server to reply to the
    /// other side with a [`ReceivedMessage::Pong`] with the given payload.
    Ping([u8; 8]),
    /// Reply to a [`ReceivedMessage::Ping`] from a client or server
    /// with the payload sent previously in the ping.
    Pong([u8; 8]),
    /// A one-way empty message from server to client, just to
    /// keep the connection alive. It's like a [`ReceivedMessage::Ping`], but doesn't solicit
    /// a reply from the client.
    KeepAlive,
    /// A one-way message from server to client, declaring the connection health state.
    Health {
        /// If set, is a description of why the connection is unhealthy.
        ///
        /// If `None` means the connection is healthy again.
        ///
        /// The default condition is healthy, so the server doesn't broadcast a [`ReceivedMessage::Health`]
        /// until a problem exists.
        problem: Option<String>,
    },
    /// A one-way message from server to client, advertising that the server is restarting.
    ServerRestarting {
        /// An advisory duration that the client should wait before attempting to reconnect.
        /// It might be zero. It exists for the server to smear out the reconnects.
        reconnect_in: Duration,
        /// An advisory duration for how long the client should attempt to reconnect
        /// before giving up and proceeding with its normal connection failure logic. The interval
        /// between retries is undefined for now. A server should not send a TryFor duration more
        /// than a few seconds.
        try_for: Duration,
    },
}

impl TryFrom<Frame> for ReceivedMessage {
    type Error = RecvError;

    fn try_from(frame: Frame) -> std::result::Result<Self, Self::Error> {
        match frame {
            Frame::KeepAlive => {
                // A one-way keep-alive message that doesn't require an ack.
                // This predated FrameType::Ping/FrameType::Pong.
                Ok(ReceivedMessage::KeepAlive)
            }
            Frame::NodeGone { node_id } => Ok(ReceivedMessage::NodeGone(node_id)),
            Frame::RecvPacket { src_key, content } => {
                let packet = ReceivedMessage::ReceivedPacket {
                    remote_node_id: src_key,
                    data: content,
                };
                Ok(packet)
            }
            Frame::Ping { data } => Ok(ReceivedMessage::Ping(data)),
            Frame::Pong { data } => Ok(ReceivedMessage::Pong(data)),
            Frame::Health { problem } => {
                let problem = std::str::from_utf8(&problem)
                    .context(InvalidProtocolMessageEncodingSnafu)?
                    .to_owned();
                let problem = Some(problem);
                Ok(ReceivedMessage::Health { problem })
            }
            Frame::Restarting {
                reconnect_in,
                try_for,
            } => {
                let reconnect_in = Duration::from_millis(reconnect_in as u64);
                let try_for = Duration::from_millis(try_for as u64);
                Ok(ReceivedMessage::ServerRestarting {
                    reconnect_in,
                    try_for,
                })
            }
            _ => Err(UnexpectedFrameSnafu {
                frame_type: frame.typ(),
            }
            .build()),
        }
    }
}

/// Messages we can send to a relay server.
#[derive(Debug)]
pub enum SendMessage {
    /// Send a packet of data to the [`NodeId`].
    SendPacket(NodeId, Bytes),
    /// Sends a ping message to the connected relay server.
    Ping([u8; 8]),
    /// Sends a pong message to the connected relay server.
    Pong([u8; 8]),
}

impl From<SendMessage> for Frame {
    fn from(source: SendMessage) -> Self {
        match source {
            SendMessage::SendPacket(dst_key, packet) => Frame::SendPacket { dst_key, packet },
            SendMessage::Ping(data) => Frame::Ping { data },
            SendMessage::Pong(data) => Frame::Pong { data },
        }
    }
}

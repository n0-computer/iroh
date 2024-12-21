//! Manages client-side connections to the relay server.
//!
//! based on tailscale/derp/derp_client.go

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{bail, ensure, Result};
use bytes::Bytes;
use futures_lite::Stream;
use futures_sink::Sink;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt,
};
use iroh_base::{NodeId, SecretKey};
use tokio_tungstenite_wasm::WebSocketStream;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, trace};

use super::KeyCache;
use crate::{
    client::streams::{MaybeTlsStreamReader, MaybeTlsStreamWriter},
    protos::relay::{
        write_frame, ClientInfo, Frame, RelayCodec, MAX_PACKET_SIZE, PROTOCOL_VERSION,
    },
};

/// A connection to a relay server.
#[derive(derive_more::Debug)]
pub(crate) struct Conn {
    #[debug("ConnFrameStream")]
    conn: ConnFramed,
}

impl Conn {
    /// Constructs the connection, including the initial server handshake.
    pub(crate) async fn new(mut conn: ConnFramed, secret_key: &SecretKey) -> Result<Self> {
        // exchange information with the server
        server_handshake(&mut conn, secret_key).await?;

        let conn = Self { conn };
        Ok(conn)
    }

    /// Sends a packet to the node identified by `dstkey`
    ///
    /// Errors if the packet is larger than [`MAX_PACKET_SIZE`]
    pub(crate) async fn send(&mut self, dst: NodeId, packet: Bytes) -> Result<()> {
        trace!(dst = dst.fmt_short(), len = packet.len(), "[RELAY] send");

        send_packet(&mut self.conn, dst, packet).await?;
        Ok(())
    }

    /// Send a ping with 8 bytes of random data.
    pub(crate) async fn send_ping(&mut self, data: [u8; 8]) -> Result<()> {
        write_frame(&mut self.conn, Frame::Ping { data }, None).await?;
        self.conn.flush().await?;
        Ok(())
    }

    /// Respond to a ping request. The `data` field should be filled
    /// by the 8 bytes of random data send by the ping.
    pub(crate) async fn send_pong(&mut self, data: [u8; 8]) -> Result<()> {
        write_frame(&mut self.conn, Frame::Pong { data }, None).await?;
        self.conn.flush().await?;
        Ok(())
    }

    /// Sends a packet that tells the server whether this
    /// connection is to the user's preferred server. This is only
    /// used in the server for stats.
    pub(crate) async fn note_preferred(&mut self, preferred: bool) -> Result<()> {
        write_frame(&mut self.conn, Frame::NotePreferred { preferred }, None).await?;
        self.conn.flush().await?;
        Ok(())
    }

    /// Close the connection
    ///
    /// Shuts down the write loop directly and marks the connection as closed. The [`Conn`] will
    /// check if the it is closed before attempting to read from it.
    pub(crate) async fn close(&mut self) {
        self.conn.close().await.ok();
    }
}

async fn server_handshake(writer: &mut ConnFramed, secret_key: &SecretKey) -> Result<()> {
    debug!("server_handshake: started");
    let client_info = ClientInfo {
        version: PROTOCOL_VERSION,
    };
    debug!("server_handshake: sending client_key: {:?}", &client_info);
    crate::protos::relay::send_client_key(writer, secret_key, &client_info).await?;

    debug!("server_handshake: done");
    Ok(())
}

fn tung_wasm_to_io_err(e: tokio_tungstenite_wasm::Error) -> std::io::Error {
    match e {
        tokio_tungstenite_wasm::Error::Io(io_err) => io_err,
        _ => std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
    }
}

impl Stream for Conn {
    type Item = Result<ReceivedMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.conn).poll_next(cx)
    }
}

impl Stream for ConnFramed {
    type Item = Result<ReceivedMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match *self {
            Self::Derp { ref mut reader, .. } => match Pin::new(reader).poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => {
                    let frame = process_incoming_frame(frame);
                    Poll::Ready(Some(frame))
                }
                Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => Poll::Ready(None),
            },
            Self::Ws {
                ref mut reader,
                ref key_cache,
                ..
            } => match Pin::new(reader).poll_next(cx) {
                Poll::Ready(Some(Ok(tokio_tungstenite_wasm::Message::Binary(vec)))) => {
                    let frame = Frame::decode_from_ws_msg(vec, key_cache);
                    let frame = frame.and_then(process_incoming_frame);
                    Poll::Ready(Some(frame))
                }
                Poll::Ready(Some(Ok(msg))) => {
                    tracing::warn!(?msg, "Got websocket message of unsupported type, skipping.");
                    Poll::Pending
                }
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

fn process_incoming_frame(frame: Frame) -> Result<ReceivedMessage> {
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
            let problem = std::str::from_utf8(&problem)?.to_owned();
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
        _ => bail!("unexpected packet: {:?}", frame.typ()),
    }
}

pub(crate) enum ConnFramed {
    Derp {
        writer: FramedWrite<MaybeTlsStreamWriter, RelayCodec>,
        reader: FramedRead<MaybeTlsStreamReader, RelayCodec>,
    },
    Ws {
        writer: SplitSink<WebSocketStream, tokio_tungstenite_wasm::Message>,
        reader: SplitStream<WebSocketStream>,
        key_cache: KeyCache,
    },
}

impl Sink<Frame> for ConnFramed {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match *self {
            Self::Derp { ref mut writer, .. } => Pin::new(writer).poll_ready(cx),
            Self::Ws { ref mut writer, .. } => {
                Pin::new(writer).poll_ready(cx).map_err(tung_wasm_to_io_err)
            }
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Frame) -> Result<(), Self::Error> {
        match *self {
            Self::Derp { ref mut writer, .. } => Pin::new(writer).start_send(item),
            Self::Ws { ref mut writer, .. } => Pin::new(writer)
                .start_send(tokio_tungstenite_wasm::Message::binary(
                    item.encode_for_ws_msg(),
                ))
                .map_err(tung_wasm_to_io_err),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match *self {
            Self::Derp { ref mut writer, .. } => Pin::new(writer).poll_flush(cx),
            Self::Ws { ref mut writer, .. } => {
                Pin::new(writer).poll_flush(cx).map_err(tung_wasm_to_io_err)
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match *self {
            Self::Derp { ref mut writer, .. } => Pin::new(writer).poll_close(cx),
            Self::Ws { ref mut writer, .. } => {
                Pin::new(writer).poll_close(cx).map_err(tung_wasm_to_io_err)
            }
        }
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

pub(crate) async fn send_packet<S: Sink<Frame, Error = std::io::Error> + Unpin>(
    mut writer: S,
    dst: NodeId,
    packet: Bytes,
) -> Result<()> {
    ensure!(
        packet.len() <= MAX_PACKET_SIZE,
        "packet too big: {}",
        packet.len()
    );

    let frame = Frame::SendPacket {
        dst_key: dst,
        packet,
    };
    writer.send(frame).await?;
    writer.flush().await?;

    Ok(())
}

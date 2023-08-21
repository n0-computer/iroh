use anyhow::{bail, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::key::PublicKey;

use super::{FrameType, MAGIC, MAX_FRAME_SIZE, NOT_PREFERRED, PREFERRED};

#[derive(Debug, Default, Clone)]
pub(crate) struct DerpCodec;

#[derive(Debug)]
pub(crate) struct Frame {
    pub(crate) typ: FrameType,
    pub(crate) content: Bytes,
}

#[derive(Debug)]
pub(crate) enum WriteFrame<'a> {
    ServerKey {
        key: PublicKey,
    },
    ClientInfo {
        client_public_key: PublicKey,
        encrypted_message: Vec<u8>,
    },
    ServerInfo {
        encrypted_message: Vec<u8>,
    },
    SendPacket {
        dst_key: PublicKey,
        packet: &'a [u8],
    },
    RecvPacket {
        src_key: PublicKey,
        content: Bytes,
    },
    KeepAlive,
    NotePreferred {
        preferred: bool,
    },
    PeerGone {
        peer: PublicKey,
    },
    PeerPresent {
        peer: PublicKey,
    },
    WatchConns,
    ClosePeer {
        peer: PublicKey,
    },
    Ping {
        data: [u8; 8],
    },
    Pong {
        data: [u8; 8],
    },
    #[allow(dead_code)]
    Health {
        data: Vec<u8>,
    },
    #[allow(dead_code)]
    Restarting {},
    ForwardPacket {
        src_key: PublicKey,
        dst_key: PublicKey,
        packet: &'a [u8],
    },
}

impl WriteFrame<'_> {
    fn typ(&self) -> FrameType {
        match self {
            WriteFrame::ServerKey { .. } => FrameType::ServerKey,
            WriteFrame::ClientInfo { .. } => FrameType::ClientInfo,
            WriteFrame::ServerInfo { .. } => FrameType::ServerInfo,
            WriteFrame::SendPacket { .. } => FrameType::SendPacket,
            WriteFrame::RecvPacket { .. } => FrameType::RecvPacket,
            WriteFrame::KeepAlive => FrameType::KeepAlive,
            WriteFrame::NotePreferred { .. } => FrameType::NotePreferred,
            WriteFrame::PeerGone { .. } => FrameType::PeerGone,
            WriteFrame::PeerPresent { .. } => FrameType::PeerPresent,
            WriteFrame::WatchConns => FrameType::WatchConns,
            WriteFrame::ClosePeer { .. } => FrameType::ClosePeer,
            WriteFrame::Ping { .. } => FrameType::Ping,
            WriteFrame::Pong { .. } => FrameType::Pong,
            WriteFrame::Health { .. } => FrameType::Health,
            WriteFrame::Restarting { .. } => FrameType::Restarting,
            WriteFrame::ForwardPacket { .. } => FrameType::ForwardPacket,
        }
    }

    /// Serialized length (without the frame header)
    pub(super) fn len(&self) -> usize {
        match self {
            WriteFrame::ServerKey { .. } => MAGIC.as_bytes().len() + 32,
            WriteFrame::ClientInfo {
                client_public_key: _,
                encrypted_message,
            } => 32 + encrypted_message.len(),
            WriteFrame::ServerInfo { encrypted_message } => encrypted_message.len(),
            WriteFrame::SendPacket { dst_key: _, packet } => 32 + packet.len(),
            WriteFrame::RecvPacket {
                src_key: _,
                content,
            } => 32 + content.len(),
            WriteFrame::KeepAlive => 0,
            WriteFrame::NotePreferred { .. } => 1,
            WriteFrame::PeerGone { .. } => 32,
            WriteFrame::PeerPresent { .. } => 32,
            WriteFrame::WatchConns => 0,
            WriteFrame::ClosePeer { .. } => 32,
            WriteFrame::Ping { .. } => 8,
            WriteFrame::Pong { .. } => 8,
            WriteFrame::Health { data } => data.len(),
            WriteFrame::Restarting {} => 0,
            WriteFrame::ForwardPacket {
                src_key: _,
                dst_key: _,
                packet,
            } => 32 + 32 + packet.len(),
        }
    }

    /// Writes it self to the given buffer.
    fn write_to(&self, dst: &mut BytesMut) {
        match self {
            WriteFrame::ServerKey { key } => {
                dst.put(MAGIC.as_bytes());
                dst.put(key.as_ref());
            }
            WriteFrame::ClientInfo {
                client_public_key,
                encrypted_message,
            } => {
                dst.put(client_public_key.as_ref());
                dst.put(&encrypted_message[..]);
            }
            WriteFrame::ServerInfo { encrypted_message } => {
                dst.put(&encrypted_message[..]);
            }
            WriteFrame::SendPacket { dst_key, packet } => {
                dst.put(dst_key.as_ref());
                dst.put(*packet);
            }
            WriteFrame::RecvPacket { src_key, content } => {
                dst.put(src_key.as_ref());
                dst.put(content.as_ref());
            }
            WriteFrame::KeepAlive => {}
            WriteFrame::NotePreferred { preferred } => {
                if *preferred {
                    dst.put_u8(PREFERRED);
                } else {
                    dst.put_u8(NOT_PREFERRED);
                }
            }
            WriteFrame::PeerGone { peer } => {
                dst.put(peer.as_ref());
            }
            WriteFrame::PeerPresent { peer } => {
                dst.put(peer.as_ref());
            }
            WriteFrame::WatchConns => {}
            WriteFrame::ClosePeer { peer } => {
                dst.put(peer.as_ref());
            }
            WriteFrame::Ping { data } => {
                dst.put(&data[..]);
            }
            WriteFrame::Pong { data } => {
                dst.put(&data[..]);
            }
            WriteFrame::Health { data } => {
                dst.put(&data[..]);
            }
            WriteFrame::Restarting {} => {}
            WriteFrame::ForwardPacket {
                src_key,
                dst_key,
                packet,
            } => {
                dst.put(src_key.as_ref());
                dst.put(dst_key.as_ref());
                dst.put(*packet);
            }
        }
    }
}

const HEADER_LEN: usize = 5;

impl Decoder for DerpCodec {
    type Item = Frame;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 5 bytes
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        // Can't use the `get_` Buf api, as that advances the buffer
        let frame_type: FrameType = src[0].into();
        let frame_len = u32::from_be_bytes(src[1..5].try_into().unwrap()) as usize;

        if frame_len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", frame_len),
            ));
        }

        if src.len() < HEADER_LEN + frame_len {
            // Optimization: prereserve the buffer space
            src.reserve(HEADER_LEN + frame_len - src.len());

            return Ok(None);
        }

        // advance the header
        src.advance(HEADER_LEN);

        let content = src.split_to(frame_len).freeze();

        Ok(Some(Frame {
            typ: frame_type,
            content,
        }))
    }
}

impl Encoder<WriteFrame<'_>> for DerpCodec {
    type Error = std::io::Error;

    fn encode(&mut self, frame: WriteFrame<'_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let frame_len: usize = frame.len();
        if frame_len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", frame_len),
            ));
        }

        let frame_len_u32 = u32::try_from(frame_len).expect("just checked");

        dst.reserve(HEADER_LEN + frame_len);
        dst.put_u8(frame.typ().into());
        dst.put_u32(frame_len_u32);
        frame.write_to(dst);

        Ok(())
    }
}

/// Receives the next frame and matches the frame type. If the correct type is found returns the content,
/// otherwise an error.
pub(super) async fn recv_frame<S: Stream<Item = std::io::Result<Frame>> + Unpin>(
    frame_type: FrameType,
    mut stream: S,
) -> anyhow::Result<Bytes> {
    match stream.next().await {
        Some(Ok(frame)) => {
            ensure!(
                frame_type == frame.typ,
                "expected frame {}, found {}",
                frame_type,
                frame.typ
            );
            Ok(frame.content)
        }
        Some(Err(err)) => Err(err.into()),
        None => bail!("EOF: unexpected stream end, expected frame {}", frame_type),
    }
}

use anyhow::{bail, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::key::PublicKey;

use super::{FrameType, MAGIC, MAX_FRAME_SIZE, NOT_PREFERRED, PREFERRED};

#[derive(Debug, Default, Clone)]
pub(crate) struct DerpCodec;

#[derive(Debug, Default, Clone)]
pub(crate) struct DerpCodec2;

#[derive(Debug)]
pub(crate) struct Frame {
    pub(crate) typ: FrameType,
    pub(crate) content: Bytes,
}

pub(crate) type ReadFrame = DecodedFrame<Bytes>;

pub(crate) type WriteFrame<'a> = DecodedFrame<&'a [u8]>;

#[derive(Debug)]
pub(crate) enum DecodedFrame<T> {
    ServerKey {
        key: PublicKey,
    },
    ClientInfo {
        client_public_key: PublicKey,
        encrypted_message: T,
    },
    ServerInfo {
        encrypted_message: T,
    },
    SendPacket {
        dst_key: PublicKey,
        packet: T,
    },
    RecvPacket {
        src_key: PublicKey,
        content: T,
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
        data: T,
    },
    #[allow(dead_code)]
    Restarting {},
    ForwardPacket {
        src_key: PublicKey,
        dst_key: PublicKey,
        packet: T,
    },
}

impl<T: AsRef<[u8]>> DecodedFrame<T> {
    fn typ(&self) -> FrameType {
        match self {
            Self::ServerKey { .. } => FrameType::ServerKey,
            Self::ClientInfo { .. } => FrameType::ClientInfo,
            Self::ServerInfo { .. } => FrameType::ServerInfo,
            Self::SendPacket { .. } => FrameType::SendPacket,
            Self::RecvPacket { .. } => FrameType::RecvPacket,
            Self::KeepAlive => FrameType::KeepAlive,
            Self::NotePreferred { .. } => FrameType::NotePreferred,
            Self::PeerGone { .. } => FrameType::PeerGone,
            Self::PeerPresent { .. } => FrameType::PeerPresent,
            Self::WatchConns => FrameType::WatchConns,
            Self::ClosePeer { .. } => FrameType::ClosePeer,
            Self::Ping { .. } => FrameType::Ping,
            Self::Pong { .. } => FrameType::Pong,
            Self::Health { .. } => FrameType::Health,
            Self::Restarting { .. } => FrameType::Restarting,
            Self::ForwardPacket { .. } => FrameType::ForwardPacket,
        }
    }

    /// Serialized length (without the frame header)
    pub(super) fn len(&self) -> usize {
        match self {
            Self::ServerKey { .. } => MAGIC.as_bytes().len() + 32,
            Self::ClientInfo {
                client_public_key: _,
                encrypted_message,
            } => 32 + encrypted_message.as_ref().len(),
            Self::ServerInfo { encrypted_message } => encrypted_message.as_ref().len(),
            Self::SendPacket { dst_key: _, packet } => 32 + packet.as_ref().len(),
            Self::RecvPacket {
                src_key: _,
                content,
            } => 32 + content.as_ref().len(),
            Self::KeepAlive => 0,
            Self::NotePreferred { .. } => 1,
            Self::PeerGone { .. } => 32,
            Self::PeerPresent { .. } => 32,
            Self::WatchConns => 0,
            Self::ClosePeer { .. } => 32,
            Self::Ping { .. } => 8,
            Self::Pong { .. } => 8,
            Self::Health { data } => data.as_ref().len(),
            Self::Restarting {} => 0,
            Self::ForwardPacket {
                src_key: _,
                dst_key: _,
                packet,
            } => 32 + 32 + packet.as_ref().len(),
        }
    }

    /// Writes it self to the given buffer.
    fn write_to(&self, dst: &mut BytesMut) {
        match self {
            Self::ServerKey { key } => {
                dst.put(MAGIC.as_bytes());
                dst.put(key.as_ref());
            }
            Self::ClientInfo {
                client_public_key,
                encrypted_message,
            } => {
                dst.put(client_public_key.as_ref());
                dst.put(&encrypted_message.as_ref()[..]);
            }
            Self::ServerInfo { encrypted_message } => {
                dst.put(&encrypted_message.as_ref()[..]);
            }
            Self::SendPacket { dst_key, packet } => {
                dst.put(dst_key.as_ref());
                dst.put(packet.as_ref());
            }
            Self::RecvPacket { src_key, content } => {
                dst.put(src_key.as_ref());
                dst.put(content.as_ref());
            }
            Self::KeepAlive => {}
            Self::NotePreferred { preferred } => {
                if *preferred {
                    dst.put_u8(PREFERRED);
                } else {
                    dst.put_u8(NOT_PREFERRED);
                }
            }
            Self::PeerGone { peer } => {
                dst.put(peer.as_ref());
            }
            Self::PeerPresent { peer } => {
                dst.put(peer.as_ref());
            }
            Self::WatchConns => {}
            Self::ClosePeer { peer } => {
                dst.put(peer.as_ref());
            }
            Self::Ping { data } => {
                dst.put(&data[..]);
            }
            Self::Pong { data } => {
                dst.put(&data[..]);
            }
            Self::Health { data } => {
                dst.put(&data.as_ref()[..]);
            }
            Self::Restarting {} => {}
            Self::ForwardPacket {
                src_key,
                dst_key,
                packet,
            } => {
                dst.put(src_key.as_ref());
                dst.put(dst_key.as_ref());
                dst.put(packet.as_ref());
            }
        }
    }
}

impl ReadFrame {
    fn parse_from(frame_type: FrameType, content: Bytes) -> anyhow::Result<Option<Self>> {
        let res = match frame_type {
            FrameType::ServerKey => {
                ensure!(
                    content.len() == 32 + MAGIC.as_bytes().len(),
                    "invalid server key frame length"
                );
                ensure!(
                    &content[..MAGIC.as_bytes().len()] == MAGIC.as_bytes(),
                    "invalid server key frame magic"
                );
                let key = PublicKey::try_from(&content[32..])?;
                Self::ServerKey { key }
            }
            FrameType::ClientInfo => {
                ensure!(
                    content.len() >= 32,
                    "invalid client info frame length: {}",
                    content.len()
                );
                let client_public_key = PublicKey::try_from(&content[..32])?;
                let encrypted_message = content.slice(32..);
                Self::ClientInfo {
                    client_public_key,
                    encrypted_message,
                }
            }
            FrameType::ServerInfo => Self::ServerInfo {
                encrypted_message: content,
            },
            FrameType::SendPacket => {
                ensure!(
                    content.len() >= 32,
                    "invalid send packet frame length: {}",
                    content.len()
                );
                let dst_key = PublicKey::try_from(&content[..32])?;
                let packet = content.slice(32..);
                Self::SendPacket { dst_key, packet }
            }
            FrameType::RecvPacket => {
                ensure!(
                    content.len() >= 32,
                    "invalid recv packet frame length: {}",
                    content.len()
                );
                let src_key = PublicKey::try_from(&content[..32])?;
                let content = content.slice(32..);
                Self::RecvPacket { src_key, content }
            }
            FrameType::KeepAlive => {
                anyhow::ensure!(content.is_empty(), "invalid keep alive frame length");
                Self::KeepAlive
            }
            FrameType::NotePreferred => {
                anyhow::ensure!(content.len() == 1, "invalid note preferred frame length");
                let preferred = match content[0] {
                    PREFERRED => true,
                    NOT_PREFERRED => false,
                    _ => anyhow::bail!("invalid note preferred frame content"),
                };
                Self::NotePreferred { preferred }
            }
            FrameType::PeerGone => {
                anyhow::ensure!(content.len() == 32, "invalid peer gone frame length");
                let peer = PublicKey::try_from(&content[..32])?;
                Self::PeerGone { peer }
            }
            FrameType::PeerPresent => {
                anyhow::ensure!(content.len() == 32, "invalid peer present frame length");
                let peer = PublicKey::try_from(&content[..32])?;
                Self::PeerPresent { peer }
            }
            FrameType::WatchConns => {
                anyhow::ensure!(content.is_empty(), "invalid watch conns frame length");
                Self::WatchConns
            }
            FrameType::ClosePeer => {
                anyhow::ensure!(content.len() == 32, "invalid close peer frame length");
                let peer = PublicKey::try_from(&content[..32])?;
                Self::ClosePeer { peer }
            }
            FrameType::Ping => {
                anyhow::ensure!(content.len() == 8, "invalid ping frame length");
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Ping { data }
            }
            FrameType::Pong => {
                anyhow::ensure!(content.len() == 8, "invalid pong frame length");
                let mut data = [0u8; 8];
                data.copy_from_slice(&content[..8]);
                Self::Pong { data }
            }
            FrameType::Health => Self::Health { data: content },
            FrameType::Restarting => {
                anyhow::ensure!(content.is_empty(), "invalid restarting frame length");
                Self::Restarting {}
            }
            FrameType::ForwardPacket => {
                ensure!(
                    content.len() >= 32 + 32,
                    "invalid forward packet frame length: {}",
                    content.len()
                );
                let src_key = PublicKey::try_from(&content[..32])?;
                let dst_key = PublicKey::try_from(&content[32..64])?;
                let packet = content.slice(64..);
                Self::ForwardPacket {
                    src_key,
                    dst_key,
                    packet,
                }
            }
            _ => {
                anyhow::bail!("invalid frame type: {:?}", frame_type);
            }
        };
        Ok(Some(res))
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

impl Decoder for DerpCodec2 {
    type Item = ReadFrame;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 5 bytes
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        // Can't use the `get_` Buf api, as that advances the buffer
        let frame_type: FrameType = src[0].into();
        let frame_len = u32::from_be_bytes(src[1..5].try_into().unwrap()) as usize;

        anyhow::ensure!(
            frame_len <= MAX_FRAME_SIZE,
            "frame too large: {}",
            frame_len
        );
        if src.len() < HEADER_LEN + frame_len {
            // Optimization: prereserve the buffer space
            src.reserve(HEADER_LEN + frame_len - src.len());

            return Ok(None);
        }

        // advance the header
        src.advance(HEADER_LEN);

        let content = src.split_to(frame_len).freeze();

        ReadFrame::parse_from(frame_type, content)
    }
}

impl Encoder<DecodedFrame<&[u8]>> for DerpCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        frame: DecodedFrame<&[u8]>,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
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

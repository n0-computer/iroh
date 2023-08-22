use anyhow::ensure;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use tokio_util::codec::{Decoder, Encoder};

use crate::{derp::MAX_PACKET_SIZE, key::PublicKey};

use super::{FrameType, MAGIC, MAX_FRAME_SIZE, NOT_PREFERRED, PREFERRED};

#[derive(Debug, Default, Clone)]
pub(crate) struct DerpCodec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WriteFrame {
    ServerKey {
        key: PublicKey,
    },
    ClientInfo {
        client_public_key: PublicKey,
        encrypted_message: Bytes,
    },
    ServerInfo {
        encrypted_message: Bytes,
    },
    SendPacket {
        dst_key: PublicKey,
        packet: Bytes,
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
    Health {
        problem: Bytes,
    },
    Restarting {
        reconnect_in: u32,
        try_for: u32,
    },
    ForwardPacket {
        src_key: PublicKey,
        dst_key: PublicKey,
        packet: Bytes,
    },
}

impl WriteFrame {
    pub(super) fn typ(&self) -> FrameType {
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
            WriteFrame::ServerKey { .. } => MAGIC.as_bytes().len() + PUBLIC_KEY_LENGTH,
            WriteFrame::ClientInfo {
                client_public_key: _,
                encrypted_message,
            } => PUBLIC_KEY_LENGTH + encrypted_message.len(),
            WriteFrame::ServerInfo { encrypted_message } => encrypted_message.len(),
            WriteFrame::SendPacket { dst_key: _, packet } => PUBLIC_KEY_LENGTH + packet.len(),
            WriteFrame::RecvPacket {
                src_key: _,
                content,
            } => PUBLIC_KEY_LENGTH + content.len(),
            WriteFrame::KeepAlive => 0,
            WriteFrame::NotePreferred { .. } => 1,
            WriteFrame::PeerGone { .. } => PUBLIC_KEY_LENGTH,
            WriteFrame::PeerPresent { .. } => PUBLIC_KEY_LENGTH,
            WriteFrame::WatchConns => 0,
            WriteFrame::ClosePeer { .. } => PUBLIC_KEY_LENGTH,
            WriteFrame::Ping { .. } => 8,
            WriteFrame::Pong { .. } => 8,
            WriteFrame::Health { problem } => problem.len(),
            WriteFrame::Restarting { .. } => 4 + 4,
            WriteFrame::ForwardPacket {
                src_key: _,
                dst_key: _,
                packet,
            } => PUBLIC_KEY_LENGTH * 2 + packet.len(),
        }
    }

    /// Write the packet to bytes including type and length header.
    pub(crate) fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len() + 5);
        buf.put_u8(self.typ().into());
        buf.put_u32(self.len() as u32);
        self.write_to(&mut buf);
        buf.freeze()
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
                dst.put(packet.as_ref());
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
            WriteFrame::Health { problem } => {
                dst.put(problem.as_ref());
            }
            WriteFrame::Restarting {
                reconnect_in,
                try_for,
            } => {
                dst.put_u32(*reconnect_in);
                dst.put_u32(*try_for);
            }
            WriteFrame::ForwardPacket {
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

    pub(super) fn from_bytes(frame_type: FrameType, content: Bytes) -> anyhow::Result<Self> {
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
                let key = PublicKey::try_from(&content[MAGIC.as_bytes().len()..])?;
                Self::ServerKey { key }
            }
            FrameType::ClientInfo => {
                ensure!(
                    content.len() >= PUBLIC_KEY_LENGTH,
                    "invalid client info frame length: {}",
                    content.len()
                );
                let client_public_key = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                let encrypted_message = content.slice(PUBLIC_KEY_LENGTH..);
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
                    content.len() >= PUBLIC_KEY_LENGTH,
                    "invalid send packet frame length: {}",
                    content.len()
                );
                let packet_len = content.len() - PUBLIC_KEY_LENGTH;
                ensure!(
                    packet_len <= MAX_PACKET_SIZE,
                    "data packet longer ({packet_len}) than max of {MAX_PACKET_SIZE}"
                );
                let dst_key = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                let packet = content.slice(PUBLIC_KEY_LENGTH..);
                Self::SendPacket { dst_key, packet }
            }
            FrameType::RecvPacket => {
                ensure!(
                    content.len() >= PUBLIC_KEY_LENGTH,
                    "invalid recv packet frame length: {}",
                    content.len()
                );
                let src_key = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                let content = content.slice(PUBLIC_KEY_LENGTH..);
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
                anyhow::ensure!(
                    content.len() == PUBLIC_KEY_LENGTH,
                    "invalid peer gone frame length"
                );
                let peer = PublicKey::try_from(&content[..32])?;
                Self::PeerGone { peer }
            }
            FrameType::PeerPresent => {
                anyhow::ensure!(
                    content.len() == PUBLIC_KEY_LENGTH,
                    "invalid peer present frame length"
                );
                let peer = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                Self::PeerPresent { peer }
            }
            FrameType::WatchConns => {
                anyhow::ensure!(content.is_empty(), "invalid watch conns frame length");
                Self::WatchConns
            }
            FrameType::ClosePeer => {
                anyhow::ensure!(
                    content.len() == PUBLIC_KEY_LENGTH,
                    "invalid close peer frame length"
                );
                let peer = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
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
            FrameType::Health => Self::Health {
                problem: content.to_vec().into(),
            },
            FrameType::Restarting => {
                ensure!(
                    content.len() == 4 + 4,
                    "invalid restarting frame length: {}",
                    content.len()
                );
                let reconnect_in = u32::from_be_bytes(content[..4].try_into().unwrap());
                let try_for = u32::from_be_bytes(content[4..].try_into().unwrap());
                Self::Restarting {
                    reconnect_in,
                    try_for,
                }
            }
            FrameType::ForwardPacket => {
                ensure!(
                    content.len() >= PUBLIC_KEY_LENGTH * 2,
                    "invalid forward packet frame length: {}",
                    content.len()
                );
                let packet_len = content.len() - PUBLIC_KEY_LENGTH * 2;
                ensure!(
                    packet_len <= MAX_PACKET_SIZE * 2,
                    "data packet longer ({packet_len}) than {MAX_PACKET_SIZE}"
                );

                let src_key = PublicKey::try_from(&content[..PUBLIC_KEY_LENGTH])?;
                let dst_key =
                    PublicKey::try_from(&content[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2])?;
                let packet = content[64..].to_vec().into();
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
        Ok(res)
    }
}

const HEADER_LEN: usize = 5;

impl Decoder for DerpCodec {
    type Item = WriteFrame;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 5 bytes
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        // Can't use the `get_` Buf api, as that advances the buffer
        let frame_type: FrameType = src[0].into();
        let frame_len = u32::from_be_bytes(src[1..5].try_into().unwrap()) as usize;

        if frame_len > MAX_FRAME_SIZE {
            anyhow::bail!("Frame of length {} is too large.", frame_len);
        }

        if src.len() < HEADER_LEN + frame_len {
            // Optimization: prereserve the buffer space
            src.reserve(HEADER_LEN + frame_len - src.len());

            return Ok(None);
        }

        // advance the header
        src.advance(HEADER_LEN);

        let mut content = src.split_to(frame_len);
        let frame = WriteFrame::from_bytes(frame_type, content.to_vec().into())?;

        Ok(Some(frame))
    }
}

impl Encoder<WriteFrame> for DerpCodec {
    type Error = std::io::Error;

    fn encode(&mut self, frame: WriteFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
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
        tracing::error!("wrote {}", frame_len_u32 + 5);

        Ok(())
    }
}

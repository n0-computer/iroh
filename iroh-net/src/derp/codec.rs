use anyhow::{bail, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use tokio_util::codec::{Decoder, Encoder};

use crate::key::node::{PublicKey, SecretKey};

use super::{FrameType, MAX_FRAME_SIZE};

#[derive(Debug, Default, Clone)]
pub(super) struct DerpCodec;

#[derive(Debug)]
pub(super) struct Frame {
    pub(super) typ: FrameType,
    pub(super) content: Bytes,
}

#[derive(Debug)]
pub(super) enum WriteFrame {
    ServerKey {},
    ClientInfo {
        secret_key: SecretKey,
        server_key: PublicKey,
    },
    ServerInfo {},
    SendPacket {},
    RecvPacket {},
    KeepAlive {},
    NotePreferred {},
    PeerGone {},
    PeerPresent {},
    WatchConns {},
    ClosePeer {},
    Ping {},
    Pong {},
    Health {},
    Restarting {},
    ForwardPacket {},
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

impl Encoder<WriteFrame<'_, '_>> for DerpCodec {
    type Error = std::io::Error;

    fn encode(&mut self, frame: WriteFrame<'_, '_>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let frame_len: usize = frame.content.iter().map(|v| v.len()).sum();
        if frame_len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", frame_len),
            ));
        }

        let frame_len_u32 = u32::try_from(frame.content.len()).expect("just checked");

        dst.reserve(HEADER_LEN + frame_len);
        dst.put_u8(frame.typ.into());
        dst.put_u32(frame_len_u32);
        for content in frame.content {
            dst.put(*content);
        }

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

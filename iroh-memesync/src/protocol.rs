use std::future::Future;
use std::pin::Pin;

use asynchronous_codec::{Decoder, Encoder, Framed};
use bytes::BytesMut;
use futures::io::{AsyncRead, AsyncWrite};
use futures::TryStreamExt;
use libp2p::core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use unsigned_varint::codec;

use crate::handler::HandlerError;
use crate::{Message, Request};

const MAX_BUF_SIZE: usize = 1024 * 1024 * 4;
const PROTOCOLS: [&[u8]; 1] = [b"/ipfs/memesync/1.0.0"];

#[derive(Default, Clone, Debug)]
pub struct MemesyncProtocol;

impl UpgradeInfo for MemesyncProtocol {
    type Info = &'static [u8];
    type InfoIter = core::array::IntoIter<Self::Info, 1>;

    fn protocol_info(&self) -> Self::InfoIter {
        PROTOCOLS.into_iter()
    }
}

impl<TSocket> InboundUpgrade<TSocket> for MemesyncProtocol
where
    TSocket: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = (Framed<TSocket, MemesyncCodec>, Request);
    type Error = HandlerError;

    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    #[inline]
    fn upgrade_inbound(self, socket: TSocket, _info: Self::Info) -> Self::Future {
        let mut length_codec = codec::UviBytes::default();
        length_codec.set_max_len(MAX_BUF_SIZE);

        Box::pin(async move {
            let mut framed = Framed::new(socket, MemesyncCodec { length_codec });

            // read initial message
            let message: Message = framed
                .try_next()
                .await?
                .ok_or_else(|| HandlerError::EmptyInbound)?;

            match message {
                Message::Request(req) => Ok((framed, req)),
                Message::Response(_) => Err(HandlerError::InvalidInbound),
            }
        })
    }
}

pub struct MemesyncCodec {
    /// Codec to encode/decode the Unsigned varint length prefix of the frames.
    pub length_codec: codec::UviBytes,
}

impl<TSocket> OutboundUpgrade<TSocket> for MemesyncProtocol
where
    TSocket: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Framed<TSocket, MemesyncCodec>;
    type Error = HandlerError;

    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    #[inline]
    fn upgrade_outbound(self, socket: TSocket, _info: Self::Info) -> Self::Future {
        let mut length_codec = codec::UviBytes::default();
        length_codec.set_max_len(MAX_BUF_SIZE);

        Box::pin(async move {
            let framed = Framed::new(socket, MemesyncCodec { length_codec });
            Ok(framed)
        })
    }
}

impl Encoder for MemesyncCodec {
    type Item = Message;
    type Error = HandlerError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let buf = item.into_bytes();
        self.length_codec
            .encode(buf.into(), dst)
            .map_err(|_| HandlerError::MaxTransmissionSize)
    }
}

impl Decoder for MemesyncCodec {
    type Item = Message;
    type Error = HandlerError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet = match self.length_codec.decode(src).map_err(|e| {
            if let std::io::ErrorKind::PermissionDenied = e.kind() {
                HandlerError::MaxTransmissionSize
            } else {
                HandlerError::Io(e)
            }
        })? {
            Some(p) => p,
            None => return Ok(None),
        };

        let message = Message::from_bytes(packet)?;

        Ok(Some(message))
    }
}

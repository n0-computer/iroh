use std::future::Future;
use std::pin::Pin;

use asynchronous_codec::{Decoder, Encoder, Framed};
use bytes::{Bytes, BytesMut};
use futures::future;
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::core::{InboundUpgrade, OutboundUpgrade, ProtocolName, UpgradeInfo};
use unsigned_varint::codec;

use crate::handler::{BitswapHandlerError, HandlerEvent};
use crate::BitswapMessage;

const MAX_BUF_SIZE: usize = 1024 * 1024 * 2;

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum ProtocolId {
    Legacy,
    Bitswap100,
    Bitswap110,
    Bitswap120,
}

impl ProtocolName for ProtocolId {
    fn protocol_name(&self) -> &[u8] {
        match self {
            ProtocolId::Legacy => b"/ipfs/bitswap",
            ProtocolId::Bitswap100 => b"/ipfs/bitswap/1.0.0",
            ProtocolId::Bitswap110 => b"/ipfs/bitswap/1.1.0",
            ProtocolId::Bitswap120 => b"/ipfs/bitswap/1.2.0",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolConfig {
    /// The bitswap protocols to listen on.
    pub protocol_ids: Vec<ProtocolId>,
    /// Maximum size of a packet.
    pub max_transmit_size: usize,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        ProtocolConfig {
            protocol_ids: vec![
                ProtocolId::Bitswap120,
                ProtocolId::Bitswap110,
                ProtocolId::Bitswap100,
                ProtocolId::Legacy,
            ],
            max_transmit_size: MAX_BUF_SIZE,
        }
    }
}

impl UpgradeInfo for ProtocolConfig {
    type Info = ProtocolId;
    type InfoIter = Vec<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocol_ids.clone()
    }
}

impl<TSocket> InboundUpgrade<TSocket> for ProtocolConfig
where
    TSocket: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Framed<TSocket, BitswapCodec>;
    type Error = BitswapHandlerError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    #[inline]
    fn upgrade_inbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        let mut length_codec = codec::UviBytes::default();
        length_codec.set_max_len(self.max_transmit_size);
        Box::pin(future::ok(Framed::new(
            socket,
            BitswapCodec::new(length_codec, protocol_id),
        )))
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for ProtocolConfig
where
    TSocket: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Framed<TSocket, BitswapCodec>;
    type Error = BitswapHandlerError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    #[inline]
    fn upgrade_outbound(self, socket: TSocket, protocol_id: Self::Info) -> Self::Future {
        let mut length_codec = codec::UviBytes::default();
        length_codec.set_max_len(self.max_transmit_size);
        Box::pin(future::ok(Framed::new(
            socket,
            BitswapCodec::new(length_codec, protocol_id),
        )))
    }
}

/// Bitswap codec for the framing
pub struct BitswapCodec {
    /// Codec to encode/decode the Unsigned varint length prefix of the frames.
    pub length_codec: codec::UviBytes,
    pub protocol: ProtocolId,
}

impl BitswapCodec {
    pub fn new(length_codec: codec::UviBytes, protocol: ProtocolId) -> Self {
        BitswapCodec {
            length_codec,
            protocol,
        }
    }
}

impl Encoder for BitswapCodec {
    type Item = BitswapMessage;
    type Error = BitswapHandlerError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let buf = item.into_bytes(self.protocol);

        // length prefix the protobuf message, ensuring the max limit is not hit
        self.length_codec
            .encode(Bytes::from(buf), dst)
            .map_err(|_| BitswapHandlerError::MaxTransmissionSize)
    }
}

impl Decoder for BitswapCodec {
    type Item = HandlerEvent;
    type Error = BitswapHandlerError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet = match self.length_codec.decode(src).map_err(|e| {
            if let std::io::ErrorKind::PermissionDenied = e.kind() {
                BitswapHandlerError::MaxTransmissionSize
            } else {
                BitswapHandlerError::Io(e)
            }
        })? {
            Some(p) => p,
            None => return Ok(None),
        };

        let message = BitswapMessage::from_bytes(self.protocol, &packet[..])?;

        Ok(Some(HandlerEvent::Message { message }))
    }
}

#[cfg(test)]
mod tests {
    use futures::prelude::*;
    use libp2p::core::upgrade;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::compat::*;

    use super::*;

    #[tokio::test]
    async fn test_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let server = async move {
            let (incoming, _) = listener.accept().await.unwrap();
            upgrade::apply_inbound(incoming.compat(), ProtocolConfig::default())
                .await
                .unwrap();
        };

        let client = async move {
            let stream = TcpStream::connect(&listener_addr).await.unwrap();
            upgrade::apply_outbound(
                stream.compat(),
                ProtocolConfig::default(),
                upgrade::Version::V1Lazy,
            )
            .await
            .unwrap();
        };

        future::select(Box::pin(server), Box::pin(client)).await;
    }
}

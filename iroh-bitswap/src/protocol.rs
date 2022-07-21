use core::future::Future;
use core::pin::Pin;
use std::io;
use std::time::Instant;

use bytes::BytesMut;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use futures::AsyncWriteExt;
use libp2p::core::{upgrade, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use tracing::trace;

use crate::error::BitswapError;
use crate::message::BitswapMessage;

const MAX_BUF_SIZE: usize = 1024 * 1024 * 2;

const PROTOCOLS: [&[u8]; 2] = [b"/ipfs/bitswap/1.1.0", b"/ipfs/bitswap/1.2.0"];

#[derive(Default, Clone, Debug)]
pub struct BitswapProtocol;

impl UpgradeInfo for BitswapProtocol {
    type Info = &'static [u8];
    type InfoIter = core::array::IntoIter<Self::Info, 2>;

    fn protocol_info(&self) -> Self::InfoIter {
        PROTOCOLS.into_iter()
    }
}

impl<TSocket> InboundUpgrade<TSocket> for BitswapProtocol
where
    TSocket: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = BitswapMessage;
    type Error = BitswapError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    #[inline]
    fn upgrade_inbound(self, mut socket: TSocket, info: Self::Info) -> Self::Future {
        Box::pin(async move {
            trace!("upgrade_inbound: {}", std::str::from_utf8(info).unwrap());
            let now = Instant::now();
            let packet = read_length_prefixed(&mut socket, MAX_BUF_SIZE).await?;
            let reading = now.elapsed();
            let len = packet.len();
            let message = BitswapMessage::from_bytes(packet)?;
            trace!(
                "upgrade_inbound_done {} in {}ms ({} blocks, {} wants) - reading {}ms",
                len,
                now.elapsed().as_millis(),
                message.blocks().len(),
                message.wantlist().blocks().count(),
                reading.as_millis(),
            );
            socket.close().await?;

            Ok(message)
        })
    }
}

pub async fn read_length_prefixed(
    socket: &mut (impl AsyncRead + Unpin),
    max_size: usize,
) -> io::Result<BytesMut> {
    let len = upgrade::read_varint(socket).await?;
    if len > max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Received data size ({} bytes) exceeds maximum ({} bytes)",
                len, max_size
            ),
        ));
    }

    let mut buf = BytesMut::new();
    buf.resize(len, 0);
    socket.read_exact(&mut buf).await?;

    Ok(buf)
}

impl UpgradeInfo for BitswapMessage {
    type Info = &'static [u8];
    type InfoIter = core::array::IntoIter<Self::Info, 2>;

    fn protocol_info(&self) -> Self::InfoIter {
        PROTOCOLS.into_iter()
    }
}

pub struct Upgrade;

impl<TSocket> OutboundUpgrade<TSocket> for BitswapMessage
where
    TSocket: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Upgrade;
    type Error = io::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    #[inline]
    fn upgrade_outbound(self, mut socket: TSocket, info: Self::Info) -> Self::Future {
        Box::pin(async move {
            trace!("upgrade_outbound: {}", std::str::from_utf8(info).unwrap());
            let bytes = self.into_bytes();
            let l = bytes.len();
            upgrade::write_length_prefixed(&mut socket, bytes).await?;
            trace!("upgrade_outbound_done {}", l);
            socket.close().await?;

            Ok(Upgrade)
        })
    }
}

#[cfg(test)]
mod tests {
    use futures::prelude::*;
    use libp2p::core::upgrade;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;

    #[tokio::test]
    async fn test_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let server = async move {
            let (incoming, _) = listener.accept().await.unwrap();
            let incoming = incoming.compat();
            upgrade::apply_inbound(incoming, BitswapProtocol::default())
                .await
                .unwrap();
        };

        let client = async move {
            let stream = TcpStream::connect(&listener_addr).await.unwrap().compat();
            upgrade::apply_outbound(stream, BitswapMessage::new(), upgrade::Version::V1Lazy)
                .await
                .unwrap();
        };

        future::select(Box::pin(server), Box::pin(client)).await;
    }
}

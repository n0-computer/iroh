//! The main event loop for the relay server.
//!
//! based on tailscale/derp/derp_server.go

use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use iroh_base::NodeId;
use iroh_metrics::inc;
use tracing::trace;

use crate::{
    defaults::timeouts::SERVER_WRITE_TIMEOUT as WRITE_TIMEOUT,
    server::{client_conn::ClientConnConfig, clients::Clients, metrics::Metrics},
};

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(super) struct Packet {
    /// The sender of the packet
    pub(super) src: NodeId,
    /// The data packet bytes.
    pub(super) data: Bytes,
}

/// The task for a running server actor.
///
/// Will forcefully abort the server actor loop when dropped.
/// For stopping gracefully, use [`ServerActorTask::close`].
///
/// Responsible for managing connections to a relay, sending packets from one client to another.
#[derive(Debug)]
pub(super) struct ServerActorTask {
    /// Specifies how long to wait before failing when writing to a client.
    pub(super) write_timeout: Duration,
    /// All clients connected to this server
    pub(super) clients: Clients, // TODO: look into lock free structure
}

impl Default for ServerActorTask {
    fn default() -> Self {
        Self {
            write_timeout: WRITE_TIMEOUT,
            clients: Clients::default(),
        }
    }
}
impl ServerActorTask {
    pub(super) async fn create_client(&self, client_builder: ClientConnConfig) -> Result<()> {
        inc!(Metrics, accepts);
        let node_id = client_builder.node_id;
        trace!(node_id = node_id.fmt_short(), "create client");

        // build and register client, starting up read & write loops for the client
        // connection
        self.clients.register(client_builder).await;
        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use bytes::Bytes;
//     use iroh_base::SecretKey;
//     use tokio::io::DuplexStream;
//     use tokio_util::codec::Framed;

//     use super::*;
//     use crate::{
//         protos::relay::{recv_frame, Frame, FrameType, RelayCodec},
//         server::{
//             client_conn::ClientConnConfig,
//             streams::{MaybeTlsStream, RelayedStream},
//         },
//     };

//     fn test_client_builder(
//         node_id: NodeId,
//         server_channel: mpsc::Sender<Message>,
//     ) -> (ClientConnConfig, Framed<DuplexStream, RelayCodec>) {
//         let (test_io, io) = tokio::io::duplex(1024);
//         (
//             ClientConnConfig {
//                 node_id,
//                 stream: RelayedStream::Relay(Framed::new(
//                     MaybeTlsStream::Test(io),
//                     RelayCodec::test(),
//                 )),
//                 write_timeout: Duration::from_secs(1),
//                 channel_capacity: 10,
//                 rate_limit: None,
//                 // server_channel,
//             },
//             Framed::new(test_io, RelayCodec::test()),
//         )
//     }

//     #[tokio::test]
//     async fn test_server_actor() -> Result<()> {
//         // make server actor
//         let (server_channel, server_channel_r) = mpsc::channel(20);
//         let server_actor: Actor = Actor::new(server_channel_r);
//         let done = CancellationToken::new();
//         let server_done = done.clone();

//         // run server actor
//         let server_task = tokio::spawn(
//             async move { server_actor.run(server_done).await }
//                 .instrument(info_span!("relay.server")),
//         );

//         let node_id_a = SecretKey::generate(rand::thread_rng()).public();
//         let (client_a, mut a_io) = test_client_builder(node_id_a, server_channel.clone());

//         // create client a
//         server_channel
//             .send(Message::CreateClient(client_a))
//             .await
//             .map_err(|_| anyhow::anyhow!("server gone"))?;

//         // server message: create client b
//         let node_id_b = SecretKey::generate(rand::thread_rng()).public();
//         let (client_b, mut b_io) = test_client_builder(node_id_b, server_channel.clone());
//         server_channel
//             .send(Message::CreateClient(client_b))
//             .await
//             .map_err(|_| anyhow::anyhow!("server gone"))?;

//         // write message from b to a
//         let msg = b"hello world!";
//         crate::client::conn::send_packet(&mut b_io, node_id_a, Bytes::from_static(msg)).await?;

//         // get message on a's reader
//         let frame = recv_frame(FrameType::RecvPacket, &mut a_io).await?;
//         assert_eq!(
//             frame,
//             Frame::RecvPacket {
//                 src_key: node_id_b,
//                 content: msg.to_vec().into()
//             }
//         );

//         // remove b
//         server_channel
//             .send(Message::RemoveClient {
//                 node_id: node_id_b,
//                 conn_num: 1,
//             })
//             .await
//             .map_err(|_| anyhow::anyhow!("server gone"))?;

//         // get the nodes gone message on a about b leaving the network
//         // (we get this message because b has sent us a packet before)
//         let frame = recv_frame(FrameType::PeerGone, &mut a_io).await?;
//         assert_eq!(Frame::NodeGone { node_id: node_id_b }, frame);

//         // close gracefully
//         done.cancel();
//         server_task.await??;
//         Ok(())
//     }
// }

//! Types that are shared between [`super::actor`] and [`super::client_conn`].

use bytes::Bytes;

use crate::key::PublicKey;
use crate::relay::server::client_conn::ClientConnBuilder;

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    /// The sender of the packet
    pub(crate) src: PublicKey,
    /// The data packet bytes.
    pub(crate) bytes: Bytes,
}

#[derive(derive_more::Debug)]
pub(crate) enum ServerMessage {
    SendPacket((PublicKey, Packet)),
    SendDiscoPacket((PublicKey, Packet)),
    #[debug("CreateClient")]
    CreateClient(ClientConnBuilder),
    RemoveClient((PublicKey, usize)),
    Shutdown,
}

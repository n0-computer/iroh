use async_trait::async_trait;
use bytecheck::CheckBytes;
use futures::prelude::*;
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
use libp2p::request_response::{
    ProtocolSupport, RequestResponse, RequestResponseCodec, RequestResponseEvent, ResponseChannel,
};
use rkyv;
use rkyv::{Archive, Deserialize, Serialize};
use std::iter;
use tokio::io;

use crate::error::RPCError;
use crate::stream::{Header, Packet};

pub type CoreBehaviour = RequestResponse<CoreCodec>;
pub type CoreEvent = RequestResponseEvent<CoreRequest, CoreResponse>;
pub type CoreResponseChannel = ResponseChannel<CoreResponse>;

pub fn new_core_behaviour() -> CoreBehaviour {
    RequestResponse::new(
        CoreCodec(),
        iter::once((CoreProtocol(), ProtocolSupport::Full)),
        Default::default(),
    )
}

// Events are how one server communicates with another
#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum CoreRequestEvent {
    Request {
        // When Some(u64), the stream_id is used to coordinate future incoming packets
        stream_id: Option<u64>,
        namespace: String,
        method: String,
        params: Vec<u8>,
    },
    Packet(Packet),
}

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum CoreResponseEvent {
    RPCError(RPCError),
    Payload(Vec<u8>),
    Header(Header),
    Ack,
}

#[derive(Debug, Clone)]
pub struct CoreProtocol();
#[derive(Clone)]
pub struct CoreCodec();
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreRequest(pub CoreRequestEvent);
#[derive(Debug)]
pub struct CoreResponse(pub CoreResponseEvent);

impl ProtocolName for CoreProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/iroh/v1/core/v1".as_bytes()
    }
}

const CHUNK_SIZE: usize = 8192;

#[async_trait]
impl RequestResponseCodec for CoreCodec {
    type Protocol = CoreProtocol;
    type Request = CoreRequest;
    type Response = CoreResponse;

    async fn read_request<T>(&mut self, _: &CoreProtocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // TODO: check to see if we can just use rkyv to read from the wire
        let vec = read_length_prefixed(io, CHUNK_SIZE).await?;
        // Need to better understand rkyv and our options to make serializing & deserializing
        // more specific and efficient
        let event = rkyv::check_archived_root::<CoreRequestEvent>(&vec)
            .expect("RPCError converting bytes to archived CoreRequest")
            .deserialize(&mut rkyv::Infallible)
            .expect("RPCError deserializing CoreResponse.");
        Ok(CoreRequest(event))
    }

    async fn read_response<T>(&mut self, _: &CoreProtocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, CHUNK_SIZE).await?;
        let event = rkyv::check_archived_root::<CoreResponseEvent>(&vec)
            .expect("Error converting read bytes to archived ResponseEvent")
            .deserialize(&mut rkyv::Infallible)
            .expect("Error deserializing Response");
        Ok(CoreResponse(event))
    }

    async fn write_request<T>(
        &mut self,
        _: &CoreProtocol,
        io: &mut T,
        CoreRequest(data): CoreRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Need to better understand rkyv and our options to make serializing & deserializing
        // more specific and efficient
        let vec = rkyv::to_bytes::<_, 1024>(&data).expect("Error serializing Request.");
        write_length_prefixed(io, vec).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &CoreProtocol,
        io: &mut T,
        CoreResponse(data): CoreResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Need to better understand rkyv and our options to make serializing & deserializing
        // more specific and efficient
        let vec = rkyv::to_bytes::<_, 1024>(&data).expect("Error serializing Response.");
        write_length_prefixed(io, vec).await?;
        io.close().await?;
        Ok(())
    }
}

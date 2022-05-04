use std::iter;

use async_trait::async_trait;
use bytecheck::CheckBytes;
use futures::prelude::*;
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
use libp2p::request_response::{
    ProtocolSupport, RequestResponse, RequestResponseCodec, RequestResponseEvent, ResponseChannel,
};
use rkyv;
use rkyv::{Archive, Deserialize, Serialize};
use tokio::io;

use crate::error::RpcError;
use crate::stream::{Header, Packet};

pub type RpcBehaviour = RequestResponse<RpcCodec>;
pub type RpcEvent = RequestResponseEvent<RpcRequest, RpcResponse>;
pub type RpcResponseChannel = ResponseChannel<RpcResponse>;

pub fn new_behaviour() -> RpcBehaviour {
    RequestResponse::new(
        RpcCodec(),
        iter::once((RpcProtocol(), ProtocolSupport::Full)),
        Default::default(),
    )
}

// Events are how one server communicates with another
#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum RpcRequestEvent {
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
pub enum RpcResponseEvent {
    RpcError(RpcError),
    Payload(Vec<u8>),
    Header(Header),
    Ack,
}

#[derive(Debug, Clone)]
pub struct RpcProtocol();
#[derive(Clone)]
pub struct RpcCodec();
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcRequest(pub RpcRequestEvent);
#[derive(Debug)]
pub struct RpcResponse(pub RpcResponseEvent);

impl ProtocolName for RpcProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/iroh/rpc/1.0.0".as_bytes()
    }
}

const CHUNK_SIZE: usize = 8192;

#[async_trait]
impl RequestResponseCodec for RpcCodec {
    type Protocol = RpcProtocol;
    type Request = RpcRequest;
    type Response = RpcResponse;

    async fn read_request<T>(&mut self, _: &RpcProtocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // TODO: check to see if we can just use rkyv to read from the wire
        let vec = read_length_prefixed(io, CHUNK_SIZE).await?;
        // Need to better understand rkyv and our options to make serializing & deserializing
        // more specific and efficient
        let event = rkyv::check_archived_root::<RpcRequestEvent>(&vec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let event = event
            .deserialize(&mut rkyv::Infallible)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(RpcRequest(event))
    }

    async fn read_response<T>(&mut self, _: &RpcProtocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, CHUNK_SIZE).await?;
        let event = rkyv::check_archived_root::<RpcResponseEvent>(&vec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let event = event
            .deserialize(&mut rkyv::Infallible)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(RpcResponse(event))
    }

    async fn write_request<T>(
        &mut self,
        _: &RpcProtocol,
        io: &mut T,
        RpcRequest(data): RpcRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Need to better understand rkyv and our options to make serializing & deserializing
        // more specific and efficient
        let vec = rkyv::to_bytes::<_, 1024>(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_length_prefixed(io, vec).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &RpcProtocol,
        io: &mut T,
        RpcResponse(data): RpcResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Need to better understand rkyv and our options to make serializing & deserializing
        // more specific and efficient
        let vec = rkyv::to_bytes::<_, 1024>(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_length_prefixed(io, vec).await?;
        io.close().await?;
        Ok(())
    }
}

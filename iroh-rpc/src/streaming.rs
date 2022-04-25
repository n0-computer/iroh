use async_trait::async_trait;
use bytecheck::CheckBytes;
use futures::prelude::*;
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
use libp2p::request_response;
use rkyv;
use rkyv::{Archive, Deserialize, Serialize};
use std::iter;
use tokio::io;

use crate::stream::{Header, Packet, StreamError};

pub type Streaming = request_response::RequestResponse<StreamingCodec>;
pub type StreamingEvent =
    request_response::RequestResponseEvent<StreamingRequest, StreamingResponse>;
pub type StreamingResponseChannel = request_response::ResponseChannel<StreamingResponse>;

pub fn new_streaming_behaviour() -> Streaming {
    request_response::RequestResponse::new(
        StreamingCodec(),
        // TODO: see how much quicker if we only support requests
        iter::once((StreamingProtocol(), request_response::ProtocolSupport::Full)),
        Default::default(),
    )
}

// Events are how one server communicates with another
#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum StreamingRequestEvent {
    DataRequest { id: u64, resource_id: String },
    Packet(Packet),
}

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum StreamingResponseEvent {
    Header(Header),
    StreamError(StreamError),
    Ack,
}

#[derive(Debug, Clone)]
pub struct StreamingProtocol();
#[derive(Clone)]
pub struct StreamingCodec();
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingRequest(pub StreamingRequestEvent);
#[derive(Debug)]
pub struct StreamingResponse(pub StreamingResponseEvent);

impl ProtocolName for StreamingProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/iroh/v1/stream/v1".as_bytes()
    }
}

const CHUNK_SIZE: usize = 8192;

#[async_trait]
impl request_response::RequestResponseCodec for StreamingCodec {
    type Protocol = StreamingProtocol;
    type Request = StreamingRequest;
    type Response = StreamingResponse;

    async fn read_request<T>(
        &mut self,
        _: &StreamingProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // TODO: check to see if we can just use rkyv to read from the wire
        let vec = read_length_prefixed(io, CHUNK_SIZE).await?;
        // Need to better understand rkyv and our options to make serializing & deserializing
        // more specific and efficient
        let event = rkyv::check_archived_root::<StreamingRequestEvent>(&vec)
            .expect("Error converting bytes to archived CoreRequest")
            .deserialize(&mut rkyv::Infallible)
            .expect("Error deserializing CoreResponse.");
        Ok(StreamingRequest(event))
    }

    async fn read_response<T>(
        &mut self,
        _: &StreamingProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let data = read_length_prefixed(io, CHUNK_SIZE).await?;
        let event = rkyv::check_archived_root::<StreamingResponseEvent>(&data)
            .expect("Error converting read bytes to archived ResponseEvent")
            .deserialize(&mut rkyv::Infallible)
            .expect("Error deserializing Response");
        Ok(StreamingResponse(event))
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamingProtocol,
        io: &mut T,
        StreamingRequest(data): Self::Request,
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
        _: &StreamingProtocol,
        io: &mut T,
        StreamingResponse(data): Self::Response,
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

use async_trait::async_trait;
use bytecheck::CheckBytes;
use futures::prelude::*;
use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
use libp2p::request_response;
use rkyv;
use rkyv::{Archive, Deserialize, Serialize};
use std::iter;
use tokio::io;

pub type RequestResponse = request_response::RequestResponse<RequestResponseCodec>;
pub type RequestResponseEvent = request_response::RequestResponseEvent<Request, Response>;
pub type ResponseChannel = request_response::ResponseChannel<Response>;

pub fn new_request_response_behaviour() -> RequestResponse {
    request_response::RequestResponse::new(
        RequestResponseCodec(),
        iter::once((
            RequestResponseProtocol(),
            request_response::ProtocolSupport::Full,
        )),
        Default::default(),
    )
}

// Events are how one server communicates with another
#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum RequestEvent {
    Ping,
}

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum ResponseEvent {
    Pong,
}

#[derive(Debug, Clone)]
pub struct RequestResponseProtocol();
#[derive(Clone)]
pub struct RequestResponseCodec();
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request(pub RequestEvent);
#[derive(Debug)]
pub struct Response(pub ResponseEvent);

impl ProtocolName for RequestResponseProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/iroh/v1/request_response/v1".as_bytes()
    }
}

const CHUNK_SIZE: usize = 8192;

#[async_trait]
impl request_response::RequestResponseCodec for RequestResponseCodec {
    type Protocol = RequestResponseProtocol;
    type Request = Request;
    type Response = Response;

    async fn read_request<T>(
        &mut self,
        _: &RequestResponseProtocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // TODO: check to see if we can just use rkyv to read from the wire
        let vec = read_length_prefixed(io, CHUNK_SIZE).await?;
        // Need to better understand rkyv and our options to make serializing & deserializing
        // more specific and efficient
        let event = rkyv::check_archived_root::<RequestEvent>(&vec)
            .expect("Error converting bytes to archived CoreRequest")
            .deserialize(&mut rkyv::Infallible)
            .expect("Error deserializing CoreResponse.");
        Ok(Request(event))
    }

    async fn read_response<T>(
        &mut self,
        _: &RequestResponseProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let data = read_length_prefixed(io, CHUNK_SIZE).await?;
        let event = rkyv::check_archived_root::<ResponseEvent>(&data)
            .expect("Error converting read bytes to archived ResponseEvent")
            .deserialize(&mut rkyv::Infallible)
            .expect("Error deserializing Response");
        Ok(Response(event))
    }

    async fn write_request<T>(
        &mut self,
        _: &RequestResponseProtocol,
        io: &mut T,
        Request(data): Request,
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
        _: &RequestResponseProtocol,
        io: &mut T,
        Response(data): Response,
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
